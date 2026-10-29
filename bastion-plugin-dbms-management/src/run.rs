//! Asynchronous runs (§6.2, §6.3): the statements of one `execute`, run in
//! the background between invocations, with a bounded page buffer the
//! client drains through `runs/<id>`. The producer stops reading from the
//! database while the buffer is full, so a large result is never held.

use std::collections::VecDeque;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::Notify;
use zeroize::Zeroize;

use crate::authz::{AuthorizedStatement, StatementMeta};
use crate::driver::{DbError, PgConn};
use crate::values::{self, Cell};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Running,
    Done,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// How one statement of the run ended (for the message pane, the audit
/// event and the journal).
#[derive(Debug, Clone)]
pub struct StatementResult {
    pub meta: StatementMeta,
    pub outcome: &'static str,
    pub rows_affected: Option<u64>,
    pub rows_returned: u64,
    pub duration_ms: u64,
    pub error: Option<DbError>,
    /// The grid cap or the row budget stopped the read.
    pub truncated: bool,
}

impl StatementResult {
    /// The message-pane entry. The database's own message is returned to
    /// the caller (it may echo values, so it is never stored, §11).
    pub fn message(&self) -> Value {
        json!({
            "index": self.meta.index,
            "kind": self.meta.kind_name(),
            "outcome": self.outcome,
            "rows_affected": self.rows_affected,
            "rows_returned": self.rows_returned,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "error": self.error.as_ref().map(|e| json!({"sqlstate": e.sqlstate, "message": e.message})),
        })
    }
}

/// Limits a run applies (§12).
#[derive(Debug, Clone, Copy)]
pub struct RunLimits {
    pub deadline: Duration,
    pub page_rows: usize,
    pub page_bytes: usize,
    pub grid_rows: u64,
    /// Rows the session may still read through the grid; `None` = no budget.
    pub budget_left: Option<u64>,
}

struct Buffered {
    cells: Vec<Value>,
    bytes: usize,
    truncated: Vec<(usize, usize)>,
}

struct State {
    status: RunStatus,
    statement_index: Option<usize>,
    columns: Vec<Value>,
    buffer: VecDeque<Buffered>,
    buffered_bytes: usize,
    rows_total: u64,
    results: Vec<StatementResult>,
    /// Results not yet handed to audit and journal.
    unreported: usize,
    finished: Option<Instant>,
    budget_exhausted: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        // Pages are zeroized when the run is dropped (§6.3).
        for row in self.buffer.iter_mut() {
            row.cells.iter_mut().for_each(scrub);
        }
    }
}

fn scrub(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::Object(m) => m.values_mut().for_each(scrub),
        _ => {}
    }
}

pub struct Run {
    pub id: String,
    pub started: Instant,
    limits: RunLimits,
    state: Mutex<State>,
    space: Notify,
    cancel: Notify,
    cancelled: AtomicBool,
}

impl Run {
    pub fn new(id: String, limits: RunLimits) -> Arc<Self> {
        Arc::new(Self {
            id,
            started: Instant::now(),
            limits,
            state: Mutex::new(State {
                status: RunStatus::Running,
                statement_index: None,
                columns: Vec::new(),
                buffer: VecDeque::new(),
                buffered_bytes: 0,
                rows_total: 0,
                results: Vec::new(),
                unreported: 0,
                finished: None,
                budget_exhausted: false,
            }),
            space: Notify::new(),
            cancel: Notify::new(),
            cancelled: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn status(&self) -> RunStatus {
        self.lock().status
    }

    pub fn finished_at(&self) -> Option<Instant> {
        self.lock().finished
    }

    pub fn rows_total(&self) -> u64 {
        self.lock().rows_total
    }

    /// Ask the producer to stop; it sends the database a `CancelRequest`.
    pub fn request_cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.cancel.notify_one();
        self.space.notify_one();
    }

    pub fn is_cancel_requested(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Results finished since the last call (audit and journal).
    pub fn take_unreported(&self) -> Vec<StatementResult> {
        let mut st = self.lock();
        let from = st.unreported;
        st.unreported = st.results.len();
        st.results[from..].to_vec()
    }

    pub fn budget_exhausted(&self) -> bool {
        self.lock().budget_exhausted
    }

    /// The next page and the run's state; frees buffer space.
    pub fn page(&self) -> Value {
        let mut st = self.lock();
        let mut rows = Vec::new();
        let mut truncated = Vec::new();
        let mut bytes = 0usize;
        while let Some(front) = st.buffer.front() {
            if !rows.is_empty() && (rows.len() >= self.limits.page_rows || bytes + front.bytes > self.limits.page_bytes)
            {
                break;
            }
            let Some(row) = st.buffer.pop_front() else { break };
            st.buffered_bytes -= row.bytes;
            bytes += row.bytes;
            for (col, full) in &row.truncated {
                truncated.push(json!({"row": rows.len(), "column": col, "full_length": full}));
            }
            rows.push(Value::Array(row.cells.clone()));
        }
        let has_more = !st.buffer.is_empty() || st.status == RunStatus::Running;
        let out = json!({
            "run_id": self.id,
            "state": st.status.as_str(),
            "statement_index": st.statement_index,
            "columns": st.columns,
            "rows": rows,
            "truncated_cells": truncated,
            "has_more": has_more,
            "rows_read": st.rows_total,
            "row_budget_exhausted": st.budget_exhausted,
            "messages": st.results.iter().map(StatementResult::message).collect::<Vec<_>>(),
            "elapsed_ms": self.started.elapsed().as_millis() as u64,
        });
        drop(st);
        self.space.notify_one();
        out
    }

    fn push_row(&self, cells: Vec<Value>, truncated: Vec<(usize, usize)>) -> bool {
        let bytes = cells.iter().map(|c| c.to_string().len() + 1).sum::<usize>() + 2;
        let mut st = self.lock();
        st.buffered_bytes += bytes;
        st.rows_total += 1;
        st.buffer.push_back(Buffered { cells, bytes, truncated });
        st.buffer.len() >= self.limits.page_rows || st.buffered_bytes >= self.limits.page_bytes
    }

    fn finish(&self, status: RunStatus) {
        let mut st = self.lock();
        if st.status == RunStatus::Running {
            st.status = status;
        }
        st.finished = Some(Instant::now());
    }
}

/// What the producer reports back to the session when it is done.
pub struct RunEnd {
    pub context_changed: bool,
    pub rows_read: u64,
}

/// Run `stmts` on `conn`, in order, stopping at the first error (§8.2
/// `on_error: stop`). Every statement reaches the driver only through
/// `send_authorized`.
pub async fn produce(conn: Arc<PgConn>, run: Arc<Run>, stmts: Vec<AuthorizedStatement>) -> RunEnd {
    let deadline = tokio::time::Instant::now() + run.limits.deadline;
    let mut end = RunEnd { context_changed: false, rows_read: 0 };
    let mut failed = false;
    for stmt in stmts {
        let meta = stmt.meta().clone();
        if run.is_cancel_requested() {
            break;
        }
        end.context_changed |= meta.changes_context();
        let t0 = Instant::now();
        let mut result = StatementResult {
            meta: meta.clone(),
            outcome: "ok",
            rows_affected: None,
            rows_returned: 0,
            duration_ms: 0,
            error: None,
            truncated: false,
        };
        let sent = tokio::select! {
            r = conn.send_authorized(stmt) => Some(r),
            _ = tokio::time::sleep_until(deadline) => None,
            _ = run.cancel.notified() => None,
        };
        match sent {
            None => {
                let _ = conn.cancel().await;
                result.outcome = if run.is_cancel_requested() { "cancelled" } else { "timeout" };
                failed = true;
            }
            Some(Err(e)) => {
                result.outcome = "error";
                result.error = Some(e);
                failed = true;
            }
            Some(Ok(q)) => {
                if !q.columns.is_empty() {
                    let mut st = run.lock();
                    st.statement_index = Some(meta.index);
                    st.columns = q
                        .columns
                        .iter()
                        .map(|(name, ty)| json!({"name": name, "type": ty.name(), "kind": values::kind(ty)}))
                        .collect();
                }
                let mut rows = pin!(q.rows);
                let mut cancel_sent = false;
                loop {
                    let next = tokio::select! {
                        r = rows.next() => r,
                        _ = tokio::time::sleep_until(deadline), if !cancel_sent => {
                            let _ = conn.cancel().await;
                            cancel_sent = true;
                            result.outcome = "timeout";
                            continue;
                        }
                        _ = run.cancel.notified(), if !cancel_sent => {
                            let _ = conn.cancel().await;
                            cancel_sent = true;
                            result.outcome = "cancelled";
                            continue;
                        }
                    };
                    let row = match next {
                        None => break,
                        Some(Err(e)) => {
                            if !cancel_sent {
                                result.outcome = "error";
                                result.error = Some(DbError::from(e));
                            }
                            failed = true;
                            break;
                        }
                        Some(Ok(row)) => row,
                    };
                    if cancel_sent {
                        continue; // draining until the server acknowledges
                    }
                    let mut cells = Vec::with_capacity(row.len());
                    let mut cut = Vec::new();
                    for i in 0..row.len() {
                        let v = row.try_get::<_, Cell>(i).map(|c| c.0).unwrap_or(Value::Null);
                        let (v, full) = values::cap(v);
                        if let Some(full) = full {
                            cut.push((i, full));
                        }
                        cells.push(v);
                    }
                    result.rows_returned += 1;
                    end.rows_read += 1;
                    let full = run.push_row(cells, cut);
                    let budget_hit = run.limits.budget_left.is_some_and(|b| end.rows_read >= b);
                    if result.rows_returned >= run.limits.grid_rows || budget_hit {
                        // Stop reading: the cap is reached, the rest stays on the server.
                        let _ = conn.cancel().await;
                        cancel_sent = true;
                        result.truncated = true;
                        if budget_hit {
                            run.lock().budget_exhausted = true;
                        }
                        continue;
                    }
                    if full {
                        tokio::select! {
                            _ = run.space.notified() => {}
                            _ = tokio::time::sleep_until(deadline) => {}
                        }
                    }
                }
                result.rows_affected = rows.rows_affected();
                if cancel_sent && result.truncated {
                    result.outcome = "ok";
                    failed = false;
                } else if cancel_sent {
                    failed = true;
                }
            }
        }
        result.duration_ms = t0.elapsed().as_millis() as u64;
        run.lock().results.push(result);
        if failed {
            break;
        }
    }
    let status = if run.is_cancel_requested() {
        RunStatus::Cancelled
    } else if failed {
        RunStatus::Failed
    } else {
        RunStatus::Done
    };
    run.finish(status);
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(page_rows: usize, page_bytes: usize) -> RunLimits {
        RunLimits { deadline: Duration::from_secs(5), page_rows, page_bytes, grid_rows: 100, budget_left: None }
    }

    #[test]
    fn pages_respect_rows_and_bytes_and_free_space() {
        let run = Run::new("r1".into(), limits(2, 1_000_000));
        for i in 0..5 {
            run.push_row(vec![json!(i)], vec![]);
        }
        let p = run.page();
        assert_eq!(p["rows"].as_array().unwrap().len(), 2);
        assert_eq!(p["has_more"], true);
        let run = Run::new("r2".into(), limits(100, 10));
        run.push_row(vec![json!("aaaaaaaaaaaa")], vec![]);
        run.push_row(vec![json!("b")], vec![]);
        assert_eq!(run.page()["rows"].as_array().unwrap().len(), 1, "one oversized row still makes a page");
    }

    #[test]
    fn finished_runs_report_and_buffers_signal_full() {
        let run = Run::new("r3".into(), limits(1, 1_000_000));
        assert!(run.push_row(vec![json!(1)], vec![(0, 70_000)]));
        run.finish(RunStatus::Done);
        let p = run.page();
        assert_eq!(p["state"], "done");
        assert_eq!(p["truncated_cells"][0]["full_length"], 70_000);
        assert_eq!(p["has_more"], false);
        run.finish(RunStatus::Failed);
        assert_eq!(run.status(), RunStatus::Done, "the first final state sticks");
    }
}
