//! Export jobs (features/sql-browser.md §8.1): one authorized SELECT,
//! rendered as CSV (RFC 4180, formula guard on by default), JSON Lines or
//! SQL `INSERT`s, streamed from the database cursor into a bounded buffer
//! the client drains in 1 MiB chunks. Nothing is written to disk: the
//! producer stops reading from the database while the buffer is full, and
//! the buffer is zeroized when the job is dropped. The SHA-256 of the exact
//! byte stream the client receives is computed as it is produced.

use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bv_sql_guard::sql;
use futures_util::StreamExt;
use serde_json::{json, Map, Value};
use tokio::sync::Notify;
use tokio_postgres::types::Type;
use zeroize::Zeroize;

use crate::api::ApiError;
use crate::authz::AuthorizedStatement;
use crate::driver::{DbError, PgConn, PluginSql, TextParam};
use crate::values::{self, Cell};

/// One pull returns at most this many bytes (§8.1).
pub const CHUNK_BYTES: usize = 1024 * 1024;
/// The producer pauses while this much is waiting to be pulled.
pub const HIGH_WATER_BYTES: usize = 2 * CHUNK_BYTES;
/// Longest identifier part accepted for an `INSERT` target.
const MAX_TARGET_PART: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Jsonl,
    SqlInsert,
}

impl Format {
    pub fn parse(v: Option<&Value>) -> Result<Self, ApiError> {
        match v.and_then(Value::as_str) {
            Some("csv") => Ok(Self::Csv),
            Some("jsonl") => Ok(Self::Jsonl),
            Some("sql-insert") => Ok(Self::SqlInsert),
            _ => Err(ApiError::bad_request("`format` is csv, jsonl or sql-insert")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Jsonl => "jsonl",
            Self::SqlInsert => "sql-insert",
        }
    }
}

/// The table an `INSERT` export writes into: `schema` is optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertTarget {
    pub schema: Option<String>,
    pub name: String,
}

impl InsertTarget {
    /// `{schema?, name}`, each 1-128 printable characters.
    pub fn parse(v: &Value) -> Result<Self, ApiError> {
        let o = v.as_object().ok_or_else(|| ApiError::bad_request("`table` must be {schema?, name}"))?;
        if o.keys().any(|k| k != "schema" && k != "name") {
            return Err(ApiError::bad_request("`table` has only `schema` and `name`"));
        }
        let part = |k: &str| -> Result<Option<String>, ApiError> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s))
                    if !s.is_empty() && s.len() <= MAX_TARGET_PART && !s.chars().any(char::is_control) =>
                {
                    Ok(Some(s.clone()))
                }
                Some(_) => {
                    Err(ApiError::bad_request(format!("`table.{k}` must be 1-{MAX_TARGET_PART} printable characters")))
                }
            }
        };
        let name = part("name")?.ok_or_else(|| ApiError::bad_request("`table.name` is required"))?;
        Ok(Self { schema: part("schema")?, name })
    }

    fn sql(&self) -> String {
        match &self.schema {
            Some(s) => format!("{}.{}", quote_ident(s), quote_ident(&self.name)),
            None => quote_ident(&self.name),
        }
    }
}

/// How the rows are written.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub format: Format,
    /// CSV only: prefix `'` to a text cell that a spreadsheet would read as
    /// a formula (§8.1). On unless the request turns it off.
    pub formula_guard: bool,
    /// `sql-insert` only.
    pub target: Option<InsertTarget>,
}

/// One result column, as the renderer needs it.
#[derive(Debug, Clone)]
pub struct Col {
    pub name: String,
    /// A database number: written as is, never formula-guarded.
    pub numeric: bool,
    /// `bytea`: base64 in CSV / JSON Lines, `decode(…, 'base64')` in SQL.
    pub bytea: bool,
}

impl Col {
    pub fn new(name: &str, ty: &Type) -> Self {
        Self { name: name.to_string(), numeric: values::is_numeric(ty), bytea: values::is_bytea(ty) }
    }
}

/// `"name"`, with `"` doubled.
pub fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// `'text'`, with `'` doubled (standard_conforming_strings = on, which the
/// file's header sets).
pub fn quote_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A CSV text field: always quoted (so `""` is the empty string and an
/// empty field is NULL), `"` doubled, and with the formula guard a leading
/// `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`.
pub fn csv_text(s: &str, guard: bool) -> String {
    let mut out = String::with_capacity(s.len() + 3);
    out.push('"');
    if guard && s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        out.push('\'');
    }
    for ch in s.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

fn plain_number(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && digits.bytes().filter(|b| *b == b'.').count() <= 1
        && digits.bytes().any(|b| b.is_ascii_digit())
}

fn base64_text(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Renders the header and each row of one result in one format.
pub struct Renderer {
    opts: ExportOptions,
    cols: Vec<Col>,
    /// JSON Lines keys: the column names, a repeated name suffixed `_2`, …
    keys: Vec<String>,
}

impl Renderer {
    pub fn new(opts: ExportOptions, cols: Vec<Col>) -> Self {
        let mut keys: Vec<String> = Vec::with_capacity(cols.len());
        for c in &cols {
            let mut key = c.name.clone();
            let mut n = 1;
            while keys.contains(&key) {
                n += 1;
                key = format!("{}_{n}", c.name);
            }
            keys.push(key);
        }
        Self { opts, cols, keys }
    }

    /// What precedes the rows: the CSV header line, or the SQL file's
    /// settings. JSON Lines has none.
    pub fn header(&self) -> Vec<u8> {
        match self.opts.format {
            Format::Csv => {
                let line: Vec<String> = self.cols.iter().map(|c| csv_text(&c.name, self.opts.formula_guard)).collect();
                format!("{}\r\n", line.join(",")).into_bytes()
            }
            Format::Jsonl => Vec::new(),
            Format::SqlInsert => {
                b"-- BastionVault SQL browser export (sql-insert)\nSET standard_conforming_strings = on;\n".to_vec()
            }
        }
    }

    pub fn row(&self, cells: &[Value]) -> Vec<u8> {
        match self.opts.format {
            Format::Csv => {
                let fields: Vec<String> = self.cols.iter().zip(cells).map(|(c, v)| self.csv_cell(c, v)).collect();
                format!("{}\r\n", fields.join(",")).into_bytes()
            }
            Format::Jsonl => {
                let mut line = String::from("{");
                for (i, (k, v)) in self.keys.iter().zip(cells).enumerate() {
                    if i > 0 {
                        line.push(',');
                    }
                    line.push_str(&Value::String(k.clone()).to_string());
                    line.push(':');
                    line.push_str(&v.to_string());
                }
                line.push_str("}\n");
                line.into_bytes()
            }
            Format::SqlInsert => {
                let target = self.opts.target.as_ref().map(InsertTarget::sql).unwrap_or_default();
                let names: Vec<String> = self.cols.iter().map(|c| quote_ident(&c.name)).collect();
                let lits: Vec<String> = self.cols.iter().zip(cells).map(|(c, v)| sql_literal(c, v)).collect();
                format!("INSERT INTO {target} ({}) VALUES ({});\n", names.join(", "), lits.join(", ")).into_bytes()
            }
        }
    }

    fn csv_cell(&self, c: &Col, v: &Value) -> String {
        match v {
            Value::Null => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) if c.numeric => s.clone(),
            Value::String(s) => csv_text(s, self.opts.formula_guard),
            other => csv_text(&other.to_string(), self.opts.formula_guard),
        }
    }
}

fn sql_literal(c: &Col, v: &Value) -> String {
    match v {
        Value::Null => "NULL".into(),
        Value::Bool(true) => "TRUE".into(),
        Value::Bool(false) => "FALSE".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) if c.numeric && plain_number(s) => s.clone(),
        Value::String(s) if c.bytea && base64_text(s) => format!("decode('{s}', 'base64')"),
        Value::String(s) => quote_literal(s),
        other => quote_literal(&other.to_string()),
    }
}

// ── the job ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Done,
    /// The row or byte limit stopped the read; the stream is complete up
    /// to it and says so.
    LimitReached(&'static str),
    Failed,
    Cancelled,
    /// Nobody pulled for `export_idle_secs` (§8.1: abandoned).
    Expired,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Done => "done",
            Self::LimitReached(_) => "limit_reached",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

/// Limits of one export (§12).
#[derive(Debug, Clone, Copy)]
pub struct ExportLimits {
    pub max_rows: u64,
    pub max_bytes: u64,
    /// The database statement timeout while the export streams, and the
    /// plugin's own deadline for it.
    pub deadline: Duration,
}

struct JobState {
    status: JobStatus,
    /// Rendered and not yet pulled.
    buf: Vec<u8>,
    /// Stream offset of `buf[0]`.
    next_offset: u64,
    /// The last chunk handed out, for a pull that is retried.
    last: Option<(u64, Vec<u8>)>,
    rows: u64,
    bytes: u64,
    hasher: Option<ring::digest::Context>,
    sha256: Option<String>,
    error: Option<DbError>,
    last_pull: Instant,
    finished: Option<Instant>,
    eof_delivered: bool,
    reported: bool,
}

impl Drop for JobState {
    fn drop(&mut self) {
        self.buf.zeroize();
        if let Some((_, c)) = self.last.as_mut() {
            c.zeroize();
        }
    }
}

pub struct ExportJob {
    pub id: String,
    pub format: Format,
    /// HMAC digest of the statement text (§11).
    pub digest: String,
    pub started: Instant,
    pub limits: ExportLimits,
    state: Mutex<JobState>,
    data: Notify,
    space: Notify,
    cancel: Notify,
    cancelled: AtomicBool,
}

/// What a push into the buffer did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    Accepted,
    /// Accepting it would pass `max_bytes`: nothing was added.
    ByteLimit,
}

impl ExportJob {
    pub fn new(id: String, format: Format, digest: String, limits: ExportLimits) -> Arc<Self> {
        Arc::new(Self {
            id,
            format,
            digest,
            started: Instant::now(),
            limits,
            state: Mutex::new(JobState {
                status: JobStatus::Running,
                buf: Vec::new(),
                next_offset: 0,
                last: None,
                rows: 0,
                bytes: 0,
                hasher: Some(ring::digest::Context::new(&ring::digest::SHA256)),
                sha256: None,
                error: None,
                last_pull: Instant::now(),
                finished: None,
                eof_delivered: false,
                reported: false,
            }),
            data: Notify::new(),
            space: Notify::new(),
            cancel: Notify::new(),
            cancelled: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, JobState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn status(&self) -> JobStatus {
        self.lock().status
    }

    pub fn is_running(&self) -> bool {
        self.status() == JobStatus::Running
    }

    pub fn idle(&self) -> Duration {
        self.lock().last_pull.elapsed()
    }

    pub fn finished_at(&self) -> Option<Instant> {
        self.lock().finished
    }

    pub fn has_data(&self) -> bool {
        !self.lock().buf.is_empty()
    }

    pub fn buffered(&self) -> usize {
        self.lock().buf.len()
    }

    pub fn rows(&self) -> u64 {
        self.lock().rows
    }

    pub fn request_cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.cancel.notify_one();
        self.space.notify_one();
    }

    pub fn is_cancel_requested(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Append rendered bytes; `row` counts one row. Refused (nothing added)
    /// when it would pass `max_bytes`.
    pub fn push(&self, mut bytes: Vec<u8>, row: bool) -> Pushed {
        let mut st = self.lock();
        if st.bytes + bytes.len() as u64 > self.limits.max_bytes {
            bytes.zeroize();
            return Pushed::ByteLimit;
        }
        if let Some(h) = st.hasher.as_mut() {
            h.update(&bytes);
        }
        st.bytes += bytes.len() as u64;
        if row {
            st.rows += 1;
        }
        st.buf.extend_from_slice(&bytes);
        bytes.zeroize();
        drop(st);
        self.data.notify_one();
        Pushed::Accepted
    }

    /// Wait until the client has drained the buffer below the high-water
    /// mark, the job is cancelled, or `until`.
    async fn wait_for_space(&self, until: tokio::time::Instant) {
        while self.buffered() >= HIGH_WATER_BYTES && !self.is_cancel_requested() {
            tokio::select! {
                _ = self.space.notified() => {}
                _ = self.cancel.notified() => return,
                _ = tokio::time::sleep_until(until) => return,
            }
        }
    }

    /// Wait up to `max` for data or the end (inside a pull, so a client
    /// does not spin on empty chunks).
    pub async fn wait_for_data(&self, max: Duration) {
        if self.has_data() || !self.is_running() {
            return;
        }
        let _ = tokio::time::timeout(max, self.data.notified()).await;
    }

    /// The first final state sticks; the stream's SHA-256 is fixed here.
    pub fn finish(&self, status: JobStatus, error: Option<DbError>) {
        let mut st = self.lock();
        if st.status == JobStatus::Running {
            st.status = status;
            st.error = error;
            if let Some(h) = st.hasher.take() {
                st.sha256 = Some(crate::ids::hex(h.finish().as_ref()));
            }
            st.finished = Some(Instant::now());
        }
        drop(st);
        self.data.notify_one();
    }

    /// Abandoned (§8.1): stop a running export and drop what nobody pulled.
    pub fn expire(&self) {
        self.request_cancel();
        self.finish(JobStatus::Expired, None);
        let mut st = self.lock();
        if !st.eof_delivered {
            // Ended but not drained: the rest is dropped, and a pull is
            // refused rather than answered with an early end of stream.
            st.status = JobStatus::Expired;
            st.buf.zeroize();
            st.buf.clear();
        }
    }

    /// `GET exports/<job>/<offset>`: the chunk at `offset`. The next offset
    /// gets fresh bytes; the previous chunk's offset gets the same bytes
    /// again (a retried pull); anything else is refused.
    pub fn pull(&self, offset: u64) -> Result<Value, ApiError> {
        let mut guard = self.lock();
        let st = &mut *guard;
        st.last_pull = Instant::now();
        if st.status == JobStatus::Expired && !st.eof_delivered {
            return Err(ApiError::refused("export_expired", "the export was abandoned and has been dropped"));
        }
        let retry = offset != st.next_offset && st.last.as_ref().is_some_and(|(o, _)| *o == offset);
        let chunk = if retry {
            st.last.as_ref().map(|(_, c)| c.clone()).unwrap_or_default()
        } else if offset == st.next_offset {
            let n = st.buf.len().min(CHUNK_BYTES);
            let chunk: Vec<u8> = st.buf.drain(..n).collect();
            st.next_offset += n as u64;
            if n > 0 {
                if let Some((_, old)) = st.last.as_mut() {
                    old.zeroize();
                }
                st.last = Some((offset, chunk.clone()));
            }
            chunk
        } else {
            return Err(ApiError::bad_request(format!(
                "offset_mismatch: the next chunk starts at offset {}",
                st.next_offset
            )));
        };
        let end = offset + chunk.len() as u64;
        let eof = st.status != JobStatus::Running && st.buf.is_empty() && end == st.next_offset;
        if eof {
            st.eof_delivered = true;
        }
        let mut out = self.view(st);
        out["offset"] = json!(offset);
        out["next_offset"] = json!(end);
        out["length"] = json!(chunk.len());
        out["chunk"] = json!(B64.encode(&chunk));
        out["eof"] = json!(eof);
        drop(guard);
        let mut chunk = chunk;
        chunk.zeroize();
        self.space.notify_one();
        Ok(out)
    }

    /// `GET exports/<job>`.
    pub fn status_view(&self) -> Value {
        let st = self.lock();
        let mut v = self.view(&st);
        v["buffered"] = json!(st.buf.len());
        v["next_offset"] = json!(st.next_offset);
        v
    }

    fn view(&self, st: &JobState) -> Value {
        let mut v = json!({
            "job": self.id,
            "format": self.format.as_str(),
            "state": st.status.as_str(),
            "rows": st.rows,
            "bytes": st.bytes,
            "max_rows": self.limits.max_rows,
            "max_bytes": self.limits.max_bytes,
            "elapsed_ms": self.started.elapsed().as_millis() as u64,
        });
        if let JobStatus::LimitReached(which) = st.status {
            v["limit"] = json!(which);
        }
        if st.status != JobStatus::Running {
            v["sha256"] = json!(st.sha256);
        }
        if let Some(e) = &st.error {
            v["error"] = json!({"sqlstate": e.sqlstate, "message": e.message});
        }
        v
    }

    /// The `dbms.export` outcome fields (§11), once: when the client has
    /// pulled the end, or when the job ended without it (failed, cancelled,
    /// abandoned). No row data, no statement text.
    pub fn take_report(&self) -> Option<Map<String, Value>> {
        let mut st = self.lock();
        let ended_without_client = matches!(st.status, JobStatus::Failed | JobStatus::Cancelled | JobStatus::Expired);
        if st.reported || st.status == JobStatus::Running || !(st.eof_delivered || ended_without_client) {
            return None;
        }
        st.reported = true;
        let mut m = Map::new();
        m.insert("job".into(), json!(self.id));
        m.insert("format".into(), json!(self.format.as_str()));
        m.insert("outcome".into(), json!(st.status.as_str()));
        m.insert("rows".into(), json!(st.rows));
        m.insert("bytes".into(), json!(st.bytes));
        m.insert("delivered_bytes".into(), json!(st.next_offset));
        m.insert("sha256".into(), json!(st.sha256));
        m.insert("digest".into(), json!(self.digest));
        if let JobStatus::LimitReached(which) = st.status {
            m.insert("limit".into(), json!(which));
        }
        if let Some(e) = &st.error {
            m.insert("sqlstate".into(), json!(e.sqlstate));
        }
        Some(m)
    }

    pub fn reported(&self) -> bool {
        self.lock().reported
    }
}

/// Run the export: raise the statement timeout for its duration, send the
/// one authorized statement, render every row into the job's buffer
/// (pausing while it is full), and restore the timeout. Every caller row
/// reaches the database only through `send_authorized`.
pub async fn produce(
    conn: Arc<PgConn>,
    job: Arc<ExportJob>,
    stmt: AuthorizedStatement,
    opts: ExportOptions,
    restore_timeout: Duration,
) {
    let set_timeout = PluginSql::guarded(sql!("SELECT pg_catalog.set_config('statement_timeout', $1::text, false)"));
    let ms = |d: Duration| TextParam(Some(d.as_millis().to_string()));
    if let Err(e) = conn.internal_query(&set_timeout, &[ms(job.limits.deadline)]).await {
        job.finish(JobStatus::Failed, Some(e));
        return;
    }
    let (status, error) = stream(&conn, &job, stmt, opts).await;
    // A CancelRequest this export sent can land after its statement ended
    // and cancel the restore instead, so it is tried twice. In an aborted
    // transaction it fails both times, and the rollback restores the value
    // the transaction started with. The plugin's own run deadline applies
    // to later statements either way.
    for _ in 0..2 {
        if conn.internal_query(&set_timeout, &[ms(restore_timeout)]).await.is_ok() {
            break;
        }
    }
    job.finish(status, error);
}

async fn stream(
    conn: &PgConn,
    job: &ExportJob,
    stmt: AuthorizedStatement,
    opts: ExportOptions,
) -> (JobStatus, Option<DbError>) {
    let deadline = tokio::time::Instant::now() + job.limits.deadline + Duration::from_secs(5);
    let sent = tokio::select! {
        r = conn.send_authorized(stmt) => r,
        _ = tokio::time::sleep_until(deadline) => {
            let _ = conn.cancel().await;
            return (JobStatus::Failed, Some(DbError::plugin("the export did not start before its deadline")));
        }
        _ = job.cancel.notified() => {
            let _ = conn.cancel().await;
            return (JobStatus::Cancelled, None);
        }
    };
    let q = match sent {
        Ok(q) => q,
        Err(e) => return (JobStatus::Failed, Some(e)),
    };
    let cols: Vec<Col> = q.columns.iter().map(|(n, t)| Col::new(n, t)).collect();
    let renderer = Renderer::new(opts, cols);
    if job.push(renderer.header(), false) == Pushed::ByteLimit {
        let _ = conn.cancel().await;
        return drain_after(q.rows, JobStatus::LimitReached("byte_limit")).await;
    }
    let mut rows = pin!(q.rows);
    let mut stop: Option<JobStatus> = None;
    loop {
        let next = tokio::select! {
            r = rows.next() => r,
            _ = tokio::time::sleep_until(deadline), if stop.is_none() => {
                let _ = conn.cancel().await;
                stop = Some(JobStatus::Failed);
                continue;
            }
            _ = job.cancel.notified(), if stop.is_none() => {
                let _ = conn.cancel().await;
                stop = Some(JobStatus::Cancelled);
                continue;
            }
        };
        let row = match next {
            None => break,
            Some(Err(e)) => {
                return match stop {
                    // The cancel this export sent ended the statement.
                    Some(s) => (s, (s == JobStatus::Failed).then(|| DbError::plugin("the export passed its deadline"))),
                    None => (JobStatus::Failed, Some(DbError::from(e))),
                };
            }
            Some(Ok(row)) => row,
        };
        if stop.is_some() {
            continue; // draining until the server acknowledges the cancel
        }
        if job.rows() >= job.limits.max_rows {
            let _ = conn.cancel().await;
            stop = Some(JobStatus::LimitReached("row_limit"));
            continue;
        }
        let mut cells: Vec<Value> =
            (0..row.len()).map(|i| row.try_get::<_, Cell>(i).map(|c| c.0).unwrap_or(Value::Null)).collect();
        let bytes = renderer.row(&cells);
        cells.iter_mut().for_each(scrub);
        if job.push(bytes, true) == Pushed::ByteLimit {
            let _ = conn.cancel().await;
            stop = Some(JobStatus::LimitReached("byte_limit"));
            continue;
        }
        job.wait_for_space(deadline).await;
        if job.is_cancel_requested() && stop.is_none() {
            let _ = conn.cancel().await;
            stop = Some(JobStatus::Cancelled);
        }
    }
    match stop {
        None => (JobStatus::Done, None),
        Some(JobStatus::Failed) => (JobStatus::Failed, Some(DbError::plugin("the export passed its deadline"))),
        Some(s) => (s, None),
    }
}

async fn drain_after(rows: tokio_postgres::RowStream, status: JobStatus) -> (JobStatus, Option<DbError>) {
    let mut rows = pin!(rows);
    while let Some(r) = rows.next().await {
        if r.is_err() {
            break;
        }
    }
    (status, None)
}

fn scrub(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::Object(m) => m.values_mut().for_each(scrub),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, numeric: bool) -> Col {
        Col { name: name.into(), numeric, bytea: false }
    }

    fn csv(guard: bool) -> Renderer {
        Renderer::new(
            ExportOptions { format: Format::Csv, formula_guard: guard, target: None },
            vec![col("id", true), col("name", false), col("note", false)],
        )
    }

    fn text(b: Vec<u8>) -> String {
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn csv_is_rfc4180_with_null_apart_from_empty() {
        let r = csv(true);
        assert_eq!(text(r.header()), "\"id\",\"name\",\"note\"\r\n");
        let row = r.row(&[json!(1), json!("a \"quoted\", value\nline 2"), Value::Null]);
        assert_eq!(text(row), "1,\"a \"\"quoted\"\", value\nline 2\",\r\n");
        assert_eq!(text(r.row(&[json!("-5"), json!(""), json!(true)])), "-5,\"\",true\r\n");
    }

    /// The formula guard (§8.1): on by default, every text cell (and the
    /// header) that a spreadsheet would evaluate is prefixed with `'`;
    /// numbers from numeric columns are left alone.
    #[test]
    fn csv_formula_guard() {
        let r = csv(true);
        for (cell, want) in [
            ("=HYPERLINK(\"http://x\")", "\"'=HYPERLINK(\"\"http://x\"\")\""),
            ("+1", "\"'+1\""),
            ("-2", "\"'-2\""),
            ("@SUM(A1)", "\"'@SUM(A1)\""),
            ("\tcmd", "\"'\tcmd\""),
            ("\rcmd", "\"'\rcmd\""),
            ("safe", "\"safe\""),
        ] {
            let line = text(r.row(&[json!("1"), json!(cell), Value::Null]));
            assert_eq!(line, format!("1,{want},\r\n"), "{cell:?}");
        }
        assert_eq!(text(r.row(&[json!("-3.5"), json!("x"), Value::Null])), "-3.5,\"x\",\r\n", "numeric column");
        let header = Renderer::new(
            ExportOptions { format: Format::Csv, formula_guard: true, target: None },
            vec![col("=cmd", false)],
        );
        assert_eq!(text(header.header()), "\"'=cmd\"\r\n");
        assert_eq!(text(csv(false).row(&[json!(1), json!("=1+1"), Value::Null])), "1,\"=1+1\",\r\n", "turned off");
    }

    #[test]
    fn json_lines_keep_column_order_types_and_repeated_names() {
        let r = Renderer::new(
            ExportOptions { format: Format::Jsonl, formula_guard: true, target: None },
            vec![col("b", true), col("a", false), col("a", false)],
        );
        assert!(r.header().is_empty());
        let line = text(r.row(&[json!(1), json!("x\"y"), Value::Null]));
        assert_eq!(line, "{\"b\":1,\"a\":\"x\\\"y\",\"a_2\":null}\n");
        let v: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["a_2"], Value::Null);
    }

    #[test]
    fn sql_inserts_quote_every_identifier_and_literal() {
        let target = InsertTarget::parse(&json!({"schema": "public", "name": "we\"ird"})).unwrap();
        let cols = vec![
            col("id", true),
            col("na\"me", false),
            Col { name: "blob".into(), numeric: false, bytea: true },
            col("ok", false),
            col("amount", true),
        ];
        let r =
            Renderer::new(ExportOptions { format: Format::SqlInsert, formula_guard: true, target: Some(target) }, cols);
        assert!(text(r.header()).contains("SET standard_conforming_strings = on;"));
        let line = text(r.row(&[json!(7), json!("O'Brien\\"), json!("AAEC"), json!(true), json!("NaN")]));
        assert_eq!(
            line,
            "INSERT INTO \"public\".\"we\"\"ird\" (\"id\", \"na\"\"me\", \"blob\", \"ok\", \"amount\") VALUES \
             (7, 'O''Brien\\', decode('AAEC', 'base64'), TRUE, 'NaN');\n"
        );
        let line = text(r.row(&[
            Value::Null,
            json!("x'); DROP TABLE t; --"),
            json!("not base64!"),
            json!(false),
            json!("-12.50"),
        ]));
        assert!(line.contains("NULL, 'x''); DROP TABLE t; --', 'not base64!', FALSE, -12.50"), "{line}");
        for bad in [json!({}), json!({"name": ""}), json!({"name": "t", "x": 1}), json!({"name": "a\nb"}), json!("t")] {
            assert!(InsertTarget::parse(&bad).is_err(), "{bad}");
        }
    }

    fn job(max_rows: u64, max_bytes: u64) -> Arc<ExportJob> {
        ExportJob::new(
            "e1".into(),
            Format::Csv,
            "d".into(),
            ExportLimits { max_rows, max_bytes, deadline: Duration::from_secs(5) },
        )
    }

    /// Chunks are at most 1 MiB, pulled at the next offset; a retried pull
    /// gets the same bytes; the end carries the SHA-256 of the stream.
    #[test]
    fn chunks_are_pulled_in_order_and_hashed() {
        let j = job(100, 10 * CHUNK_BYTES as u64);
        let a = vec![b'a'; CHUNK_BYTES + 10];
        assert_eq!(j.push(a.clone(), true), Pushed::Accepted);
        let p = j.pull(0).unwrap();
        assert_eq!((p["length"].as_u64(), p["eof"].as_bool()), (Some(CHUNK_BYTES as u64), Some(false)));
        let again = j.pull(0).unwrap();
        assert_eq!(again["chunk"], p["chunk"], "a retried pull returns the same chunk");
        assert_eq!(j.pull(5).unwrap_err().code, "bad_request");
        j.finish(JobStatus::Done, None);
        let p = j.pull(CHUNK_BYTES as u64).unwrap();
        assert_eq!((p["length"].as_u64(), p["eof"].as_bool()), (Some(10), Some(true)));
        let want = crate::ids::hex(ring::digest::digest(&ring::digest::SHA256, &a).as_ref());
        assert_eq!(p["sha256"], json!(want));
        let report = j.take_report().unwrap();
        assert_eq!((report["outcome"].clone(), report["rows"].clone()), (json!("done"), json!(1)));
        assert_eq!(report["sha256"], json!(want));
        assert!(j.take_report().is_none(), "reported once");
    }

    #[test]
    fn limits_and_abandonment() {
        let j = job(10, 8);
        assert_eq!(j.push(b"12345".to_vec(), true), Pushed::Accepted);
        assert_eq!(j.push(b"6789".to_vec(), true), Pushed::ByteLimit, "nothing past max_bytes");
        j.finish(JobStatus::LimitReached("byte_limit"), None);
        let p = j.pull(0).unwrap();
        assert_eq!(
            (p["state"].clone(), p["limit"].clone(), p["eof"].clone()),
            (json!("limit_reached"), json!("byte_limit"), json!(true))
        );

        let j = job(10, 1_000);
        j.push(b"data".to_vec(), true);
        assert!(j.take_report().is_none(), "running");
        j.expire();
        assert_eq!(j.pull(0).unwrap_err().code, "export_expired");
        assert_eq!(j.take_report().unwrap()["outcome"], "expired");
        assert!(j.is_cancel_requested());
    }
}
