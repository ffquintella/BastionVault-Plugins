//! The Oracle connection of one session (T129, Phase 8). The session layer
//! (`tns`) is private to this module, and the only function that sends
//! caller SQL is [`OraConn::send_authorized`], which takes an
//! [`AuthorizedStatement`] (§Phase 3, the rule every engine follows).

// One classified span per round trip: an Oracle execute call carries one
// SQL statement or one PL/SQL block, never more (§4.3). Oracle has no
// server auto-commit, so the plugin emulates it (§6.4): outside an explicit
// transaction every statement is followed by COMMIT, or ROLLBACK if it
// failed. Read-only sessions run each statement inside the plugin's own
// SET TRANSACTION READ ONLY (§5.3; autonomous transactions escape it).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bv_sql_classify::{LexerSettings, NameContext, ObjectRef, StatementKind};
use bv_sql_guard::sql;
use oraclemcp_driver_cx_protocol::sql as ora_sql;
use oraclemcp_driver_cx_protocol::thin::{self, BindValue, ColumnMetadata, QueryResult, QueryValue};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroize;

use super::tns::{self, Breaker, Login, Session, TlsSetup, TnsError};
use super::values::{cell, ColMeta};
use crate::authz::{AuthorizedEdit, AuthorizedStatement, Resolutions};
use crate::driver::{resolve, ConnectError, ConnectSpec, DbError, PluginSql};
use crate::host::Credential;
use crate::profile::TlsMode;
use crate::tls;
use crate::wire::TxStatus;

/// Rows per execute / fetch round trip, and rows in flight to the run.
const ARRAY: u32 = 100;
const ROWS_IN_FLIGHT: usize = 16;
/// Rows a plugin-authored catalog read may return.
const MAX_INTERNAL_ROWS: usize = 5_000;
/// Failed statements leave their server cursor open (the protocol crate's
/// error does not carry its id); past this many the session is tainted
/// before ORA-01000 (`OPEN_CURSORS`) would end it anyway.
const MAX_FAILED_STATEMENTS: u32 = 200;
/// The session formats grid edits and catalog reads rely on (§7): values go
/// back to the server as the text the grid shows.
const NLS_PIN: &str = "ALTER SESSION SET NLS_NUMERIC_CHARACTERS = '.,' NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS' \
     NLS_TIMESTAMP_FORMAT = 'YYYY-MM-DD HH24:MI:SS.FF9'";

/// Whether a profile's TLS mode can serve an Oracle session. TCPS only: a
/// plaintext session would carry the O5LOGON exchange, which a passive
/// observer can attack offline, and every statement in the clear (§5.4).
pub fn check_tls_mode(mode: TlsMode) -> Result<(), ConnectError> {
    match mode {
        TlsMode::Disable => Err(ConnectError::new(
            "tls_required",
            "Oracle sessions need TCPS (`require`, `verify-ca` or `verify-full`)",
        )),
        TlsMode::Require | TlsMode::VerifyCa | TlsMode::VerifyFull => Ok(()),
    }
}

/// The service name as the session's catalog path segment (§3.2): Oracle
/// compares service names without case, so the upper-case form is the one
/// policies name.
pub fn catalog_of(service: &str) -> Option<String> {
    tns::descriptor_value_ok(service).then(|| service.to_ascii_uppercase())
}

/// What the session learns once the connection is up.
pub struct Established {
    pub lexer: LexerSettings,
    pub ctx: NameContext,
    pub server_version: String,
}

struct Track {
    /// A transaction the operator (or a script, or an edit) opened.
    explicit: bool,
    /// The server's end-of-call status: a transaction is in progress.
    server_tx: bool,
    taint: Option<String>,
    closed: bool,
    failed_statements: u32,
}

pub struct OraConn {
    tns: tokio::sync::Mutex<Option<Session>>,
    breaker: Breaker,
    session_id: String,
    read_only: bool,
    service: String,
    track: Mutex<Track>,
    active: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The run asked the statement to stop (cancel, deadline, grid cap):
    /// no further fetch is sent, whether or not a BREAK was.
    stop: AtomicBool,
}

/// A statement the server accepted: its columns, its rows as JSON cells,
/// then how it ended (rows affected).
pub struct OraQuery {
    pub columns: Vec<ColMeta>,
    pub rows: mpsc::Receiver<Result<Vec<serde_json::Value>, DbError>>,
    pub end: oneshot::Receiver<Result<u64, DbError>>,
}

/// A server or session-layer error. The server's message may echo values
/// and is never stored (§11); its `ORA-` number stands in for a SQLSTATE.
pub fn db_error(e: &TnsError) -> DbError {
    match e {
        TnsError::Server { code, message } => DbError {
            sqlstate: Some(format!("ORA-{code:05}")),
            severity: None,
            message: message.chars().take(2000).collect(),
            from_server: true,
        },
        TnsError::Broken(m) => DbError::plugin(m.clone()),
        TnsError::Refused { message, .. } => DbError::plugin(message.clone()),
    }
}

/// Whether a statement returns rows: the classifier's kind, or for an
/// unclassified one the protocol crate's own reading of its first word.
fn is_query(kind: Option<StatementKind>, text: &str) -> bool {
    match kind {
        Some(k) => matches!(k, StatementKind::Select | StatementKind::Values),
        None => {
            !ora_sql::statement_is_plsql(text) && !ora_sql::statement_is_ddl(text) && !ora_sql::statement_is_dml(text)
        }
    }
}

fn text_of(v: Option<&QueryValue>) -> Option<String> {
    match v? {
        QueryValue::Text(s) => Some(s.clone()),
        QueryValue::Number(n) => Some(n.to_canonical_string()),
        other => other.as_text().map(str::to_string),
    }
}

impl OraConn {
    /// Open the session's connection with `credential`, which is consumed
    /// and zeroized here whatever the outcome (§5.4).
    pub async fn connect(spec: ConnectSpec<'_>, mut credential: Credential) -> Result<Self, ConnectError> {
        let r = Self::connect_inner(&spec, &credential).await;
        credential.password.zeroize();
        credential.username.zeroize();
        r
    }

    async fn connect_inner(spec: &ConnectSpec<'_>, cred: &Credential) -> Result<Self, ConnectError> {
        let profile = spec.profile;
        // The host released the login for this endpoint only (§5.4 rule 5).
        if cred.endpoint != profile.endpoint {
            return Err(ConnectError::new(
                "endpoint_mismatch",
                "the released credential is bound to another endpoint than the profile's",
            ));
        }
        if catalog_of(spec.catalog).is_none() {
            return Err(ConnectError::new("bad_request", "invalid service name"));
        }
        check_tls_mode(profile.tls.mode)?;
        let config = tls::client_config(&profile.tls, spec.roots)
            .map_err(|m| ConnectError::new("tls_config", m))?
            .ok_or_else(|| ConnectError::new("tls_required", "Oracle sessions need TCPS"))?;
        let name = tls::server_name(&profile.tls, &profile.host).map_err(|m| ConnectError::new("tls_config", m))?;
        let addrs = resolve(profile, spec.allowed, spec.denied).await?;
        let mut last = ConnectError::new("connect_failed", "no address could be dialled");
        for addr in addrs {
            match tokio::time::timeout(spec.connect_timeout, Self::dial(addr, config.clone(), name.clone(), spec, cred))
                .await
            {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) if e.code == "connect_failed" => last = e,
                Ok(Err(e)) => return Err(e),
                Err(_) => last = ConnectError::new("connect_timeout", "the database did not answer in time"),
            }
        }
        Err(last)
    }

    async fn dial(
        addr: SocketAddr,
        config: Arc<rustls::ClientConfig>,
        name: rustls::pki_types::ServerName<'static>,
        spec: &ConnectSpec<'_>,
        cred: &Credential,
    ) -> Result<Self, ConnectError> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| ConnectError::new("connect_failed", format!("could not reach the database: {}", e.kind())))?;
        let _ = tcp.set_nodelay(true);
        let host = spec.profile.host.trim_start_matches('[').trim_end_matches(']');
        let mut password = cred.password.as_bytes().to_vec();
        let login =
            Login { host, port: addr.port(), service: spec.catalog, user: cred.username.as_str(), password: &password };
        let session = tns::connect(tcp, &TlsSetup { config, name }, &login).await;
        password.zeroize();
        let session = session.map_err(|e| match e {
            TnsError::Refused { code, message } => ConnectError::new(code, message),
            TnsError::Server { code, .. } => {
                ConnectError::new("login_failed", format!("the database refused the login (ORA-{code:05})"))
            }
            TnsError::Broken(m) => ConnectError::new("connect_failed", m),
        })?;
        Ok(Self {
            breaker: session.breaker(),
            tns: tokio::sync::Mutex::new(Some(session)),
            session_id: spec.session_id.to_string(),
            read_only: spec.read_only,
            service: spec.catalog.to_string(),
            track: Mutex::new(Track {
                explicit: false,
                server_tx: false,
                taint: None,
                closed: false,
                failed_statements: 0,
            }),
            active: Mutex::new(None),
            stop: AtomicBool::new(false),
        })
    }

    fn track(&self) -> std::sync::MutexGuard<'_, Track> {
        self.track.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn tx(&self) -> TxStatus {
        let t = self.track();
        if t.explicit || t.server_tx {
            TxStatus::InTransaction
        } else {
            TxStatus::Idle
        }
    }

    pub fn taint(&self) -> Option<String> {
        self.track().taint.clone()
    }

    fn set_taint(&self, why: impl Into<String>) {
        let mut t = self.track();
        if t.taint.is_none() {
            t.taint = Some(why.into());
        }
    }

    pub fn is_closed(&self) -> bool {
        self.track().closed
    }

    async fn lock(&self) -> Result<tokio::sync::MutexGuard<'_, Option<Session>>, DbError> {
        let guard = self.tns.lock().await;
        if guard.is_none() || self.is_closed() {
            return Err(DbError::plugin("the database connection is closed"));
        }
        Ok(guard)
    }

    /// Note a call's outcome: a dead session layer closes the connection.
    fn noted<T>(&self, s: &Session, r: Result<T, TnsError>) -> Result<T, DbError> {
        if let Some(why) = s.dead() {
            let mut t = self.track();
            t.closed = true;
            if t.taint.is_none() {
                t.taint = Some(why.to_string());
            }
        }
        r.map_err(|e| db_error(&e))
    }

    /// A plugin-authored statement, rows read in full (bounded); every
    /// bind is text.
    pub async fn internal_query(&self, q: &PluginSql, binds: &[&str]) -> Result<Vec<Vec<Option<QueryValue>>>, DbError> {
        let mut guard = self.lock().await?;
        let s = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        let binds: Vec<BindValue> = binds.iter().map(|b| BindValue::Text(b.to_string())).collect();
        let r = s.execute(q.as_str(), true, &binds, ARRAY).await;
        let first = self.noted(s, r)?;
        let mut rows = first.rows;
        let (cursor, columns, mut more) = (first.cursor_id, first.columns, first.more_rows);
        while more && rows.len() < MAX_INTERNAL_ROWS {
            let previous = rows.last().cloned();
            let r = s.fetch(cursor, ARRAY, &columns, previous.as_deref()).await;
            let next = self.noted(s, r)?;
            more = next.more_rows;
            rows.extend(next.rows);
        }
        s.close_cursor(cursor);
        Ok(rows)
    }

    /// A plugin-authored statement without rows; the server's row count.
    async fn plain(&self, s: &mut Session, text: &str, binds: &[BindValue]) -> Result<QueryResult, DbError> {
        let r = s.execute(text, false, binds, 1).await;
        let out = self.noted(s, r)?;
        s.close_cursor(out.cursor_id);
        if let Some(tx) = out.txn_in_progress {
            self.track().server_tx = tx;
        }
        Ok(out)
    }

    async fn end_tx(&self, s: &mut Session, commit: bool) -> Result<(), DbError> {
        let code = if commit { thin::TNS_FUNC_COMMIT } else { thin::TNS_FUNC_ROLLBACK };
        let r = s.function(code).await;
        let in_tx = self.noted(s, r)?;
        let mut t = self.track();
        t.server_tx = in_tx;
        t.explicit = false;
        Ok(())
    }

    /// The statement that opens an explicit transaction: read-only in a
    /// read-only session (§5.3).
    fn begin_text(&self) -> &'static str {
        if self.read_only {
            "SET TRANSACTION READ ONLY"
        } else {
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
        }
    }

    /// Plugin-authored transaction control (`BEGIN`, `COMMIT`, `ROLLBACK`,
    /// `SAVEPOINT …`, `ROLLBACK TO SAVEPOINT …`). Oracle has no `BEGIN`
    /// statement: a transaction is opened with SET TRANSACTION.
    pub async fn internal_execute(&self, q: &PluginSql) -> Result<u64, DbError> {
        let mut guard = self.lock().await?;
        let s = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        match q.as_str() {
            "BEGIN" | "START TRANSACTION" => {
                self.plain(s, self.begin_text(), &[]).await?;
                self.track().explicit = true;
                Ok(0)
            }
            "COMMIT" => self.end_tx(s, true).await.map(|_| 0),
            "ROLLBACK" => self.end_tx(s, false).await.map(|_| 0),
            other => self.plain(s, other, &[]).await.map(|r| r.row_count),
        }
    }

    /// A structured row edit, authorized for exactly this statement; the
    /// server's row count. Its values are bound as text.
    pub async fn send_edit(&self, edit: AuthorizedEdit) -> Result<u64, DbError> {
        if edit.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let (q, params) = edit.into_parts();
        let binds: Vec<BindValue> =
            params.into_iter().map(|p| p.0.map(BindValue::Text).unwrap_or(BindValue::Null)).collect();
        let mut guard = self.lock().await?;
        let s = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        self.plain(s, NLS_PIN, &[]).await?;
        self.plain(s, q.as_str(), &binds).await.map(|r| r.row_count)
    }

    /// The only path for caller SQL: one authorized statement, run by a
    /// task that streams its rows (§6.3: it stops fetching while the run's
    /// buffer is full).
    pub async fn send_authorized(self: &Arc<Self>, stmt: AuthorizedStatement) -> Result<OraQuery, DbError> {
        if stmt.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let kind = stmt.meta().kind;
        if self.read_only && kind == Some(StatementKind::TxBegin) {
            return Err(DbError::plugin(
                "a read-only Oracle session runs every statement in its own SET TRANSACTION READ ONLY; \
                 manual transactions are not available in it",
            ));
        }
        let text = stmt.text().to_string();
        drop(stmt);
        self.stop.store(false, Ordering::SeqCst);
        let (cols_tx, cols_rx) = oneshot::channel();
        let (rows_tx, rows_rx) = mpsc::channel(ROWS_IN_FLIGHT);
        let (end_tx, end_rx) = oneshot::channel();
        let me = self.clone();
        let task = tokio::spawn(async move {
            let ended = me.stream(text, kind, cols_tx, rows_tx).await;
            let _ = end_tx.send(ended);
        });
        *self.active.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
        match cols_rx.await {
            Ok(Ok(columns)) => Ok(OraQuery { columns, rows: rows_rx, end: end_rx }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DbError::plugin("the statement task ended before it answered")),
        }
    }

    async fn stream(
        &self,
        text: String,
        kind: Option<StatementKind>,
        cols_tx: oneshot::Sender<Result<Vec<ColMeta>, DbError>>,
        rows_tx: mpsc::Sender<Result<Vec<serde_json::Value>, DbError>>,
    ) -> Result<u64, DbError> {
        let mut guard = match self.lock().await {
            Ok(g) => g,
            Err(e) => {
                let _ = cols_tx.send(Err(e.clone()));
                return Err(e);
            }
        };
        let Some(s) = guard.as_mut() else {
            let e = DbError::plugin("the database connection is closed");
            let _ = cols_tx.send(Err(e.clone()));
            return Err(e);
        };
        let explicit = self.track().explicit;
        // The read-only guard opens the statement's own transaction.
        if self.read_only && !explicit {
            if let Err(e) = self.plain(s, "SET TRANSACTION READ ONLY", &[]).await {
                let _ = cols_tx.send(Err(e.clone()));
                return Err(e);
            }
        }
        let outcome = self.run_one(s, &text, kind, cols_tx, &rows_tx).await;
        self.finish(s, kind, explicit, outcome).await
    }

    /// Execute, then fetch while the run keeps reading.
    async fn run_one(
        &self,
        s: &mut Session,
        text: &str,
        kind: Option<StatementKind>,
        cols_tx: oneshot::Sender<Result<Vec<ColMeta>, DbError>>,
        rows_tx: &mpsc::Sender<Result<Vec<serde_json::Value>, DbError>>,
    ) -> Result<u64, DbError> {
        let query = is_query(kind, text);
        let r = s.execute(text, query, &[], ARRAY).await;
        let first = match self.noted(s, r) {
            Ok(f) => f,
            Err(e) => {
                self.track().failed_statements += 1;
                let _ = cols_tx.send(Err(e.clone()));
                return Err(e);
            }
        };
        if let Some(tx) = first.txn_in_progress {
            self.track().server_tx = tx;
        }
        let columns: Vec<ColumnMetadata> = first.columns.clone();
        let metas: Vec<ColMeta> = if query { columns.iter().map(ColMeta::new).collect() } else { Vec::new() };
        let _ = cols_tx.send(Ok(metas.clone()));
        let cursor = first.cursor_id;
        let mut more = query && first.more_rows;
        let mut count = first.row_count;
        let mut previous: Option<Vec<Option<QueryValue>>> = first.rows.last().cloned();
        let mut receiver_gone = false;
        if query {
            for row in &first.rows {
                let cells = row.iter().zip(&metas).map(|(v, m)| cell(m, v.as_ref())).collect();
                if rows_tx.send(Ok(cells)).await.is_err() {
                    receiver_gone = true;
                    break;
                }
            }
        }
        while more && !receiver_gone && !self.stop.load(Ordering::SeqCst) {
            let r = s.fetch(cursor, ARRAY, &columns, previous.as_deref()).await;
            let next = match self.noted(s, r) {
                Ok(n) => n,
                Err(e) => {
                    let _ = rows_tx.send(Err(e.clone())).await;
                    return Err(e);
                }
            };
            more = next.more_rows;
            count = next.row_count;
            if let Some(last) = next.rows.last() {
                previous = Some(last.clone());
            }
            for row in &next.rows {
                let cells = row.iter().zip(&metas).map(|(v, m)| cell(m, v.as_ref())).collect();
                if rows_tx.send(Ok(cells)).await.is_err() {
                    // The run stopped reading (grid cap or cancel).
                    receiver_gone = true;
                    break;
                }
            }
        }
        s.close_cursor(cursor);
        Ok(count)
    }

    /// After a caller statement: track the transaction, and emulate
    /// auto-commit outside an explicit one (the read-only guard's
    /// transaction always ends here).
    async fn finish(
        &self,
        s: &mut Session,
        kind: Option<StatementKind>,
        explicit: bool,
        outcome: Result<u64, DbError>,
    ) -> Result<u64, DbError> {
        if self.is_closed() {
            return outcome;
        }
        let ok = outcome.is_ok();
        let ended = match kind {
            Some(StatementKind::TxBegin) if ok => {
                self.track().explicit = true;
                Ok(())
            }
            Some(StatementKind::TxCommit) if ok => {
                self.track().explicit = false;
                Ok(())
            }
            // ROLLBACK TO SAVEPOINT keeps the transaction open.
            Some(StatementKind::TxRollback) if ok => {
                let mut t = self.track();
                t.explicit = t.explicit && t.server_tx;
                Ok(())
            }
            _ if explicit => Ok(()),
            _ => self.end_tx(s, ok && !self.read_only).await,
        };
        if self.track().failed_statements > MAX_FAILED_STATEMENTS {
            self.set_taint("too many failed statements left server cursors open; reopen the session");
        }
        match (outcome, ended) {
            (Ok(n), Ok(())) => Ok(n),
            (Err(e), _) | (Ok(_), Err(e)) => Err(e),
        }
    }

    /// Stop the running statement (§6.2): no further fetch is sent, and a
    /// call in flight gets the in-band BREAK.
    pub async fn cancel(&self) -> Result<(), DbError> {
        self.stop.store(true, Ordering::SeqCst);
        self.breaker.request().await.map(|_| ()).map_err(|e| db_error(&e))
    }

    /// Drop the connection (the server rolls back an open transaction).
    pub fn shutdown(&self) {
        self.track().closed = true;
        if let Some(task) = self.active.lock().unwrap_or_else(|p| p.into_inner()).take() {
            task.abort();
        }
        if let Ok(mut guard) = self.tns.try_lock() {
            drop(guard.take());
        }
    }

    // ── session setup and the name context ─────────────────────────────

    async fn context_row(&self) -> Result<Vec<Option<String>>, DbError> {
        let q = PluginSql::guarded(sql!(
            "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA'), SYS_CONTEXT('USERENV', 'SERVICE_NAME'), \
             SYS_CONTEXT('USERENV', 'CON_NAME') FROM dual"
        ));
        let rows = self.internal_query(&q, &[]).await?;
        let row = rows.first().ok_or_else(|| DbError::plugin("no session context row"))?;
        Ok((0..3).map(|i| text_of(row.get(i).and_then(Option::as_ref))).collect())
    }

    /// After the connection is up: pin the NLS formats, confirm the service
    /// the session landed on, read the name context.
    pub async fn establish(&self, server_version: Option<String>) -> Result<Established, String> {
        {
            let mut guard = self.lock().await.map_err(|e| e.message)?;
            let s = guard.as_mut().ok_or("the database connection is closed")?;
            self.plain(s, NLS_PIN, &[]).await.map_err(|e| format!("pinning the NLS formats: {}", e.message))?;
        }
        let row = self.context_row().await.map_err(|e| format!("reading the session context: {}", e.message))?;
        let service = row[1].clone().unwrap_or_default();
        if !service.eq_ignore_ascii_case(&self.service) {
            return Err("the session landed on another service than the profile's".into());
        }
        let schema = row[0].clone().ok_or("the server reported no current schema")?;
        let catalog = catalog_of(&self.service).ok_or("invalid service name")?;
        Ok(Established {
            lexer: LexerSettings::Oracle,
            ctx: NameContext::oracle(catalog, schema),
            server_version: server_version.unwrap_or_else(|| "Oracle Database".into()),
        })
    }

    /// The server's version banner, from the authentication.
    pub async fn server_version(&self) -> Option<String> {
        let guard = self.tns.lock().await;
        guard.as_ref().and_then(|s| s.server.version_string.clone())
    }

    /// The name context, re-read after a statement that may have changed it
    /// (`ALTER SESSION SET CURRENT_SCHEMA`, a block, an unclassified
    /// statement). Another service or container taints the session: its
    /// paths and its credential binding no longer describe it.
    pub async fn read_context(&self, database_read_only: bool) -> Result<NameContext, DbError> {
        let row = self.context_row().await?;
        if !row[1].as_deref().is_some_and(|s| s.eq_ignore_ascii_case(&self.service)) {
            self.set_taint("the session moved to another service or container; reopen it");
        }
        let schema = row[0].clone().ok_or_else(|| DbError::plugin("the server reported no current schema"))?;
        let catalog = catalog_of(&self.service).ok_or_else(|| DbError::plugin("invalid service name"))?;
        Ok(NameContext { database_read_only, ..NameContext::oracle(catalog, schema) })
    }

    /// Resolve unqualified names the way the server will (§4.4): an object
    /// of the current schema. A synonym (private, or a PUBLIC one when the
    /// schema has no such object) stays unaddressable: its target has
    /// another name, so a check on the synonym's path would not be a check
    /// on what is read.
    pub async fn resolve(&self, refs: &[ObjectRef]) -> Result<Resolutions, DbError> {
        let q = PluginSql::guarded(sql!(
            "SELECT owner, object_type FROM all_objects \
             WHERE owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') AND object_name = :1 \
               AND subobject_name IS NULL AND object_type NOT IN ('INDEX PARTITION', 'TABLE PARTITION')"
        ));
        let mut out = Resolutions::new();
        for r in refs {
            let rows = self.internal_query(&q, &[r.name.as_str()]).await?;
            let types: Vec<String> =
                rows.iter().filter_map(|row| text_of(row.get(1).and_then(Option::as_ref))).collect();
            let owner = rows.first().and_then(|row| text_of(row.first().and_then(Option::as_ref)));
            let schema = if types.is_empty() || types.iter().any(|t| t == "SYNONYM") { None } else { owner };
            out.insert(r.clone(), schema);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_disable_is_refused_and_the_rest_allowed() {
        assert_eq!(check_tls_mode(TlsMode::Disable).unwrap_err().code, "tls_required");
        for m in [TlsMode::Require, TlsMode::VerifyCa, TlsMode::VerifyFull] {
            assert!(check_tls_mode(m).is_ok());
        }
    }

    #[test]
    fn service_names_are_upper_case_paths() {
        assert_eq!(catalog_of("freepdb1").as_deref(), Some("FREEPDB1"));
        assert_eq!(catalog_of("sales.example.com").as_deref(), Some("SALES.EXAMPLE.COM"));
        assert_eq!(catalog_of("x)(SERVER=dedicated"), None);
        assert_eq!(catalog_of(""), None);
    }

    #[test]
    fn only_queries_fetch_rows() {
        assert!(is_query(Some(StatementKind::Select), "SELECT 1 FROM dual"));
        assert!(!is_query(Some(StatementKind::Update), "UPDATE t SET a = 1"));
        assert!(!is_query(Some(StatementKind::Do), "BEGIN NULL; END;"));
        assert!(is_query(None, "WITH x AS (SELECT 1 a FROM dual) SELECT a FROM x"));
        assert!(!is_query(None, "BEGIN NULL; END;"));
        assert!(!is_query(None, "CREATE TABLE t (a NUMBER)"));
    }

    /// The plugin's names agree with the classifier's for catalog names.
    #[test]
    fn classifier_paths_use_the_upper_case_service() {
        let ctx = NameContext::oracle(catalog_of("freepdb1").unwrap(), "APP");
        let got = bv_sql_classify::classify(
            bv_sql_classify::Dialect::Oracle,
            LexerSettings::Oracle,
            "SELECT * FROM app.t",
            &ctx,
        )
        .unwrap();
        match &got[0].required[0].1 {
            bv_sql_classify::SqlTarget::Object(o) => {
                assert_eq!((o.catalog.as_str(), o.schema.as_deref(), o.name.as_str()), ("FREEPDB1", Some("APP"), "T"))
            }
            other => panic!("{other:?}"),
        }
    }
}
