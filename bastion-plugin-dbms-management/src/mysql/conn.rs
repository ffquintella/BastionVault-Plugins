//! The MySQL / MariaDB connection of one session (T127, Phase 6). The
//! driver's `Conn` is private to this module, and the only function that
//! sends caller SQL is [`MyConn::send_authorized`], which takes an
//! [`AuthorizedStatement`] (§Phase 3, the same rule as `driver::PgConn`).

// One statement per round trip (§4.3). mysql_async always advertises
// CLIENT_MULTI_STATEMENTS (`Opts::get_capabilities`), so the protocol is
// chosen per span: a span without any `;` byte goes through COM_QUERY, where
// the server cannot find a second statement; a span holding a `;` (inside a
// literal or a comment) goes through COM_STMT_PREPARE, whose parser runs
// with multi-statements off. Either way the server runs exactly one.

// Never installed: a LOCAL INFILE handler. A server's file request then
// fails in the driver before any byte of a local file is read.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bv_sql_classify::{LexerSettings, NameContext, StatementKind};
use bv_sql_guard::sql;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder, Params, Row, SslOpts, Value as My};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use tokio::sync::{mpsc, oneshot};
use zeroize::{Zeroize, Zeroizing};

use super::values::{cell, ColMeta};
use crate::authz::{AuthorizedEdit, AuthorizedStatement};
use crate::driver::{resolve, ConnectError, ConnectSpec, DbError, PluginSql, TextParam};
use crate::host::Credential;
use crate::profile::{Tls, TlsMode};
use crate::tls::RootSource;
use crate::wire::TxStatus;

/// `sql_mode` flags that switch the server to another grammar (MariaDB
/// `ORACLE`, the legacy compatibility modes): the classifier does not read
/// it, so a session in one is refused.
const GRAMMAR_MODES: &[&str] = &["ORACLE", "MSSQL", "DB2", "POSTGRESQL", "MAXDB"];

/// Rows a statement may have in flight between the driver task and the run
/// buffer; the run's own bound applies after that.
const ROWS_IN_FLIGHT: usize = 16;

/// The lexer-relevant settings the session started with (§4.3 pinning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub sql_mode: String,
    pub charsets: [String; 4],
    pub fold_table_names: bool,
    pub read_only: bool,
}

impl Pinned {
    pub fn lexer(&self) -> LexerSettings {
        let has = |m: &str| self.sql_mode.split(',').any(|f| f.trim().eq_ignore_ascii_case(m));
        LexerSettings::MySql {
            ansi_quotes: has("ANSI_QUOTES"),
            no_backslash_escapes: has("NO_BACKSLASH_ESCAPES"),
            fold_table_names: self.fold_table_names,
        }
    }
}

/// What the session learns once the connection is up.
pub struct Established {
    pub lexer: LexerSettings,
    pub ctx: NameContext,
    pub database_read_only: bool,
    pub server_version: String,
}

/// How to reach the server again for `KILL QUERY`: the address already
/// dialled, the same TLS, and the login, which the side connection needs.
/// The login stays in zeroized buffers until the session closes (§5.4).
struct KillRoute {
    addr: SocketAddr,
    user: Zeroizing<String>,
    pass: Zeroizing<String>,
    ssl: SslOpts,
}

struct Track {
    tx: TxStatus,
    autocommit: bool,
    taint: Option<String>,
    closed: bool,
}

pub struct MyConn {
    conn: tokio::sync::Mutex<Option<Conn>>,
    session_id: String,
    connection_id: u32,
    pub mariadb: bool,
    pinned: Mutex<Option<Pinned>>,
    kill: KillRoute,
    track: Mutex<Track>,
    active: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// A statement the server accepted: its columns, then its rows as JSON
/// cells, then how it ended.
pub struct MyQuery {
    pub columns: Vec<ColMeta>,
    pub rows: mpsc::Receiver<Result<Vec<serde_json::Value>, DbError>>,
    pub end: oneshot::Receiver<Result<u64, DbError>>,
}

/// A database or driver error, split as `driver::DbError` asks: the
/// server's message may echo row values and is never stored (§11).
pub fn db_error(e: mysql_async::Error) -> DbError {
    match e {
        mysql_async::Error::Server(s) => DbError {
            sqlstate: Some(s.state.clone()),
            severity: None,
            message: format!("{} (MySQL error {})", s.message, s.code),
            from_server: true,
        },
        other => {
            let s = other.to_string();
            let s = match s.char_indices().nth(300) {
                Some((i, _)) => format!("{}…", &s[..i]),
                None => s,
            };
            DbError::plugin(s)
        }
    }
}

fn lost(e: &mysql_async::Error) -> bool {
    matches!(e, mysql_async::Error::Io(_))
        || matches!(e, mysql_async::Error::Driver(mysql_async::DriverError::ConnectionClosed))
}

/// The driver's TLS options for a profile. MySQL and MariaDB sessions are
/// encrypted: the driver gives no hook to refuse a weak authentication
/// method on a plaintext connection, so `disable` is refused rather than
/// allowed with that check missing (§5.4).
/// Whether a profile's TLS mode can serve a MySQL / MariaDB session.
pub fn check_tls_mode(mode: TlsMode) -> Result<(), ConnectError> {
    match mode {
        TlsMode::Disable => Err(ConnectError::new(
            "tls_required",
            "MySQL and MariaDB sessions need TLS (`require` or `verify-full`): without it the plugin cannot refuse \
             an authentication that hands the password to the network",
        )),
        TlsMode::VerifyCa => Err(ConnectError::new(
            "tls_mode_unsupported",
            "`verify-ca` is not available for MySQL and MariaDB: the driver cannot check the chain without the \
             name. Use `verify-full` (set `tls.server_name` to the certificate's name) or `require`",
        )),
        TlsMode::Require | TlsMode::VerifyFull => Ok(()),
    }
}

fn ssl_opts(tls: &Tls, host: &str, roots: RootSource) -> Result<SslOpts, ConnectError> {
    check_tls_mode(tls.mode)?;
    let name =
        tls.server_name.clone().unwrap_or_else(|| host.trim_start_matches('[').trim_end_matches(']').to_string());
    match tls.mode {
        TlsMode::Disable | TlsMode::VerifyCa => Err(ConnectError::new("tls_config", "TLS mode refused")),
        // No chain or name check; the handshake signatures are still
        // verified (the driver's verifier delegates them to webpki).
        TlsMode::Require => {
            Ok(SslOpts::default().with_danger_accept_invalid_certs(true).with_danger_tls_hostname_override(Some(name)))
        }
        TlsMode::VerifyFull => {
            let certs: Vec<CertificateDer<'static>> = match &tls.ca_pem {
                Some(pem) => CertificateDer::pem_slice_iter(pem.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ConnectError::new("tls_config", "the profile's tls.ca_pem is not a PEM bundle"))?,
                None => roots().map_err(|m| ConnectError::new("tls_config", m))?,
            };
            // Only anchors webpki can use: the driver fails the whole
            // connection on one it cannot parse.
            let mut usable = Vec::new();
            for c in certs {
                let mut probe = rustls::RootCertStore::empty();
                if probe.add(c.clone()).is_ok() {
                    usable.push(c.as_ref().to_vec().into());
                }
            }
            if usable.is_empty() {
                return Err(ConnectError::new("tls_config", "no usable trust anchor for the connection"));
            }
            Ok(SslOpts::default()
                .with_root_certs(usable)
                .with_disable_built_in_roots(true)
                .with_danger_tls_hostname_override(Some(name)))
        }
    }
}

fn opts(addr: SocketAddr, user: &str, pass: &str, db: Option<&str>, ssl: SslOpts) -> Opts {
    OptsBuilder::default()
        // The checked address, never a name to resolve again; TLS checks
        // the profile's name through the hostname override.
        .ip_or_hostname(addr.ip().to_string())
        .tcp_port(addr.port())
        .prefer_socket(false)
        .user(Some(user))
        .pass(Some(pass))
        .db_name(db)
        .ssl_opts(Some(ssl))
        .secure_auth(true)
        // Every session is encrypted (`ssl_opts`): §5.4 allows a reversible
        // method there, and LDAP / PAM logins need it.
        .enable_cleartext_plugin(true)
        // UPDATE reports matched rows, so an edit that writes the same
        // value is not mistaken for a conflict.
        .client_found_rows(true)
        .stmt_cache_size(0)
        .tcp_nodelay(true)
        .connect_attribute("program_name", "bastionvault-sql-browser")
        .into()
}

impl MyConn {
    /// Open the session's connection with `credential`, which is consumed:
    /// the plugin's copy moves into zeroized buffers kept for `KILL QUERY`.
    pub async fn connect(spec: ConnectSpec<'_>, mut credential: Credential) -> Result<Self, ConnectError> {
        let user = Zeroizing::new(std::mem::take(&mut credential.username));
        let pass = Zeroizing::new(std::mem::take(&mut *credential.password));
        let endpoint = std::mem::take(&mut credential.endpoint);
        credential.password.zeroize();
        let profile = spec.profile;
        // The host released the login for this endpoint only (§5.4 rule 5).
        if endpoint != profile.endpoint {
            return Err(ConnectError::new(
                "endpoint_mismatch",
                "the released credential is bound to another endpoint than the profile's",
            ));
        }
        if spec.catalog.is_empty() || spec.catalog.len() > 64 || spec.catalog.chars().any(char::is_control) {
            return Err(ConnectError::new("bad_request", "invalid database name"));
        }
        let ssl = ssl_opts(&profile.tls, &profile.host, spec.roots)?;
        let addrs = resolve(profile, spec.allowed, spec.denied).await?;
        let mut last = ConnectError::new("connect_failed", "no address could be dialled");
        for addr in addrs {
            let o = opts(addr, &user, &pass, Some(spec.catalog), ssl.clone());
            let conn = match tokio::time::timeout(spec.connect_timeout, Conn::new(o)).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    let code = match &e {
                        mysql_async::Error::Driver(mysql_async::DriverError::CleartextPluginDisabled)
                        | mysql_async::Error::Driver(mysql_async::DriverError::MysqlOldPasswordDisabled) => {
                            "weak_auth_refused"
                        }
                        mysql_async::Error::Io(_) => "connect_failed",
                        _ => "connect_failed",
                    };
                    last = ConnectError::new(code, format!("could not open the session: {}", db_error(e).message));
                    if matches!(code, "weak_auth_refused") {
                        return Err(last);
                    }
                    continue;
                }
                Err(_) => {
                    last = ConnectError::new("connect_timeout", "the database did not answer in time");
                    continue;
                }
            };
            // MariaDB reports 10.x and later; MySQL 8.x and 9.x.
            let mariadb = conn.server_version().0 >= 10;
            return Ok(Self {
                connection_id: conn.id(),
                conn: tokio::sync::Mutex::new(Some(conn)),
                session_id: spec.session_id.to_string(),
                mariadb,
                pinned: Mutex::new(None),
                kill: KillRoute { addr, user, pass, ssl },
                track: Mutex::new(Track { tx: TxStatus::Idle, autocommit: true, taint: None, closed: false }),
                active: Mutex::new(None),
            });
        }
        Err(last)
    }

    fn track(&self) -> std::sync::MutexGuard<'_, Track> {
        self.track.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn tx(&self) -> TxStatus {
        self.track().tx
    }

    pub fn taint(&self) -> Option<String> {
        self.track().taint.clone()
    }

    fn set_taint(&self, why: String) {
        let mut t = self.track();
        if t.taint.is_none() {
            t.taint = Some(why);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.track().closed
    }

    fn note_error(&self, e: &mysql_async::Error) {
        if lost(e) {
            self.track().closed = true;
        }
        // A deadlock rolls the whole transaction back (error 1213).
        if let mysql_async::Error::Server(s) = e {
            if s.code == 1213 {
                self.track().tx = TxStatus::Idle;
            }
        }
    }

    /// Transaction state after a statement that succeeded. MySQL reports it
    /// in a status flag the driver keeps private, so it is tracked from the
    /// classified kinds, erring towards "open": an implicit commit (DDL)
    /// leaves it shown open, and a needless ROLLBACK is harmless.
    pub fn note_statement(&self, kind: Option<StatementKind>) {
        let mut t = self.track();
        t.tx = match kind {
            Some(StatementKind::TxBegin) => TxStatus::InTransaction,
            Some(StatementKind::TxCommit | StatementKind::TxRollback) => TxStatus::Idle,
            _ if !t.autocommit => TxStatus::InTransaction,
            _ => t.tx,
        };
    }

    async fn lock(&self) -> Result<tokio::sync::MutexGuard<'_, Option<Conn>>, DbError> {
        let guard = self.conn.lock().await;
        if guard.is_none() {
            return Err(DbError::plugin("the database connection is closed"));
        }
        Ok(guard)
    }

    fn fail(&self, e: mysql_async::Error) -> DbError {
        self.note_error(&e);
        db_error(e)
    }

    /// Plugin-authored SQL with typed bound values (binary protocol when
    /// there are values).
    pub async fn internal_values(&self, sql: &PluginSql, values: Vec<My>) -> Result<Vec<Row>, DbError> {
        let mut guard = self.lock().await?;
        let conn = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        let r = if values.is_empty() {
            conn.query::<Row, _>(sql.as_str()).await
        } else {
            conn.exec::<Row, _, _>(sql.as_str(), Params::Positional(values)).await
        };
        drop(guard);
        r.map_err(|e| self.fail(e))
    }

    /// Plugin-authored SQL with bound text parameters.
    pub async fn internal_query(&self, sql: &PluginSql, params: &[TextParam]) -> Result<Vec<Row>, DbError> {
        let values: Vec<My> =
            params.iter().map(|p| p.0.clone().map_or(My::NULL, |s| My::Bytes(s.into_bytes()))).collect();
        self.internal_values(sql, values).await
    }

    /// Plugin-authored SQL without a result. The transaction tracker follows
    /// the plugin's own BEGIN / COMMIT / ROLLBACK.
    pub async fn internal_execute(&self, sql: &PluginSql) -> Result<u64, DbError> {
        let mut guard = self.lock().await?;
        let conn = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        let r = conn.query_drop(sql.as_str()).await.map(|_| conn.affected_rows());
        drop(guard);
        let affected = r.map_err(|e| self.fail(e))?;
        let kind = match sql.as_str() {
            "BEGIN" | "START TRANSACTION" => Some(StatementKind::TxBegin),
            "COMMIT" => Some(StatementKind::TxCommit),
            "ROLLBACK" => Some(StatementKind::TxRollback),
            _ => None,
        };
        if kind.is_some() {
            self.note_statement(kind);
        }
        Ok(affected)
    }

    /// A structured row edit, authorized for exactly this statement.
    pub async fn send_edit(&self, edit: AuthorizedEdit) -> Result<u64, DbError> {
        if edit.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let (sql, params) = edit.into_parts();
        let values: Vec<My> = params.into_iter().map(|p| p.0.map_or(My::NULL, |s| My::Bytes(s.into_bytes()))).collect();
        let mut guard = self.lock().await?;
        let conn = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        let r = conn.exec_drop(sql.as_str(), Params::Positional(values)).await.map(|_| conn.affected_rows());
        drop(guard);
        r.map_err(|e| self.fail(e))
    }

    /// The only path for caller SQL: one authorized statement, run by a task
    /// that streams its rows (§6.3: the task stops reading while the run's
    /// buffer is full). The protocol is chosen so that the server runs
    /// exactly one statement (module comment).
    pub async fn send_authorized(self: &Arc<Self>, stmt: AuthorizedStatement) -> Result<MyQuery, DbError> {
        if stmt.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let kind = stmt.meta().kind;
        let text = stmt.text().to_string();
        drop(stmt);
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
            Ok(Ok(columns)) => Ok(MyQuery { columns, rows: rows_rx, end: end_rx }),
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
        let mut guard = self.conn.lock().await;
        let Some(conn) = guard.as_mut() else {
            let e = DbError::plugin("the database connection is closed");
            let _ = cols_tx.send(Err(e.clone()));
            return Err(e);
        };
        let prepared = text.contains(';');
        let outcome = if prepared {
            match conn.prep(text.as_str()).await {
                Ok(stmt) => {
                    let r = match conn.exec_iter(&stmt, ()).await {
                        Ok(result) => drain(result, cols_tx, rows_tx).await,
                        Err(e) => {
                            let d = db_error_ref(&e);
                            let _ = cols_tx.send(Err(d));
                            Err(e)
                        }
                    };
                    let _ = conn.close(stmt).await;
                    r
                }
                Err(e) => {
                    let _ = cols_tx.send(Err(db_error_ref(&e)));
                    Err(e)
                }
            }
        } else {
            match conn.query_iter(text.as_str()).await {
                Ok(result) => drain(result, cols_tx, rows_tx).await,
                Err(e) => {
                    let _ = cols_tx.send(Err(db_error_ref(&e)));
                    Err(e)
                }
            }
        };
        drop(guard);
        match outcome {
            Ok(n) => {
                self.note_statement(kind);
                Ok(n)
            }
            Err(e) => {
                self.note_error(&e);
                Err(db_error(e))
            }
        }
    }

    /// `KILL QUERY` on a side connection to the same checked address, with
    /// the same TLS and login (§6.2). A server that has finished the
    /// statement ignores it.
    pub async fn cancel(&self) -> Result<(), DbError> {
        let k = &self.kill;
        let o = opts(k.addr, &k.user, &k.pass, None, k.ssl.clone());
        let kill = PluginSql::kill_query(self.connection_id);
        let work = async move {
            let mut side = Conn::new(o).await.map_err(db_error)?;
            let r = side.query_drop(kill.as_str()).await.map_err(db_error);
            let _ = side.disconnect().await;
            r
        };
        tokio::time::timeout(Duration::from_secs(10), work)
            .await
            .map_err(|_| DbError::plugin("cancel: the database did not answer in time"))?
    }

    /// Drop the connection (the server rolls back an open transaction).
    pub fn shutdown(&self) {
        self.track().closed = true;
        if let Some(task) = self.active.lock().unwrap_or_else(|p| p.into_inner()).take() {
            task.abort();
        }
        if let Ok(mut guard) = self.conn.try_lock() {
            drop(guard.take());
        }
    }

    // ── session setup and the pinned settings ───────────────────────────

    async fn read_settings(&self) -> Result<(Pinned, Option<String>, bool, String, bool), DbError> {
        let ro_var = if self.mariadb {
            PluginSql::guarded(sql!(
                "SELECT VERSION(), @@SESSION.sql_mode, @@lower_case_table_names, @@SESSION.character_set_client, \
                 @@SESSION.character_set_connection, @@SESSION.character_set_results, @@SESSION.collation_connection, \
                 DATABASE(), @@SESSION.autocommit, @@SESSION.tx_read_only"
            ))
        } else {
            PluginSql::guarded(sql!(
                "SELECT VERSION(), @@SESSION.sql_mode, @@lower_case_table_names, @@SESSION.character_set_client, \
                 @@SESSION.character_set_connection, @@SESSION.character_set_results, @@SESSION.collation_connection, \
                 DATABASE(), @@SESSION.autocommit, @@SESSION.transaction_read_only"
            ))
        };
        let rows = self.internal_query(&ro_var, &[]).await?;
        let row = rows.first().ok_or_else(|| DbError::plugin("no session settings row"))?;
        let text = |i: usize| -> Option<String> {
            match row.as_ref(i)? {
                My::Bytes(b) => String::from_utf8(b.clone()).ok(),
                My::Int(n) => Some(n.to_string()),
                My::UInt(n) => Some(n.to_string()),
                _ => None,
            }
        };
        let version = text(0).unwrap_or_default();
        let pinned = Pinned {
            sql_mode: text(1).unwrap_or_default(),
            fold_table_names: text(2).as_deref() != Some("0"),
            charsets: [
                text(3).unwrap_or_default(),
                text(4).unwrap_or_default(),
                text(5).unwrap_or_default(),
                text(6).unwrap_or_default(),
            ],
            read_only: text(9).as_deref() == Some("1"),
        };
        let database = text(7);
        let autocommit = text(8).as_deref() != Some("0");
        Ok((pinned, database, autocommit, version, text(2).is_some()))
    }

    /// After the connection is up: pin the settings the classifier depends
    /// on, set the database-side guards, and read the name context.
    pub async fn establish(
        &self,
        engine_is_mariadb: bool,
        read_only: bool,
        statement_timeout: Duration,
    ) -> Result<Established, String> {
        let (pinned, _, _, version, lctn_known) =
            self.read_settings().await.map_err(|e| format!("reading the session settings: {}", e.message))?;
        let is_mariadb = version.to_ascii_lowercase().contains("mariadb");
        if is_mariadb != engine_is_mariadb || is_mariadb != self.mariadb {
            return Err(format!(
                "the resource's engine is {} but the server reports version {version}",
                if engine_is_mariadb { "mariadb" } else { "mysql" }
            ));
        }
        let numbers: Vec<u32> = version
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .take(2)
            .filter_map(|s| s.parse().ok())
            .collect();
        let (major, minor) = (numbers.first().copied().unwrap_or(0), numbers.get(1).copied().unwrap_or(0));
        let supported = if is_mariadb { (major, minor) >= (10, 6) } else { major >= 8 };
        if !supported {
            return Err(format!(
                "server version {version} is not supported (MySQL 8.0 or MariaDB 10.6 and later): the classifier's \
                 function table assumes them"
            ));
        }
        if !lctn_known {
            return Err("the server did not report lower_case_table_names".into());
        }
        let modes: Vec<String> = pinned.sql_mode.split(',').map(|m| m.trim().to_ascii_uppercase()).collect();
        if let Some(m) = modes.iter().find(|m| GRAMMAR_MODES.contains(&m.as_str())) {
            return Err(format!(
                "the session's sql_mode includes {m}, which switches the server to a grammar the SQL browser does not \
                 classify; give the login another default sql_mode"
            ));
        }
        // mysql_async asks for utf8mb4 in the handshake; anything else would
        // change how the server reads the bytes it is sent.
        let utf8 = |s: &str| s == "utf8mb4" || s.starts_with("utf8mb4_");
        if !pinned.charsets.iter().all(|c| utf8(c)) {
            return Err("the server did not accept the utf8mb4 connection character set".into());
        }
        // Timeouts at the database (§5.3): MySQL limits SELECT, MariaDB
        // every statement. The plugin's own run deadline applies anyway.
        let (set, value) = if is_mariadb {
            (
                PluginSql::guarded(sql!("SET SESSION max_statement_time = ?")),
                My::Double(statement_timeout.as_secs_f64()),
            )
        } else {
            let ms = u64::try_from(statement_timeout.as_millis()).unwrap_or(u64::MAX);
            (PluginSql::guarded(sql!("SET SESSION max_execution_time = ?")), My::UInt(ms))
        };
        self.internal_values(&set, vec![value]).await.map_err(|e| format!("setting the timeout: {}", e.message))?;
        if read_only {
            let ro = PluginSql::guarded(sql!("SET SESSION TRANSACTION READ ONLY"));
            self.internal_execute(&ro).await.map_err(|e| format!("setting READ ONLY: {}", e.message))?;
        }
        let (pinned, database, autocommit, _, _) =
            self.read_settings().await.map_err(|e| format!("reading the session settings: {}", e.message))?;
        // Database-enforced only if the server confirms it.
        let database_read_only = read_only && pinned.read_only;
        if read_only && !database_read_only {
            return Err("the server did not confirm the read-only transaction guard".into());
        }
        self.track().autocommit = autocommit;
        let lexer = pinned.lexer();
        *self.pinned.lock().unwrap_or_else(|p| p.into_inner()) = Some(pinned);
        Ok(Established {
            lexer,
            ctx: NameContext { database_read_only, ..NameContext::mysql(database) },
            database_read_only,
            server_version: version,
        })
    }

    /// The name context, re-read after a statement that may have changed it
    /// (`USE`, a routine, an unclassified statement). A pinned setting found
    /// changed taints the session: it is closed on its next request.
    pub async fn read_context(&self, database_read_only: bool) -> Result<NameContext, DbError> {
        let (now, database, autocommit, _, _) = self.read_settings().await?;
        self.track().autocommit = autocommit;
        let before = self.pinned.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(before) = before {
            if now.sql_mode != before.sql_mode {
                self.set_taint("the session's sql_mode changed behind the classifier".into());
            } else if now.charsets != before.charsets {
                self.set_taint("the session's character set changed behind the classifier".into());
            } else if database_read_only && !now.read_only {
                self.set_taint("the session's read-only guard was lifted".into());
            }
        }
        Ok(NameContext { database_read_only, ..NameContext::mysql(database) })
    }
}

/// `mysql_async::Error` is not `Clone`; the caller-facing copy for the
/// first answer, while the original goes to the tracker.
fn db_error_ref(e: &mysql_async::Error) -> DbError {
    match e {
        mysql_async::Error::Server(s) => DbError {
            sqlstate: Some(s.state.clone()),
            severity: None,
            message: format!("{} (MySQL error {})", s.message, s.code),
            from_server: true,
        },
        other => DbError::plugin(other.to_string().chars().take(300).collect::<String>()),
    }
}

/// Send the columns, then every row of the first result set as cells; drop
/// any further result sets (a procedure's). Returns the affected rows.
async fn drain<P: mysql_async::prelude::Protocol>(
    mut result: mysql_async::QueryResult<'_, 'static, P>,
    cols_tx: oneshot::Sender<Result<Vec<ColMeta>, DbError>>,
    rows_tx: mpsc::Sender<Result<Vec<serde_json::Value>, DbError>>,
) -> Result<u64, mysql_async::Error> {
    let columns: Vec<ColMeta> = result.columns_ref().iter().map(ColMeta::new).collect();
    let _ = cols_tx.send(Ok(columns.clone()));
    let mut receiver_gone = false;
    loop {
        match result.next().await {
            Ok(Some(row)) => {
                if receiver_gone {
                    continue;
                }
                let cells: Vec<serde_json::Value> =
                    row.unwrap().into_iter().zip(&columns).map(|(v, m)| cell(m, v)).collect();
                if rows_tx.send(Ok(cells)).await.is_err() {
                    // The run stopped reading (it sent KILL QUERY first):
                    // drain what the server still sends.
                    receiver_gone = true;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = rows_tx.send(Err(db_error_ref(&e))).await;
                return Err(e);
            }
        }
    }
    let affected = result.affected_rows();
    result.drop_result().await?;
    Ok(affected)
}
