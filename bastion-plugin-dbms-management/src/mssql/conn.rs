//! The SQL Server connection of one session (T128, Phase 7). The driver's
//! `Client` is private to this module, and the only function that sends
//! caller SQL is [`MsConn::send_authorized`], which takes an
//! [`AuthorizedStatement`] (§Phase 3, the rule every engine follows).

// One classified span per round trip: each is sent as its own T-SQL batch.
// SQL Server runs a whole batch and the protocol cannot be told to stop
// after one statement (§4.3's residual), so the classifier refuses a span it
// reads as two statements, and the login's ceiling bounds the rest.

// After every user statement the plugin reads `@@ROWCOUNT`, `@@TRANCOUNT`,
// `XACT_STATE()` and `@@OPTIONS` in the next batch, with a marker: rows
// affected, the transaction state, the pinned QUOTED_IDENTIFIER, and proof
// the connection is still in step with the server.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bv_sql_classify::{LexerSettings, NameContext, NameMatch, ObjectRef};
use bv_sql_guard::sql;
use futures_util::StreamExt;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel, Query, QueryItem, Row};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use zeroize::Zeroize;

use super::tds_tls::{self, Attention, PreloginFraming, TdsTransport};
use super::values::{cell, ColMeta};
use crate::authz::{AuthorizedEdit, AuthorizedStatement, Resolutions};
use crate::driver::{resolve, ConnectError, ConnectSpec, DbError, PluginSql, TextParam};
use crate::host::Credential;
use crate::profile::TlsMode;
use crate::tls;
use crate::wire::TxStatus;

type Stream = Compat<TdsTransport<tokio_rustls::client::TlsStream<PreloginFraming<TcpStream>>>>;

/// Rows a statement may have in flight between the driver task and the run
/// buffer; the run's own bound applies after that.
const ROWS_IN_FLIGHT: usize = 16;
/// `@@OPTIONS` bit for QUOTED_IDENTIFIER.
const OPT_QUOTED_IDENTIFIER: i64 = 256;
/// SQL Server 2016: the oldest release the classifier's tables assume.
const MIN_MAJOR_VERSION: i64 = 13;
/// The marker the bookkeeping batch must return.
const SYNC_MARKER: &str = "bv-sync";

/// Whether a profile's TLS mode can serve a SQL Server session. SQL
/// authentication sends a reversibly obfuscated password, so `disable` is
/// refused (§5.4's weak-authentication rule); every other mode is rustls.
pub fn check_tls_mode(mode: TlsMode) -> Result<(), ConnectError> {
    match mode {
        TlsMode::Disable => Err(ConnectError::new(
            "tls_required",
            "SQL Server sessions need TLS (`require`, `verify-ca` or `verify-full`): SQL authentication sends a \
             reversibly obfuscated password",
        )),
        TlsMode::Require | TlsMode::VerifyCa | TlsMode::VerifyFull => Ok(()),
    }
}

/// How a collation compares identifiers, or `None` when the classifier
/// cannot follow it exactly (Turkic case rules, an unknown name).
pub fn name_match(collation: &str) -> Option<NameMatch> {
    let c = collation.to_ascii_uppercase();
    let has = |flag: &str| c.split('_').any(|p| p == flag);
    if c.contains("_BIN") {
        return Some(NameMatch::Exact);
    }
    if (c.starts_with("TURKISH_") || c.starts_with("AZERI_")) && has("CI") {
        // `I` does not fold to `i` there.
        return None;
    }
    if has("CI") {
        Some(NameMatch::AsciiCaseInsensitive)
    } else if has("CS") {
        Some(NameMatch::AsciiCaseSensitive)
    } else {
        None
    }
}

/// One name in the canonical form the classifier gives it
/// (`bv_sql_classify` §4.4 rules for T-SQL), for catalog-side names.
pub fn canon(m: NameMatch, s: &str) -> Option<String> {
    if s.is_empty() || s.chars().count() > 128 {
        return None;
    }
    let printable_ascii = s.bytes().all(|b| (0x20..0x7f).contains(&b));
    match m {
        NameMatch::Exact if !s.chars().any(char::is_control) => Some(s.to_string()),
        NameMatch::AsciiCaseSensitive if printable_ascii => Some(s.to_string()),
        NameMatch::AsciiCaseInsensitive if printable_ascii => Some(s.to_ascii_lowercase()),
        _ => None,
    }
}

/// The settings the session started with (§4.3 pinning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub names: NameMatch,
    pub catalogs: NameMatch,
}

impl Pinned {
    pub fn lexer(&self) -> LexerSettings {
        LexerSettings::MsSql { quoted_identifier: true, names: self.names, catalogs: self.catalogs }
    }
}

/// What the session learns once the connection is up.
pub struct Established {
    pub lexer: LexerSettings,
    pub ctx: NameContext,
    pub server_version: String,
}

struct Track {
    tx: TxStatus,
    taint: Option<String>,
    closed: bool,
}

pub struct MsConn {
    client: tokio::sync::Mutex<Option<Client<Stream>>>,
    session_id: String,
    attention: Arc<Attention>,
    pinned: Mutex<Option<Pinned>>,
    track: Mutex<Track>,
    active: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// A statement the server accepted: its columns, then its rows as JSON
/// cells, then how it ended (rows affected).
pub struct MsQuery {
    pub columns: Vec<ColMeta>,
    pub rows: mpsc::Receiver<Result<Vec<serde_json::Value>, DbError>>,
    pub end: oneshot::Receiver<Result<u64, DbError>>,
}

/// A database or driver error. The server's message may echo row values
/// and is never stored (§11); its error number stands in for a SQLSTATE.
pub fn db_error(e: &tiberius::error::Error) -> DbError {
    match e {
        tiberius::error::Error::Server(s) => DbError {
            sqlstate: Some(s.code().to_string()),
            severity: Some(s.class().to_string()),
            message: format!("{} (SQL Server error {})", s.message(), s.code()),
            from_server: true,
        },
        other => DbError::plugin(other.to_string().chars().take(300).collect::<String>()),
    }
}

fn lost(e: &tiberius::error::Error) -> bool {
    matches!(e, tiberius::error::Error::Io { .. } | tiberius::error::Error::Protocol(_))
}

fn text(row: &Row, i: usize) -> Option<String> {
    row.try_get::<&str, _>(i).ok().flatten().map(str::to_string)
}

fn int(row: &Row, i: usize) -> Option<i64> {
    match row.cells().nth(i).map(|(_, d)| d) {
        Some(tiberius::ColumnData::U8(Some(n))) => Some(i64::from(*n)),
        Some(tiberius::ColumnData::I16(Some(n))) => Some(i64::from(*n)),
        Some(tiberius::ColumnData::I32(Some(n))) => Some(i64::from(*n)),
        Some(tiberius::ColumnData::I64(Some(n))) => Some(*n),
        _ => None,
    }
}

/// The bookkeeping batch after every statement (module comment).
const STATE_SQL: &str = "SELECT CAST(@@ROWCOUNT AS bigint), @@TRANCOUNT, XACT_STATE(), @@OPTIONS, N'bv-sync'";

struct After {
    rows: u64,
    tx: TxStatus,
    quoted_identifier: bool,
}

impl MsConn {
    /// Open the session's connection with `credential`, which is consumed
    /// and zeroized here whatever the outcome (§5.4). `instance` is the
    /// profile's named instance: the server must confirm it before the
    /// login is sent. SQL Browser (UDP 1434) is never asked for a port.
    pub async fn connect(
        spec: ConnectSpec<'_>,
        mut credential: Credential,
        instance: Option<&str>,
    ) -> Result<Self, ConnectError> {
        let r = Self::connect_inner(&spec, &credential, instance).await;
        credential.password.zeroize();
        credential.username.zeroize();
        r
    }

    async fn connect_inner(
        spec: &ConnectSpec<'_>,
        cred: &Credential,
        instance: Option<&str>,
    ) -> Result<Self, ConnectError> {
        let profile = spec.profile;
        // The host released the login for this endpoint only (§5.4 rule 5).
        if cred.endpoint != profile.endpoint {
            return Err(ConnectError::new(
                "endpoint_mismatch",
                "the released credential is bound to another endpoint than the profile's",
            ));
        }
        if spec.catalog.is_empty() || spec.catalog.chars().count() > 128 || spec.catalog.chars().any(char::is_control) {
            return Err(ConnectError::new("bad_request", "invalid database name"));
        }
        check_tls_mode(profile.tls.mode)?;
        let config = tls::client_config(&profile.tls, spec.roots)
            .map_err(|m| ConnectError::new("tls_config", m))?
            .ok_or_else(|| ConnectError::new("tls_required", "SQL Server sessions need TLS"))?;
        let name = tls::server_name(&profile.tls, &profile.host).map_err(|m| ConnectError::new("tls_config", m))?;
        let addrs = resolve(profile, spec.allowed, spec.denied).await?;
        let mut last = ConnectError::new("connect_failed", "no address could be dialled");
        for addr in addrs {
            match tokio::time::timeout(
                spec.connect_timeout,
                Self::dial(addr, config.clone(), name.clone(), spec, cred, instance),
            )
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
        instance: Option<&str>,
    ) -> Result<Self, ConnectError> {
        let mut tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| ConnectError::new("connect_failed", format!("could not reach the database: {}", e.kind())))?;
        let _ = tcp.set_nodelay(true);
        tds_tls::negotiate(&mut tcp, instance).await.map_err(|(code, m)| ConnectError::new(code, m))?;
        let mut stream = tokio_rustls::TlsConnector::from(config)
            .connect(name, PreloginFraming::new(tcp))
            .await
            .map_err(|e| ConnectError::new("tls_failed", format!("TLS handshake with the database failed: {e}")))?;
        stream.get_mut().0.handshake_complete().map_err(|e| ConnectError::new("tls_failed", e.to_string()))?;
        let attention = Arc::new(Attention::default());
        let mut c = Config::new();
        c.host(spec.profile.host.trim_start_matches('[').trim_end_matches(']'));
        c.port(addr.port());
        c.database(spec.catalog);
        c.application_name("bastionvault-sql-browser");
        c.authentication(AuthMethod::sql_server(cred.username.as_str(), cred.password.as_str()));
        // The transport underneath is TLS already (`tds_tls`).
        c.encryption(EncryptionLevel::NotSupported);
        let client = Client::connect(c, TdsTransport::new(stream, attention.clone()).compat()).await.map_err(|e| {
            let d = db_error(&e);
            ConnectError::new("connect_failed", format!("could not open the session: {}", d.message))
        })?;
        Ok(Self {
            client: tokio::sync::Mutex::new(Some(client)),
            session_id: spec.session_id.to_string(),
            attention,
            pinned: Mutex::new(None),
            track: Mutex::new(Track { tx: TxStatus::Idle, taint: None, closed: false }),
            active: Mutex::new(None),
        })
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

    fn fail(&self, e: &tiberius::error::Error) -> DbError {
        if lost(e) {
            self.track().closed = true;
        }
        db_error(e)
    }

    /// Read the bookkeeping batch on a client already locked.
    async fn after(&self, client: &mut Client<Stream>) -> Result<After, DbError> {
        let row = client
            .simple_query(STATE_SQL)
            .await
            .map_err(|e| self.fail(&e))?
            .into_row()
            .await
            .map_err(|e| self.fail(&e))?;
        let ok = row.as_ref().and_then(|r| text(r, 4)).as_deref() == Some(SYNC_MARKER);
        let Some(row) = row.filter(|_| ok) else {
            // Out of step with the server: nothing more is sent on it.
            self.track().closed = true;
            self.set_taint("the connection fell out of step with the server".into());
            return Err(DbError::plugin("the connection fell out of step with the server; the session is closed"));
        };
        let trancount = int(&row, 1).unwrap_or(1);
        let xact = int(&row, 2).unwrap_or(0);
        let tx = if xact == -1 {
            TxStatus::Failed
        } else if trancount > 0 {
            TxStatus::InTransaction
        } else {
            TxStatus::Idle
        };
        let options = int(&row, 3).unwrap_or(0);
        Ok(After {
            rows: u64::try_from(int(&row, 0).unwrap_or(0)).unwrap_or(0),
            tx,
            quoted_identifier: options & OPT_QUOTED_IDENTIFIER != 0,
        })
    }

    fn note(&self, a: &After) {
        self.track().tx = a.tx;
        if !a.quoted_identifier {
            self.set_taint("QUOTED_IDENTIFIER was turned off behind the classifier".into());
        }
    }

    async fn lock(&self) -> Result<tokio::sync::MutexGuard<'_, Option<Client<Stream>>>, DbError> {
        let guard = self.client.lock().await;
        if guard.is_none() || self.is_closed() {
            return Err(DbError::plugin("the database connection is closed"));
        }
        Ok(guard)
    }

    /// Plugin-authored SQL with bound text parameters (`@P1`, …), run
    /// through `sp_executesql`.
    pub async fn internal_query(&self, q: &PluginSql, params: &[TextParam]) -> Result<Vec<Row>, DbError> {
        let mut guard = self.lock().await?;
        let client = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        let mut query = Query::new(q.as_str().to_string());
        for p in params {
            query.bind(p.0.clone());
        }
        let r = match query.query(client).await {
            Ok(s) => s.into_first_result().await,
            Err(e) => Err(e),
        };
        r.map_err(|e| self.fail(&e))
    }

    /// Plugin-authored SQL without a result, as its own batch
    /// (`BEGIN TRANSACTION`, `COMMIT`, `ROLLBACK`, `SAVE TRANSACTION …`).
    /// A bare `BEGIN` is T-SQL's block keyword, so it is spelled out.
    pub async fn internal_execute(&self, q: &PluginSql) -> Result<u64, DbError> {
        let text = match q.as_str() {
            "BEGIN" | "START TRANSACTION" => "BEGIN TRANSACTION",
            other => other,
        };
        let mut guard = self.lock().await?;
        let client = guard.as_mut().ok_or_else(|| DbError::plugin("the database connection is closed"))?;
        let r = match client.simple_query(text).await {
            Ok(s) => s.into_results().await.map(|_| ()),
            Err(e) => Err(e),
        };
        r.map_err(|e| self.fail(&e))?;
        let a = self.after(client).await?;
        self.note(&a);
        Ok(a.rows)
    }

    /// A structured row edit, authorized for exactly this statement. The
    /// count comes from `@@ROWCOUNT` right after it, so a trigger's own
    /// writes are not counted.
    pub async fn send_edit(&self, edit: AuthorizedEdit) -> Result<u64, DbError> {
        if edit.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let (q, params) = edit.into_parts();
        let rows = self.internal_query(&PluginSql::mssql_counted(&q), &params).await?;
        Ok(rows.first().and_then(|r| int(r, 0)).and_then(|n| u64::try_from(n).ok()).unwrap_or(0))
    }

    /// The only path for caller SQL: one authorized statement as one
    /// batch, run by a task that streams its rows (§6.3: the task stops
    /// reading while the run's buffer is full).
    pub async fn send_authorized(self: &Arc<Self>, stmt: AuthorizedStatement) -> Result<MsQuery, DbError> {
        if stmt.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let text = stmt.text().to_string();
        drop(stmt);
        let (cols_tx, cols_rx) = oneshot::channel();
        let (rows_tx, rows_rx) = mpsc::channel(ROWS_IN_FLIGHT);
        let (end_tx, end_rx) = oneshot::channel();
        let me = self.clone();
        let task = tokio::spawn(async move {
            let ended = me.stream(text, cols_tx, rows_tx).await;
            let _ = end_tx.send(ended);
        });
        *self.active.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
        match cols_rx.await {
            Ok(Ok(columns)) => Ok(MsQuery { columns, rows: rows_rx, end: end_rx }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DbError::plugin("the statement task ended before it answered")),
        }
    }

    async fn stream(
        &self,
        text: String,
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
        let Some(client) = guard.as_mut() else {
            let e = DbError::plugin("the database connection is closed");
            let _ = cols_tx.send(Err(e.clone()));
            return Err(e);
        };
        self.attention.arm(true);
        let outcome = match client.simple_query(text.as_str()).await {
            Err(e) => {
                let d = self.fail(&e);
                let _ = cols_tx.send(Err(d.clone()));
                Err(d)
            }
            Ok(mut s) => 'read: {
                let columns: Vec<ColMeta> = match s.columns().await {
                    Ok(c) => c.map(|c| c.iter().map(ColMeta::new).collect()).unwrap_or_default(),
                    Err(e) => {
                        let d = self.fail(&e);
                        let _ = cols_tx.send(Err(d.clone()));
                        break 'read Err(d);
                    }
                };
                let _ = cols_tx.send(Ok(columns.clone()));
                let mut receiver_gone = false;
                let mut result_sets = 0usize;
                let mut failed = None;
                while let Some(item) = s.next().await {
                    match item {
                        Ok(QueryItem::Metadata(_)) => result_sets += 1,
                        // Only the first result set reaches the grid; later
                        // ones (a procedure's) are read and dropped.
                        Ok(QueryItem::Row(_)) if receiver_gone || result_sets > 1 => {}
                        Ok(QueryItem::Row(row)) => {
                            let cells: Vec<serde_json::Value> =
                                row.cells().zip(&columns).map(|((_, d), m)| cell(m, d)).collect();
                            if rows_tx.send(Ok(cells)).await.is_err() {
                                // The run stopped reading (it asked for an
                                // attention first): drain what still comes.
                                receiver_gone = true;
                            }
                        }
                        Err(e) => {
                            let d = self.fail(&e);
                            let _ = rows_tx.send(Err(d.clone())).await;
                            failed = Some(d);
                            break;
                        }
                    }
                }
                drop(s);
                match failed {
                    Some(d) => Err(d),
                    None => Ok(()),
                }
            }
        };
        self.finish(client, outcome).await
    }

    /// The bookkeeping batch after a user statement, whatever its outcome.
    /// A cancel arriving now is for a statement that has ended: dropped.
    async fn finish(&self, client: &mut Client<Stream>, outcome: Result<(), DbError>) -> Result<u64, DbError> {
        self.attention.arm(false);
        if self.is_closed() {
            return outcome.map(|_| 0);
        }
        let after = self.after(client).await;
        match (&after, &outcome) {
            (Ok(a), _) => self.note(a),
            (Err(_), _) => {}
        }
        match (outcome, after) {
            (Ok(()), Ok(a)) => Ok(a.rows),
            (Err(e), _) | (Ok(()), Err(e)) => Err(e),
        }
    }

    /// The TDS attention signal (§6.2): the transport sends it between
    /// packets of the response being read, and keeps the driver in step.
    /// Nothing is sent when no statement is running.
    pub async fn cancel(&self) -> Result<(), DbError> {
        self.attention.request();
        Ok(())
    }

    /// Drop the connection (the server rolls back an open transaction).
    pub fn shutdown(&self) {
        self.track().closed = true;
        if let Some(task) = self.active.lock().unwrap_or_else(|p| p.into_inner()).take() {
            task.abort();
        }
        if let Ok(mut guard) = self.client.try_lock() {
            drop(guard.take());
        }
    }

    // ── session setup and the pinned settings ───────────────────────────

    async fn settings(&self) -> Result<Vec<Option<String>>, DbError> {
        let q = PluginSql::guarded(sql!(
            "SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS nvarchar(16)), CAST(@@VERSION AS nvarchar(300)), \
             CAST(@@OPTIONS AS nvarchar(16)), CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128)), \
             CAST(SERVERPROPERTY('Collation') AS nvarchar(128)), DB_NAME(), SCHEMA_NAME(), \
             CAST(SERVERPROPERTY('InstanceName') AS nvarchar(128))"
        ));
        let rows = self.internal_query(&q, &[]).await?;
        let row = rows.first().ok_or_else(|| DbError::plugin("no session settings row"))?;
        Ok((0..8).map(|i| text(row, i)).collect())
    }

    /// After the connection is up: pin QUOTED_IDENTIFIER, check the server,
    /// the instance and the collations, and read the name context.
    pub async fn establish(&self, instance: Option<&str>) -> Result<Established, String> {
        let on = PluginSql::guarded(sql!("SET QUOTED_IDENTIFIER ON"));
        self.internal_execute(&on).await.map_err(|e| format!("pinning QUOTED_IDENTIFIER: {}", e.message))?;
        let s = self.settings().await.map_err(|e| format!("reading the session settings: {}", e.message))?;
        let major: i64 = s[0].as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
        let version = s[1].clone().unwrap_or_default().lines().next().unwrap_or("").to_string();
        if major < MIN_MAJOR_VERSION {
            return Err(format!("server version {version} is not supported (SQL Server 2016 or later)"));
        }
        let options: i64 = s[2].as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
        if options & OPT_QUOTED_IDENTIFIER == 0 {
            return Err("the server did not confirm QUOTED_IDENTIFIER ON".into());
        }
        if let Some(want) = instance {
            let got = s[7].clone().unwrap_or_default();
            if !got.eq_ignore_ascii_case(want) {
                return Err("the server is not the profile's named instance (SERVERPROPERTY('InstanceName'))".into());
            }
        }
        let collation = |i: usize, what: &str| -> Result<NameMatch, String> {
            let c = s[i].clone().unwrap_or_default();
            name_match(&c).ok_or_else(|| {
                format!("the {what} collation `{c}` compares names in a way the classifier cannot follow exactly")
            })
        };
        let pinned = Pinned { names: collation(3, "database")?, catalogs: collation(4, "server")? };
        let database = s[5].clone().ok_or("the server reported no database")?;
        if canon(pinned.catalogs, &database).is_none() {
            return Err("the database's name cannot be compared exactly under the server collation".into());
        }
        let lexer = pinned.lexer();
        *self.pinned.lock().unwrap_or_else(|p| p.into_inner()) = Some(pinned);
        Ok(Established { lexer, ctx: NameContext::mssql(database, s[6].clone()), server_version: version })
    }

    /// The name context, re-read after a statement that may have changed it
    /// (`USE`, a routine, an unclassified statement). A changed collation
    /// (another database) or QUOTED_IDENTIFIER taints the session: the
    /// classifier's settings no longer describe it.
    pub async fn read_context(&self, database_read_only: bool) -> Result<NameContext, DbError> {
        let s = self.settings().await?;
        let options: i64 = s[2].as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
        if options & OPT_QUOTED_IDENTIFIER == 0 {
            self.set_taint("QUOTED_IDENTIFIER was turned off behind the classifier".into());
        }
        let before = self.pinned.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(before) = before {
            let now = s[3].as_deref().and_then(name_match);
            if now != Some(before.names) {
                self.set_taint("the current database compares names differently; reopen the session in it".into());
            }
        }
        let database = s[5].clone().ok_or_else(|| DbError::plugin("the server reported no database"))?;
        Ok(NameContext { database_read_only, ..NameContext::mssql(database, s[6].clone()) })
    }

    /// Resolve unqualified names the way the server will (§4.4): the
    /// default schema, then `dbo`, through `OBJECT_ID`. A name that does
    /// not resolve stays `None`: unaddressable.
    pub async fn resolve(&self, refs: &[ObjectRef]) -> Result<Resolutions, DbError> {
        let q = PluginSql::guarded(sql!(
            "SELECT OBJECT_SCHEMA_NAME(OBJECT_ID(QUOTENAME(@P1) + N'..' + QUOTENAME(@P2)), DB_ID(@P1))"
        ));
        let names = self.pinned.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|p| p.names);
        let mut out = Resolutions::new();
        for r in refs {
            let rows =
                self.internal_query(&q, &[TextParam(Some(r.catalog.clone())), TextParam(Some(r.name.clone()))]).await?;
            let schema = rows.first().and_then(|row| text(row, 0)).and_then(|s| names.and_then(|m| canon(m, &s)));
            out.insert(r.clone(), schema);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collations_map_onto_name_rules() {
        assert_eq!(name_match("SQL_Latin1_General_CP1_CI_AS"), Some(NameMatch::AsciiCaseInsensitive));
        assert_eq!(name_match("Latin1_General_100_CS_AS_SC_UTF8"), Some(NameMatch::AsciiCaseSensitive));
        assert_eq!(name_match("Latin1_General_BIN2"), Some(NameMatch::Exact));
        assert_eq!(name_match("Turkish_CI_AS"), None);
        assert_eq!(name_match("Azeri_Latin_100_CI_AI"), None);
        assert_eq!(name_match("Turkish_BIN"), Some(NameMatch::Exact));
        assert_eq!(name_match("mystery"), None);
        assert_eq!(canon(NameMatch::AsciiCaseInsensitive, "Users").as_deref(), Some("users"));
        assert_eq!(canon(NameMatch::AsciiCaseInsensitive, "Ação"), None);
        assert_eq!(canon(NameMatch::Exact, "Ação").as_deref(), Some("Ação"));
    }

    /// The plugin's folding agrees with the classifier's for every mode.
    #[test]
    fn canonical_names_agree_with_the_classifier() {
        for m in [NameMatch::Exact, NameMatch::AsciiCaseSensitive, NameMatch::AsciiCaseInsensitive] {
            let lexer = LexerSettings::MsSql { quoted_identifier: true, names: m, catalogs: m };
            for name in ["Users", "users", "Mixed_Case9", "Ação", "a b"] {
                let text = format!("SELECT * FROM [App].[Sales].[{name}]");
                let ctx = NameContext::mssql("App", Some("dbo".into()));
                let got =
                    bv_sql_classify::classify(bv_sql_classify::Dialect::MsSql, lexer, &text, &ctx).ok().and_then(|v| {
                        match &v[0].required[0].1 {
                            bv_sql_classify::SqlTarget::Object(o) => Some(o.name.clone()),
                            _ => None,
                        }
                    });
                assert_eq!(got, canon(m, name), "{m:?} {name}");
            }
        }
    }

    #[test]
    fn tls_disable_is_refused_and_the_rest_allowed() {
        assert_eq!(check_tls_mode(TlsMode::Disable).unwrap_err().code, "tls_required");
        for m in [TlsMode::Require, TlsMode::VerifyCa, TlsMode::VerifyFull] {
            assert!(check_tls_mode(m).is_ok());
        }
    }
}
