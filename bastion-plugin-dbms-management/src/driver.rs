//! The PostgreSQL connection of one session. The driver's `Client` is
//! private to this module, and the only function that sends caller SQL is
//! [`PgConn::send_authorized`], which takes an [`AuthorizedStatement`]: a path
//! that runs unauthorized user text does not compile (§Phase 3). Plugin
//! SQL goes through [`PluginSql`], which has no constructor from a `String`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bv_sql_guard::{Sql, SqlIdent};
use futures_util::StreamExt;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::{to_sql_checked, Format, IsNull, ToSql, Type};
use tokio_postgres::{CancelToken, Client, Column, NoTls, Row, RowStream};
use zeroize::Zeroize;

use crate::authz::{AuthorizedEdit, AuthorizedStatement};
use crate::host::Credential;
use crate::netpolicy::{self, Cidr};
use crate::profile::Profile;
use crate::tls::{self, RootSource, RustlsConnect};
use crate::wire::{Watched, Wire};

/// SQL the plugin itself authored: a `bv_sql_guard` literal, or a row edit
/// assembled by [`EditSql`] from literals, allow-listed identifiers and
/// `$n` placeholders. Never caller text.
pub struct PluginSql(String);

impl PluginSql {
    pub fn guarded(sql: Sql) -> Self {
        Self(sql.into_cow().into_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `KILL QUERY <id>` for MySQL / MariaDB cancellation (§6.2). The only
    /// runtime part is the connection id the driver reported, an integer.
    pub fn kill_query(connection_id: u32) -> Self {
        Self(format!("KILL QUERY {connection_id}"))
    }

    /// A SQL Server row edit followed by its own row count: `@@ROWCOUNT`
    /// read right after it (so a trigger's writes are not counted), with
    /// `NOCOUNT` scoped to the `sp_executesql` batch. Only a plugin-authored
    /// edit goes in; the wrapper is literal.
    pub fn mssql_counted(edit: &PluginSql) -> Self {
        Self(format!("SET NOCOUNT ON; {}; SELECT CAST(@@ROWCOUNT AS bigint)", edit.0))
    }
}

/// Builder for structured row edits (§7). Identifiers are `SqlIdent`s
/// (`[A-Za-z_][A-Za-z0-9_]{0,62}`), quoted so their case is kept (double
/// quotes for PostgreSQL, backticks for MySQL / MariaDB, brackets for SQL
/// Server); every value is a bound placeholder (`$n`, `?` or `@Pn`).
#[derive(Default)]
pub struct EditSql {
    text: String,
    params: usize,
    mysql: bool,
    mssql: bool,
    oracle: bool,
}

impl EditSql {
    /// The MySQL / MariaDB form: backticks and `?` placeholders.
    pub fn mysql() -> Self {
        Self { mysql: true, ..Self::default() }
    }

    /// The SQL Server form: brackets and `@P1`, `@P2`, … placeholders.
    pub fn mssql() -> Self {
        Self { mssql: true, ..Self::default() }
    }

    /// The Oracle form: double quotes (`oracle_quoted`) and `:1`, `:2`, …
    /// placeholders, each used once (positional binding, T129).
    pub fn oracle() -> Self {
        Self { oracle: true, ..Self::default() }
    }

    /// The placeholder `n` again (SQL Server can name one twice).
    pub fn param_again(mut self, n: usize) -> Self {
        self.text.push_str(&format!("@P{n}"));
        self
    }

    pub fn lit(mut self, s: &'static str) -> Self {
        self.text.push_str(s);
        self
    }

    pub fn ident(mut self, id: &SqlIdent) -> Self {
        let quoted = if self.mysql {
            id.backticked()
        } else if self.mssql {
            id.bracketed()
        } else if self.oracle {
            id.oracle_quoted()
        } else {
            id.double_quoted()
        };
        self.text.push_str(&quoted);
        self
    }

    /// The next placeholder.
    pub fn param(mut self) -> Self {
        self.params += 1;
        if self.mysql {
            self.text.push('?');
        } else if self.mssql {
            self.text.push_str(&format!("@P{}", self.params));
        } else if self.oracle {
            self.text.push_str(&format!(":{}", self.params));
        } else {
            self.text.push_str(&format!("${}", self.params));
        }
        self
    }

    pub fn params(&self) -> usize {
        self.params
    }

    pub fn build(self) -> PluginSql {
        PluginSql(self.text)
    }
}

/// A value bound in text format: the server parses it with the column
/// type's input function, so one representation serves every type.
#[derive(Debug, Clone)]
pub struct TextParam(pub Option<String>);

impl ToSql for TextParam {
    fn to_sql(
        &self,
        _: &Type,
        out: &mut bytes_shim::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match &self.0 {
            Some(s) => {
                out.extend_from_slice(s.as_bytes());
                Ok(IsNull::No)
            }
            None => Ok(IsNull::Yes),
        }
    }

    fn accepts(_: &Type) -> bool {
        true
    }

    fn encode_format(&self, _: &Type) -> Format {
        Format::Text
    }

    to_sql_checked!();
}

/// `bytes::BytesMut`, as tokio-postgres re-exports it through `ToSql`.
mod bytes_shim {
    pub use tokio_postgres::types::private::BytesMut;
}

/// What a session needs to open its connection.
pub struct ConnectSpec<'a> {
    pub session_id: &'a str,
    pub profile: &'a Profile,
    pub catalog: &'a str,
    pub read_only: bool,
    pub statement_timeout: Duration,
    /// Server-side backstop; the plugin's own idle-in-transaction rollback
    /// fires first (§6.1).
    pub idle_tx_backstop: Duration,
    pub connect_timeout: Duration,
    pub allowed: &'a [Cidr],
    pub denied: &'a [Cidr],
    pub roots: RootSource,
}

/// Why a connection could not be opened. Messages never hold a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectError {
    pub code: &'static str,
    pub message: String,
}

impl ConnectError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

/// How to reach the server again for a `CancelRequest`.
#[derive(Clone)]
struct CancelRoute {
    addr: SocketAddr,
    tls: Option<(Arc<ClientConfig>, ServerName<'static>)>,
    token: CancelToken,
}

/// One live connection.
pub struct PgConn {
    client: Client,
    session_id: String,
    wire: Arc<Wire>,
    cancel: CancelRoute,
    conn_task: tokio::task::JoinHandle<()>,
}

/// A statement the server accepted, with its result columns (name, type).
pub struct UserQuery {
    pub columns: Vec<(String, Type)>,
    pub rows: RowStream,
}

/// Validate a database name before it goes into the startup packet.
fn catalog_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= 63 && !c.chars().any(|ch| ch.is_control())
}

/// Resolve `host:port` and keep the addresses `allowed_networks` permits.
pub(crate) async fn resolve(
    profile: &Profile,
    allowed: &[Cidr],
    denied: &[Cidr],
) -> Result<Vec<SocketAddr>, ConnectError> {
    let host = profile.host.trim_start_matches('[').trim_end_matches(']');
    let found: Vec<SocketAddr> = tokio::net::lookup_host((host, profile.port))
        .await
        .map_err(|_| ConnectError::new("endpoint_unresolvable", "the profile's host does not resolve"))?
        .collect();
    netpolicy::filter(&found, allowed, denied).map_err(|m| ConnectError::new("network_not_allowed", m))
}

impl PgConn {
    /// Open the session's connection with `credential`, which is consumed
    /// and zeroized here whatever the outcome (§5.4: kept for the
    /// connection only).
    pub async fn connect(spec: ConnectSpec<'_>, mut credential: Credential) -> Result<Self, ConnectError> {
        let result = Self::connect_inner(&spec, &credential).await;
        credential.password.zeroize();
        credential.username.zeroize();
        result
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
        if !catalog_ok(spec.catalog) {
            return Err(ConnectError::new("bad_request", "invalid database name"));
        }
        let tls = tls::client_config(&profile.tls, spec.roots).map_err(|m| ConnectError::new("tls_config", m))?;
        let name = match tls {
            Some(_) => {
                Some(tls::server_name(&profile.tls, &profile.host).map_err(|m| ConnectError::new("tls_config", m))?)
            }
            None => None,
        };
        let addrs = resolve(profile, spec.allowed, spec.denied).await?;

        let mut cfg = tokio_postgres::Config::new();
        cfg.user(cred.username.as_str());
        cfg.password(cred.password.as_bytes());
        cfg.dbname(spec.catalog);
        cfg.application_name("bastionvault-sql-browser");
        cfg.ssl_mode(if tls.is_some() { SslMode::Require } else { SslMode::Disable });
        let mut opts = format!(
            "-c statement_timeout={} -c idle_in_transaction_session_timeout={}",
            spec.statement_timeout.as_millis(),
            spec.idle_tx_backstop.as_millis()
        );
        if spec.read_only {
            opts.push_str(" -c default_transaction_read_only=on");
        }
        cfg.options(opts);

        let encrypted = tls.is_some();
        let wire = Wire::new(encrypted);
        let mut last = ConnectError::new("connect_failed", "no address could be dialled");
        for addr in addrs {
            let dial = tokio::time::timeout(spec.connect_timeout, TcpStream::connect(addr)).await;
            let stream = match dial {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    last = ConnectError::new("connect_failed", format!("could not reach the database: {}", e.kind()));
                    continue;
                }
                Err(_) => {
                    last = ConnectError::new("connect_timeout", "the database did not answer in time");
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let opened = match (&tls, &name) {
                (Some(config), Some(name)) => {
                    let connect = RustlsConnect { config: config.clone(), name: name.clone(), wire: wire.clone() };
                    let fut = cfg.connect_raw(stream, connect);
                    match tokio::time::timeout(spec.connect_timeout, fut).await {
                        Ok(Ok((client, conn))) => Ok((
                            client,
                            tokio::spawn(async move {
                                let _ = conn.await;
                            }),
                        )),
                        Ok(Err(e)) => Err(e),
                        Err(_) => return Err(ConnectError::new("connect_timeout", "the database handshake timed out")),
                    }
                }
                _ => {
                    let fut = cfg.connect_raw(Watched::new(stream, wire.clone()), NoTls);
                    match tokio::time::timeout(spec.connect_timeout, fut).await {
                        Ok(Ok((client, conn))) => Ok((
                            client,
                            tokio::spawn(async move {
                                let _ = conn.await;
                            }),
                        )),
                        Ok(Err(e)) => Err(e),
                        Err(_) => return Err(ConnectError::new("connect_timeout", "the database handshake timed out")),
                    }
                }
            };
            match opened {
                Ok((client, conn_task)) => {
                    let token = client.cancel_token();
                    let tls_route = tls.clone().zip(name.clone());
                    return Ok(Self {
                        client,
                        session_id: spec.session_id.to_string(),
                        wire,
                        cancel: CancelRoute { addr, tls: tls_route, token },
                        conn_task,
                    });
                }
                Err(e) => {
                    // The wire's own refusal (weak auth) is the precise reason.
                    if let Some(why) = wire.taint() {
                        return Err(ConnectError::new("weak_auth_refused", why));
                    }
                    return Err(ConnectError::new("connect_failed", describe(&e)));
                }
            }
        }
        Err(last)
    }

    pub fn wire(&self) -> &Arc<Wire> {
        &self.wire
    }

    pub fn is_closed(&self) -> bool {
        self.client.is_closed()
    }

    /// The only path for caller SQL: one authorized statement, one Parse
    /// (the server refuses several commands in one), then its execution.
    pub async fn send_authorized(&self, stmt: AuthorizedStatement) -> Result<UserQuery, DbError> {
        if stmt.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let prepared = self.client.prepare(stmt.text()).await.map_err(DbError::from)?;
        if !prepared.params().is_empty() {
            return Err(DbError::plugin("statements with `$n` parameters are not supported"));
        }
        let columns = prepared.columns().iter().map(|c: &Column| (c.name().to_string(), c.type_().clone())).collect();
        let rows = self.client.query_raw(&prepared, std::iter::empty::<&TextParam>()).await.map_err(DbError::from)?;
        Ok(UserQuery { columns, rows })
    }

    /// A structured row edit, authorized for exactly this statement.
    pub async fn send_edit(&self, edit: AuthorizedEdit) -> Result<u64, DbError> {
        if edit.session_id() != self.session_id {
            return Err(DbError::plugin("an authorization made for another session"));
        }
        let (sql, params) = edit.into_parts();
        let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
        self.client.execute(sql.as_str(), &refs).await.map_err(DbError::from)
    }

    /// Plugin-authored SQL with bound text parameters.
    pub async fn internal_query(&self, sql: &PluginSql, params: &[TextParam]) -> Result<Vec<Row>, DbError> {
        let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
        self.client.query(sql.as_str(), &refs).await.map_err(DbError::from)
    }

    pub async fn internal_execute(&self, sql: &PluginSql) -> Result<u64, DbError> {
        self.client.execute(sql.as_str(), &[]).await.map_err(DbError::from)
    }

    /// Send a `CancelRequest` on a fresh connection to the same address,
    /// re-checked against nothing new: it is the address already dialled.
    pub async fn cancel(&self) -> Result<(), DbError> {
        let route = self.cancel.clone();
        let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(route.addr))
            .await
            .map_err(|_| DbError::plugin("cancel: the database did not answer in time"))?
            .map_err(|e| DbError::plugin(format!("cancel: {}", e.kind())))?;
        match route.tls {
            Some((config, name)) => {
                let connect = RustlsConnect { config, name, wire: Wire::new(true) };
                route.token.cancel_query_raw(stream, connect).await.map_err(DbError::from)
            }
            None => route.token.cancel_query_raw(stream, NoTls).await.map_err(DbError::from),
        }
    }

    /// Drop the connection (the server rolls back an open transaction).
    pub fn shutdown(&self) {
        self.conn_task.abort();
    }
}

/// Read every row of a plugin query stream (bounded by the caller's SQL).
pub async fn drain(mut rows: std::pin::Pin<&mut RowStream>) -> Result<Vec<Row>, DbError> {
    let mut out = Vec::new();
    while let Some(r) = rows.next().await {
        out.push(r.map_err(DbError::from)?);
    }
    Ok(out)
}

/// A database or driver error, split into what the caller may see and what
/// may be stored. The message can echo row values ("Key (email)=(…)"), so
/// only the SQLSTATE and severity are kept at rest (§11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError {
    pub sqlstate: Option<String>,
    pub severity: Option<String>,
    pub message: String,
    pub from_server: bool,
}

impl DbError {
    pub fn plugin(m: impl Into<String>) -> Self {
        Self { sqlstate: None, severity: None, message: m.into(), from_server: false }
    }

    /// What the journal stores: never the server's message text.
    pub fn redacted(&self) -> String {
        match (&self.sqlstate, self.from_server) {
            (Some(code), _) => format!("SQLSTATE {code}"),
            (None, true) => "database error".into(),
            (None, false) => self.message.clone(),
        }
    }
}

impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        match e.as_db_error() {
            Some(db) => Self {
                sqlstate: Some(db.code().code().to_string()),
                severity: Some(db.severity().to_string()),
                message: db.message().to_string(),
                from_server: true,
            },
            None => Self { sqlstate: None, severity: None, message: describe(&e), from_server: false },
        }
    }
}

/// A driver error without its source chain's free text where that could
/// carry server-supplied data.
fn describe(e: &tokio_postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return format!("{} ({})", db.message(), db.code().code());
    }
    if e.is_closed() {
        return "the database connection is closed".into();
    }
    let s = e.to_string();
    if s.len() > 300 {
        format!("{}…", &s[..s.char_indices().nth(300).map(|(i, _)| i).unwrap_or(s.len())])
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bv_sql_guard::sql;

    #[test]
    fn edit_sql_quotes_identifiers_and_numbers_placeholders() {
        let t = SqlIdent::new("Users").unwrap();
        let c = SqlIdent::new("email").unwrap();
        let e = EditSql::default()
            .lit("UPDATE ")
            .ident(&t)
            .lit(" SET ")
            .ident(&c)
            .lit(" = ")
            .param()
            .lit(" WHERE ")
            .ident(&c)
            .lit(" = ")
            .param();
        assert_eq!(e.params(), 2);
        assert_eq!(e.build().as_str(), "UPDATE \"Users\" SET \"email\" = $1 WHERE \"email\" = $2");
        let m = EditSql::mysql()
            .lit("UPDATE ")
            .ident(&t)
            .lit(" SET ")
            .ident(&c)
            .lit(" = ")
            .param()
            .lit(" WHERE ")
            .ident(&c)
            .lit(" <=> ")
            .param();
        assert_eq!(m.params(), 2);
        assert_eq!(m.build().as_str(), "UPDATE `Users` SET `email` = ? WHERE `email` <=> ?");
        assert_eq!(PluginSql::kill_query(42).as_str(), "KILL QUERY 42");
        let s = EditSql::mssql()
            .lit("UPDATE ")
            .ident(&t)
            .lit(" SET ")
            .ident(&c)
            .lit(" = ")
            .param()
            .lit(" WHERE (")
            .ident(&c)
            .lit(" = ")
            .param()
            .lit(" OR (")
            .ident(&c)
            .lit(" IS NULL AND ")
            .param_again(2)
            .lit(" IS NULL))");
        assert_eq!(s.params(), 2);
        let built = s.build();
        assert_eq!(
            built.as_str(),
            "UPDATE [Users] SET [email] = @P1 WHERE ([email] = @P2 OR ([email] IS NULL AND @P2 IS NULL))"
        );
        assert_eq!(
            PluginSql::mssql_counted(&built).as_str(),
            "SET NOCOUNT ON; UPDATE [Users] SET [email] = @P1 WHERE ([email] = @P2 OR ([email] IS NULL AND @P2 IS NULL)); \
             SELECT CAST(@@ROWCOUNT AS bigint)"
        );
        assert_eq!(PluginSql::guarded(sql!("SELECT 1")).as_str(), "SELECT 1");
    }

    #[test]
    fn errors_keep_only_the_sqlstate_at_rest() {
        let e = DbError {
            sqlstate: Some("23505".into()),
            severity: Some("ERROR".into()),
            message: "duplicate key value violates unique constraint; Key (email)=(ana@example.com)".into(),
            from_server: true,
        };
        assert_eq!(e.redacted(), "SQLSTATE 23505");
        assert!(!e.redacted().contains("ana@"));
    }

    #[test]
    fn database_names_are_checked_before_the_startup_packet() {
        assert!(catalog_ok("app"));
        assert!(!catalog_ok(""));
        assert!(!catalog_ok("a\0b"));
        assert!(!catalog_ok(&"x".repeat(64)));
    }
}
