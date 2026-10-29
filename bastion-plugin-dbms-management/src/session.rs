//! Sessions (§6.1): opening one (profile selection, MFA, credential release,
//! connect), the binding every request re-checks, statement execution
//! through the authorization step, idle / lifetime / idle-in-transaction
//! limits, and closing (with rollback of an open transaction).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bv_sql_classify::{redact, Dialect, LexerSettings, NameContext, ObjectKind, ObjectRef, StatementKind};
use bv_sql_guard::sql;
use serde_json::{json, Value};
use tokio::runtime::Runtime;

use crate::api::{ApiError, Caller, Owner};
use crate::audit::{self, Outbox, Pending};
use crate::authz::{self, Resolutions};
use crate::config::Config;
use crate::driver::{ConnectSpec, DbError, PgConn, PluginSql, TextParam};
use crate::host::Host;
use crate::ids;
use crate::journal::{self, Record};
use crate::profile::{self, Enforcement, Selection, Target, TlsMode};
use crate::run::{self, Run, RunLimits, RunStatus, StatementResult};
use crate::tls::RootSource;
use crate::wire::TxStatus;

/// What the session's profile and connection established.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub server_version: String,
    pub enforcement: Enforcement,
    pub read_only: bool,
    pub db_enforced: bool,
    pub grant: Vec<&'static str>,
    pub ceiling: Vec<&'static str>,
    pub vault_only: Vec<&'static str>,
    pub tls_mode: TlsMode,
    /// The database itself enforces read-only transactions, and the server
    /// reports the setting so a change is seen (§5.3, Phase 2 obligation).
    pub database_read_only: bool,
}

struct State {
    lexer: LexerSettings,
    ctx: NameContext,
    /// The name context could not be re-read (typically inside an aborted
    /// transaction): it is re-read before the next classification, and
    /// until that succeeds only transaction control runs.
    ctx_stale: bool,
    last_used: Instant,
    active: Option<Arc<Run>>,
    runs: BTreeMap<String, Arc<Run>>,
    closed: Option<String>,
    rows_read: u64,
    tx_since: Option<Instant>,
    tx_statements: u64,
    run_seq: u64,
    journal: Record,
    /// An execute or a row edit is being set up on the connection.
    op: bool,
}

pub struct Session {
    pub id: String,
    pub owner: Owner,
    pub namespace: String,
    pub resource: String,
    pub profile: String,
    pub catalog: String,
    pub info: SessionInfo,
    pub opened: Instant,
    pub opened_ms: u64,
    conn: Arc<PgConn>,
    state: Mutex<State>,
}

impl Session {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn conn(&self) -> &Arc<PgConn> {
        &self.conn
    }

    fn event(&self, name: &str) -> Value {
        audit::base(name, &self.id, &self.resource, &self.profile, self.info.db_enforced)
    }

    pub fn status(&self) -> Value {
        let st = self.lock();
        let tx = self.conn.wire().tx();
        json!({
            "session_id": self.id,
            "resource": self.resource,
            "profile": self.profile,
            "catalog": self.catalog,
            "engine": "postgresql",
            "server_version": self.info.server_version,
            "enforcement": self.info.enforcement.as_str(),
            "db_enforced": self.info.db_enforced,
            "read_only": self.info.read_only,
            "database_read_only": self.info.database_read_only,
            "privileges": self.info.grant,
            "ceiling": self.info.ceiling,
            "vault_only": self.info.vault_only,
            "transport": "direct",
            "tls_mode": self.info.tls_mode.as_str(),
            "search_path": st.ctx.search_path,
            "current_schema": st.ctx.current_schema,
            "transaction": {
                "open": matches!(tx, TxStatus::InTransaction | TxStatus::Failed),
                "failed": tx == TxStatus::Failed,
                "statements": st.tx_statements,
                "open_secs": st.tx_since.map(|t| t.elapsed().as_secs()),
            },
            "active_run": st.active.as_ref().filter(|r| r.status() == RunStatus::Running).map(|r| r.id.clone()),
            "idle_secs": st.last_used.elapsed().as_secs(),
            "age_secs": self.opened.elapsed().as_secs(),
            "rows_read": st.rows_read,
            "closed": st.closed,
            "taint": self.conn.wire().taint(),
        })
    }

    /// The name context and lexer settings to classify with.
    fn classify_inputs(&self) -> Result<(LexerSettings, NameContext, bool), ApiError> {
        let st = self.lock();
        if let Some(r) = &st.closed {
            return Err(ApiError::refused("session_closed", format!("the session is closed ({r})")));
        }
        Ok((st.lexer, st.ctx.clone(), st.ctx_stale))
    }

    /// Flush the journal record (inside the owner's invocation).
    pub fn flush_journal(&self, host: &dyn Host) {
        self.lock().journal.flush(host);
    }

    pub fn touch(&self) {
        self.lock().last_used = Instant::now();
    }

    pub fn journal_push(&self, entry: Value) {
        self.lock().journal.push(entry);
    }

    /// Claim the connection for one execute or edit: refused while a run
    /// is in progress or another operation is being set up.
    pub fn begin_op(&self) -> Result<OpGuard<'_>, ApiError> {
        let mut st = self.lock();
        if st.op || st.active.as_ref().is_some_and(|r| r.status() == RunStatus::Running) {
            return Err(ApiError::refused(
                "session_busy",
                "a run is in progress on this session; wait for it or cancel it",
            ));
        }
        st.op = true;
        Ok(OpGuard(self))
    }
}

/// Releases [`Session::begin_op`] on drop.
pub struct OpGuard<'a>(&'a Session);

impl Drop for OpGuard<'_> {
    fn drop(&mut self) {
        self.0.lock().op = false;
    }
}

/// Every session this process holds, and the per-owner outbox.
pub struct Registry {
    pub instance: String,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    /// Opens in progress: (owner, resource), counted against the limits.
    reserved: Mutex<Vec<(String, Owner, String)>>,
    pub outbox: Outbox,
}

impl Registry {
    pub fn new(instance: String) -> Self {
        Self { instance, sessions: Mutex::default(), reserved: Mutex::default(), outbox: Outbox::default() }
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Arc<Session>>> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn all(&self) -> Vec<Arc<Session>> {
        self.sessions().values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.sessions().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The caller's session `id`, or why not. A session of another owner is
    /// reported as absent: its existence is not disclosed.
    pub fn get(&self, id: &str, caller: &Caller) -> Result<Arc<Session>, ApiError> {
        let Some(prefix) = ids::instance_of(id) else {
            return Err(ApiError::bad_request("malformed session id"));
        };
        if prefix != self.instance {
            return Err(ApiError::refused(
                "session_on_other_node",
                format!(
                    "the session belongs to plugin instance {prefix}, not this one ({}); it is served by another node, \
                     or this node's plugin restarted. Sessions never fail over: reconnect to its node or open a new one",
                    self.instance
                ),
            ));
        }
        let s = self.sessions().get(id).cloned().ok_or_else(|| ApiError::not_found("no such session"))?;
        if s.owner != caller.owner() {
            return Err(ApiError::not_found("no such session"));
        }
        Ok(s)
    }

    pub fn list(&self, owner: &Owner) -> Vec<Value> {
        self.sessions()
            .values()
            .filter(|s| &s.owner == owner)
            .map(|s| json!({"session_id": s.id, "resource": s.resource, "profile": s.profile, "age_secs": s.opened.elapsed().as_secs()}))
            .collect()
    }

    /// Reserve a slot for an open, or refuse with the limit that applies.
    fn reserve(&self, cfg: &Config, owner: &Owner, resource: &str) -> Result<String, ApiError> {
        let sessions = self.sessions();
        let mut reserved = self.reserved.lock().unwrap_or_else(|p| p.into_inner());
        let user = sessions.values().filter(|s| s.owner.entity_id == owner.entity_id).count()
            + reserved.iter().filter(|(_, o, _)| o.entity_id == owner.entity_id).count();
        let per_resource =
            sessions.values().filter(|s| s.resource == resource && s.namespace == owner.namespace).count()
                + reserved.iter().filter(|(_, o, r)| r == resource && o.namespace == owner.namespace).count();
        let total = sessions.len() + reserved.len();
        if user as u64 >= cfg.sessions_per_user {
            return Err(ApiError::refused(
                "session_limit",
                format!("at most {} sessions per user", cfg.sessions_per_user),
            ));
        }
        if per_resource as u64 >= cfg.sessions_per_resource {
            return Err(ApiError::refused(
                "session_limit",
                format!("at most {} sessions per resource", cfg.sessions_per_resource),
            ));
        }
        if total as u64 >= cfg.sessions_per_node {
            return Err(ApiError::refused(
                "session_limit",
                format!("at most {} sessions per node", cfg.sessions_per_node),
            ));
        }
        let ticket = ids::random_hex(8).ok_or_else(|| ApiError::internal("no randomness"))?;
        reserved.push((ticket.clone(), owner.clone(), resource.to_string()));
        Ok(ticket)
    }

    fn release(&self, ticket: &str) {
        self.reserved.lock().unwrap_or_else(|p| p.into_inner()).retain(|(t, _, _)| t != ticket);
    }

    fn insert(&self, s: Arc<Session>) {
        self.sessions().insert(s.id.clone(), s);
    }

    fn remove(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions().remove(id)
    }
}

/// Everything an operation needs from the plugin.
pub struct Ctx<'a> {
    pub rt: &'a Runtime,
    pub reg: &'a Arc<Registry>,
    pub cfg: &'a Config,
    pub host: &'a dyn Host,
    pub digest_key: &'a [u8],
    pub roots: RootSource,
}

fn text_field<'a>(data: &'a serde_json::Map<String, Value>, k: &str, max: usize) -> Result<Option<&'a str>, ApiError> {
    match data.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control) => Ok(Some(s)),
        Some(_) => Err(ApiError::bad_request(format!("`{k}` must be a string of 1-{max} printable characters"))),
    }
}

const OPEN_KEYS: [&str; 4] = ["resource", "profile", "catalog", "mfa_ticket"];

/// `POST v2/sessions {resource, profile?, catalog?, mfa_ticket?}`.
pub fn open(cx: &Ctx<'_>, caller: &Caller, data: &serde_json::Map<String, Value>) -> Result<Value, ApiError> {
    if let Some(k) = data.keys().find(|k| !OPEN_KEYS.contains(&k.as_str())) {
        return Err(ApiError::bad_request(format!("unknown field `{k}`")));
    }
    let resource = text_field(data, "resource", 256)?.ok_or_else(|| ApiError::bad_request("`resource` is required"))?;
    let requested = text_field(data, "profile", 128)?;
    let catalog_override = text_field(data, "catalog", 63)?;
    let ticket = text_field(data, "mfa_ticket", 256)?;
    let owner = caller.owner();

    let reservation = cx.reg.reserve(cx.cfg, &owner, resource)?;
    let result = open_reserved(cx, caller, &owner, resource, requested, catalog_override, ticket);
    cx.reg.release(&reservation);
    result
}

fn open_reserved(
    cx: &Ctx<'_>,
    caller: &Caller,
    owner: &Owner,
    resource: &str,
    requested: Option<&str>,
    catalog_override: Option<&str>,
    ticket: Option<&str>,
) -> Result<Value, ApiError> {
    let target = Target::parse(&cx.host.sql_target(resource)?)?;
    if target.engine != "postgresql" {
        return Err(ApiError::unsupported(format!(
            "engine `{}` is not supported by this plugin version (PostgreSQL only; T127-T129)",
            target.engine
        )));
    }
    let selection: Selection = profile::select(&target, requested)?;
    let p = &selection.profile;
    if p.require_mfa {
        let ticket =
            ticket.ok_or_else(|| ApiError::refused("mfa_required", "this SQL profile requires an MFA ticket"))?;
        if !cx.host.ticket_redeem(&target.resource, &p.id, ticket)? {
            return Err(ApiError::refused("mfa_required", "the MFA ticket was not redeemed for this profile"));
        }
    }
    let catalog = catalog_override
        .map(str::to_string)
        .or_else(|| p.catalog.clone())
        .ok_or_else(|| ApiError::bad_request("the profile names no database; pass `catalog`"))?;
    let id = ids::session_id(&cx.reg.instance).ok_or_else(|| ApiError::internal("no randomness"))?;
    let credential = cx.host.sql_credential(&target.resource, &p.id, &id)?;

    let spec = ConnectSpec {
        session_id: &id,
        profile: p,
        catalog: &catalog,
        read_only: selection.read_only,
        statement_timeout: Duration::from_secs(cx.cfg.run_timeout_secs),
        idle_tx_backstop: Duration::from_secs(cx.cfg.idle_tx_secs + 60),
        connect_timeout: Duration::from_secs(cx.cfg.connect_timeout_secs),
        allowed: &cx.cfg.allowed(),
        denied: &cx.cfg.denied(),
        roots: cx.roots,
    };
    let conn = cx.rt.block_on(PgConn::connect(spec, credential)).map_err(|e| {
        let mut ev = audit::base("dbms.session.open", &id, &target.resource, &p.id, selection.db_enforced);
        ev["outcome"] = json!("failed");
        ev["reason"] = json!(e.code);
        let _ = cx.host.audit(ev);
        ApiError::refused(e.code, e.message)
    })?;
    let conn = Arc::new(conn);

    let setup = cx.rt.block_on(establish(&conn, selection.read_only));
    let (lexer, ctx, database_read_only, server_version) = match setup {
        Ok(v) => v,
        Err(e) => {
            conn.shutdown();
            return Err(ApiError::refused("session_setup", e));
        }
    };
    let opened_ms = journal::now_ms();
    let info = SessionInfo {
        server_version,
        enforcement: target.enforcement,
        read_only: selection.read_only,
        db_enforced: selection.db_enforced,
        grant: selection.grant.iter().copied().collect(),
        ceiling: p.ceiling.iter().copied().collect(),
        vault_only: selection.vault_only.clone(),
        tls_mode: p.tls.mode,
        database_read_only,
    };
    let ns = if target.namespace.is_empty() { caller.namespace.clone() } else { target.namespace.clone() };
    let mut record = Record::new(owner, &id, &target.resource, &p.id, opened_ms, &ns);
    record.flush(cx.host);
    let session = Arc::new(Session {
        id: id.clone(),
        owner: owner.clone(),
        namespace: ns,
        resource: target.resource.clone(),
        profile: p.id.clone(),
        catalog,
        info,
        opened: Instant::now(),
        opened_ms,
        conn,
        state: Mutex::new(State {
            lexer,
            ctx,
            ctx_stale: false,
            last_used: Instant::now(),
            active: None,
            runs: BTreeMap::new(),
            closed: None,
            rows_read: 0,
            tx_since: None,
            tx_statements: 0,
            run_seq: 0,
            journal: record,
            op: false,
        }),
    });
    let mut ev = session.event("dbms.session.open");
    ev["outcome"] = json!("opened");
    ev["engine"] = json!("postgresql");
    ev["server_version"] = json!(session.info.server_version);
    ev["enforcement"] = json!(session.info.enforcement.as_str());
    ev["read_only"] = json!(session.info.read_only);
    ev["transport"] = json!("direct");
    ev["tls_mode"] = json!(session.info.tls_mode.as_str());
    let _ = cx.host.audit(ev);
    let status = session.status();
    cx.reg.insert(session);
    let mut reply = status;
    if !target.invalid.is_empty() {
        reply["invalid_profiles"] =
            json!(target.invalid.iter().map(|(id, r)| json!({"id": id, "reason": r})).collect::<Vec<_>>());
    }
    Ok(reply)
}

/// After the connection is up: check the settings the classifier depends
/// on, read the name context, and arm the wire watcher.
async fn establish(conn: &PgConn, read_only: bool) -> Result<(LexerSettings, NameContext, bool, String), String> {
    let wire = conn.wire();
    // tokio-postgres asks for UTF8; anything else would change the lexer.
    if wire.param("client_encoding").as_deref() != Some("UTF8") {
        return Err("the server did not accept client_encoding UTF8".into());
    }
    let scs = match wire.param("standard_conforming_strings").as_deref() {
        Some("on") => true,
        Some("off") => false,
        _ => return Err("the server did not report standard_conforming_strings".into()),
    };
    // Read-only is database-enforced only if the server reports the setting,
    // so a change by a user function is seen (PostgreSQL 14+).
    let database_read_only = read_only && wire.param("default_transaction_read_only").as_deref() == Some("on");
    let ctx =
        read_context(conn, database_read_only).await.map_err(|e| format!("reading the name context: {}", e.message))?;
    wire.establish(read_only);
    let version = wire.param("server_version").unwrap_or_default();
    Ok((LexerSettings::PostgreSql { standard_conforming_strings: scs }, ctx, database_read_only, version))
}

/// The classifier's name context, from the session's own state (§4.4).
pub async fn read_context(conn: &PgConn, database_read_only: bool) -> Result<NameContext, DbError> {
    let q = PluginSql::guarded(sql!(
        "SELECT pg_catalog.current_database()::text, pg_catalog.current_schema()::text, \
         pg_catalog.current_schemas(true)::text[], pg_catalog.current_setting('max_identifier_length')::int4"
    ));
    let rows = conn.internal_query(&q, &[]).await?;
    let row = rows.first().ok_or_else(|| DbError::plugin("no name context row"))?;
    let catalog: String = row.try_get(0).map_err(DbError::from)?;
    let schema: Option<String> = row.try_get(1).map_err(DbError::from)?;
    let path: Vec<String> = row.try_get(2).map_err(DbError::from)?;
    let max_len: i32 = row.try_get(3).map_err(DbError::from)?;
    Ok(NameContext {
        current_catalog: catalog,
        current_schema: schema,
        search_path: path,
        max_identifier_length: usize::try_from(max_len).unwrap_or(63),
        database_read_only,
    })
}

/// Resolve unqualified names the way the server will (§4.4). A name that
/// does not resolve to exactly one schema stays `None`: unaddressable.
pub async fn resolve(conn: &PgConn, refs: &[ObjectRef]) -> Result<Resolutions, DbError> {
    let class = PluginSql::guarded(sql!(
        "SELECT n.nspname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         WHERE c.oid OPERATOR(pg_catalog.=) pg_catalog.to_regclass(pg_catalog.quote_ident($1::text))"
    ));
    let typ = PluginSql::guarded(sql!(
        "SELECT n.nspname::text FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) t.typnamespace \
         WHERE t.oid OPERATOR(pg_catalog.=) pg_catalog.to_regtype(pg_catalog.quote_ident($1::text))"
    ));
    let proc = PluginSql::guarded(sql!(
        "SELECT DISTINCT n.nspname::text FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n \
         ON n.oid OPERATOR(pg_catalog.=) p.pronamespace WHERE p.proname OPERATOR(pg_catalog.=) $1::text AND n.nspname OPERATOR(pg_catalog.=) ANY (pg_catalog.current_schemas(true))"
    ));
    let coll = PluginSql::guarded(sql!(
        "SELECT DISTINCT n.nspname::text FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n \
         ON n.oid OPERATOR(pg_catalog.=) c.collnamespace WHERE c.collname OPERATOR(pg_catalog.=) $1::text AND n.nspname OPERATOR(pg_catalog.=) ANY (pg_catalog.current_schemas(true))"
    ));
    let mut out = Resolutions::new();
    for r in refs {
        let q = match r.kind {
            k if authz::resolves_through_class(k) => &class,
            ObjectKind::Type => &typ,
            ObjectKind::Routine => &proc,
            ObjectKind::Collation => &coll,
            _ => {
                out.insert(r.clone(), None);
                continue;
            }
        };
        let rows = conn.internal_query(q, &[TextParam(Some(r.name.clone()))]).await?;
        let schema = match rows.as_slice() {
            [one] => one.try_get::<_, String>(0).ok(),
            _ => None,
        };
        out.insert(r.clone(), schema);
    }
    Ok(out)
}

const EXECUTE_KEYS: [&str; 1] = ["sql"];

/// `POST v2/sessions/<id>/execute {sql}` (§6.2): classify, resolve, ask the
/// host, then start the run. Returns within the invoke deadline.
pub fn execute(cx: &Ctx<'_>, s: &Arc<Session>, data: &serde_json::Map<String, Value>) -> Result<Value, ApiError> {
    if let Some(k) = data.keys().find(|k| !EXECUTE_KEYS.contains(&k.as_str())) {
        return Err(ApiError::bad_request(format!("unknown field `{k}`")));
    }
    let text = match data.get("sql") {
        Some(Value::String(t)) if !t.trim().is_empty() => t.as_str(),
        _ => return Err(ApiError::bad_request("`sql` must be a non-empty string")),
    };
    if text.len() > bv_sql_classify::MAX_TEXT_BYTES {
        return Err(ApiError::bad_request("`sql` is too large"));
    }
    s.touch();
    if let Some(why) = s.conn.wire().taint() {
        close(cx, s, "tainted");
        return Err(ApiError::refused("session_tainted", format!("{why}; the session was closed")));
    }
    let _op = s.begin_op()?;
    let (lexer, mut ctx, mut stale) = s.classify_inputs()?;
    if stale {
        if let Ok(fresh) = cx.rt.block_on(read_context(&s.conn, s.info.database_read_only)) {
            let mut st = s.lock();
            st.ctx = fresh.clone();
            st.ctx_stale = false;
            ctx = fresh;
            stale = false;
        }
    }
    let digest = ids::digest(cx.digest_key, "statement", text.as_bytes());
    let prepared = match authz::prepare(text, lexer, &ctx, true) {
        Ok(p) => p,
        Err(r) => {
            let mut ev = s.event("dbms.statement");
            ev["outcome"] = json!("refused");
            ev["reason"] = json!(r.code);
            ev["digest"] = json!(digest);
            let _ = cx.host.audit(ev);
            return Err(ApiError::refused(r.code, r.message));
        }
    };
    if stale && !prepared.only_tx_control() {
        return Err(ApiError::refused(
            "context_stale",
            "the session's name context cannot be re-read (is the transaction aborted?); only ROLLBACK or COMMIT runs now",
        ));
    }
    let refs = prepared.unresolved();
    let res = if refs.is_empty() {
        Resolutions::new()
    } else {
        cx.rt
            .block_on(resolve(&s.conn, &refs))
            .map_err(|e| ApiError::refused("name_resolution", format!("resolving names: {}", e.message)))?
    };
    let (decision, minted) = authz::authorize(cx.host, &s.resource, &s.id, prepared, &res)?;
    let Some(stmts) = minted else {
        for (meta, verdicts) in &decision.statements {
            let mut ev = s.event("dbms.statement");
            ev["outcome"] = json!("refused");
            ev["index"] = json!(meta.index);
            ev["kinds"] = json!([meta.kind_name()]);
            ev["required"] = json!(meta.required_json());
            ev["refused"] = json!(verdicts
                .iter()
                .filter(|v| !v.allowed)
                .map(|v| json!({"capability": v.capability, "path": v.path}))
                .collect::<Vec<_>>());
            ev["unclassified"] = json!(meta.unclassified);
            ev["digest"] = json!(digest);
            let _ = cx.host.audit(ev);
        }
        return Ok(json!({"state": "refused", "message": decision.message(), "statements": decision.report()}));
    };

    let journal_text = {
        let redacted = redact(Dialect::PostgreSql, lexer, text).ok();
        journal::text_for(&cx.cfg.journal_text, text, redacted)
    };
    let (run, budget_left) = {
        let mut st = s.lock();
        st.run_seq += 1;
        let run_id = format!("r{}", st.run_seq);
        let budget_left = cx.cfg.row_budget.map(|b| b.saturating_sub(st.rows_read));
        if budget_left == Some(0) {
            return Err(ApiError::refused("row_budget", "the session's row budget is spent"));
        }
        let limits = RunLimits {
            deadline: Duration::from_secs(cx.cfg.run_timeout_secs),
            page_rows: cx.cfg.page_rows as usize,
            page_bytes: cx.cfg.page_bytes as usize,
            grid_rows: cx.cfg.grid_rows,
            budget_left,
        };
        let run = Run::new(run_id.clone(), limits);
        for st_meta in stmts.iter().map(|a| a.meta()) {
            st.journal.push(json!({
                "run": run_id, "index": st_meta.index, "at_ms": journal::now_ms(), "kinds": [st_meta.kind_name()],
                "required": st_meta.required_json(), "unclassified": st_meta.unclassified,
                "digest": digest, "text": journal_text, "outcome": "started",
            }));
        }
        st.active = Some(run.clone());
        st.runs.insert(run_id, run.clone());
        (run, budget_left)
    };
    let _ = budget_left;
    s.flush_journal(cx.host);
    let (conn, session, reg) = (s.conn.clone(), s.clone(), cx.reg.clone());
    let run2 = run.clone();
    cx.rt.spawn(async move {
        let end = run::produce(conn, run2, stmts).await;
        after_run(&session, end).await;
        drop(reg);
    });
    Ok(json!({"run_id": run.id, "state": "running", "statements": decision.report(), "digest": digest}))
}

/// Book-keeping once a run ends: rows read, transaction state, and the name
/// context after a statement that may have changed it.
async fn after_run(s: &Arc<Session>, end: run::RunEnd) {
    let refreshed =
        if end.context_changed { Some(read_context(&s.conn, s.info.database_read_only).await) } else { None };
    let mut st = s.lock();
    st.rows_read += end.rows_read;
    match refreshed {
        Some(Ok(ctx)) => st.ctx = ctx,
        Some(Err(_)) => st.ctx_stale = true,
        None => {}
    }
    st.last_used = Instant::now();
}

/// Statement outcomes of `run` to the audit stream and the journal.
fn report(cx_host: Option<&dyn Host>, outbox: &Outbox, s: &Session, run: &Run) -> Vec<Value> {
    let results: Vec<StatementResult> = run.take_unreported();
    let mut events = Vec::new();
    let mut st = s.lock();
    for r in &results {
        let mut ev = s.event("dbms.statement");
        ev["run"] = json!(run.id);
        ev["index"] = json!(r.meta.index);
        ev["kinds"] = json!([r.meta.kind_name()]);
        ev["required"] = json!(r.meta.required_json());
        ev["objects"] = json!(r.meta.objects());
        ev["outcome"] = json!(r.outcome);
        ev["rows_affected"] = json!(r.rows_affected);
        ev["rows_returned"] = json!(r.rows_returned);
        ev["duration_ms"] = json!(r.duration_ms);
        ev["unclassified"] = json!(r.meta.unclassified);
        ev["sqlstate"] = json!(r.error.as_ref().and_then(|e| e.sqlstate.clone()));
        st.journal.complete(
            &run.id,
            r.meta.index,
            json!({"outcome": r.outcome, "rows_affected": r.rows_affected, "rows_returned": r.rows_returned,
                "duration_ms": r.duration_ms, "error": r.error.as_ref().map(DbError::redacted), "truncated": r.truncated}),
        );
        if r.meta.tx_control {
            let tx = s.conn.wire().tx();
            match r.meta.kind {
                Some(StatementKind::TxBegin) => {
                    st.tx_since = Some(Instant::now());
                    st.tx_statements = 0;
                }
                Some(StatementKind::TxCommit | StatementKind::TxRollback) if tx == TxStatus::Idle => {
                    let mut t = s.event("dbms.tx");
                    t["action"] =
                        json!(if r.meta.kind == Some(StatementKind::TxCommit) { "commit" } else { "rollback" });
                    t["statement_count"] = json!(st.tx_statements);
                    t["reason"] = json!("operator");
                    events.push(t);
                    st.tx_since = None;
                    st.tx_statements = 0;
                }
                _ => {}
            }
        } else if st.tx_since.is_some() {
            st.tx_statements += 1;
        }
        events.push(ev);
    }
    if run.budget_exhausted() {
        let mut ev = s.event("dbms.row_budget");
        ev["rows_read"] = json!(st.rows_read);
        events.push(ev);
    }
    drop(st);
    match cx_host {
        Some(h) => {
            for e in &events {
                let _ = h.audit(e.clone());
            }
            s.flush_journal(h);
        }
        None => {
            for e in &events {
                outbox.push(&s.owner, Pending::Audit(e.clone()));
            }
        }
    }
    results.iter().map(StatementResult::message).collect()
}

/// `GET v2/sessions/<id>/runs/<run>`: the next page.
pub fn page(cx: &Ctx<'_>, s: &Arc<Session>, run_id: &str) -> Result<Value, ApiError> {
    s.touch();
    let run = s.lock().runs.get(run_id).cloned().ok_or_else(|| ApiError::not_found("no such run"))?;
    let page = run.page();
    report(Some(cx.host), &cx.reg.outbox, s, &run);
    Ok(page)
}

/// `POST v2/sessions/<id>/runs/<run>/cancel`.
pub fn cancel(cx: &Ctx<'_>, s: &Arc<Session>, run_id: &str) -> Result<Value, ApiError> {
    s.touch();
    let run = s.lock().runs.get(run_id).cloned().ok_or_else(|| ApiError::not_found("no such run"))?;
    if run.status() == RunStatus::Running {
        run.request_cancel();
    }
    let mut ev = s.event("dbms.cancel");
    ev["run"] = json!(run.id);
    let _ = cx.host.audit(ev);
    Ok(json!({"run_id": run.id, "state": run.status().as_str(), "cancel_requested": true}))
}

/// Close `s` for `reason`: stop its run, roll back an open transaction,
/// drop the connection and every buffer. Events go to the owner's outbox.
pub fn close(cx: &Ctx<'_>, s: &Arc<Session>, reason: &str) {
    cx.rt.block_on(close_async(cx.reg, s, reason));
}

pub async fn close_async(reg: &Registry, s: &Arc<Session>, reason: &str) {
    let (active, runs) = {
        let mut st = s.lock();
        if st.closed.is_some() {
            return;
        }
        st.closed = Some(reason.to_string());
        (st.active.take(), std::mem::take(&mut st.runs))
    };
    if let Some(run) = &active {
        if run.status() == RunStatus::Running {
            run.request_cancel();
            let _ = tokio::time::timeout(Duration::from_secs(3), s.conn.cancel()).await;
        }
    }
    if matches!(s.conn.wire().tx(), TxStatus::InTransaction | TxStatus::Failed) && !s.conn.is_closed() {
        let rollback = PluginSql::guarded(sql!("ROLLBACK"));
        let rolled = tokio::time::timeout(Duration::from_secs(5), s.conn.internal_execute(&rollback)).await;
        let mut ev = s.event("dbms.tx");
        ev["action"] = json!("auto-rollback");
        ev["reason"] = json!(reason);
        ev["statement_count"] = json!(s.lock().tx_statements);
        ev["outcome"] = json!(if matches!(rolled, Ok(Ok(_))) { "rolled_back" } else { "connection_dropped" });
        reg.outbox.push(&s.owner, Pending::Audit(ev));
    }
    s.conn.shutdown();
    for run in runs.values() {
        report(None, &reg.outbox, s, run);
    }
    let record = {
        let mut st = s.lock();
        st.journal.close(reason);
        (st.journal.key.clone(), st.journal.body.clone())
    };
    reg.outbox.push(&s.owner, Pending::Journal { key: record.0, record: record.1 });
    let mut ev = s.event("dbms.session.close");
    ev["reason"] = json!(reason);
    ev["rows_read"] = json!(s.lock().rows_read);
    reg.outbox.push(&s.owner, Pending::Audit(ev));
    reg.remove(&s.id);
    drop(runs);
}

/// The background sweep (§6.1, §6.3, §12): idle and lifetime limits, lost
/// connections, idle-in-transaction rollback, and expired run buffers.
pub async fn sweep(reg: &Registry, cfg: &Config) {
    for s in reg.all() {
        let (idle, busy, tx_idle) = {
            let st = s.lock();
            let busy = st.active.as_ref().is_some_and(|r| r.status() == RunStatus::Running);
            (st.last_used.elapsed(), busy, st.last_used.elapsed())
        };
        let reason = if s.conn.is_closed() {
            Some("connection_lost")
        } else if s.opened.elapsed() >= Duration::from_secs(cfg.lifetime_secs) {
            Some("lifetime")
        } else if !busy && idle >= Duration::from_secs(cfg.idle_secs) {
            Some("idle_timeout")
        } else {
            None
        };
        if let Some(r) = reason {
            close_async(reg, &s, r).await;
            continue;
        }
        let in_tx = matches!(s.conn.wire().tx(), TxStatus::InTransaction | TxStatus::Failed);
        if in_tx && !busy && tx_idle >= Duration::from_secs(cfg.idle_tx_secs) {
            let rollback = PluginSql::guarded(sql!("ROLLBACK"));
            let rolled = tokio::time::timeout(Duration::from_secs(5), s.conn.internal_execute(&rollback)).await;
            let mut ev = s.event("dbms.tx");
            ev["action"] = json!("auto-rollback");
            ev["reason"] = json!("idle_in_transaction");
            ev["outcome"] = json!(if matches!(rolled, Ok(Ok(_))) { "rolled_back" } else { "failed" });
            let mut st = s.lock();
            ev["statement_count"] = json!(st.tx_statements);
            st.tx_since = None;
            st.tx_statements = 0;
            drop(st);
            reg.outbox.push(&s.owner, Pending::Audit(ev));
        }
        let retention = Duration::from_secs(cfg.run_retention_secs);
        let expired: Vec<Arc<Run>> = {
            let mut st = s.lock();
            let ids: Vec<String> = st
                .runs
                .iter()
                .filter(|(_, r)| r.finished_at().is_some_and(|f| f.elapsed() >= retention))
                .map(|(k, _)| k.clone())
                .collect();
            ids.iter().filter_map(|k| st.runs.remove(k)).collect()
        };
        for run in expired {
            report(None, &reg.outbox, &s, &run);
        }
    }
}

/// Seal, reload or shutdown (§6.7): close every session, in parallel,
/// within `deadline`.
pub async fn close_all(reg: &Arc<Registry>, reason: &str, deadline: Duration) {
    let sessions = reg.all();
    let tasks = sessions.into_iter().map(|s| {
        let reg = reg.clone();
        let reason = reason.to_string();
        async move { close_async(&reg, &s, &reason).await }
    });
    let _ = tokio::time::timeout(deadline, futures_util::future::join_all(tasks)).await;
    // Whatever did not finish in time is dropped without a rollback: the
    // server rolls back when the connection goes.
    for s in reg.all() {
        s.conn.shutdown();
        reg.remove(&s.id);
    }
}
