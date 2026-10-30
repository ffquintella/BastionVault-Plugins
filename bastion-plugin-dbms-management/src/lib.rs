//! `dbms-management`: the SQL browser's server half (features/sql-browser.md,
//! S109, T125 Phase 3; scripts, exports and per-action step-up T126 Phase 5;
//! MySQL and MariaDB T127 Phase 6; SQL Server T128 Phase 7; Oracle T129
//! Phase 8). A long-lived, multiplexed process plugin. Sessions hold a
//! database connection opened with a login the host releases; every
//! statement is classified (`bv-sql-classify`), authorized by the vault
//! (`resource_sql_authorize`), executed through `driver::PgConn`,
//! `mysql::conn::MyConn`, `mssql::conn::MsConn` or `oracle::conn::OraConn`,
//! and audited.

#![forbid(unsafe_code)]

pub mod api;
pub mod audit;
pub mod authz;
pub mod config;
pub mod driver;
pub mod engine;
pub mod export;
pub mod host;
pub mod ids;
pub mod journal;
pub mod mssql;
pub mod mysql;
pub mod netpolicy;
pub mod objects;
pub mod oracle;
pub mod probe;
pub mod profile;
pub mod rows;
pub mod run;
pub mod session;
pub mod tls;
pub mod values;
pub mod wire;

#[doc = include_str!("invariants.md")]
pub mod invariants {}

#[cfg(test)]
mod live_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod testutil;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_plugin_sdk::process::{Invocation, Lifecycle, ProcessPlugin};
use bastion_plugin_sdk::Response;
use serde_json::{json, Value};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use api::{ApiError, Op, Request};
use config::{Config, CONFIG_KEY};
use host::{Host, ProcessHostAdapter};
use session::{Ctx, Registry};
use tls::RootSource;

/// Where the digest key lives (HMAC for statement and row-key digests).
const DIGEST_KEY: &str = "dbms/keys/digest";
/// How long a cached config is trusted before it is read again.
const CONFIG_TTL: Duration = Duration::from_secs(30);
/// The host kills the child 10 s after a lifecycle message; finish first.
const LIFECYCLE_DEADLINE: Duration = Duration::from_secs(8);

pub struct Plugin {
    rt: Runtime,
    registry: Arc<Registry>,
    config: Arc<Mutex<(Option<Instant>, Config)>>,
    digest_key: Mutex<Option<Zeroizing<Vec<u8>>>>,
    last_purge: Mutex<Option<Instant>>,
    roots: RootSource,
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin {
    pub fn new() -> Self {
        Self::with_roots(tls::system_roots)
    }

    /// A plugin whose verify modes trust `roots` when a profile has no CA
    /// bundle (tests inject their own).
    pub fn with_roots(roots: RootSource) -> Self {
        // The MySQL driver builds its rustls config from the process default
        // provider: make it `ring`, as everywhere else in this plugin. An
        // already installed default (a second Plugin in tests) is kept.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("dbms-worker")
            .enable_all()
            .build()
            .expect("the plugin cannot run without its runtime");
        let registry = Arc::new(Registry::new(ids::instance_id()));
        let config = Arc::new(Mutex::new((None, Config::default())));
        // The sweep runs between invocations, so it makes no host call; its
        // events wait in the owners' outboxes.
        let (reg, cfg) = (registry.clone(), config.clone());
        rt.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let snapshot = cfg.lock().unwrap_or_else(|p| p.into_inner()).1.clone();
                session::sweep(&reg, &snapshot).await;
            }
        });
        Self { rt, registry, config, digest_key: Mutex::new(None), last_purge: Mutex::new(None), roots }
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// The current config: cached, re-read after [`CONFIG_TTL`]. A stored
    /// record that does not parse is not trusted; the defaults apply.
    fn config(&self, host: &dyn Host) -> Config {
        let mut guard = self.config.lock().unwrap_or_else(|p| p.into_inner());
        if guard.0.is_some_and(|t| t.elapsed() < CONFIG_TTL) {
            return guard.1.clone();
        }
        let loaded = match host.storage_get(CONFIG_KEY) {
            Ok(Some(b)) => {
                serde_json::from_slice::<Value>(&b).ok().and_then(|v| Config::parse(&v).ok()).unwrap_or_else(|| {
                    host.log(4, "dbms-management: the stored config does not parse; using defaults");
                    Config::default()
                })
            }
            Ok(None) => Config::default(),
            Err(_) => guard.1.clone(),
        };
        *guard = (Some(Instant::now()), loaded.clone());
        loaded
    }

    /// The HMAC key for digests, created on first use and kept in barrier
    /// storage. No key, no digest: the request is refused.
    fn digest_key(&self, host: &dyn Host) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        let mut guard = self.digest_key.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(k) = guard.as_ref() {
            return Ok(k.clone());
        }
        let stored = host.storage_get(DIGEST_KEY).map_err(|e| ApiError::unavailable(format!("digest key: {e}")))?;
        let key = match stored {
            Some(k) if k.len() == 32 => Zeroizing::new(k),
            _ => {
                let mut k = vec![0u8; 32];
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut k)
                    .map_err(|_| ApiError::internal("no randomness"))?;
                host.storage_put(DIGEST_KEY, &k).map_err(|e| ApiError::unavailable(format!("digest key: {e}")))?;
                // Another node may have written first: use what is stored.
                let k = host.storage_get(DIGEST_KEY).ok().flatten().filter(|s| s.len() == 32).unwrap_or(k);
                Zeroizing::new(k)
            }
        };
        *guard = Some(key.clone());
        Ok(key)
    }

    /// At most once a day per process, inside an invocation: purge journal
    /// days past their retention.
    fn maybe_purge(&self, host: &dyn Host, cfg: &Config) {
        let mut last = self.last_purge.lock().unwrap_or_else(|p| p.into_inner());
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(86_400)) {
            return;
        }
        *last = Some(Instant::now());
        drop(last);
        let n = journal::purge(host, cfg.journal_retention_days, journal::now_ms(), 500);
        if n > 0 {
            host.log(3, &format!("dbms-management: purged {n} journal records past retention"));
        }
    }

    /// The whole request path, for one decoded invocation on `host`.
    pub fn dispatch(&self, host: &dyn Host, input: &[u8]) -> Response {
        match self.route(host, input) {
            Ok(v) => api::ok(v),
            Err(e) => e.into_response(),
        }
    }

    fn route(&self, host: &dyn Host, input: &[u8]) -> Result<Value, ApiError> {
        let req = Request::parse(input)?;
        let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
        let Some(("v2", rest)) = segs.split_first().map(|(a, b)| (*a, b)) else {
            return Err(ApiError::not_found("unknown path (this plugin serves v2/ only)"));
        };
        let caller = req.caller()?;
        let owner = caller.owner();
        // Events that happened while this caller was away go out now, under
        // this caller's own identity.
        self.registry.outbox.flush(&owner, host);
        let cfg = self.config(host);
        self.maybe_purge(host, &cfg);
        match (req.op, rest) {
            (Op::Read, ["config"]) => Ok(cfg.view()),
            (Op::Write, ["config"]) => {
                let next = cfg.merged(&req.data)?;
                let bytes = serde_json::to_vec(&next).map_err(|_| ApiError::internal("config serialise"))?;
                host.storage_put(CONFIG_KEY, &bytes)?;
                *self.config.lock().unwrap_or_else(|p| p.into_inner()) = (Some(Instant::now()), next.clone());
                let _ = host.audit(json!({"event": "dbms.config", "keys": req.data.keys().collect::<Vec<_>>()}));
                Ok(next.view())
            }
            (Op::List, ["sessions"]) | (Op::Read, ["sessions"]) => Ok(
                json!({"keys": self.registry.list(&owner).iter().filter_map(|s| s["session_id"].as_str().map(str::to_string)).collect::<Vec<_>>(),
                    "sessions": self.registry.list(&owner)}),
            ),
            (Op::Write, ["sessions"]) => {
                let key = self.digest_key(host)?;
                let cx = self.ctx(host, &cfg, &key);
                session::open(&cx, caller, &req.data)
            }
            (_, ["sessions", id, more @ ..]) => {
                let s = self.registry.get(id, caller)?;
                let key = self.digest_key(host)?;
                let cx = self.ctx(host, &cfg, &key);
                let out = match (req.op, more) {
                    (Op::Read, []) => Ok(s.status()),
                    (Op::Delete, []) => {
                        session::close(&cx, &s, "operator");
                        self.registry.outbox.flush(&owner, host);
                        Ok(json!({"session_id": s.id, "closed": true}))
                    }
                    (Op::Write, ["execute"]) => session::execute(&cx, &s, &req.data),
                    (Op::Write, ["script"]) => session::script(&cx, &s, &req.data),
                    (Op::Write, ["export"]) => session::export(&cx, &s, &req.data),
                    (Op::Read, ["exports", job]) => session::export_status(&cx, &s, job),
                    (Op::Read, ["exports", job, offset]) => session::export_pull(&cx, &s, job, offset),
                    (Op::Write, ["exports", job, "cancel"]) => session::export_cancel(&cx, &s, job),
                    (Op::Read, ["runs", run]) => session::page(&cx, &s, run),
                    (Op::Write, ["runs", run, "cancel"]) => session::cancel(&cx, &s, run),
                    (Op::List | Op::Read, ["objects"]) => objects::schemas(&cx, &s),
                    (Op::List | Op::Read, ["objects", schema]) => objects::list(&cx, &s, &api::decode_segment(schema)?),
                    (Op::Read, ["objects", schema, object]) => {
                        objects::describe(&cx, &s, &api::decode_segment(schema)?, &api::decode_segment(object)?)
                    }
                    (Op::Write, ["rows"]) => rows::apply(&cx, &s, &req.data),
                    (Op::Read, ["ceiling"]) => probe::probe(&cx, &s),
                    _ => Err(ApiError::not_found("unknown session path")),
                };
                if !matches!(req.op, Op::Delete) {
                    s.flush_journal(host);
                }
                out
            }
            (Op::List | Op::Read, ["journal", "self", more @ ..]) => journal::read_self(host, &owner, more),
            (Op::List | Op::Read, ["journal", "all", more @ ..]) => journal::read_all(host, more),
            _ => Err(ApiError::not_found("unknown path")),
        }
    }

    fn ctx<'a>(&'a self, host: &'a dyn Host, cfg: &'a Config, key: &'a [u8]) -> Ctx<'a> {
        Ctx { rt: &self.rt, reg: &self.registry, cfg, host, digest_key: key, roots: self.roots }
    }

    /// Seal, reload or shutdown: close every session (rolling back open
    /// transactions) and drop every buffer before acknowledging (§6.7).
    pub fn lifecycle(&self, event: Lifecycle) {
        let reason = match event {
            Lifecycle::Seal => "seal",
            Lifecycle::Reload => "reload",
            Lifecycle::Shutdown => "shutdown",
        };
        self.rt.block_on(session::close_all(&self.registry, reason, LIFECYCLE_DEADLINE));
        *self.digest_key.lock().unwrap_or_else(|p| p.into_inner()) = None;
        eprintln!("dbms-management: {reason}: every session closed");
    }
}

impl ProcessPlugin for Plugin {
    fn handle(&self, inv: &Invocation, input: &[u8]) -> Response {
        self.dispatch(&ProcessHostAdapter { inv }, input)
    }

    fn on_lifecycle(&self, event: Lifecycle) {
        self.lifecycle(event);
    }
}
