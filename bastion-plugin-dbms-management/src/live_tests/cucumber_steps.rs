//! `tests/features/sql_browser.feature` (features/sql-browser.md, Testing
//! Plan, "Cucumber"), run against the container the other live tests use.
//! The steps drive the real plugin through the scripted host, like those tests.

use std::sync::{Arc, Mutex};

use cucumber::{given, then, when, StatsWriter as _, World};
use serde_json::{json, Value};

use super::{exec, export, fixture, local, open, rows, script, Fixture};
use crate::profile::tests::target_json;
use crate::testutil::{loopback_config, MockHost};
use crate::Plugin;

/// The scenarios share one container; `cucumber_scenarios` owns it.
static FIXTURE: Mutex<Option<Arc<Fixture>>> = Mutex::new(None);

#[derive(World)]
#[world(init = Self::new)]
struct SqlWorld {
    fx: Arc<Fixture>,
    plugin: Plugin,
    host: Option<Arc<MockHost>>,
    sid: String,
    reply: Value,
    pages: Vec<Value>,
}

impl std::fmt::Debug for SqlWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlWorld").field("sid", &self.sid).field("reply", &self.reply).finish_non_exhaustive()
    }
}

impl SqlWorld {
    fn new() -> Self {
        let fx = FIXTURE.lock().unwrap().clone().expect("the container is started by the test");
        Self { fx, plugin: Plugin::new(), host: None, sid: String::new(), reply: Value::Null, pages: Vec::new() }
    }

    fn host(&self) -> &Arc<MockHost> {
        self.host.as_ref().expect("a caller was set up")
    }
}

const WHO: &str = "ana";

fn caps(list: &str) -> Vec<String> {
    list.split(',').map(|c| c.trim().to_string()).collect()
}

#[given("a PostgreSQL database with a canary table")]
fn database(w: &mut SqlWorld) {
    w.fx.pg.psql(
        "app",
        "UPDATE public.canary SET v = 'intact'; DELETE FROM public.t WHERE id > 2;
         INSERT INTO public.canary SELECT 'intact' WHERE NOT EXISTS (SELECT 1 FROM public.canary);",
    );
    assert_eq!(w.fx.canary(), "intact");
}

#[given(expr = "a caller holding {string}")]
fn caller(w: &mut SqlWorld, held: String) {
    let held = caps(&held);
    let refs: Vec<&str> = held.iter().map(String::as_str).collect();
    w.host = Some(w.fx.host(&refs, "disable"));
}

#[given(expr = "a caller holding {string} on a classifier-only resource")]
fn classifier_only_caller(w: &mut SqlWorld, held: String) {
    let held = caps(&held);
    let refs: Vec<&str> = held.iter().map(String::as_str).collect();
    // No read-only login exists, so the broader one serves, flagged.
    let h = MockHost::new(target_json(
        "classifier-only",
        &refs,
        vec![local("admin", &crate::profile::STATEMENT_CAPS, &w.fx.pg, "disable")],
    ));
    h.creds.lock().unwrap().insert("admin".into(), (w.fx.pg.endpoint(), "postgres".into(), w.fx.pg.admin_pw.clone()));
    h.set_config(loopback_config());
    let held = held.clone();
    h.allow(move |c| held.iter().any(|p| p == c.capability));
    w.host = Some(h);
}

#[given("an open SQL session")]
#[when("the caller opens a SQL session")]
fn open_session(w: &mut SqlWorld) {
    w.sid = open(&w.plugin, w.host(), WHO);
}

#[when(expr = "the caller runs {string}")]
fn run(w: &mut SqlWorld, sql: String) {
    let (reply, pages) = exec(&w.plugin, w.host(), WHO, &w.sid, &sql);
    w.reply = reply;
    w.pages = pages;
}

#[when("the share is revoked")]
fn revoke(w: &mut SqlWorld) {
    w.host().allow(|_| false);
}

#[when(expr = "the caller exports {string} as {string}")]
fn run_export(w: &mut SqlWorld, sql: String, format: String) {
    let (reply, _, _) = export(&w.plugin, w.host(), WHO, &w.sid, json!({"sql": sql, "format": format}));
    w.reply = reply;
}

#[when(expr = "the caller runs the script")]
fn run_script(w: &mut SqlWorld, step: &cucumber::gherkin::Step) {
    let sql = step.docstring.clone().expect("a script docstring");
    let (reply, pages) = script(&w.plugin, w.host(), WHO, &w.sid, json!({"sql": sql}));
    w.reply = reply;
    w.pages = pages;
}

fn message(w: &SqlWorld) -> String {
    w.reply["data"]["message"].as_str().unwrap_or_default().to_string()
}

#[then(expr = "the statement is refused naming {string}")]
fn statement_refused(w: &mut SqlWorld, cap: String) {
    assert_eq!(w.reply["data"]["state"], "refused", "{}", w.reply);
    assert!(message(w).contains(&cap), "{}", w.reply);
}

#[then(expr = "the statement returns {int} row")]
fn statement_rows(w: &mut SqlWorld, n: usize) {
    assert_eq!(rows(&w.pages).len(), n, "{:?}", w.pages);
}

#[then(expr = "the export is refused naming {string}")]
fn export_refused(w: &mut SqlWorld, cap: String) {
    statement_refused(w, cap);
}

#[then(expr = "the audit log records a refused {string}")]
fn refused_audit(w: &mut SqlWorld, event: String) {
    assert!(w.host().audit_events().iter().any(|e| e["event"] == event.as_str() && e["outcome"] == "refused"));
}

#[then(expr = "the script is refused naming statement {int} and {string}")]
fn script_refused(w: &mut SqlWorld, n: u32, cap: String) {
    assert_eq!(w.reply["data"]["state"], "refused", "{}", w.reply);
    assert!(message(w).starts_with(&format!("statement {n} needs `{cap}`")), "{}", w.reply);
}

#[then(expr = "no row with id {int} exists")]
fn no_row(w: &mut SqlWorld, id: i32) {
    assert_eq!(w.fx.pg.psql("app", &format!("SELECT count(*) FROM public.t WHERE id = {id}")), "0");
}

#[then("the canary table is unchanged")]
fn canary(w: &mut SqlWorld) {
    assert_eq!(w.fx.canary(), "intact");
}

#[then(expr = "the audit log records {string} with enforcement {string}")]
fn audited_enforcement(w: &mut SqlWorld, event: String, enforcement: String) {
    let ev = w.host().audit_events().into_iter().find(|e| e["event"] == event.as_str()).expect("the event");
    assert_eq!(ev["enforcement"], json!(enforcement), "{ev}");
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn cucumber_scenarios() {
    let Some(fx) = fixture() else { return };
    *FIXTURE.lock().unwrap() = Some(Arc::new(fx));
    let features = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/features/sql_browser.feature");
    // Sequential: the scenarios share one database.
    let writer = futures::executor::block_on(
        SqlWorld::cucumber().with_default_cli().max_concurrent_scenarios(1).fail_on_skipped().run(features),
    );
    let failed = writer.execution_has_failed();
    FIXTURE.lock().unwrap().take();
    assert!(!failed, "cucumber scenarios failed");
}
