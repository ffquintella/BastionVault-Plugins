//! Live tests against a throwaway `postgres:16` container (docker CLI).
//! Ignored by default: `cargo nextest run -p bastion-plugin-dbms-management
//! --lib --run-ignored only`. Without docker they print a skip and pass,
//! unless `BV_TEST_REQUIRE_CONTAINER=1`.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::profile::tests::{profile_json, target_json};
use crate::profile::STATEMENT_CAPS;
use crate::testutil::{call, code, loopback_config, MockHost};
use crate::Plugin;

mod cucumber_steps;
mod mssql;
mod mysql;
mod oracle;

const IMAGE: &str = "postgres:16";

struct Pg {
    name: String,
    port: u16,
    admin_pw: String,
}

impl Drop for Pg {
    fn drop(&mut self) {
        let _ =
            Command::new("docker").args(["rm", "-f", &self.name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

fn rand() -> String {
    crate::ids::random_hex(12).unwrap()
}

impl Pg {
    fn start(env: &[&str], args: &[&str]) -> Option<Self> {
        let ok = Command::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            assert!(std::env::var("BV_TEST_REQUIRE_CONTAINER").as_deref() != Ok("1"), "docker is required");
            eprintln!("skipped: docker is not available");
            return None;
        }
        let name = format!("bv-test-dbms-{}-{}", std::process::id(), &rand()[..8]);
        let mut pg = Pg { name: name.clone(), port: 0, admin_pw: rand() };
        // The password reaches docker through the child's environment, not argv.
        let mut cmd = Command::new("docker");
        cmd.args(["run", "-d", "--name", &name, "--label", "bv-test=dbms-management", "-p", "127.0.0.1::5432"])
            .args(env.iter().flat_map(|e| ["-e", *e]))
            .args(["-e", "POSTGRES_PASSWORD", IMAGE])
            .args(args)
            .env("POSTGRES_PASSWORD", &pg.admin_pw);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
        let mapped = Command::new("docker").args(["port", &name, "5432/tcp"]).output().unwrap();
        let text = String::from_utf8_lossy(&mapped.stdout).to_string();
        let port = text.lines().find_map(|l| l.trim().rsplit(':').next().and_then(|p| p.parse().ok())).unwrap();
        pg.port = port;
        let t0 = Instant::now();
        loop {
            let ready = Command::new("docker")
                .args(["exec", &name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ready {
                break;
            }
            assert!(t0.elapsed() < Duration::from_secs(60), "postgres did not become ready");
            std::thread::sleep(Duration::from_millis(300));
        }
        // The entrypoint restarts the server once after init; wait it out.
        std::thread::sleep(Duration::from_millis(1500));
        Some(pg)
    }

    /// Run SQL as the superuser over the container's socket (SQL on stdin).
    fn psql(&self, db: &str, sql: &str) -> String {
        let mut child = Command::new("docker")
            .args([
                "exec",
                "-i",
                &self.name,
                "psql",
                "-U",
                "postgres",
                "-d",
                db,
                "-v",
                "ON_ERROR_STOP=1",
                "-tA",
                "-f",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(sql.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "psql: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

fn local(id: &str, ceiling: &[&str], pg: &Pg, tls: &str) -> Value {
    let mut p = profile_json(id, ceiling);
    p["endpoint"] = json!(pg.endpoint());
    p["host"] = json!("127.0.0.1");
    p["port"] = json!(pg.port);
    p["tls"]["mode"] = json!(tls);
    p
}

struct Fixture {
    pg: Pg,
    ro_pw: String,
    rw_pw: String,
}

fn fixture() -> Option<Fixture> {
    let pg = Pg::start(&[], &[])?;
    let (ro_pw, rw_pw) = (rand(), rand());
    pg.psql("postgres", "CREATE DATABASE app;");
    pg.psql(
        "app",
        &format!(
            "CREATE TABLE public.t (id int PRIMARY KEY, name text NOT NULL, amount numeric(10,2), \"Mixed\" int);
             INSERT INTO public.t VALUES (1, 'alpha', 10.50, 7), (2, 'beta', NULL, NULL);
             CREATE TABLE public.canary (v text); INSERT INTO public.canary VALUES ('intact');
             CREATE TABLE public.nokey (v text);
             CREATE SCHEMA app; CREATE TABLE app.t2 (x int); INSERT INTO app.t2 VALUES (42);
             CREATE VIEW public.v AS SELECT id, name FROM public.t;
             CREATE SEQUENCE public.s;
             CREATE FUNCTION public.flip() RETURNS int LANGUAGE sql AS $$ SELECT 1 FROM pg_catalog.set_config('standard_conforming_strings', 'off', false) $$;
             CREATE ROLE ro LOGIN PASSWORD '{ro_pw}';
             CREATE ROLE rw LOGIN PASSWORD '{rw_pw}';
             GRANT USAGE ON SCHEMA public, app TO ro, rw;
             GRANT SELECT ON ALL TABLES IN SCHEMA public, app TO ro;
             GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public, app TO rw;"
        ),
    );
    Some(Fixture { pg, ro_pw, rw_pw })
}

impl Fixture {
    /// A host whose caller holds `privs` (server-level) and is allowed
    /// whatever `allow` says on each check.
    fn host(&self, privs: &[&str], tls: &str) -> std::sync::Arc<MockHost> {
        let profiles = vec![
            local("ro", &["sql_select"], &self.pg, tls),
            local("rw", &["sql_select", "sql_insert", "sql_update", "sql_delete"], &self.pg, tls),
            local("admin", &STATEMENT_CAPS, &self.pg, tls),
        ];
        let h = MockHost::new(target_json("database-first", privs, profiles));
        let ep = self.pg.endpoint();
        let mut creds = h.creds.lock().unwrap();
        creds.insert("ro".into(), (ep.clone(), "ro".into(), self.ro_pw.clone()));
        creds.insert("rw".into(), (ep.clone(), "rw".into(), self.rw_pw.clone()));
        creds.insert("admin".into(), (ep, "postgres".into(), self.pg.admin_pw.clone()));
        drop(creds);
        h.set_config(loopback_config());
        let held: Vec<String> = privs.iter().map(|s| s.to_string()).collect();
        h.allow(move |c| held.iter().any(|p| p == c.capability));
        h
    }

    fn canary(&self) -> String {
        self.pg.psql("app", "SELECT v FROM public.canary")
    }
}

fn open(p: &Plugin, h: &MockHost, who: &str) -> String {
    let (st, v, bytes) = call(p, h, who, "write", "v2/sessions", json!({"resource": "db"}));
    assert_eq!(st, 0, "open: {v}");
    h.assert_no_leak(&bytes);
    v["data"]["session_id"].as_str().unwrap().to_string()
}

/// Execute and poll to the end; returns (execute reply, pages).
fn exec(p: &Plugin, h: &MockHost, who: &str, sid: &str, sql: &str) -> (Value, Vec<Value>) {
    let (st, v, bytes) = call(p, h, who, "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": sql}));
    h.assert_no_leak(&bytes);
    if st != 0 || v["data"]["state"] != "running" {
        return (v, Vec::new());
    }
    let run = v["data"]["run_id"].as_str().unwrap().to_string();
    let mut pages = Vec::new();
    let t0 = Instant::now();
    loop {
        let (st, page, bytes) = call(p, h, who, "read", &format!("v2/sessions/{sid}/runs/{run}"), json!({}));
        assert_eq!(st, 0, "{page}");
        h.assert_no_leak(&bytes);
        let page = page["data"].clone();
        let done = page["state"] != "running" && page["has_more"] == false;
        pages.push(page);
        if done {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(60), "run did not finish");
        std::thread::sleep(Duration::from_millis(30));
    }
    (v, pages)
}

fn rows(pages: &[Value]) -> Vec<Value> {
    pages.iter().flat_map(|p| p["rows"].as_array().cloned().unwrap_or_default()).collect()
}

fn last(pages: &[Value]) -> &Value {
    pages.last().expect("at least one page")
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_sessions_runs_and_enforcement() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();

    // ── a read-only caller gets the read-only login, enforced by the database
    let ana = fx.host(&["sql_select"], "disable");
    let sid = open(&p, &ana, "ana");
    let (_, status, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}"), json!({}));
    assert_eq!(status["data"]["profile"], "ro");
    assert_eq!(status["data"]["read_only"], true);
    assert_eq!(status["data"]["database_read_only"], true);
    assert_eq!(status["data"]["db_enforced"], true);

    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT id, name, amount, \"Mixed\" FROM t ORDER BY id");
    assert_eq!(last(&pages)["state"], "done");
    assert_eq!(rows(&pages), vec![json!([1, "alpha", "10.50", 7]), json!([2, "beta", null, null])]);
    let cols = &last(&pages)["columns"];
    assert_eq!(cols[0]["kind"], "number");
    assert_eq!(cols[2]["kind"], "string");
    // The unqualified `t` was resolved through the catalog to public.t.
    let asked = ana.authorized.lock().unwrap().last().unwrap().clone();
    assert!(asked.contains(&crate::host::Check::object("sql_select", "app", "public", "t")), "{asked:?}");

    // ── the vault refuses a write the caller does not hold: nothing runs
    let (v, _) = exec(&p, &ana, "ana", &sid, "UPDATE public.canary SET v = 'changed'");
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert!(v["data"]["message"].as_str().unwrap().contains("sql_update"));
    assert_eq!(fx.canary(), "intact");

    // ── even if the vault allowed it, the read-only login refuses (§5.3)
    ana.allow(|_| true);
    let (_, pages) = exec(&p, &ana, "ana", &sid, "UPDATE public.canary SET v = 'changed'");
    let msg = &last(&pages)["messages"][0];
    assert_eq!(msg["outcome"], "error");
    assert!(matches!(msg["error"]["sqlstate"].as_str(), Some("25006" | "42501")), "{msg}");
    assert_eq!(fx.canary(), "intact");
    ana.allow(|c| c.capability == "sql_select");

    // ── smuggling and hazards never reach the server
    for (sql, expect) in [
        ("SELECT 1; DELETE FROM public.canary", "use_script"),
        ("SELECT pg_read_file('/etc/passwd')", "refused_statement"),
        ("SET default_transaction_read_only = off", "refused_statement"),
        ("SET standard_conforming_strings = off", "refused_statement"),
    ] {
        let (v, _) = exec(&p, &ana, "ana", &sid, sql);
        assert_eq!(code(&v), expect, "{sql}: {v}");
    }
    assert_eq!(fx.canary(), "intact");

    // ── another principal cannot see or use the session
    let bob = fx.host(&["sql_select"], "disable");
    let (_, v, _) = call(&p, &bob, "bob", "read", &format!("v2/sessions/{sid}"), json!({}));
    assert_eq!(code(&v), "not_found");
    let (_, v, _) = call(&p, &bob, "bob", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": "SELECT 1"}));
    assert_eq!(code(&v), "not_found");

    // ── paging, the grid cap
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT g FROM generate_series(1, 1200) g");
    assert_eq!(rows(&pages).len(), 1200);
    assert!(pages.iter().all(|p| p["rows"].as_array().unwrap().len() <= 500));
    let mut cfg = loopback_config();
    cfg["grid_rows"] = json!(1000);
    cfg["run_timeout_secs"] = json!(3);
    ana.set_config(cfg.clone());
    let p2 = Plugin::new();
    let sid2 = open(&p2, &ana, "ana");
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT g FROM generate_series(1, 5000000) g");
    assert_eq!(rows(&pages).len(), 1000, "the grid cap stops the read");
    assert_eq!(last(&pages)["messages"][0]["truncated"], true);
    assert_eq!(last(&pages)["state"], "done");

    // ── the run deadline (statement_timeout) and cancel
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT pg_sleep(10)");
    assert_ne!(last(&pages)["state"], "done");
    let (_, v, _) =
        call(&p, &ana, "ana", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": "SELECT pg_sleep(20)"}));
    let run = v["data"]["run_id"].as_str().unwrap().to_string();
    std::thread::sleep(Duration::from_millis(300));
    let (_, busy, _) =
        call(&p, &ana, "ana", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": "SELECT 1"}));
    assert_eq!(code(&busy), "session_busy");
    let t0 = Instant::now();
    call(&p, &ana, "ana", "write", &format!("v2/sessions/{sid}/runs/{run}/cancel"), json!({}));
    loop {
        let (_, page, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/runs/{run}"), json!({}));
        if page["data"]["state"] != "running" {
            assert_eq!(page["data"]["state"], "cancelled");
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "cancel took too long");
        std::thread::sleep(Duration::from_millis(50));
    }

    // ── a read/write caller: transactions, rollback on close
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "disable");
    let sid3 = open(&p, &rw, "carol");
    let (_, st, _) = call(&p, &rw, "carol", "read", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(st["data"]["profile"], "rw");
    assert_eq!(st["data"]["read_only"], false);
    let (_, pages) = exec(&p, &rw, "carol", &sid3, "BEGIN; INSERT INTO public.t (id, name) VALUES (10, 'tx')");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    let (_, st, _) = call(&p, &rw, "carol", "read", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(st["data"]["transaction"]["open"], true);
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 10"), "0", "not visible before commit");
    let (_, v, _) = call(&p, &rw, "carol", "delete", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(v["data"]["closed"], true);
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 10"), "0", "rolled back on close");
    let events = rw.audit_events();
    assert!(events.iter().any(|e| e["event"] == "dbms.tx" && e["action"] == "auto-rollback"), "{events:?}");
    assert!(events.iter().any(|e| e["event"] == "dbms.session.close" && e["reason"] == "operator"));

    let sid4 = open(&p, &rw, "carol");
    let (_, pages) = exec(&p, &rw, "carol", &sid4, "BEGIN; UPDATE public.t SET name = 'gamma' WHERE id = 2; COMMIT");
    assert_eq!(last(&pages)["state"], "done");
    assert_eq!(fx.pg.psql("app", "SELECT name FROM public.t WHERE id = 2"), "gamma");
    assert!(rw.audit_events().iter().any(|e| e["event"] == "dbms.tx" && e["action"] == "commit"));

    // ── the name context follows SET search_path
    let (_, pages) = exec(&p, &rw, "carol", &sid4, "SET search_path TO app");
    assert_eq!(last(&pages)["state"], "done");
    let (_, pages) = exec(&p, &rw, "carol", &sid4, "SELECT x FROM t2");
    assert_eq!(rows(&pages), vec![json!([42])]);
    let asked = rw.authorized.lock().unwrap().last().unwrap().clone();
    assert!(asked.contains(&crate::host::Check::object("sql_select", "app", "app", "t2")), "{asked:?}");

    // ── a lexer setting changed behind the classifier's back taints
    let admin = fx.host(&STATEMENT_CAPS, "disable");
    let sid5 = open(&p, &admin, "dave");
    let (_, pages) = exec(&p, &admin, "dave", &sid5, "SELECT public.flip()");
    assert_eq!(last(&pages)["state"], "done");
    let (_, v, _) =
        call(&p, &admin, "dave", "write", &format!("v2/sessions/{sid5}/execute"), json!({"sql": "SELECT 1"}));
    assert_eq!(code(&v), "session_tainted", "{v}");

    // ── seal closes everything and rolls back open transactions
    let sid6 = open(&p, &rw, "carol");
    exec(&p, &rw, "carol", &sid6, "BEGIN; INSERT INTO public.t (id, name) VALUES (11, 'sealed')");
    p.lifecycle(bastion_plugin_sdk::process::Lifecycle::Seal);
    assert!(p.registry().is_empty());
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 11"), "0");
    // The close events wait for carol's next invocation, under her identity.
    let before = rw.audit_events().len();
    call(&p, &rw, "carol", "list", "v2/sessions", json!({}));
    let flushed: Vec<Value> = rw.audit_events()[before..].to_vec();
    assert!(flushed.iter().any(|e| e["event"] == "dbms.session.close" && e["reason"] == "seal"), "{flushed:?}");

    // ── nothing ever leaked a password
    for h in [&ana, &bob, &rw, &admin] {
        h.assert_no_leak(b"");
    }
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_tls_modes_and_weak_auth() {
    // Cleartext password authentication, with TLS available on the server.
    let Some(pg) = Pg::start(
        &["POSTGRES_HOST_AUTH_METHOD=password"],
        &[
            "-c",
            "ssl=on",
            "-c",
            "ssl_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem",
            "-c",
            "ssl_key_file=/etc/ssl/private/ssl-cert-snakeoil.key",
        ],
    ) else {
        return;
    };
    pg.psql("postgres", "CREATE DATABASE app;");
    let cert = {
        let out = Command::new("docker")
            .args(["exec", &pg.name, "cat", "/etc/ssl/certs/ssl-cert-snakeoil.pem"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let p = Plugin::new();
    let try_open = |tls: &str, ca: Option<&str>| -> (i32, Value) {
        let mut prof = local("admin", &STATEMENT_CAPS, &pg, tls);
        if let Some(ca) = ca {
            prof["tls"]["ca_pem"] = json!(ca);
        }
        let h = MockHost::new(target_json("database-first", &STATEMENT_CAPS, vec![prof]));
        h.creds.lock().unwrap().insert("admin".into(), (pg.endpoint(), "postgres".into(), pg.admin_pw.clone()));
        h.set_config(loopback_config());
        let (st, v, bytes) = call(&p, &h, "erin", "write", "v2/sessions", json!({"resource": "db"}));
        h.assert_no_leak(&bytes);
        (st, v)
    };
    // Plaintext with a cleartext-password server: refused before sending it.
    let (st, v) = try_open("disable", None);
    assert_ne!(st, 0);
    assert_eq!(code(&v), "weak_auth_refused", "{v}");
    // The same method inside TLS is acceptable (§5.4: at least `require`).
    let (st, v) = try_open("require", None);
    assert_eq!(st, 0, "{v}");
    assert_eq!(v["data"]["tls_mode"], "require");
    // verify-full: an untrusted chain, then a trusted chain with the wrong name.
    let (st, v) = try_open("verify-full", None);
    assert_ne!(st, 0, "{v}");
    let (st, v) = try_open("verify-full", Some(&cert));
    assert_ne!(st, 0, "the snakeoil certificate does not name 127.0.0.1: {v}");
    // verify-ca: the chain is what matters.
    let (st, v) = try_open("verify-ca", Some(&cert));
    assert_eq!(st, 0, "{v}");
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_limits_budget_and_idle_transactions() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "disable");
    let mut cfg = loopback_config();
    cfg["sessions_per_user"] = json!(2);
    cfg["row_budget"] = json!(5);
    cfg["idle_tx_secs"] = json!(1);
    rw.set_config(cfg);

    // Sessions per user.
    let a = open(&p, &rw, "frank");
    let _b = open(&p, &rw, "frank");
    let (_, v, _) = call(&p, &rw, "frank", "write", "v2/sessions", json!({"resource": "db"}));
    assert_eq!(code(&v), "session_limit", "{v}");

    // The per-session row budget stops the grid and then refuses.
    let (_, pages) = exec(&p, &rw, "frank", &a, "SELECT g FROM generate_series(1, 100) g");
    assert_eq!(rows(&pages).len(), 5);
    assert_eq!(last(&pages)["row_budget_exhausted"], true);
    let (_, v, _) = call(&p, &rw, "frank", "write", &format!("v2/sessions/{a}/execute"), json!({"sql": "SELECT 1"}));
    assert_eq!(code(&v), "row_budget", "{v}");
    assert!(rw.audit_events().iter().any(|e| e["event"] == "dbms.row_budget"));

    // Idle in transaction: rolled back by the sweep, the session kept.
    let c = {
        call(&p, &rw, "frank", "delete", &format!("v2/sessions/{a}"), json!({}));
        open(&p, &rw, "frank")
    };
    let mut cfg = loopback_config();
    cfg["idle_tx_secs"] = json!(1);
    rw.set_config(cfg);
    let p2 = Plugin::new();
    let d = open(&p2, &rw, "frank");
    exec(&p2, &rw, "frank", &d, "BEGIN; INSERT INTO public.t (id, name) VALUES (20, 'idle')");
    let t0 = Instant::now();
    loop {
        let (_, st, _) = call(&p2, &rw, "frank", "read", &format!("v2/sessions/{d}"), json!({}));
        if st["data"]["transaction"]["open"] == false {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(15), "the idle transaction was not rolled back");
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 20"), "0");
    call(&p2, &rw, "frank", "list", "v2/sessions", json!({}));
    assert!(rw
        .audit_events()
        .iter()
        .any(|e| e["event"] == "dbms.tx" && e["reason"] == "idle_in_transaction" && e["outcome"] == "rolled_back"));
    let _ = c;
    rw.assert_no_leak(b"");
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_objects_rows_and_probe() {
    let Some(fx) = fixture() else { return };
    fx.pg.psql(
        "app",
        "CREATE TABLE public.\"odd name\" (id int PRIMARY KEY); GRANT SELECT ON public.\"odd name\" TO ro, rw;",
    );
    let p = Plugin::new();

    // ── object browser: resource-wide sees all, object-scoped sees its own
    let wide = fx.host(&["sql_select"], "disable");
    let sid = open(&p, &wide, "gina");
    let (st, v, _) = call(&p, &wide, "gina", "list", &format!("v2/sessions/{sid}/objects"), json!({}));
    assert_eq!(st, 0, "{v}");
    let schemas: Vec<String> = serde_json::from_value(v["data"]["keys"].clone()).unwrap();
    assert!(schemas.contains(&"public".to_string()) && schemas.contains(&"app".to_string()), "{schemas:?}");
    let (_, v, _) = call(&p, &wide, "gina", "list", &format!("v2/sessions/{sid}/objects/public"), json!({}));
    let names: Vec<String> =
        v["data"]["objects"].as_array().unwrap().iter().map(|o| o["name"].as_str().unwrap().to_string()).collect();
    for want in ["t", "canary", "v", "s", "flip", "t_pkey", "odd name"] {
        assert!(names.contains(&want.to_string()), "{want} missing from {names:?}");
    }
    let scoped = fx.host(&["sql_select"], "disable");
    scoped.allow(|c| match &c.target {
        crate::host::CheckTarget::Server => c.capability == "sql_select",
        crate::host::CheckTarget::Object { schema, object, .. } => {
            c.capability == "sql_select" && schema == "public" && object == "t"
        }
    });
    let (_, v, _) = call(&p, &scoped, "gina", "list", &format!("v2/sessions/{sid}/objects/public"), json!({}));
    let names: Vec<&str> =
        v["data"]["objects"].as_array().unwrap().iter().map(|o| o["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["t"], "only the object the grant covers");

    // ── describe
    let (_, v, _) = call(&p, &wide, "gina", "read", &format!("v2/sessions/{sid}/objects/public/t"), json!({}));
    let d = &v["data"];
    assert_eq!(d["kind"], "table");
    assert_eq!(d["edit"]["editable"], true);
    assert_eq!(d["edit"]["key"], json!(["id"]));
    assert_eq!(d["columns"][2]["type"], "numeric(10,2)");
    let (_, v, _) = call(&p, &wide, "gina", "read", &format!("v2/sessions/{sid}/objects/public/v"), json!({}));
    assert!(v["data"]["definition"].as_str().unwrap().contains("FROM t"), "{v}");
    let (_, v, _) = call(&p, &wide, "gina", "read", &format!("v2/sessions/{sid}/objects/public/odd%20name"), json!({}));
    assert_eq!(v["data"]["edit"]["editable"], false, "{v}");
    let (_, v, _) = call(&p, &wide, "gina", "read", &format!("v2/sessions/{sid}/objects/public/nokey"), json!({}));
    assert_eq!(v["data"]["edit"]["editable"], false);
    let (_, v, _) = call(&p, &scoped, "gina", "read", &format!("v2/sessions/{sid}/objects/public/canary"), json!({}));
    assert_eq!(code(&v), "refused", "describe needs sql_select on the object");

    // ── the ceiling probe: a read-only login with PUBLIC execute on a function
    let (_, v, _) = call(&p, &wide, "gina", "read", &format!("v2/sessions/{sid}/ceiling"), json!({}));
    assert_eq!(v["data"]["declared"], json!(["sql_select"]));
    assert!(v["data"]["probed"].as_array().unwrap().contains(&json!("sql_select")));
    assert!(v["data"]["undeclared"].as_array().unwrap().contains(&json!("sql_execute")), "{v}");

    // ── row edits on the read/write login
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "disable");
    let sid2 = open(&p, &rw, "hank");
    let edit = |data: Value| call(&p, &rw, "hank", "write", &format!("v2/sessions/{sid2}/rows"), data);
    let obj = json!({"schema": "public", "name": "t"});
    let (st, v, _) = edit(json!({"object": obj, "op": "update", "key": {"id": 1},
        "values": {"name": "alpha2", "amount": "11.25"}, "original": {"name": "alpha", "amount": "10.50"}}));
    assert_eq!(st, 0, "{v}");
    assert_eq!(v["data"]["state"], "done", "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT name || ' ' || amount FROM public.t WHERE id = 1"), "alpha2 11.25");
    // The same edit again: the original no longer matches.
    let (_, v, _) = edit(json!({"object": obj, "op": "update", "key": {"id": 1},
        "values": {"name": "alpha3"}, "original": {"name": "alpha"}}));
    assert_eq!(v["data"]["state"], "conflict", "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT name FROM public.t WHERE id = 1"), "alpha2");
    let (_, v, _) = edit(json!({"object": obj, "op": "insert", "values": {"id": 30, "name": "new", "amount": null}}));
    assert_eq!(v["data"]["state"], "done", "{v}");
    let (_, v, _) = edit(json!({"object": obj, "op": "delete", "key": {"id": 30}}));
    assert_eq!(v["data"]["state"], "done", "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 30"), "0");
    // Not without the capability.
    rw.allow(|c| c.capability != "sql_delete");
    let (_, v, _) = edit(json!({"object": obj, "op": "delete", "key": {"id": 2}}));
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 2"), "1");
    // Names outside SqlIdent are read-only in the grid; tables need a key.
    let (_, v, _) = edit(json!({"object": {"schema": "public", "name": "odd name"}, "op": "delete", "key": {"id": 1}}));
    assert_eq!(code(&v), "read_only_in_grid");
    let (_, v, _) =
        edit(json!({"object": {"schema": "public", "name": "nokey"}, "op": "insert", "values": {"v": "x"}}));
    assert_eq!(code(&v), "not_editable");
    // Inside an open transaction the edit uses a savepoint and stays uncommitted.
    rw.allow(|_| true);
    exec(&p, &rw, "hank", &sid2, "BEGIN");
    let (_, v, _) = edit(
        json!({"object": obj, "op": "update", "key": {"id": 2}, "values": {"name": "in-tx"}, "original": {"name": "beta"}}),
    );
    assert_eq!(v["data"]["state"], "done", "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT name FROM public.t WHERE id = 2"), "beta", "not committed yet");
    exec(&p, &rw, "hank", &sid2, "ROLLBACK");
    assert_eq!(fx.pg.psql("app", "SELECT name FROM public.t WHERE id = 2"), "beta");

    // The audit carries the key HMAC and column names, never values.
    let edits: Vec<Value> = rw.audit_events().into_iter().filter(|e| e["event"] == "dbms.row_edit").collect();
    assert!(edits.len() >= 5);
    for e in &edits {
        let text = e.to_string();
        for value in ["alpha2", "11.25", "in-tx", "\"new\""] {
            assert!(!text.contains(value), "a value in the audit: {text}");
        }
        assert_eq!(e["key_hmac"].as_str().unwrap().len(), 64);
    }
    for h in [&wide, &scoped, &rw] {
        h.assert_no_leak(b"");
    }
}

fn journal_record(h: &MockHost, sid: &str) -> Value {
    let storage = h.storage.lock().unwrap();
    let (_, bytes) =
        storage.iter().find(|(k, _)| k.starts_with("dbms/journal/") && k.ends_with(sid)).expect("a journal record");
    serde_json::from_slice(bytes).unwrap()
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_audit_and_journal() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();
    let ana = fx.host(&["sql_select"], "disable");
    let sid = open(&p, &ana, "ivy");
    exec(&p, &ana, "ivy", &sid, "SELECT name FROM public.t WHERE name = 'alpha' AND id = 1");
    exec(&p, &ana, "ivy", &sid, "SELECT * FROM public.missing_table");
    exec(&p, &ana, "ivy", &sid, "UPDATE public.canary SET v = 'secret-value'");

    // Audit: open, each statement with its outcome, refusals; never text.
    let events = ana.audit_events();
    let open_ev = events.iter().find(|e| e["event"] == "dbms.session.open").unwrap();
    assert_eq!(open_ev["outcome"], "opened");
    assert_eq!(open_ev["db_enforced"], true);
    assert_eq!(open_ev["transport"], "direct");
    let stmts: Vec<&Value> = events.iter().filter(|e| e["event"] == "dbms.statement").collect();
    let outcomes: Vec<&str> = stmts.iter().map(|e| e["outcome"].as_str().unwrap()).collect();
    assert!(outcomes.contains(&"ok") && outcomes.contains(&"error") && outcomes.contains(&"refused"), "{outcomes:?}");
    let ok = stmts.iter().find(|e| e["outcome"] == "ok").unwrap();
    assert_eq!(ok["rows_returned"], 1);
    assert_eq!(ok["objects"], json!(["app.public.t"]));
    assert_eq!(ok["session"], sid.as_str());
    let all = serde_json::to_string(&events).unwrap();
    // Object names are audited (§11: objects touched); literals and the
    // statement text are not.
    for text in ["alpha", "secret-value", "SELECT", "UPDATE", "WHERE"] {
        assert!(!all.contains(text), "statement text `{text}` in the audit stream");
    }

    // Journal: redacted text by default, outcomes, SQLSTATE only for errors.
    let rec = journal_record(&ana, &sid);
    assert_eq!(rec["v"], 1);
    assert_eq!(rec["entity_id"], "ivy");
    let entries = rec["statements"].as_array().unwrap();
    assert_eq!(entries[0]["text"], "SELECT name FROM public.t WHERE name = ? AND id = ?");
    assert_eq!(entries[0]["outcome"], "ok");
    assert_eq!(entries[1]["outcome"], "error");
    assert_eq!(entries[1]["error"], "SQLSTATE 42P01");
    assert!(!rec.to_string().contains("alpha"));

    // The owner reads it back; another entity does not see it.
    let (_, dates, _) = call(&p, &ana, "ivy", "list", "v2/journal/self", json!({}));
    let date = dates["data"]["keys"][0].as_str().unwrap().to_string();
    let (_, day, _) = call(&p, &ana, "ivy", "read", &format!("v2/journal/self/{date}"), json!({}));
    assert_eq!(day["data"]["sessions"][0]["session"], sid.as_str());
    let (_, other, _) = call(&p, &ana, "jack", "read", &format!("v2/journal/self/{date}/{sid}"), json!({}));
    assert_eq!(code(&other), "not_found");

    // Close: the record gets the reason; the close event names it.
    call(&p, &ana, "ivy", "delete", &format!("v2/sessions/{sid}"), json!({}));
    let rec = journal_record(&ana, &sid);
    assert_eq!(rec["close_reason"], "operator");
    assert!(ana.audit_events().iter().any(|e| e["event"] == "dbms.session.close"));

    // journal_text = full keeps the text (an explicit opt-in); none drops it.
    for (mode, expect) in [("full", json!("SELECT 'x' AS y")), ("none", Value::Null)] {
        let h = fx.host(&["sql_select"], "disable");
        let mut cfg = loopback_config();
        cfg["journal_text"] = json!(mode);
        h.set_config(cfg);
        let p = Plugin::new();
        let sid = open(&p, &h, "ivy");
        exec(&p, &h, "ivy", &sid, "SELECT 'x' AS y");
        assert_eq!(journal_record(&h, &sid)["statements"][0]["text"], expect, "{mode}");
    }
    ana.assert_no_leak(b"");
}

/// Regression: plugin catalog queries run on the caller's session, so an
/// operator a user schema puts ahead of pg_catalog must never be what they
/// call (every operator in them is pinned to pg_catalog).
#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_internal_queries_ignore_user_operators() {
    let Some(fx) = fixture() else { return };
    fx.pg.psql(
        "app",
        "CREATE FUNCTION public.evil_eq(oid, regclass) RETURNS boolean LANGUAGE sql AS \
           $$ UPDATE public.canary SET v = 'hijacked'; SELECT $1 OPERATOR(pg_catalog.=) $2::oid $$;
         CREATE OPERATOR public.= (LEFTARG = oid, RIGHTARG = regclass, FUNCTION = public.evil_eq);
         CREATE FUNCTION public.evil_ne(name, name) RETURNS boolean LANGUAGE sql AS \
           $$ UPDATE public.canary SET v = 'hijacked'; SELECT $1 OPERATOR(pg_catalog.<>) $2 $$;
         CREATE OPERATOR public.<> (LEFTARG = name, RIGHTARG = name, FUNCTION = public.evil_ne);
         CREATE FUNCTION public.evil_int(integer, integer) RETURNS boolean LANGUAGE sql AS \
           $$ UPDATE public.canary SET v = 'hijacked'; SELECT $1 OPERATOR(pg_catalog.=) $2 $$;
         CREATE OPERATOR public.= (LEFTARG = integer, RIGHTARG = integer, FUNCTION = public.evil_int);",
    );
    let p = Plugin::new();
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "disable");
    let sid = open(&p, &rw, "kim");
    let (_, pages) = exec(&p, &rw, "kim", &sid, "SET search_path TO public, pg_catalog");
    assert_eq!(last(&pages)["state"], "done");
    let (_, pages) = exec(&p, &rw, "kim", &sid, "SELECT id FROM t ORDER BY id");
    assert_eq!(last(&pages)["state"], "done");
    call(&p, &rw, "kim", "list", &format!("v2/sessions/{sid}/objects/public"), json!({}));
    call(&p, &rw, "kim", "read", &format!("v2/sessions/{sid}/objects/public/t"), json!({}));
    call(&p, &rw, "kim", "read", &format!("v2/sessions/{sid}/ceiling"), json!({}));
    assert_eq!(fx.canary(), "intact", "a user operator ran inside a plugin catalog query");
    // A grid edit's WHERE id = $n, in auto-commit and inside a transaction.
    let edit = json!({"object": {"schema": "public", "name": "t"}, "op": "update", "key": {"id": 1},
        "values": {"name": "edited"}, "original": {"name": "alpha"}});
    let (_, v, _) = call(&p, &rw, "kim", "write", &format!("v2/sessions/{sid}/rows"), edit.clone());
    assert_eq!(v["data"]["state"], "done", "{v}");
    exec(&p, &rw, "kim", &sid, "BEGIN");
    let mut again = edit.clone();
    again["values"] = json!({"name": "edited2"});
    again["original"] = json!({"name": "edited"});
    let (_, v, _) = call(&p, &rw, "kim", "write", &format!("v2/sessions/{sid}/rows"), again);
    assert_eq!(v["data"]["state"], "done", "{v}");
    let (_, pages) = exec(&p, &rw, "kim", &sid, "SHOW search_path");
    assert_eq!(rows(&pages), vec![json!(["public, pg_catalog"])], "the caller's search path is restored");
    exec(&p, &rw, "kim", &sid, "COMMIT");
    assert_eq!(fx.pg.psql("app", "SELECT name FROM public.t WHERE id = 1"), "edited2");
    assert_eq!(fx.canary(), "intact", "a user operator ran inside a grid edit");
}

/// A statement that changes the name context inside a transaction that then
/// aborts leaves the context unreadable; only transaction control may run
/// until it is rolled back, and the session recovers afterwards.
#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_aborted_transaction_recovers_after_rollback() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "disable");
    let sid = open(&p, &rw, "lea");
    exec(&p, &rw, "lea", &sid, "BEGIN");
    let (_, pages) = exec(&p, &rw, "lea", &sid, "SELECT 1/0");
    assert_eq!(last(&pages)["messages"][0]["outcome"], "error");
    // The transaction is aborted: this SET fails, and so does the re-read.
    exec(&p, &rw, "lea", &sid, "SET search_path TO app");
    let (_, v, _) =
        call(&p, &rw, "lea", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": "SELECT * FROM t"}));
    assert!(matches!(code(&v).as_str(), "context_stale" | "name_resolution"), "{v}");
    let (_, pages) = exec(&p, &rw, "lea", &sid, "ROLLBACK");
    assert_eq!(last(&pages)["state"], "done");
    let (_, pages) = exec(&p, &rw, "lea", &sid, "SELECT id FROM t ORDER BY id");
    assert_eq!(rows(&pages), vec![json!([1]), json!([2])]);
}

// ── T126: scripts, exports, per-action step-up ──────────────────────────

/// Poll a run to its end.
fn poll(p: &Plugin, h: &MockHost, who: &str, sid: &str, run: &str) -> Vec<Value> {
    let mut pages = Vec::new();
    let t0 = Instant::now();
    loop {
        let (st, page, bytes) = call(p, h, who, "read", &format!("v2/sessions/{sid}/runs/{run}"), json!({}));
        assert_eq!(st, 0, "{page}");
        h.assert_no_leak(&bytes);
        let page = page["data"].clone();
        let done = page["state"] != "running" && page["has_more"] == false;
        pages.push(page);
        if done {
            return pages;
        }
        assert!(t0.elapsed() < Duration::from_secs(60), "run did not finish");
        std::thread::sleep(Duration::from_millis(30));
    }
}

/// `POST script` and, when it started, poll it to the end.
fn script(p: &Plugin, h: &MockHost, who: &str, sid: &str, body: Value) -> (Value, Vec<Value>) {
    let (_, v, bytes) = call(p, h, who, "write", &format!("v2/sessions/{sid}/script"), body);
    h.assert_no_leak(&bytes);
    if v["data"]["state"] != "running" {
        return (v, Vec::new());
    }
    let run = v["data"]["run_id"].as_str().unwrap().to_string();
    let pages = poll(p, h, who, sid, &run);
    (v, pages)
}

/// `POST export` and, when it started, pull every chunk: (start reply, the
/// bytes, the last pull).
fn export(p: &Plugin, h: &MockHost, who: &str, sid: &str, body: Value) -> (Value, Vec<u8>, Value) {
    use base64::Engine as _;
    let (_, v, bytes) = call(p, h, who, "write", &format!("v2/sessions/{sid}/export"), body);
    h.assert_no_leak(&bytes);
    if v["data"]["state"] != "running" {
        return (v, Vec::new(), Value::Null);
    }
    let job = v["data"]["job"].as_str().unwrap().to_string();
    let mut out = Vec::new();
    let t0 = Instant::now();
    loop {
        let (st, chunk, bytes) =
            call(p, h, who, "read", &format!("v2/sessions/{sid}/exports/{job}/{}", out.len()), json!({}));
        assert_eq!(st, 0, "{chunk}");
        h.assert_no_leak(&bytes);
        let c = chunk["data"].clone();
        assert!(c["length"].as_u64().unwrap() <= crate::export::CHUNK_BYTES as u64);
        out.extend(base64::engine::general_purpose::STANDARD.decode(c["chunk"].as_str().unwrap()).unwrap());
        if c["eof"] == true {
            return (v, out, c);
        }
        assert!(t0.elapsed() < Duration::from_secs(60), "export did not finish");
    }
}

fn sha256_hex(b: &[u8]) -> String {
    crate::ids::hex(ring::digest::digest(&ring::digest::SHA256, b).as_ref())
}

/// The profiles' `step_up` lists, as the host's target view carries them.
fn set_step_up(h: &MockHost, step_up: &[&str]) {
    let mut t = h.target.lock().unwrap();
    let target = t.as_mut().unwrap();
    for p in target["target"]["profiles"].as_array_mut().unwrap() {
        p["step_up"] = json!(step_up);
    }
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_exports() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();

    // ── sql_select alone: refused, nothing read
    let ana = fx.host(&["sql_select"], "disable");
    let sid = open(&p, &ana, "ana");
    let (v, _, _) = export(&p, &ana, "ana", &sid, json!({"sql": "SELECT * FROM public.t", "format": "csv"}));
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert!(v["data"]["message"].as_str().unwrap().contains("sql_export"), "{v}");
    assert!(ana.audit_events().iter().any(|e| e["event"] == "dbms.export" && e["outcome"] == "refused"));

    // ── sql_select + sql_export: CSV, pulled in chunks, hashed, audited
    let exp = fx.host(&["sql_select", "sql_export"], "disable");
    let sid = open(&p, &exp, "erin");
    let sql = "SELECT id, name, amount, '=1+1' AS f FROM t ORDER BY id";
    let (v, bytes, end) = export(&p, &exp, "erin", &sid, json!({"sql": sql, "format": "csv"}));
    assert_eq!(v["data"]["state"], "running", "{v}");
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert_eq!(text, "\"id\",\"name\",\"amount\",\"f\"\r\n1,\"alpha\",10.50,\"'=1+1\"\r\n2,\"beta\",,\"'=1+1\"\r\n");
    assert_eq!((end["state"].clone(), end["rows"].clone()), (json!("done"), json!(2)));
    assert_eq!(end["sha256"], json!(sha256_hex(&bytes)));
    let asked = exp.authorized.lock().unwrap().last().unwrap().clone();
    assert!(asked.contains(&crate::host::Check::object("sql_export", "app", "public", "t")), "{asked:?}");
    let ev = exp.audit_events().into_iter().rev().find(|e| e["event"] == "dbms.export").unwrap();
    assert_eq!((ev["outcome"].clone(), ev["rows"].clone()), (json!("done"), json!(2)));
    assert_eq!(ev["sha256"], json!(sha256_hex(&bytes)));
    assert_eq!(ev["bytes"], json!(bytes.len()));
    assert!(ev["digest"].as_str().is_some_and(|d| d.len() == 64));
    assert!(!ev.to_string().contains("alpha"), "no row data in the audit");

    // ── JSON Lines and SQL INSERT
    let (_, bytes, _) = export(
        &p,
        &exp,
        "erin",
        &sid,
        json!({"sql": "SELECT id, name, amount FROM public.t ORDER BY id", "format": "jsonl"}),
    );
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "{\"id\":1,\"name\":\"alpha\",\"amount\":\"10.50\"}\n{\"id\":2,\"name\":\"beta\",\"amount\":null}\n"
    );
    let body = json!({"sql": "SELECT id, name FROM public.t ORDER BY id", "format": "sql-insert",
        "table": {"schema": "public", "name": "t_copy"}});
    let (_, bytes, _) = export(&p, &exp, "erin", &sid, body);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("INSERT INTO \"public\".\"t_copy\" (\"id\", \"name\") VALUES (1, 'alpha');\n"), "{text}");

    // ── a row limit stops the read and says so; a large export streams in
    //    1 MiB chunks from the cursor
    let (_, bytes, end) = export(
        &p,
        &exp,
        "erin",
        &sid,
        json!({"sql": "SELECT g FROM generate_series(1, 100) g", "format": "csv", "max_rows": 10}),
    );
    assert_eq!(
        (end["state"].clone(), end["limit"].clone(), end["rows"].clone()),
        (json!("limit_reached"), json!("row_limit"), json!(10))
    );
    assert_eq!(String::from_utf8(bytes).unwrap().lines().count(), 11);
    let (_, bytes, end) = export(
        &p,
        &exp,
        "erin",
        &sid,
        json!({"sql": "SELECT g, repeat('x', 200) FROM generate_series(1, 20000) g", "format": "csv"}),
    );
    assert_eq!(end["rows"], 20000);
    assert!(bytes.len() > 2 * crate::export::CHUNK_BYTES, "{}", bytes.len());
    assert_eq!(end["sha256"], json!(sha256_hex(&bytes)));

    // ── only SELECT-only statements, refused before the database
    for sql in [
        "DELETE FROM public.canary RETURNING *",
        "WITH d AS (DELETE FROM public.canary RETURNING *) SELECT * FROM d",
        "SELECT * FROM public.canary FOR UPDATE",
        "SELECT 1; SELECT 2",
    ] {
        let (_, v, _) =
            call(&p, &exp, "erin", "write", &format!("v2/sessions/{sid}/export"), json!({"sql": sql, "format": "csv"}));
        assert!(matches!(code(&v).as_str(), "export_not_select" | "export_one_statement" | "use_script"), "{sql}: {v}");
    }
    assert_eq!(fx.canary(), "intact");

    // ── malformed requests and pulls
    for body in [
        json!({"sql": "SELECT 1", "format": "xlsx"}),
        json!({"sql": "SELECT 1", "format": "sql-insert"}),
        json!({"sql": "SELECT 1", "format": "csv", "table": {"name": "t"}}),
        json!({"sql": "SELECT 1", "format": "jsonl", "formula_guard": false}),
        json!({"sql": "SELECT 1", "format": "csv", "max_rows": 0}),
        json!({"sql": "SELECT 1", "format": "csv", "path": "/tmp/x"}),
    ] {
        let (_, v, _) = call(&p, &exp, "erin", "write", &format!("v2/sessions/{sid}/export"), body.clone());
        assert_eq!(code(&v), "bad_request", "{body}: {v}");
    }
    let (_, v, _) = call(
        &p,
        &exp,
        "erin",
        "write",
        &format!("v2/sessions/{sid}/export"),
        json!({"sql": "SELECT g FROM generate_series(1, 3) g", "format": "csv"}),
    );
    let job = v["data"]["job"].as_str().unwrap().to_string();
    let (_, v, _) = call(&p, &exp, "erin", "read", &format!("v2/sessions/{sid}/exports/{job}/7"), json!({}));
    assert_eq!(code(&v), "bad_request", "{v}");
    let (_, v, _) = call(&p, &exp, "erin", "read", &format!("v2/sessions/{sid}/exports/{job}/x"), json!({}));
    assert_eq!(code(&v), "bad_request");
    // Another principal cannot pull it.
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/exports/{job}/0"), json!({}));
    assert_eq!(code(&v), "not_found");

    // Drain it: a pull waits for data or the end, and the end frees the session.
    let mut offset = 0;
    loop {
        let (_, v, _) = call(&p, &exp, "erin", "read", &format!("v2/sessions/{sid}/exports/{job}/{offset}"), json!({}));
        offset = v["data"]["next_offset"].as_u64().unwrap_or_else(|| panic!("{v}"));
        if v["data"]["eof"] == true {
            break;
        }
    }
    // ── a running export makes the session busy; cancel ends it
    let (_, v, _) = call(
        &p,
        &exp,
        "erin",
        "write",
        &format!("v2/sessions/{sid}/export"),
        json!({"sql": "SELECT g, repeat('y', 500) FROM generate_series(1, 2000000) g", "format": "csv"}),
    );
    assert_eq!(code(&v), "", "{v}");
    let job = v["data"]["job"].as_str().unwrap().to_string();
    std::thread::sleep(Duration::from_millis(300));
    let (_, busy, _) =
        call(&p, &exp, "erin", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": "SELECT 1"}));
    assert_eq!(code(&busy), "session_busy");
    let (_, v, _) = call(&p, &exp, "erin", "write", &format!("v2/sessions/{sid}/exports/{job}/cancel"), json!({}));
    assert_eq!(v["data"]["state"], "cancelled", "{v}");
    let ev = exp.audit_events().into_iter().rev().find(|e| e["event"] == "dbms.export").unwrap();
    assert_eq!(ev["outcome"], "cancelled");
    let (_, pages) = exec(&p, &exp, "erin", &sid, "SELECT 1");
    assert_eq!(last(&pages)["state"], "done", "the session is usable after a cancel");

    // ── abandoned: no pull for export_idle_secs → expired, buffer dropped
    let mut cfg = loopback_config();
    cfg["export_idle_secs"] = json!(1);
    exp.set_config(cfg);
    let p2 = Plugin::new();
    let sid2 = open(&p2, &exp, "erin");
    let (_, v, _) = call(
        &p2,
        &exp,
        "erin",
        "write",
        &format!("v2/sessions/{sid2}/export"),
        json!({"sql": "SELECT g, repeat('z', 500) FROM generate_series(1, 200000) g", "format": "csv"}),
    );
    let job = v["data"]["job"].as_str().unwrap().to_string();
    let t0 = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let (_, v, _) = call(&p2, &exp, "erin", "read", &format!("v2/sessions/{sid2}/exports/{job}"), json!({}));
        if v["data"]["state"] == "expired" {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "the abandoned export did not expire: {v}");
    }
    let (_, v, _) = call(&p2, &exp, "erin", "read", &format!("v2/sessions/{sid2}/exports/{job}/0"), json!({}));
    assert_eq!(code(&v), "export_expired");
    assert!(exp.audit_events().iter().any(|e| e["event"] == "dbms.export" && e["outcome"] == "expired"));

    for h in [&ana, &exp] {
        h.assert_no_leak(b"");
    }
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_scripts() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();
    let rw = &["sql_select", "sql_insert", "sql_update", "sql_delete"];

    // ── execute never runs two statements; a script needs sql_script
    let carol = fx.host(rw, "disable");
    let sid = open(&p, &carol, "carol");
    let (v, _) = exec(&p, &carol, "carol", &sid, "INSERT INTO public.t (id, name) VALUES (40, 'x'); SELECT 1");
    assert_eq!(code(&v), "use_script", "{v}");
    let (v, _) =
        script(&p, &carol, "carol", &sid, json!({"sql": "INSERT INTO public.t (id, name) VALUES (40, 'x'); SELECT 1"}));
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert_eq!(v["data"]["message"], "the script needs `sql_script` on the server");
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 40"), "0");

    // ── all or nothing: one refused statement runs nothing, and is named
    let scripter = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_script"], "disable");
    let sid = open(&p, &scripter, "sam");
    let body =
        json!({"sql": "INSERT INTO public.t (id, name) VALUES (41, 'a');\nDELETE FROM public.canary;\nSELECT 1"});
    let (v, _) = script(&p, &scripter, "sam", &sid, body);
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert_eq!(v["data"]["refused_statement"], 1);
    assert!(v["data"]["message"].as_str().unwrap().starts_with("statement 2 needs `sql_delete`"), "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 41"), "0", "nothing ran");
    assert_eq!(fx.canary(), "intact");
    // A statement that is always refused is named too.
    let (_, v, _) = call(
        &p,
        &scripter,
        "sam",
        "write",
        &format!("v2/sessions/{sid}/script"),
        json!({"sql": "SELECT 1; SELECT pg_read_file('/etc/passwd')"}),
    );
    assert_eq!(code(&v), "refused_statement");
    assert!(v["error"].as_str().unwrap().contains("statement 2"), "{v}");

    // ── a script runs every statement, with per-statement progress
    let body = json!({"sql": "INSERT INTO public.t (id, name) VALUES (42, 'b');\nUPDATE public.t SET name = 'c' WHERE id = 42;\nSELECT g FROM generate_series(1, 3) g"});
    let (v, pages) = script(&p, &scripter, "sam", &sid, body);
    assert_eq!(v["data"]["state"], "running", "{v}");
    let end = last(&pages);
    assert_eq!(end["state"], "done", "{end}");
    let msgs = end["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 3);
    assert_eq!((msgs[0]["rows_affected"].clone(), msgs[1]["rows_affected"].clone()), (json!(1), json!(1)));
    assert_eq!(msgs[2]["rows_returned"], 3);
    assert!(rows(&pages).is_empty(), "a script's result rows are counted, not returned");
    assert_eq!(fx.pg.psql("app", "SELECT name FROM public.t WHERE id = 42"), "c");
    let ev = scripter.audit_events().into_iter().rev().find(|e| e["event"] == "dbms.script").unwrap();
    assert_eq!((ev["statements"].clone(), ev["outcomes"]["ok"].clone()), (json!(3), json!(3)));
    assert!(ev["digest"].as_str().is_some_and(|d| d.len() == 64));

    // ── transaction: single rolls everything back on an error
    let body = json!({"sql": "INSERT INTO public.t (id, name) VALUES (43, 'd');\nINSERT INTO public.t (id, name) VALUES (43, 'dup')",
        "transaction": "single"});
    let (_, pages) = script(&p, &scripter, "sam", &sid, body);
    let end = last(&pages);
    assert_eq!(
        (end["state"].clone(), end["script"]["tx_outcome"].clone()),
        (json!("failed"), json!("rolled_back")),
        "{end}"
    );
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 43"), "0", "rolled back");
    let body = json!({"sql": "INSERT INTO public.t (id, name) VALUES (44, 'e');\nUPDATE public.t SET name = 'f' WHERE id = 44",
        "transaction": "single"});
    let (_, pages) = script(&p, &scripter, "sam", &sid, body);
    assert_eq!(last(&pages)["script"]["tx_outcome"], "committed");
    assert_eq!(fx.pg.psql("app", "SELECT name FROM public.t WHERE id = 44"), "f");

    // ── on_error: continue runs the rest and reports the failure
    let body = json!({"sql": "INSERT INTO public.t (id, name) VALUES (45, 'g');\nINSERT INTO public.t (id, name) VALUES (45, 'dup');\nINSERT INTO public.t (id, name) VALUES (46, 'h')",
        "on_error": "continue"});
    let (_, pages) = script(&p, &scripter, "sam", &sid, body);
    let end = last(&pages);
    assert_eq!(end["state"], "failed");
    let outcomes: Vec<&str> =
        end["messages"].as_array().unwrap().iter().map(|m| m["outcome"].as_str().unwrap()).collect();
    assert_eq!(outcomes, ["ok", "error", "ok"]);
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id IN (45, 46)"), "2");
    // on_error: stop (the default) skips the rest.
    let body = json!({"sql": "INSERT INTO public.t (id, name) VALUES (47, 'i');\nINSERT INTO public.t (id, name) VALUES (47, 'dup');\nINSERT INTO public.t (id, name) VALUES (48, 'j')"});
    let (_, pages) = script(&p, &scripter, "sam", &sid, body);
    assert_eq!(last(&pages)["messages"].as_array().unwrap().len(), 2);
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 48"), "0");
    let ev = scripter.audit_events().into_iter().rev().find(|e| e["event"] == "dbms.script").unwrap();
    assert_eq!(ev["skipped"], 1);

    // ── option and limit refusals
    for (body, want) in [
        (json!({"sql": "SELECT 1", "transaction": "single", "on_error": "continue"}), "bad_request"),
        (json!({"sql": "BEGIN; SELECT 1; COMMIT", "transaction": "single"}), "script_tx_control"),
        (json!({"sql": "SELECT 1", "on_error": "maybe"}), "bad_request"),
        (json!({"sql": "SELECT 1", "unknown": 1}), "bad_request"),
    ] {
        let (_, v, _) = call(&p, &scripter, "sam", "write", &format!("v2/sessions/{sid}/script"), body.clone());
        assert_eq!(code(&v), want, "{body}: {v}");
    }
    let mut cfg = loopback_config();
    cfg["script_statements"] = json!(2);
    scripter.set_config(cfg);
    let p2 = Plugin::new();
    let sid2 = open(&p2, &scripter, "sam");
    let (_, v, _) = call(
        &p2,
        &scripter,
        "sam",
        "write",
        &format!("v2/sessions/{sid2}/script"),
        json!({"sql": "SELECT 1; SELECT 2; SELECT 3"}),
    );
    assert_eq!(code(&v), "script_too_long", "{v}");
    assert_eq!(fx.canary(), "intact");
    scripter.assert_no_leak(b"");
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_step_up() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();
    let h = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete", "sql_export", "sql_script"], "disable");
    set_step_up(&h, &["sql_delete", "sql_export", "sql_script"]);
    let sid = open(&p, &h, "sam");
    let (_, st, _) = call(&p, &h, "sam", "read", &format!("v2/sessions/{sid}"), json!({}));
    assert_eq!(st["data"]["step_up"], json!(["sql_delete", "sql_export", "sql_script"]));

    // Uses no step-up capability: runs as before.
    let (_, pages) = exec(&p, &h, "sam", &sid, "UPDATE public.t SET name = 'k' WHERE id = 1");
    assert_eq!(last(&pages)["state"], "done");

    // DELETE needs a ticket for exactly `sql_delete`; nothing runs without.
    let sql = "DELETE FROM public.t WHERE id = 2";
    let (v, _) = exec(&p, &h, "sam", &sid, sql);
    assert_eq!(
        (v["data"]["state"].clone(), v["data"]["action"].clone()),
        (json!("step_up_required"), json!("sql_delete")),
        "{v}"
    );
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 2"), "1");
    // Regression: a connect ticket (no action) is not accepted for an action.
    h.tickets.lock().unwrap().push("connect-1".into());
    let (_, v, _) = call(
        &p,
        &h,
        "sam",
        "write",
        &format!("v2/sessions/{sid}/execute"),
        json!({"sql": sql, "step_up_ticket": "connect-1"}),
    );
    assert_eq!(code(&v), "step_up_failed", "{v}");
    // Nor a ticket bound to another action.
    h.action_tickets.lock().unwrap().push(("sql_export".into(), "export-1".into()));
    let (_, v, _) = call(
        &p,
        &h,
        "sam",
        "write",
        &format!("v2/sessions/{sid}/execute"),
        json!({"sql": sql, "step_up_ticket": "export-1"}),
    );
    assert_eq!(code(&v), "step_up_failed", "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 2"), "1");
    h.action_tickets.lock().unwrap().push(("sql_delete".into(), "delete-1".into()));
    let (_, v, _) = call(
        &p,
        &h,
        "sam",
        "write",
        &format!("v2/sessions/{sid}/execute"),
        json!({"sql": sql, "step_up_ticket": "delete-1"}),
    );
    let run = v["data"]["run_id"].as_str().unwrap_or_else(|| panic!("{v}")).to_string();
    assert_eq!(last(&poll(&p, &h, "sam", &sid, &run))["state"], "done");
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 2"), "0");
    // The ticket was single use.
    let (_, v, _) = call(
        &p,
        &h,
        "sam",
        "write",
        &format!("v2/sessions/{sid}/execute"),
        json!({"sql": "DELETE FROM public.t WHERE id = 1", "step_up_ticket": "delete-1"}),
    );
    assert_eq!(code(&v), "step_up_failed", "{v}");
    let ev: Vec<Value> = h.audit_events().into_iter().filter(|e| e["event"] == "dbms.step_up").collect();
    assert!(ev.iter().any(|e| e["outcome"] == "redeemed" && e["action"] == "sql_delete"), "{ev:?}");
    assert!(ev.iter().any(|e| e["outcome"] == "refused"), "{ev:?}");

    // A script with a DELETE needs one ticket for both actions.
    let body = json!({"sql": "INSERT INTO public.t (id, name) VALUES (50, 'l'); DELETE FROM public.t WHERE id = 50"});
    let (v, _) = script(&p, &h, "sam", &sid, body.clone());
    assert_eq!(v["data"]["action"], "sql_delete,sql_script", "{v}");
    h.action_tickets.lock().unwrap().push(("sql_delete,sql_script".into(), "both-1".into()));
    let mut with = body.clone();
    with["step_up_ticket"] = json!("both-1");
    let (v, pages) = script(&p, &h, "sam", &sid, with);
    assert_eq!(v["data"]["state"], "running", "{v}");
    assert_eq!(last(&pages)["state"], "done");

    // An export, and a grid delete.
    let (v, _, _) = export(&p, &h, "sam", &sid, json!({"sql": "SELECT id FROM public.t", "format": "csv"}));
    assert_eq!(v["data"]["action"], "sql_export", "{v}");
    h.action_tickets.lock().unwrap().push(("sql_export".into(), "export-2".into()));
    let (v, bytes, _) = export(
        &p,
        &h,
        "sam",
        &sid,
        json!({"sql": "SELECT id FROM public.t", "format": "csv", "step_up_ticket": "export-2"}),
    );
    assert_eq!(v["data"]["state"], "running", "{v}");
    assert!(String::from_utf8(bytes).unwrap().starts_with("\"id\"\r\n"));
    let edit = json!({"object": {"schema": "public", "name": "t"}, "op": "delete", "key": {"id": 1}});
    let (_, v, _) = call(&p, &h, "sam", "write", &format!("v2/sessions/{sid}/rows"), edit);
    assert_eq!(v["data"]["state"], "step_up_required", "{v}");
    assert_eq!(fx.pg.psql("app", "SELECT count(*) FROM public.t WHERE id = 1"), "1");
    h.assert_no_leak(b"");
}
