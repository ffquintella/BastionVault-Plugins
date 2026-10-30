//! Live tests against throwaway `mysql:8.4` and `mariadb:11.4` containers
//! (T127, Phase 6), behind the same gate as the PostgreSQL ones: ignored by
//! default, run by `make test-dbms`; without docker they print a skip and
//! pass unless `BV_TEST_REQUIRE_CONTAINER=1`.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{exec, last, open, rand, rows};
use crate::profile::tests::{profile_json, target_json};
use crate::profile::STATEMENT_CAPS;
use crate::testutil::{call, code, loopback_config, MockHost};
use crate::Plugin;

struct Server {
    name: String,
    port: u16,
    root_pw: String,
    client: &'static str,
    engine: &'static str,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ =
            Command::new("docker").args(["rm", "-f", &self.name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

impl Server {
    fn start(engine: &'static str) -> Option<Self> {
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
        let (image, pw_var, client) = match engine {
            "mysql" => ("mysql:8.4", "MYSQL_ROOT_PASSWORD", "mysql"),
            _ => ("mariadb:11.4", "MARIADB_ROOT_PASSWORD", "mariadb"),
        };
        let name = format!("bv-test-dbms-{engine}-{}-{}", std::process::id(), &rand()[..8]);
        let mut s = Server { name: name.clone(), port: 0, root_pw: rand(), client, engine };
        // The password reaches docker through the child's environment.
        let out = Command::new("docker")
            .args(["run", "-d", "--name", &name, "--label", "bv-test=dbms-management", "-p", "127.0.0.1::3306"])
            .args(["-e", pw_var, image])
            .env(pw_var, &s.root_pw)
            .output()
            .unwrap();
        assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
        let mapped = Command::new("docker").args(["port", &name, "3306/tcp"]).output().unwrap();
        let text = String::from_utf8_lossy(&mapped.stdout).to_string();
        s.port = text.lines().find_map(|l| l.trim().rsplit(':').next().and_then(|p| p.parse().ok())).unwrap();
        // The entrypoint initialises on a socket-only server first; TCP
        // answers once the real server is up.
        let t0 = Instant::now();
        while s.try_sql("SELECT 1").is_none() {
            assert!(t0.elapsed() < Duration::from_secs(180), "{engine} did not become ready");
            std::thread::sleep(Duration::from_millis(500));
        }
        Some(s)
    }

    fn try_sql(&self, sql: &str) -> Option<String> {
        let mut child = Command::new("docker")
            .args(["exec", "-i", "-e", "MYSQL_PWD", &self.name, self.client, "-uroot", "-h127.0.0.1", "-N", "-B"])
            .env("MYSQL_PWD", &self.root_pw)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(sql.as_bytes()).ok()?;
        let out = child.wait_with_output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Run SQL as root over TCP inside the container (SQL on stdin).
    fn sql(&self, sql: &str) -> String {
        self.try_sql(sql).unwrap_or_else(|| panic!("{} failed: {sql}", self.client))
    }

    fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

struct Fixture {
    srv: Server,
    ro_pw: String,
    rw_pw: String,
}

fn fixture(engine: &'static str) -> Option<Fixture> {
    let srv = Server::start(engine)?;
    let (ro_pw, rw_pw) = (rand(), rand());
    let fill = match engine {
        "mysql" => {
            "SET SESSION cte_max_recursion_depth = 5000;
             INSERT INTO app.seq WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < 2000) \
             SELECT n FROM g;"
        }
        // MariaDB's Sequence engine.
        _ => "INSERT INTO app.seq SELECT seq FROM app.seq_1_to_2000;",
    };
    srv.sql(&format!(
        "CREATE DATABASE app;
         CREATE TABLE app.t (id INT PRIMARY KEY, name VARCHAR(50) NOT NULL, amount DECIMAL(10,2), big BIGINT);
         INSERT INTO app.t VALUES (1, 'alpha', 10.50, 9007199254740993), (2, 'beta', NULL, NULL);
         CREATE TABLE app.canary (v VARCHAR(20)); INSERT INTO app.canary VALUES ('intact');
         CREATE TABLE app.seq (n INT PRIMARY KEY);
         {fill}
         CREATE VIEW app.v AS SELECT id, name FROM app.t;
         CREATE USER 'ro'@'%' IDENTIFIED BY '{ro_pw}';
         CREATE USER 'rw'@'%' IDENTIFIED BY '{rw_pw}';
         GRANT SELECT, SHOW VIEW ON app.* TO 'ro'@'%';
         GRANT SELECT, INSERT, UPDATE, DELETE ON app.* TO 'rw'@'%';"
    ));
    Some(Fixture { srv, ro_pw, rw_pw })
}

fn local(id: &str, ceiling: &[&str], srv: &Server, tls: &str) -> Value {
    let mut p = profile_json(id, ceiling);
    p["endpoint"] = json!(srv.endpoint());
    p["host"] = json!("127.0.0.1");
    p["port"] = json!(srv.port);
    p["tls"]["mode"] = json!(tls);
    p
}

impl Fixture {
    fn host(&self, privs: &[&str], tls: &str) -> std::sync::Arc<MockHost> {
        let profiles = vec![
            local("ro", &["sql_select"], &self.srv, tls),
            local("rw", &["sql_select", "sql_insert", "sql_update", "sql_delete"], &self.srv, tls),
            local("admin", &STATEMENT_CAPS, &self.srv, tls),
        ];
        let mut t = target_json("database-first", privs, profiles);
        t["target"]["engine"] = json!(self.srv.engine);
        let h = MockHost::new(t);
        let ep = self.srv.endpoint();
        let mut creds = h.creds.lock().unwrap();
        creds.insert("ro".into(), (ep.clone(), "ro".into(), self.ro_pw.clone()));
        creds.insert("rw".into(), (ep.clone(), "rw".into(), self.rw_pw.clone()));
        creds.insert("admin".into(), (ep, "root".into(), self.srv.root_pw.clone()));
        drop(creds);
        h.set_config(loopback_config());
        let held: Vec<String> = privs.iter().map(|s| s.to_string()).collect();
        h.allow(move |c| held.iter().any(|p| p == c.capability));
        h
    }

    fn canary(&self) -> String {
        self.srv.sql("SELECT v FROM app.canary")
    }
}

/// Start a run and cancel it once it is running; returns its final page.
fn start_and_cancel(p: &Plugin, h: &MockHost, sid: &str, sql: &str) -> Value {
    let (_, v, _) = call(p, h, "ana", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": sql}));
    let run = v["data"]["run_id"].as_str().unwrap_or_else(|| panic!("{v}")).to_string();
    std::thread::sleep(Duration::from_millis(500));
    let (_, busy, _) = call(p, h, "ana", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": "SELECT 1"}));
    assert_eq!(code(&busy), "session_busy");
    let t0 = Instant::now();
    call(p, h, "ana", "write", &format!("v2/sessions/{sid}/runs/{run}/cancel"), json!({}));
    loop {
        let (_, page, _) = call(p, h, "ana", "read", &format!("v2/sessions/{sid}/runs/{run}"), json!({}));
        if page["data"]["state"] != "running" {
            return page["data"].clone();
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "KILL QUERY took too long");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn live_engine(engine: &'static str) {
    let Some(fx) = fixture(engine) else { return };
    let p = Plugin::new();

    // ── a read-only caller: the read-only login, READ ONLY at the database
    let ana = fx.host(&["sql_select"], "require");
    let sid = open(&p, &ana, "ana");
    let (_, status, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}"), json!({}));
    let st = &status["data"];
    assert_eq!((st["engine"].as_str(), st["profile"].as_str()), (Some(engine), Some("ro")), "{st}");
    assert_eq!((st["read_only"].as_bool(), st["database_read_only"].as_bool()), (Some(true), Some(true)));
    assert_eq!(st["tls_mode"], "require");

    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT id, name, amount, big FROM t ORDER BY id");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    assert_eq!(rows(&pages), vec![json!([1, "alpha", "10.50", "9007199254740993"]), json!([2, "beta", null, null])]);
    let cols = &last(&pages)["columns"];
    assert_eq!(
        (cols[0]["kind"].as_str(), cols[2]["kind"].as_str(), cols[3]["kind"].as_str()),
        (Some("number"), Some("string"), Some("string"))
    );
    // The unqualified `t` is the current database's, in catalog `def`.
    let asked = ana.authorized.lock().unwrap().last().unwrap().clone();
    assert!(asked.contains(&crate::host::Check::object("sql_select", "def", "app", "t")), "{asked:?}");

    // A literal holding `;` runs through the prepared-statement protocol.
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT 'a;b' AS x, \"c\" AS y");
    assert_eq!(rows(&pages), vec![json!(["a;b", "c"])], "{pages:?}");

    // ── the vault refuses a write the caller does not hold: nothing runs
    let (v, _) = exec(&p, &ana, "ana", &sid, "UPDATE canary SET v = 'changed'");
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert_eq!(fx.canary(), "intact");

    // ── even if the vault allowed it, the read-only login refuses (§5.3)
    ana.allow(|_| true);
    let (_, pages) = exec(&p, &ana, "ana", &sid, "UPDATE canary SET v = 'changed'");
    assert_eq!(last(&pages)["messages"][0]["outcome"], "error", "{pages:?}");
    assert_eq!(fx.canary(), "intact");
    ana.allow(|c| c.capability == "sql_select");

    // ── smuggling and hazards never reach the server
    for (sql, expect) in [
        ("SELECT 1; DELETE FROM canary", "use_script"),
        ("SELECT 1 /*! , (SELECT 1 FROM canary) */", "unclassifiable"),
        ("SELECT 1 /*M! ; DELETE FROM canary */", "unclassifiable"),
        ("LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE canary", "refused_statement"),
        ("SELECT * FROM canary INTO OUTFILE '/tmp/x'", "refused_statement"),
        ("SELECT LOAD_FILE('/etc/passwd')", "refused_statement"),
        ("SET sql_mode = 'ANSI_QUOTES,NO_BACKSLASH_ESCAPES'", "refused_statement"),
        ("SET NAMES gbk", "refused_statement"),
        ("SET SESSION TRANSACTION READ WRITE", "refused_statement"),
        ("SET @@session.transaction_read_only = 0", "refused_statement"),
    ] {
        let (v, _) = exec(&p, &ana, "ana", &sid, sql);
        assert_eq!(code(&v), expect, "{sql}: {v}");
    }
    assert_eq!(fx.canary(), "intact");

    // ── paging, the grid cap (KILL QUERY stops the read)
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT n FROM seq ORDER BY n");
    assert_eq!(rows(&pages).len(), 2000);
    assert!(pages.iter().all(|p| p["rows"].as_array().unwrap().len() <= 500));
    let mut cfg = loopback_config();
    cfg["grid_rows"] = json!(1000);
    cfg["run_timeout_secs"] = json!(3);
    ana.set_config(cfg);
    let p2 = Plugin::new();
    let sid2 = open(&p2, &ana, "ana");
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT a.n FROM seq a, seq b");
    assert_eq!(rows(&pages).len(), 1000, "the grid cap stops the read");
    assert_eq!(last(&pages)["messages"][0]["truncated"], true);
    assert_eq!(last(&pages)["state"], "done");

    // ── the run deadline, then cancel (KILL QUERY on a side connection)
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT SUM(a.n * b.n - c.n) FROM seq a, seq b, seq c");
    assert_ne!(last(&pages)["state"], "done", "{pages:?}");
    let page = start_and_cancel(&p, &ana, &sid, "SELECT SUM(a.n * b.n - c.n) FROM seq a, seq b, seq c");
    assert_eq!(page["state"], "cancelled", "{page}");
    // The session is usable after a KILL QUERY.
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT COUNT(*) FROM t");
    // COUNT(*) is BIGINT: a decimal string, as every 64-bit integer (§6.3).
    assert_eq!(rows(&pages), vec![json!(["2"])]);

    // ── browser, describe, probe
    let (_, v, _) = call(&p, &ana, "ana", "list", &format!("v2/sessions/{sid}/objects"), json!({}));
    assert!(v["data"]["keys"].as_array().unwrap().contains(&json!("app")), "{v}");
    let (_, v, _) = call(&p, &ana, "ana", "list", &format!("v2/sessions/{sid}/objects/app"), json!({}));
    let names: Vec<&str> = v["data"]["objects"].as_array().unwrap().iter().filter_map(|o| o["name"].as_str()).collect();
    assert!(names.contains(&"t") && names.contains(&"v"), "{v}");
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/objects/app/t"), json!({}));
    assert_eq!(v["data"]["edit"]["key"], json!(["id"]), "{v}");
    assert_eq!(v["data"]["edit"]["editable"], true);
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/ceiling"), json!({}));
    assert!(v["data"]["probed"].as_array().unwrap().contains(&json!("sql_select")), "{v}");
    assert_eq!(v["data"]["undeclared"], json!([]), "{v}");

    // ── a read/write caller: transactions, grid edits, rollback on close
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "require");
    let sid3 = open(&p, &rw, "carol");
    let (_, st, _) = call(&p, &rw, "carol", "read", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!((st["data"]["profile"].as_str(), st["data"]["read_only"].as_bool()), (Some("rw"), Some(false)));
    let (_, pages) = exec(&p, &rw, "carol", &sid3, "BEGIN; INSERT INTO t (id, name) VALUES (10, 'tx')");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    let (_, st, _) = call(&p, &rw, "carol", "read", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(st["data"]["transaction"]["open"], true);
    let edit = json!({"object": {"schema": "app", "name": "t"}, "op": "update", "key": {"id": 2},
        "values": {"name": "gamma"}, "original": {"name": "beta"}});
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid3}/rows"), edit.clone());
    assert_eq!(v["data"]["state"], "done", "{v}");
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid3}/rows"), edit);
    assert_eq!(v["data"]["state"], "conflict", "the original no longer matches: {v}");
    call(&p, &rw, "carol", "delete", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(fx.srv.sql("SELECT COUNT(*) FROM app.t WHERE id = 10 OR name = 'gamma'"), "0", "rolled back on close");
    let sid4 = open(&p, &rw, "carol");
    let edit = json!({"object": {"schema": "app", "name": "t"}, "op": "update", "key": {"id": 2},
        "values": {"name": "delta"}, "original": {"name": "beta"}});
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid4}/rows"), edit);
    assert_eq!(v["data"]["state"], "done", "{v}");
    assert_eq!(fx.srv.sql("SELECT name FROM app.t WHERE id = 2"), "delta", "committed outside a transaction");

    // ── a script in one transaction: the second INSERT fails, both roll back
    let sc = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete", "sql_script"], "require");
    let sid5 = open(&p, &sc, "dave");
    let body = json!({"sql": "INSERT INTO t (id, name) VALUES (20, 's1'); INSERT INTO t (id, name) VALUES (20, 'dup')",
        "transaction": "single"});
    let (v, pages) = super::script(&p, &sc, "dave", &sid5, body);
    assert!(v["data"]["warnings"][0].as_str().unwrap_or("").contains("commits DDL implicitly"), "{v}");
    assert_eq!(last(&pages)["script"]["tx_outcome"], "rolled_back", "{pages:?}");
    assert_eq!(fx.srv.sql("SELECT COUNT(*) FROM app.t WHERE id = 20"), "0");

    // ── exports: CSV streams; sql-insert is PostgreSQL-only in this version
    let ex = fx.host(&["sql_select", "sql_export"], "require");
    let sid6 = open(&p, &ex, "erin");
    let (v, bytes, _) =
        super::export(&p, &ex, "erin", &sid6, json!({"sql": "SELECT id, name FROM t ORDER BY id", "format": "csv"}));
    assert_eq!(v["data"]["state"], "running", "{v}");
    assert_eq!(String::from_utf8(bytes).unwrap(), "\"id\",\"name\"\r\n1,\"alpha\"\r\n2,\"delta\"\r\n");
    let (v, _, _) = super::export(
        &p,
        &ex,
        "erin",
        &sid6,
        json!({"sql": "SELECT id FROM t", "format": "sql-insert",
        "table": {"name": "t"}}),
    );
    assert_eq!(code(&v), "unsupported", "{v}");

    // ── verify-full against the server's self-signed certificate: refused,
    // nothing falls back to a weaker mode
    let strict = fx.host(&["sql_select"], "verify-full");
    let (st, v, _) = call(&p, &strict, "ana", "write", "v2/sessions", json!({"resource": "db"}));
    assert_ne!(st, 0, "{v}");
    assert!(matches!(code(&v).as_str(), "connect_failed" | "tls_config"), "{v}");

    // ── seal closes every session
    p.lifecycle(bastion_plugin_sdk::process::Lifecycle::Seal);
    assert!(p.registry().is_empty());
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_mysql_sessions_runs_and_enforcement() {
    live_engine("mysql");
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_mariadb_sessions_runs_and_enforcement() {
    live_engine("mariadb");
}
