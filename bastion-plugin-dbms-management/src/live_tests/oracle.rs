//! Live tests against a throwaway `gvenzl/oracle-free:23-full` container
//! (T129, Phase 8), behind the same gate as the others: ignored by default,
//! run by `make test-dbms`; without docker they print a skip and pass unless
//! `BV_TEST_REQUIRE_CONTAINER=1`. The `full` image is used because it ships
//! `orapki` and a JDK: the listener is given a TCPS endpoint with a wallet
//! made here (a test CA and a `localhost` certificate), since Oracle
//! sessions are TCPS only.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{exec, last, open, rand, rows};
use crate::profile::tests::{profile_json, target_json};
use crate::profile::STATEMENT_CAPS;
use crate::testutil::{call, code, loopback_config, MockHost};
use crate::Plugin;

const IMAGE: &str = "gvenzl/oracle-free:23-full";

/// Run inside the container as `oracle`: a CA and a server certificate with
/// keytool, an auto-login wallet with orapki, a TCPS listener on 2484.
/// Prints the CA certificate.
const TCPS_SETUP: &str = r#"set -euo pipefail
K="$ORACLE_HOME/jdk/bin/keytool"; W=/opt/oracle/bvwallet; T=/tmp/bvtls
rm -rf "$T" "$W"; mkdir -p "$T"; cd "$T"
SP=bvstore$RANDOM$RANDOM; WP=Bvwallet1$RANDOM$RANDOM
q() { "$@" >/dev/null 2>&1; }
q $K -genkeypair -alias ca -keyalg RSA -keysize 2048 -dname CN=bv-test-ca -ext bc:c=ca:true -validity 30 -keystore ca.p12 -storetype PKCS12 -storepass "$SP" -keypass "$SP"
q $K -exportcert -rfc -alias ca -keystore ca.p12 -storepass "$SP" -file ca.pem
q $K -genkeypair -alias server -keyalg RSA -keysize 2048 -dname CN=localhost -validity 30 -keystore server.p12 -storetype PKCS12 -storepass "$SP" -keypass "$SP"
q $K -certreq -alias server -keystore server.p12 -storepass "$SP" -file server.csr
q $K -gencert -alias ca -keystore ca.p12 -storepass "$SP" -infile server.csr -outfile server.pem -rfc -ext san=dns:localhost,ip:127.0.0.1 -ext ku=digitalSignature,keyEncipherment -ext eku=serverAuth -validity 30
q $K -importcert -alias ca -file ca.pem -keystore server.p12 -storepass "$SP" -noprompt
q $K -importcert -alias server -file server.pem -keystore server.p12 -storepass "$SP" -noprompt
q orapki wallet create -wallet "$W" -auto_login -pwd "$WP"
q orapki wallet import_pkcs12 -wallet "$W" -pwd "$WP" -pkcs12file server.p12 -pkcs12pwd "$SP"
NA="$ORACLE_HOME/network/admin"
printf 'WALLET_LOCATION = (SOURCE = (METHOD = FILE)(METHOD_DATA = (DIRECTORY = %s)))\nSSL_CLIENT_AUTHENTICATION = FALSE\n' "$W" >> "$NA/sqlnet.ora"
cat > "$NA/listener.ora" <<EOF
LISTENER = (DESCRIPTION_LIST =
  (DESCRIPTION = (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC_FOR_FREE)))
  (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = 0.0.0.0)(PORT = 1521)))
  (DESCRIPTION = (ADDRESS = (PROTOCOL = TCPS)(HOST = 0.0.0.0)(PORT = 2484))))
WALLET_LOCATION = (SOURCE = (METHOD = FILE)(METHOD_DATA = (DIRECTORY = $W)))
SSL_CLIENT_AUTHENTICATION = FALSE
DEFAULT_SERVICE_LISTENER = FREE
EOF
q lsnrctl stop || true
q lsnrctl start
echo "ALTER SYSTEM REGISTER;" | sqlplus -s / as sysdba >/dev/null
rm -f server.p12 ca.p12 server.csr
cat ca.pem
"#;

struct Server {
    name: String,
    port: u16,
    ca_pem: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ =
            Command::new("docker").args(["rm", "-f", &self.name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// Feed `input` to a docker command; its stdout, or its output as the error.
fn docker_stdin(args: &[&str], input: &str) -> Result<String, String> {
    let mut child = Command::new("docker")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child.stdin.take().ok_or("no stdin")?.write_all(input.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr)))
    }
}

impl Server {
    fn start() -> Option<Self> {
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
        let name = format!("bv-test-dbms-oracle-{}-{}", std::process::id(), &rand()[..8]);
        // SYS and SYSTEM are never used: the fixture works as SYSDBA through
        // the container's OS authentication.
        let unused_pw = format!("Oa1{}", rand());
        let out = Command::new("docker")
            .args(["run", "-d", "--name", &name, "--label", "bv-test=dbms-management"])
            .args(["-p", "127.0.0.1::2484", "-e", "ORACLE_PASSWORD", IMAGE])
            .env("ORACLE_PASSWORD", &unused_pw)
            .output()
            .unwrap();
        assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
        let t0 = Instant::now();
        loop {
            let logs = Command::new("docker").args(["logs", &name]).output().unwrap();
            if String::from_utf8_lossy(&logs.stdout).contains("DATABASE IS READY TO USE") {
                break;
            }
            assert!(t0.elapsed() < Duration::from_secs(600), "Oracle did not become ready");
            std::thread::sleep(Duration::from_secs(2));
        }
        let ca_pem = docker_stdin(&["exec", "-i", &name, "bash", "-s"], TCPS_SETUP)
            .unwrap_or_else(|e| panic!("TCPS setup failed: {e}"));
        let mapped = Command::new("docker").args(["port", &name, "2484/tcp"]).output().unwrap();
        let text = String::from_utf8_lossy(&mapped.stdout).to_string();
        let port = text.lines().find_map(|l| l.trim().rsplit(':').next().and_then(|p| p.parse().ok())).unwrap();
        let s = Server { name, port, ca_pem };
        // The service registers with the restarted listener within a minute.
        let t0 = Instant::now();
        while !Command::new("docker")
            .args(["exec", &s.name, "lsnrctl", "status"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("Service \"freepdb1\""))
            .unwrap_or(false)
        {
            assert!(t0.elapsed() < Duration::from_secs(120), "FREEPDB1 did not register with the listener");
            std::thread::sleep(Duration::from_secs(2));
        }
        Some(s)
    }

    /// Run SQL as SYSDBA in FREEPDB1 (OS authentication; no password).
    /// SQL*Plus wants one statement per line.
    fn try_sql(&self, sql: &str) -> Result<String, String> {
        let script = format!(
            "WHENEVER SQLERROR EXIT FAILURE\nSET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 32767 TRIMOUT ON\n\
             ALTER SESSION SET CONTAINER = FREEPDB1;\n{sql}\nEXIT\n"
        );
        docker_stdin(&["exec", "-i", &self.name, "sqlplus", "-s", "/", "as", "sysdba"], &script)
    }

    fn sql(&self, sql: &str) -> String {
        self.try_sql(sql).unwrap_or_else(|e| panic!("sqlplus failed: {e}"))
    }

    fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

struct Fixture {
    srv: Server,
    ro_pw: String,
    rw_pw: String,
    app_pw: String,
}

fn fixture() -> Option<Fixture> {
    let srv = Server::start()?;
    let (ro_pw, rw_pw, app_pw) = (format!("Oa1{}", rand()), format!("Oa1{}", rand()), format!("Oa1{}", rand()));
    srv.sql(&format!(
        "CREATE USER app IDENTIFIED BY \"{app_pw}\" QUOTA UNLIMITED ON users;
         GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE SEQUENCE, CREATE PROCEDURE TO app;
         CREATE TABLE app.t (id NUMBER(10) PRIMARY KEY, name VARCHAR2(50) NOT NULL, amount NUMBER(10,2), big NUMBER(19));
         INSERT INTO app.t VALUES (1, 'alpha', 10.50, 9007199254740993);
         INSERT INTO app.t VALUES (2, 'beta', NULL, NULL);
         CREATE TABLE app.canary (v VARCHAR2(20));
         INSERT INTO app.canary VALUES ('intact');
         CREATE TABLE app.seq (n NUMBER(10) PRIMARY KEY);
         INSERT INTO app.seq SELECT LEVEL FROM dual CONNECT BY LEVEL <= 2000;
         CREATE VIEW app.v AS SELECT id, name FROM app.t;
         COMMIT;
         CREATE USER ro IDENTIFIED BY \"{ro_pw}\";
         CREATE USER rw IDENTIFIED BY \"{rw_pw}\";
         GRANT CREATE SESSION TO ro, rw;
         GRANT SELECT ON app.t TO ro;
         GRANT SELECT ON app.canary TO ro;
         GRANT SELECT ON app.seq TO ro;
         GRANT SELECT ON app.v TO ro;
         GRANT SELECT, INSERT, UPDATE, DELETE ON app.t TO rw;
         GRANT SELECT, INSERT, UPDATE, DELETE ON app.canary TO rw;"
    ));
    // A read-only transaction refuses a table whose DDL is newer than its
    // snapshot can resolve (ORA-01466); let the fixture's DDL age first.
    std::thread::sleep(Duration::from_secs(8));
    Some(Fixture { srv, ro_pw, rw_pw, app_pw })
}

fn local(id: &str, ceiling: &[&str], srv: &Server, tls: &str) -> Value {
    let mut p = profile_json(id, ceiling);
    p["endpoint"] = json!(srv.endpoint());
    p["host"] = json!("127.0.0.1");
    p["port"] = json!(srv.port);
    p["catalog"] = json!("freepdb1");
    p["tls"]["mode"] = json!(tls);
    p
}

impl Fixture {
    fn host_with(&self, privs: &[&str], profiles: Vec<Value>) -> std::sync::Arc<MockHost> {
        let mut t = target_json("database-first", privs, profiles);
        t["target"]["engine"] = json!("oracle");
        let h = MockHost::new(t);
        let ep = self.srv.endpoint();
        let mut creds = h.creds.lock().unwrap();
        creds.insert("ro".into(), (ep.clone(), "ro".into(), self.ro_pw.clone()));
        creds.insert("rw".into(), (ep.clone(), "rw".into(), self.rw_pw.clone()));
        creds.insert("admin".into(), (ep, "app".into(), self.app_pw.clone()));
        drop(creds);
        h.set_config(loopback_config());
        let held: Vec<String> = privs.iter().map(|s| s.to_string()).collect();
        h.allow(move |c| held.iter().any(|p| p == c.capability));
        h
    }

    fn host(&self, privs: &[&str], tls: &str) -> std::sync::Arc<MockHost> {
        let profiles = vec![
            local("ro", &["sql_select"], &self.srv, tls),
            local("rw", &["sql_select", "sql_insert", "sql_update", "sql_delete"], &self.srv, tls),
            local("admin", &STATEMENT_CAPS, &self.srv, tls),
        ];
        self.host_with(privs, profiles)
    }

    fn canary(&self) -> String {
        self.srv.sql("SELECT v FROM app.canary;")
    }
}

/// Start a run and cancel it once it is running; returns its final page.
fn start_and_cancel(p: &Plugin, h: &MockHost, who: &str, sid: &str, sql: &str) -> Value {
    let (_, v, _) = call(p, h, who, "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": sql}));
    let run = v["data"]["run_id"].as_str().unwrap_or_else(|| panic!("{v}")).to_string();
    std::thread::sleep(Duration::from_millis(1500));
    let t0 = Instant::now();
    call(p, h, who, "write", &format!("v2/sessions/{sid}/runs/{run}/cancel"), json!({}));
    loop {
        let (_, page, _) = call(p, h, who, "read", &format!("v2/sessions/{sid}/runs/{run}"), json!({}));
        if page["data"]["state"] != "running" {
            return page["data"].clone();
        }
        assert!(t0.elapsed() < Duration::from_secs(15), "the break took too long");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A query that runs for minutes unless broken.
const LONG_QUERY: &str = "SELECT COUNT(*) FROM app.seq a, app.seq b, app.seq c";

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_oracle_sessions_runs_and_enforcement() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();

    // ── a read-only caller: the read-only login, the read-only guard
    let ana = fx.host(&["sql_select"], "require");
    let sid = open(&p, &ana, "ana");
    let (_, status, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}"), json!({}));
    let st = &status["data"];
    assert_eq!((st["engine"].as_str(), st["profile"].as_str()), (Some("oracle"), Some("ro")), "{st}");
    assert_eq!((st["read_only"].as_bool(), st["database_read_only"].as_bool()), (Some(true), Some(false)));
    assert_eq!(st["residuals"].as_array().map(Vec::len), Some(3), "{st}");

    // The current schema moves unqualified names; the plugin re-reads it.
    let (_, pages) = exec(&p, &ana, "ana", &sid, "ALTER SESSION SET CURRENT_SCHEMA = APP");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT id, name, amount, big FROM t ORDER BY id");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    assert_eq!(rows(&pages), vec![json!([1, "alpha", "10.5", "9007199254740993"]), json!([2, "beta", null, null])]);
    let asked = ana.authorized.lock().unwrap().last().unwrap().clone();
    assert!(asked.contains(&crate::host::Check::object("sql_select", "FREEPDB1", "APP", "T")), "{asked:?}");
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT q'[a;b]' AS x, 'c''d' AS y FROM dual");
    assert_eq!(rows(&pages), vec![json!(["a;b", "c'd"])], "{pages:?}");
    // The guard's transaction ends with the statement.
    let (_, st, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}"), json!({}));
    assert_eq!(st["data"]["transaction"]["open"], false, "{st}");

    // ── the vault refuses a write the caller does not hold: nothing runs
    let (v, _) = exec(&p, &ana, "ana", &sid, "UPDATE canary SET v = 'changed'");
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert_eq!(fx.canary(), "intact");

    // ── even if the vault allowed it, the read-only login (and the
    // read-only transaction) refuse it
    ana.allow(|_| true);
    let (_, pages) = exec(&p, &ana, "ana", &sid, "UPDATE canary SET v = 'changed'");
    assert_eq!(last(&pages)["messages"][0]["outcome"], "error", "{pages:?}");
    assert_eq!(fx.canary(), "intact");
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SET TRANSACTION READ ONLY");
    assert_eq!(last(&pages)["messages"][0]["outcome"], "error", "manual transactions are refused: {pages:?}");
    ana.allow(|c| c.capability == "sql_select");

    // ── smuggling and hazards never reach the server
    for (sql, expect) in [
        ("SELECT 1 FROM dual; DELETE FROM canary", "use_script"),
        ("SELECT * FROM canary\n/\nDELETE FROM canary", "use_script"),
        ("BEGIN UTL_FILE.FREMOVE('DATA_PUMP_DIR', 'x'); END;", "refused_statement"),
        ("SELECT UTL_HTTP.REQUEST('http://127.0.0.1/') FROM dual", "refused_statement"),
        ("SELECT * FROM canary@elsewhere", "refused_statement"),
        ("ALTER SESSION SET CONTAINER = CDB$ROOT", "refused_statement"),
        ("SET TRANSACTION READ WRITE", "refused_statement"),
        ("HOST rm -rf /", "unclassifiable"),
    ] {
        let (v, _) = exec(&p, &ana, "ana", &sid, sql);
        assert_eq!(code(&v), expect, "{sql}: {v}");
    }
    assert_eq!(fx.canary(), "intact");

    // ── paging and the grid cap
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT n FROM seq ORDER BY n");
    assert_eq!(rows(&pages).len(), 2000);
    assert!(pages.iter().all(|p| p["rows"].as_array().unwrap().len() <= 500));
    let mut cfg = loopback_config();
    cfg["grid_rows"] = json!(1000);
    cfg["run_timeout_secs"] = json!(3);
    ana.set_config(cfg);
    let p2 = Plugin::new();
    let sid2 = open(&p2, &ana, "ana");
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT a.n FROM app.seq a CROSS JOIN app.seq b");
    assert_eq!(rows(&pages).len(), 1000, "the grid cap stops the fetch");
    assert_eq!(last(&pages)["messages"][0]["truncated"], true);
    assert_eq!(last(&pages)["state"], "done");
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT COUNT(*) FROM app.t");
    assert_eq!(rows(&pages), vec![json!(["2"])], "an unconstrained NUMBER is a decimal string: {pages:?}");

    // ── the run deadline, then cancel by an in-band BREAK over TCPS
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, LONG_QUERY);
    assert_ne!(last(&pages)["state"], "done", "{pages:?}");
    let page = start_and_cancel(&p, &ana, "ana", &sid, LONG_QUERY);
    assert_eq!(page["state"], "cancelled", "{page}");
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT COUNT(*) FROM t");
    assert_eq!(rows(&pages), vec![json!(["2"])], "the session is in step after the break: {pages:?}");

    // ── browser, describe, probe
    let (_, v, _) = call(&p, &ana, "ana", "list", &format!("v2/sessions/{sid}/objects"), json!({}));
    assert!(v["data"]["keys"].as_array().unwrap().contains(&json!("APP")), "{v}");
    let (_, v, _) = call(&p, &ana, "ana", "list", &format!("v2/sessions/{sid}/objects/APP"), json!({}));
    let names: Vec<&str> = v["data"]["objects"].as_array().unwrap().iter().filter_map(|o| o["name"].as_str()).collect();
    assert!(names.contains(&"T") && names.contains(&"V"), "{v}");
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/objects/APP/T"), json!({}));
    assert_eq!(v["data"]["edit"]["key"], json!(["ID"]), "{v}");
    assert_eq!(v["data"]["edit"]["editable"], true);
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/objects/APP/V"), json!({}));
    assert!(v["data"]["definition"].as_str().unwrap_or("").contains("SELECT"), "{v}");
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/ceiling"), json!({}));
    assert!(v["data"]["probed"].as_array().unwrap().contains(&json!("sql_select")), "{v}");
    assert_eq!(v["data"]["undeclared"], json!([]), "{v}");

    // ── a read/write caller: transactions, grid edits, rollback on close
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "require");
    let sid3 = open(&p, &rw, "carol");
    let (_, pages) = exec(
        &p,
        &rw,
        "carol",
        &sid3,
        "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; INSERT INTO app.t (id, name) VALUES (10, 'tx')",
    );
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    assert_eq!(last(&pages)["messages"][1]["rows_affected"], 1, "{pages:?}");
    let (_, st, _) = call(&p, &rw, "carol", "read", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(st["data"]["transaction"]["open"], true);
    let edit = json!({"object": {"schema": "APP", "name": "T"}, "op": "update", "key": {"ID": 2},
        "values": {"NAME": "gamma"}, "original": {"NAME": "beta"}});
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid3}/rows"), edit.clone());
    assert_eq!(v["data"]["state"], "done", "{v}");
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid3}/rows"), edit);
    assert_eq!(v["data"]["state"], "conflict", "the original no longer matches: {v}");
    call(&p, &rw, "carol", "delete", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(fx.srv.sql("SELECT COUNT(*) FROM app.t WHERE id = 10 OR name = 'gamma';"), "0", "rolled back");
    // Outside a transaction a statement is committed by the plugin.
    let sid4 = open(&p, &rw, "carol");
    let (_, pages) = exec(&p, &rw, "carol", &sid4, "UPDATE app.t SET amount = 7 WHERE id = 2");
    assert_eq!(last(&pages)["messages"][0]["rows_affected"], 1, "{pages:?}");
    assert_eq!(fx.srv.sql("SELECT amount FROM app.t WHERE id = 2;"), "7", "auto-commit emulation");
    let edit = json!({"object": {"schema": "APP", "name": "T"}, "op": "update", "key": {"ID": 2},
        "values": {"NAME": "delta", "AMOUNT": null}, "original": {"NAME": "beta", "AMOUNT": "7"}});
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid4}/rows"), edit);
    assert_eq!(v["data"]["state"], "done", "{v}");
    assert_eq!(fx.srv.sql("SELECT name FROM app.t WHERE id = 2;"), "delta", "committed outside a transaction");
    let edit = json!({"object": {"schema": "APP", "name": "T"}, "op": "update", "key": {"ID": 2},
        "values": {"NAME": "eps"}, "original": {"NAME": "delta", "AMOUNT": null}});
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid4}/rows"), edit);
    assert_eq!(v["data"]["state"], "done", "a NULL original matches NULL: {v}");

    // ── a script in one transaction: the second INSERT fails, both roll back
    let sc = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete", "sql_script"], "require");
    let sid5 = open(&p, &sc, "dave");
    let body = json!({"sql": "INSERT INTO app.t (id, name) VALUES (20, 's1'); INSERT INTO app.t (id, name) VALUES (20, 'dup')",
        "transaction": "single"});
    let (v, pages) = super::script(&p, &sc, "dave", &sid5, body);
    assert_eq!(v["data"]["warnings"].as_array().map(Vec::len), Some(1), "Oracle commits DDL implicitly: {v}");
    assert_eq!(last(&pages)["script"]["tx_outcome"], "rolled_back", "{pages:?}");
    assert_eq!(fx.srv.sql("SELECT COUNT(*) FROM app.t WHERE id = 20;"), "0");

    // ── PL/SQL: a block is one opaque statement, sent with its `END;`, and
    // a BREAK stops it like a query
    let ad = fx.host(&STATEMENT_CAPS, "require");
    let sid8 = open(&p, &ad, "frank");
    let (_, pages) = exec(&p, &ad, "frank", &sid8, "BEGIN\n  UPDATE app.canary SET v = v WHERE 1 = 0;\nEND;");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    // In-band, the server notices a BREAK when it polls for one: a busy
    // block is stopped; a sleep or lock wait only when its wait ends.
    let busy = "DECLARE n NUMBER := 0; BEGIN FOR i IN 1 .. 2000000000 LOOP n := n + 1; END LOOP; END;";
    let page = start_and_cancel(&p, &ad, "frank", &sid8, busy);
    assert_eq!(page["state"], "cancelled", "{page}");
    let (_, pages) = exec(&p, &ad, "frank", &sid8, "SELECT v FROM app.canary");
    assert_eq!(rows(&pages), vec![json!(["intact"])], "{pages:?}");

    // ── exports: CSV streams; sql-insert is PostgreSQL-only in this version
    let ex = fx.host(&["sql_select", "sql_export"], "require");
    let sid6 = open(&p, &ex, "erin");
    let (v, bytes, _) = super::export(
        &p,
        &ex,
        "erin",
        &sid6,
        json!({"sql": "SELECT id, name FROM app.t ORDER BY id", "format": "csv"}),
    );
    assert_eq!(v["data"]["state"], "running", "{v}");
    assert_eq!(String::from_utf8(bytes).unwrap(), "\"ID\",\"NAME\"\r\n1,\"alpha\"\r\n2,\"eps\"\r\n");
    let (v, _, _) = super::export(
        &p,
        &ex,
        "erin",
        &sid6,
        json!({"sql": "SELECT id FROM app.t", "format": "sql-insert", "table": {"name": "t"}}),
    );
    assert_eq!(code(&v), "unsupported", "{v}");

    // ── verify-full: the profile's CA and name succeed; the OS store and
    // a plaintext profile are refused before the login is sent
    let mut good = local("ro", &["sql_select"], &fx.srv, "verify-full");
    good["tls"]["ca_pem"] = json!(fx.srv.ca_pem);
    good["tls"]["server_name"] = json!("localhost");
    let full = fx.host_with(&["sql_select"], vec![good.clone()]);
    let sid7 = open(&p, &full, "ana");
    let (_, st, _) = call(&p, &full, "ana", "read", &format!("v2/sessions/{sid7}"), json!({}));
    assert_eq!(st["data"]["tls_mode"], "verify-full");
    let strict = fx.host(&["sql_select"], "verify-full");
    let (s, v, _) = call(&p, &strict, "ana", "write", "v2/sessions", json!({"resource": "db"}));
    assert_ne!(s, 0, "{v}");
    assert!(matches!(code(&v).as_str(), "tls_failed" | "tls_config"), "{v}");
    let plain = fx.host(&["sql_select"], "disable");
    let (s, v, _) = call(&p, &plain, "ana", "write", "v2/sessions", json!({"resource": "db"}));
    assert_ne!(s, 0, "{v}");
    assert_eq!(code(&v), "tls_required", "{v}");
    let mut wrong = good;
    wrong["catalog"] = json!("NOSUCHSERVICE");
    let svc = fx.host_with(&["sql_select"], vec![wrong]);
    let (s, v, _) = call(&p, &svc, "ana", "write", "v2/sessions", json!({"resource": "db"}));
    assert_ne!(s, 0, "{v}");
    assert_eq!(code(&v), "connect_failed", "an unknown service is refused by the listener: {v}");

    // ── seal closes every session
    p.lifecycle(bastion_plugin_sdk::process::Lifecycle::Seal);
    assert!(p.registry().is_empty());
}
