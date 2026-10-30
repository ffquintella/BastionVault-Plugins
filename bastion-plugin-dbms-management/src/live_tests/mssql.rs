//! Live tests against a throwaway `mcr.microsoft.com/mssql/server:2022-latest`
//! container (T128, Phase 7), behind the same gate as the others: ignored by
//! default, run by `make test-dbms`; without docker they print a skip and
//! pass unless `BV_TEST_REQUIRE_CONTAINER=1`. The image is linux/amd64.

// The server is given a certificate made here: the one SQL Server generates
// for itself is X.509 v1, which webpki cannot parse, so even `require` is
// refused against it (the handshake signature is always verified).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{exec, last, open, rand, rows};
use crate::profile::tests::{profile_json, target_json};
use crate::profile::STATEMENT_CAPS;
use crate::testutil::{call, code, loopback_config, MockHost};
use crate::Plugin;

const IMAGE: &str = "mcr.microsoft.com/mssql/server:2022-latest";
const SQLCMD: &str = "/opt/mssql-tools18/bin/sqlcmd";

struct Server {
    name: String,
    port: u16,
    sa_pw: String,
    cert_pem: String,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ =
            Command::new("docker").args(["rm", "-f", &self.name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(&self.dir);
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
        // A v3 certificate for `localhost`, mounted with an mssql.conf.
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!("bv-test-mssql-{}", &rand()[..12]));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), signing_key.serialize_pem()).unwrap();
        std::fs::write(
            dir.join("mssql.conf"),
            "[network]\ntlscert = /etc/bvtls/cert.pem\ntlskey = /etc/bvtls/key.pem\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["cert.pem", "key.pem", "mssql.conf"] {
                std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        let name = format!("bv-test-dbms-mssql-{}-{}", std::process::id(), &rand()[..8]);
        // Complexity rules: upper, lower, digit and symbol.
        let sa_pw = format!("Aa1!{}", rand());
        let mount = |f: &str, to: &str| format!("{}:{to}:ro", dir.join(f).display());
        let out = Command::new("docker")
            .args(["run", "-d", "--platform", "linux/amd64", "--name", &name, "--label", "bv-test=dbms-management"])
            .args(["-p", "127.0.0.1::1433", "-e", "ACCEPT_EULA=Y", "-e", "MSSQL_SA_PASSWORD"])
            .args(["-v", &mount("cert.pem", "/etc/bvtls/cert.pem"), "-v", &mount("key.pem", "/etc/bvtls/key.pem")])
            .args(["-v", &mount("mssql.conf", "/var/opt/mssql/mssql.conf"), IMAGE])
            .env("MSSQL_SA_PASSWORD", &sa_pw)
            .output()
            .unwrap();
        assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
        let mapped = Command::new("docker").args(["port", &name, "1433/tcp"]).output().unwrap();
        let text = String::from_utf8_lossy(&mapped.stdout).to_string();
        let port = text.lines().find_map(|l| l.trim().rsplit(':').next().and_then(|p| p.parse().ok())).unwrap();
        let s = Server { name, port, sa_pw, cert_pem: cert.pem(), dir };
        let t0 = Instant::now();
        while s.try_sql("SELECT 1").is_none() {
            assert!(t0.elapsed() < Duration::from_secs(240), "SQL Server did not become ready");
            std::thread::sleep(Duration::from_secs(1));
        }
        Some(s)
    }

    /// Run T-SQL as `sa` inside the container; the password travels in
    /// sqlcmd's environment, never on a command line.
    fn try_sql(&self, sql: &str) -> Option<String> {
        let out = Command::new("docker")
            .args(["exec", "-e", "SQLCMDPASSWORD", &self.name, SQLCMD, "-C", "-S", "localhost", "-U", "sa"])
            .args(["-b", "-h", "-1", "-W", "-Q", &format!("SET NOCOUNT ON; {sql}")])
            .env("SQLCMDPASSWORD", &self.sa_pw)
            .output()
            .ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn sql(&self, sql: &str) -> String {
        self.try_sql(sql).unwrap_or_else(|| panic!("sqlcmd failed: {sql}"))
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

fn fixture() -> Option<Fixture> {
    let srv = Server::start()?;
    let (ro_pw, rw_pw) = (format!("Aa1!{}", rand()), format!("Aa1!{}", rand()));
    srv.sql("CREATE DATABASE app");
    srv.sql(&format!(
        "USE app;
         CREATE TABLE dbo.t (id int PRIMARY KEY, name nvarchar(50) NOT NULL, amount decimal(10,2), big bigint);
         INSERT INTO dbo.t VALUES (1, N'alpha', 10.50, 9007199254740993), (2, N'beta', NULL, NULL);
         CREATE TABLE dbo.canary (v nvarchar(20)); INSERT INTO dbo.canary VALUES (N'intact');
         CREATE TABLE dbo.seq (n int PRIMARY KEY);
         WITH g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < 2000) INSERT INTO dbo.seq SELECT n FROM g
           OPTION (MAXRECURSION 2000);
         EXEC (N'CREATE VIEW dbo.v AS SELECT id, name FROM dbo.t');
         CREATE LOGIN ro WITH PASSWORD = '{ro_pw}', CHECK_POLICY = OFF, DEFAULT_DATABASE = app;
         CREATE LOGIN rw WITH PASSWORD = '{rw_pw}', CHECK_POLICY = OFF, DEFAULT_DATABASE = app;
         CREATE USER ro FOR LOGIN ro; CREATE USER rw FOR LOGIN rw;
         ALTER ROLE db_datareader ADD MEMBER ro;
         GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::dbo TO rw;"
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
    fn host_with(&self, privs: &[&str], profiles: Vec<Value>) -> std::sync::Arc<MockHost> {
        let mut t = target_json("database-first", privs, profiles);
        t["target"]["engine"] = json!("mssql");
        let h = MockHost::new(t);
        let ep = self.srv.endpoint();
        let mut creds = h.creds.lock().unwrap();
        creds.insert("ro".into(), (ep.clone(), "ro".into(), self.ro_pw.clone()));
        creds.insert("rw".into(), (ep.clone(), "rw".into(), self.rw_pw.clone()));
        creds.insert("admin".into(), (ep, "sa".into(), self.srv.sa_pw.clone()));
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
        self.srv.sql("SELECT v FROM app.dbo.canary")
    }
}

/// Start a run and cancel it once it is running; returns its final page.
fn start_and_cancel(p: &Plugin, h: &MockHost, sid: &str, sql: &str) -> Value {
    let (_, v, _) = call(p, h, "ana", "write", &format!("v2/sessions/{sid}/execute"), json!({"sql": sql}));
    let run = v["data"]["run_id"].as_str().unwrap_or_else(|| panic!("{v}")).to_string();
    std::thread::sleep(Duration::from_millis(800));
    let t0 = Instant::now();
    call(p, h, "ana", "write", &format!("v2/sessions/{sid}/runs/{run}/cancel"), json!({}));
    loop {
        let (_, page, _) = call(p, h, "ana", "read", &format!("v2/sessions/{sid}/runs/{run}"), json!({}));
        if page["data"]["state"] != "running" {
            return page["data"].clone();
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "the attention took too long");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "needs docker; run with --run-ignored"]
fn live_mssql_sessions_runs_and_enforcement() {
    let Some(fx) = fixture() else { return };
    let p = Plugin::new();

    // ── a read-only caller: the read-only login; no database-side guard
    let ana = fx.host(&["sql_select"], "require");
    let sid = open(&p, &ana, "ana");
    let (_, status, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}"), json!({}));
    let st = &status["data"];
    assert_eq!((st["engine"].as_str(), st["profile"].as_str()), (Some("mssql"), Some("ro")), "{st}");
    assert_eq!((st["read_only"].as_bool(), st["database_read_only"].as_bool()), (Some(true), Some(false)));
    assert_eq!(st["residuals"].as_array().map(Vec::len), Some(2), "{st}");

    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT id, name, amount, big FROM t ORDER BY id");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    assert_eq!(rows(&pages), vec![json!([1, "alpha", "10.50", "9007199254740993"]), json!([2, "beta", null, null])]);
    // The unqualified `t` is dbo's (the default schema), named in lower
    // case under the database's case-insensitive collation.
    let asked = ana.authorized.lock().unwrap().last().unwrap().clone();
    assert!(asked.contains(&crate::host::Check::object("sql_select", "app", "dbo", "t")), "{asked:?}");
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT N'a;b' AS x, [c d] = 1");
    assert_eq!(rows(&pages), vec![json!(["a;b", 1])], "{pages:?}");

    // ── the vault refuses a write the caller does not hold: nothing runs
    let (v, _) = exec(&p, &ana, "ana", &sid, "UPDATE canary SET v = N'changed'");
    assert_eq!(v["data"]["state"], "refused", "{v}");
    assert_eq!(fx.canary(), "intact");

    // ── even if the vault allowed it, the read-only login refuses
    ana.allow(|_| true);
    let (_, pages) = exec(&p, &ana, "ana", &sid, "UPDATE canary SET v = N'changed'");
    assert_eq!(last(&pages)["messages"][0]["outcome"], "error", "{pages:?}");
    assert_eq!(fx.canary(), "intact");
    ana.allow(|c| c.capability == "sql_select");

    // ── smuggling and hazards never reach the server
    for (sql, expect) in [
        ("SELECT 1; DELETE FROM canary", "use_script"),
        ("SELECT 1 DELETE FROM canary", "refused_statement"),
        ("SELECT * FROM canary\nGO\nDELETE FROM canary", "unclassifiable"),
        ("EXEC xp_cmdshell 'whoami'", "refused_statement"),
        ("SELECT * FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) AS r", "refused_statement"),
        ("SET QUOTED_IDENTIFIER OFF", "refused_statement"),
        ("BACKUP DATABASE app TO DISK = '/tmp/x.bak'", "refused_statement"),
        ("SELECT * FROM srv.app.dbo.canary", "refused_statement"),
    ] {
        let (v, _) = exec(&p, &ana, "ana", &sid, sql);
        assert_eq!(code(&v), expect, "{sql}: {v}");
    }
    assert_eq!(fx.canary(), "intact");

    // ── paging and the grid cap (the attention stops the read)
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT n FROM seq ORDER BY n");
    assert_eq!(rows(&pages).len(), 2000);
    assert!(pages.iter().all(|p| p["rows"].as_array().unwrap().len() <= 500));
    let mut cfg = loopback_config();
    cfg["grid_rows"] = json!(1000);
    cfg["run_timeout_secs"] = json!(3);
    ana.set_config(cfg);
    let p2 = Plugin::new();
    let sid2 = open(&p2, &ana, "ana");
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT a.n FROM seq a CROSS JOIN seq b");
    assert_eq!(rows(&pages).len(), 1000, "the grid cap stops the read");
    assert_eq!(last(&pages)["messages"][0]["truncated"], true);
    assert_eq!(last(&pages)["state"], "done");
    // The connection stays in step after the attention.
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "SELECT COUNT(*) FROM t");
    assert_eq!(rows(&pages), vec![json!([2])], "{pages:?}");

    // ── the run deadline, then cancel (the TDS attention signal)
    let (_, pages) = exec(&p2, &ana, "ana", &sid2, "WAITFOR DELAY '00:00:20'");
    assert_ne!(last(&pages)["state"], "done", "{pages:?}");
    let page = start_and_cancel(&p, &ana, &sid, "WAITFOR DELAY '00:00:20'");
    assert_eq!(page["state"], "cancelled", "{page}");
    let (_, pages) = exec(&p, &ana, "ana", &sid, "SELECT COUNT_BIG(*) FROM t");
    assert_eq!(rows(&pages), vec![json!(["2"])], "bigint is a decimal string (§6.3): {pages:?}");

    // ── browser, describe, probe
    let (_, v, _) = call(&p, &ana, "ana", "list", &format!("v2/sessions/{sid}/objects"), json!({}));
    assert!(v["data"]["keys"].as_array().unwrap().contains(&json!("dbo")), "{v}");
    let (_, v, _) = call(&p, &ana, "ana", "list", &format!("v2/sessions/{sid}/objects/dbo"), json!({}));
    let names: Vec<&str> = v["data"]["objects"].as_array().unwrap().iter().filter_map(|o| o["name"].as_str()).collect();
    assert!(names.contains(&"t") && names.contains(&"v"), "{v}");
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/objects/dbo/t"), json!({}));
    assert_eq!(v["data"]["edit"]["key"], json!(["id"]), "{v}");
    assert_eq!(v["data"]["edit"]["editable"], true);
    let (_, v, _) = call(&p, &ana, "ana", "read", &format!("v2/sessions/{sid}/ceiling"), json!({}));
    assert!(v["data"]["probed"].as_array().unwrap().contains(&json!("sql_select")), "{v}");
    assert_eq!(v["data"]["undeclared"], json!([]), "{v}");

    // ── a read/write caller: transactions, grid edits, rollback on close
    let rw = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete"], "require");
    let sid3 = open(&p, &rw, "carol");
    let (_, pages) = exec(&p, &rw, "carol", &sid3, "BEGIN TRANSACTION; INSERT INTO t (id, name) VALUES (10, N'tx')");
    assert_eq!(last(&pages)["state"], "done", "{pages:?}");
    assert_eq!(last(&pages)["messages"][1]["rows_affected"], 1, "{pages:?}");
    let (_, st, _) = call(&p, &rw, "carol", "read", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(st["data"]["transaction"]["open"], true);
    let edit = json!({"object": {"schema": "dbo", "name": "t"}, "op": "update", "key": {"id": 2},
        "values": {"name": "gamma"}, "original": {"name": "beta"}});
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid3}/rows"), edit.clone());
    assert_eq!(v["data"]["state"], "done", "{v}");
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid3}/rows"), edit);
    assert_eq!(v["data"]["state"], "conflict", "the original no longer matches: {v}");
    call(&p, &rw, "carol", "delete", &format!("v2/sessions/{sid3}"), json!({}));
    assert_eq!(fx.srv.sql("SELECT COUNT(*) FROM app.dbo.t WHERE id = 10 OR name = N'gamma'"), "0", "rolled back");
    let sid4 = open(&p, &rw, "carol");
    let edit = json!({"object": {"schema": "dbo", "name": "t"}, "op": "update", "key": {"id": 2},
        "values": {"name": "delta", "amount": null}, "original": {"name": "beta", "amount": null}});
    let (_, v, _) = call(&p, &rw, "carol", "write", &format!("v2/sessions/{sid4}/rows"), edit);
    assert_eq!(v["data"]["state"], "done", "a NULL original matches NULL: {v}");
    assert_eq!(fx.srv.sql("SELECT name FROM app.dbo.t WHERE id = 2"), "delta", "committed outside a transaction");

    // ── a script in one transaction: the second INSERT fails, both roll back
    let sc = fx.host(&["sql_select", "sql_insert", "sql_update", "sql_delete", "sql_script"], "require");
    let sid5 = open(&p, &sc, "dave");
    let body = json!({"sql": "INSERT INTO t (id, name) VALUES (20, N's1'); INSERT INTO t (id, name) VALUES (20, N'dup')",
        "transaction": "single"});
    let (v, pages) = super::script(&p, &sc, "dave", &sid5, body);
    assert_eq!(v["data"]["warnings"], json!([]), "SQL Server DDL is transactional: {v}");
    assert_eq!(last(&pages)["script"]["tx_outcome"], "rolled_back", "{pages:?}");
    assert_eq!(fx.srv.sql("SELECT COUNT(*) FROM app.dbo.t WHERE id = 20"), "0");

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
        json!({"sql": "SELECT id FROM t", "format": "sql-insert", "table": {"name": "t"}}),
    );
    assert_eq!(code(&v), "unsupported", "{v}");

    // ── verify-full: the profile's CA and name succeed; the OS store is
    // refused; a wrong named instance is refused before the login is sent
    let mut good = local("ro", &["sql_select"], &fx.srv, "verify-full");
    good["tls"]["ca_pem"] = json!(fx.srv.cert_pem);
    good["tls"]["server_name"] = json!("localhost");
    let full = fx.host_with(&["sql_select"], vec![good.clone()]);
    let sid7 = open(&p, &full, "ana");
    let (_, st, _) = call(&p, &full, "ana", "read", &format!("v2/sessions/{sid7}"), json!({}));
    assert_eq!(st["data"]["tls_mode"], "verify-full");
    let strict = fx.host(&["sql_select"], "verify-full");
    let (s, v, _) = call(&p, &strict, "ana", "write", "v2/sessions", json!({"resource": "db"}));
    assert_ne!(s, 0, "{v}");
    assert!(matches!(code(&v).as_str(), "tls_failed" | "tls_config"), "{v}");
    let mut wrong = good;
    wrong["instance"] = json!("NOSUCHINSTANCE");
    let inst = fx.host_with(&["sql_select"], vec![wrong]);
    let (s, v, _) = call(&p, &inst, "ana", "write", "v2/sessions", json!({"resource": "db"}));
    assert_ne!(s, 0, "{v}");
    assert_eq!(code(&v), "instance_mismatch", "{v}");

    // ── seal closes every session
    p.lifecycle(bastion_plugin_sdk::process::Lifecycle::Seal);
    assert!(p.registry().is_empty());
}
