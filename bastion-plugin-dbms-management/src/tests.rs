//! Request-level tests through `Plugin::dispatch` with a scripted host.
//! Live PostgreSQL tests are in `live_tests.rs` (ignored by default).

use serde_json::{json, Value};

use crate::profile::tests::{profile_json, target_json};
use crate::testutil::{call, code, loopback_config, FakeServer, MockHost, PASSWORD};
use crate::Plugin;

fn local_profile(id: &str, ceiling: &[&str], port: u16, tls: &str) -> Value {
    let mut p = profile_json(id, ceiling);
    p["endpoint"] = json!(format!("127.0.0.1:{port}"));
    p["host"] = json!("127.0.0.1");
    p["port"] = json!(port);
    p["tls"]["mode"] = json!(tls);
    p
}

fn host_for(privs: &[&str], profiles: Vec<Value>, endpoint: &str) -> std::sync::Arc<MockHost> {
    let h = MockHost::new(target_json("database-first", privs, profiles));
    *h.credential.lock().unwrap() = Ok((endpoint.into(), "svc".into()));
    h
}

fn open(p: &Plugin, h: &MockHost, data: Value) -> (i32, Value, Vec<u8>) {
    call(p, h, "ent-ana", "write", "v2/sessions", data)
}

#[test]
fn a_caller_without_an_entity_cannot_open() {
    let p = Plugin::new();
    let h = host_for(&["sql_select"], vec![profile_json("ro", &["sql_select"])], "10.0.0.5:5432");
    let (st, v, _) = call(&p, &h, "", "write", "v2/sessions", json!({"resource": "db"}));
    assert_ne!(st, 0);
    assert_eq!(code(&v), "forbidden");
    assert!(!h.called("resource_sql_target"));
}

#[test]
fn refusals_before_release_never_ask_for_the_credential() {
    let p = Plugin::new();
    // The host refuses the target: the caller holds no SQL privilege.
    let h = host_for(&["sql_select"], vec![], "x:1");
    *h.target.lock().unwrap() = Err(crate::host::HostError::new("no_sql_privilege", "none"));
    assert_eq!(code(&open(&p, &h, json!({"resource": "db"})).1), "no_sql_privilege");
    assert!(!h.called("resource_sql_credential"));

    // Another engine.
    let mut t = target_json("database-first", &["sql_select"], vec![profile_json("ro", &["sql_select"])]);
    t["target"]["engine"] = json!("mysql");
    let h = MockHost::new(t);
    assert_eq!(code(&open(&p, &h, json!({"resource": "db"})).1), "unsupported");
    assert!(!h.called("resource_sql_credential"));

    // A read-only grant on a resource with only an admin login.
    let h = host_for(&["sql_select"], vec![profile_json("admin", &crate::profile::STATEMENT_CAPS)], "x:1");
    assert_eq!(code(&open(&p, &h, json!({"resource": "db"})).1), "no_profile_for_grant");
    assert!(!h.called("resource_sql_credential"));

    // Unknown fields are refused, not ignored.
    let h = host_for(&["sql_select"], vec![profile_json("ro", &["sql_select"])], "x:1");
    assert_eq!(code(&open(&p, &h, json!({"resource": "db", "password": "x"})).1), "bad_request");
}

#[test]
fn an_mfa_profile_needs_a_redeemed_ticket_before_release() {
    let p = Plugin::new();
    let mut prof = profile_json("ro", &["sql_select"]);
    prof["require_mfa"] = json!(true);
    let h = host_for(&["sql_select"], vec![prof], "10.0.0.5:5432");
    assert_eq!(code(&open(&p, &h, json!({"resource": "db"})).1), "mfa_required");
    assert!(!h.called("resource_sql_credential"));
    assert_eq!(code(&open(&p, &h, json!({"resource": "db", "mfa_ticket": "nope"})).1), "refused");
    assert!(!h.called("resource_sql_credential"));
    h.tickets.lock().unwrap().push("t-1".into());
    // Redeemed, then released; the release names another endpoint here, so
    // the open stops right after the MFA gate without dialling.
    *h.credential.lock().unwrap() = Ok(("10.9.9.9:5432".into(), "svc".into()));
    let (_, v, bytes) = open(&p, &h, json!({"resource": "db", "mfa_ticket": "t-1"}));
    assert!(h.called("resource_sql_credential"), "{v}");
    assert_eq!(code(&v), "endpoint_mismatch");
    h.assert_no_leak(&bytes);
}

#[test]
fn host_release_refusals_pass_through() {
    let p = Plugin::new();
    let h = host_for(&["sql_select"], vec![profile_json("ro", &["sql_select"])], "x:1");
    *h.credential.lock().unwrap() =
        Err(crate::host::HostError::new("refused", "endpoint_unbound: the credential is not bound to an endpoint"));
    let (st, v, _) = open(&p, &h, json!({"resource": "db"}));
    assert_ne!(st, 0);
    assert_eq!(code(&v), "refused");
    assert!(v["error"].as_str().unwrap().contains("endpoint_unbound"));
    assert!(p.registry().is_empty());
}

#[test]
fn a_credential_for_another_endpoint_is_not_used() {
    let p = Plugin::new();
    let h = host_for(&["sql_select"], vec![profile_json("ro", &["sql_select"])], "10.9.9.9:5432");
    let (_, v, bytes) = open(&p, &h, json!({"resource": "db"}));
    assert_eq!(code(&v), "endpoint_mismatch");
    h.assert_no_leak(&bytes);
    let ev = h.audit_events();
    assert_eq!(ev.last().unwrap()["outcome"], "failed");
    assert_eq!(ev.last().unwrap()["reason"], "endpoint_mismatch");
}

#[test]
fn loopback_and_metadata_addresses_are_never_dialled_by_default() {
    let p = Plugin::new();
    for host in ["127.0.0.1", "169.254.169.254"] {
        let mut prof = profile_json("ro", &["sql_select"]);
        prof["endpoint"] = json!(format!("{host}:5432"));
        prof["host"] = json!(host);
        let h = host_for(&["sql_select"], vec![prof], &format!("{host}:5432"));
        let (_, v, bytes) = open(&p, &h, json!({"resource": "db"}));
        assert_eq!(code(&v), "network_not_allowed", "{host}");
        h.assert_no_leak(&bytes);
    }
}

#[test]
fn cleartext_and_md5_authentication_without_tls_never_receive_the_password() {
    for auth in [vec![b'R', 0, 0, 0, 8, 0, 0, 0, 3], vec![b'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4]] {
        let server = FakeServer::start(b'N', auth);
        let p = Plugin::new();
        let endpoint = format!("127.0.0.1:{}", server.port);
        let h =
            host_for(&["sql_select"], vec![local_profile("ro", &["sql_select"], server.port, "disable")], &endpoint);
        h.set_config(loopback_config());
        let (st, v, bytes) = open(&p, &h, json!({"resource": "db"}));
        assert_ne!(st, 0);
        assert_eq!(code(&v), "weak_auth_refused", "{v}");
        h.assert_no_leak(&bytes);
        let after = server.finish();
        assert!(!after.contains(&b'p'), "the client sent a password message: {after:?}");
        assert!(!String::from_utf8_lossy(&after).contains(PASSWORD));
    }
}

#[test]
fn a_tls_profile_never_falls_back_to_plaintext() {
    // The server refuses TLS ('N'); the client must stop, not continue in
    // plaintext with the startup packet.
    let server = FakeServer::start(b'N', Vec::new());
    let p = Plugin::new();
    let endpoint = format!("127.0.0.1:{}", server.port);
    let h = host_for(&["sql_select"], vec![local_profile("ro", &["sql_select"], server.port, "require")], &endpoint);
    h.set_config(loopback_config());
    let (st, v, bytes) = open(&p, &h, json!({"resource": "db"}));
    assert_ne!(st, 0);
    assert_eq!(code(&v), "connect_failed", "{v}");
    h.assert_no_leak(&bytes);
    assert!(server.finish().is_empty(), "nothing is sent after the server refused TLS");
}

#[test]
fn a_closed_port_fails_cleanly_without_leaking() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let p = Plugin::new();
    let h = host_for(
        &["sql_select"],
        vec![local_profile("ro", &["sql_select"], port, "disable")],
        &format!("127.0.0.1:{port}"),
    );
    h.set_config(loopback_config());
    let (_, v, bytes) = open(&p, &h, json!({"resource": "db"}));
    assert_eq!(code(&v), "connect_failed");
    h.assert_no_leak(&bytes);
    assert!(p.registry().is_empty());
}

#[test]
fn session_paths_check_the_id_and_the_node() {
    let p = Plugin::new();
    let h = host_for(&["sql_select"], vec![], "x:1");
    let (_, v, _) = call(&p, &h, "ent-ana", "read", "v2/sessions/not-an-id", json!({}));
    assert_eq!(code(&v), "bad_request");
    let other = format!("{}-{}", "0123456789abcdef", "a".repeat(64));
    let (_, v, _) = call(&p, &h, "ent-ana", "read", &format!("v2/sessions/{other}"), json!({}));
    assert_eq!(code(&v), "session_on_other_node");
    let mine = crate::ids::session_id(&p.registry().instance).unwrap();
    let (_, v, _) = call(&p, &h, "ent-ana", "read", &format!("v2/sessions/{mine}"), json!({}));
    assert_eq!(code(&v), "not_found");
    let (_, v, _) = call(&p, &h, "ent-ana", "read", "v1/sessions", json!({}));
    assert_eq!(code(&v), "not_found", "v1 is not served");
}

#[test]
fn config_writes_are_validated_and_audited() {
    let p = Plugin::new();
    let h = host_for(&["sql_select"], vec![], "x:1");
    let (st, v, _) = call(&p, &h, "ent-admin", "write", "v2/config", json!({"page_rows": 100}));
    assert_eq!(st, 0, "{v}");
    assert_eq!(v["data"]["page_rows"], 100);
    let (_, v, _) = call(&p, &h, "ent-admin", "write", "v2/config", json!({"page_rows": 999_999}));
    assert_eq!(code(&v), "bad_request");
    let (_, v, _) = call(&p, &h, "ent-admin", "read", "v2/config", json!({}));
    assert_eq!(v["data"]["page_rows"], 100);
    assert!(h.audit_events().iter().any(|e| e["event"] == "dbms.config"));
}

/// A `Read` fed line by line from a channel; EOF when the sender drops.
struct ChannelReader {
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    buf: std::io::Cursor<Vec<u8>>,
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let n = std::io::Read::read(&mut self.buf, out)?;
            if n > 0 {
                return Ok(n);
            }
            match self.rx.recv() {
                Ok(next) => self.buf = std::io::Cursor::new(next),
                Err(_) => return Ok(0),
            }
        }
    }
}

#[derive(Clone, Default)]
struct SharedOut(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for SharedOut {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_seal_message_is_handled_and_acknowledged_on_the_multiplexed_protocol() {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let out = SharedOut::default();
    let reader = std::io::BufReader::new(ChannelReader { rx, buf: std::io::Cursor::new(Vec::new()) });
    let plugin = std::sync::Arc::new(Plugin::new());
    let (o, p) = (out.clone(), plugin.clone());
    let runner = std::thread::spawn(move || {
        bastion_plugin_sdk::process::serve(p, Box::new(reader), Box::new(o), true, "tok").unwrap()
    });
    tx.send(b"{\"type\":\"init\",\"protocol\":\"multiplexed\"}\n".to_vec()).unwrap();
    tx.send(b"{\"type\":\"lifecycle\",\"event\":\"seal\"}\n".to_vec()).unwrap();
    let t0 = std::time::Instant::now();
    loop {
        let text = String::from_utf8_lossy(&out.0.lock().unwrap()).to_string();
        if text.contains("lifecycle_ack") {
            assert!(text.contains("\"seal\""), "{text}");
            break;
        }
        assert!(t0.elapsed() < std::time::Duration::from_secs(9), "no ack within the host's deadline: {text}");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    drop(tx);
    runner.join().unwrap();
}
