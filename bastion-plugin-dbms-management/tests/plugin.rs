//! The built binary through the testkit's process harness (the host's wire
//! protocol and the mocked ABI 1.4 host calls), and `plugin.toml` through
//! the host's own manifest rules. No database needed.

use std::path::Path;

use bastion_plugin_testkit::sql::MockRelease;
use bastion_plugin_testkit::{TestCaller, TestHost};
use bv_plugin_manifest::PluginManifest;
use serde_json::{json, Value};

const EXE: &str = env!("CARGO_BIN_EXE_bastion-plugin-dbms-management");
const PASSWORD: &str = "Pl4nted-db-password-9c1e0b";

fn exe() -> &'static Path {
    Path::new(EXE)
}

#[test]
fn the_manifest_passes_the_hosts_rules() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.toml")).unwrap();
    let m: PluginManifest = toml::from_str(&text).unwrap();
    m.validate().unwrap();
    assert_eq!(m.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(m.abi_version, "1.4");
    let c = &m.capabilities;
    assert!(c.long_lived && c.concurrent && c.caller_identity && c.sql_gate && c.sql_console && c.audit_emit);
    assert_eq!(c.resource_credentials.len(), 1);
    assert_eq!(c.storage_prefix.as_deref(), Some("dbms/"));
    assert!(c.allowed_hosts.is_empty(), "no declared egress");
}

fn target(endpoint_host: &str, port: u16) -> Value {
    json!({"resource": "db", "type": "database", "engine": "postgresql", "default_port": 5432,
        "hostname": endpoint_host, "ip_address": null, "database_name": "app", "enforcement": "database-first",
        "invalid_profiles": [],
        "profiles": [{"id": "ro", "label": "ro", "endpoint": format!("{endpoint_host}:{port}"), "host": endpoint_host,
            "port": port, "catalog": "app", "instance": null,
            "tls": {"mode": "verify-full", "server_name": null, "ca_pem": null},
            "ceiling": ["sql_select"], "require_mfa": false, "step_up": [],
            "credential_source": {"kind": "secret", "secret_id": "svc"}}]})
}

fn host(granted: bool) -> TestHost {
    TestHost::builder("dbms-management")
        .storage_prefix("dbms/")
        .audit_emit(true)
        .abi_minor(4)
        .caller_identity(true)
        .sql_gate(granted)
        .resource_credentials(granted)
        .sql_privileges("db", &["sql_select"])
        .sql_target("db", target("127.0.0.1", 1))
        .sql_release("db", "ro", MockRelease::bound("127.0.0.1:1", "svc", PASSWORD))
        .build()
}

fn assert_clean(h: &TestHost, response: &[u8]) {
    let text = String::from_utf8_lossy(response);
    assert!(!text.contains(PASSWORD), "response: {text}");
    for line in h.process_stderr() {
        assert!(!line.contains(PASSWORD), "stderr: {line}");
    }
    assert!(!serde_json::to_string(&h.audit_events()).unwrap().contains(PASSWORD), "audit");
    for l in h.logs() {
        assert!(!l.line.contains(PASSWORD), "log: {}", l.line);
    }
    for (k, v) in h.storage_dump() {
        assert!(!String::from_utf8_lossy(&v).contains(PASSWORD), "storage {k}");
    }
}

fn error_of(out: &bastion_plugin_testkit::TestInvocation) -> String {
    serde_json::from_slice::<Value>(&out.response)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_default()
}

#[test]
fn without_the_admin_grant_nothing_is_reached() {
    let h = host(false);
    let ana = TestCaller::new("ent-ana");
    let out = h.invoke_process_as(exe(), &ana, "write", "v2/sessions", json!({"resource": "db"})).unwrap();
    assert!(!out.is_success());
    assert!(error_of(&out).starts_with("not_granted"), "{}", error_of(&out));
    assert!(h.audit_events().iter().all(|e| e["path"] != "resource-credential-release"), "nothing was released");
}

#[test]
fn a_release_is_host_audited_and_the_password_never_surfaces() {
    let h = host(true);
    let ana = TestCaller::new("ent-ana");
    let out = h.invoke_process_as(exe(), &ana, "write", "v2/sessions", json!({"resource": "db"})).unwrap();
    // Released by the host (bound endpoint), then refused by the plugin's own
    // network policy: loopback is never dialled by default.
    assert!(error_of(&out).starts_with("network_not_allowed"), "{}", error_of(&out));
    let release =
        h.audit_events().into_iter().find(|e| e["path"] == "resource-credential-release").expect("host audit");
    assert_eq!(release["data"]["outcome"], "released");
    assert_eq!(release["actor"]["entity_id"], "ent-ana");
    let session_ref = release["data"]["session_ref"].as_str().unwrap();
    assert_eq!(session_ref.len(), 16 + 1 + 64, "the session id is the session reference");
    assert_clean(&h, &out.response);
}

#[test]
fn the_plugins_own_audit_events_are_actor_stamped() {
    let h = host(true);
    let ana = TestCaller::new("ent-ana");
    h.invoke_process_as(exe(), &ana, "write", "v2/sessions", json!({"resource": "db"})).unwrap();
    let ev = h
        .audit_events()
        .into_iter()
        .find(|e| e["data"]["plugin_event"]["event"] == "dbms.session.open")
        .expect("the failed open is audited");
    assert_eq!(ev["actor"]["entity_id"], "ent-ana", "stamped by the host, not the plugin");
    assert_eq!(ev["data"]["plugin_event"]["outcome"], "failed");
}

#[test]
fn a_caller_without_sql_privileges_is_refused_by_the_host() {
    let h = TestHost::builder("dbms-management")
        .storage_prefix("dbms/")
        .audit_emit(true)
        .abi_minor(4)
        .caller_identity(true)
        .sql_gate(true)
        .resource_credentials(true)
        .sql_target("db", target("10.0.0.5", 5432))
        .build();
    let out = h
        .invoke_process_as(exe(), &TestCaller::new("ent-bob"), "write", "v2/sessions", json!({"resource": "db"}))
        .unwrap();
    assert!(error_of(&out).starts_with("no_sql_privilege"), "{}", error_of(&out));
}

#[test]
fn malformed_requests_are_refused() {
    let h = host(true);
    let ana = TestCaller::new("ent-ana");
    for (op, path, data) in [
        ("write", "v2/sessions", json!({"resource": 5})),
        ("write", "v2/sessions", json!({})),
        ("read", "v2/sessions/../../config", json!({})),
        ("write", "v2/sessions/zz/execute", json!({"sql": "SELECT 1"})),
        ("read", "v1/sessions", json!({})),
    ] {
        let out = h.invoke_process_as(exe(), &ana, op, path, data).unwrap();
        assert!(!out.is_success(), "{op} {path}");
    }
}
