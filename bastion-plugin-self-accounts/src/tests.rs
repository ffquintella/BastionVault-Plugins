//! Handler tests against the SDK's in-memory host stubs. Entity isolation is a
//! property of the *host* rebasing storage, so it is covered end to end, with a
//! real wasmtime instance, in `tests/testkit.rs`.

use bastion_plugin_sdk::provider::dispatch;
use bastion_plugin_sdk::test_support as host;
use bastion_plugin_sdk::{Host, Request};
use serde_json::{json, Value};
use serial_test::serial;

use crate::SelfAccounts;

/// A throwaway OpenSSH ed25519 key made by the system `ssh-keygen` for this test
/// run, so no private key is committed to the repository. `passphrase` empty =
/// unencrypted. Cached per process and per kind.
fn generated_key(passphrase: &str) -> &'static str {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<std::collections::BTreeMap<String, &'static str>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    if let Some(k) = cache.get(passphrase) {
        return k;
    }
    let dir = std::env::temp_dir().join(format!("bv-self-accounts-key-{}-{}", std::process::id(), passphrase.len()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("id_ed25519");
    let _ = std::fs::remove_file(&path);
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-C", "test", "-N", passphrase, "-f"])
        .arg(&path)
        .status()
        .expect("these tests need `ssh-keygen` on PATH to make a throwaway key");
    assert!(status.success(), "ssh-keygen failed");
    let pem: &'static str = Box::leak(std::fs::read_to_string(&path).unwrap().into_boxed_str());
    let _ = std::fs::remove_dir_all(&dir);
    cache.insert(passphrase.to_string(), pem);
    pem
}

fn key() -> &'static str {
    generated_key("")
}

fn encrypted_key() -> &'static str {
    generated_key("passphrase")
}

fn setup() {
    host::reset();
    host::enable_storage();
    host::set_now_ms(Some(1_791_201_600_000));
}

fn call(op: &str, path: &str, data: Value) -> (i32, Value, Vec<u8>) {
    let env = json!({
        "op": op, "path": path, "data": data,
        "caller": { "entity_id": "e1", "principal": { "mount": "userpass/", "name": "felipe" } }
    });
    let bytes = serde_json::to_vec(&env).unwrap();
    let r = dispatch::<SelfAccounts>(Request::new(&bytes), &Host::new());
    let v = serde_json::from_slice(&r.bytes).unwrap_or(Value::Null);
    (r.status, v, r.bytes)
}

fn pw_account(extra: Value) -> Value {
    let mut base = json!({
        "label": "Domain admin", "username": "felipe.adm", "domain": "CORP",
        "secret_kind": "password", "password": "hunter2-S3CRET",
        "resource_types": ["server"], "os_types": ["windows"], "protocols": ["rdp"],
        "targets": "*.corp.example.com, 10.20.0.0/16",
    });
    base.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    base
}

fn create(data: Value) -> String {
    let (st, v, raw) = call("write", "v2/accounts", data);
    assert_eq!(st, 0, "{}", String::from_utf8_lossy(&raw));
    v["data"]["id"].as_str().unwrap().to_string()
}

fn query(protocol: &str, rtype: &str, os: Option<&str>, target: Value) -> Value {
    let mut resource = json!({ "type": rtype });
    if let Some(o) = os {
        resource["os_type"] = json!(o);
    }
    json!({ "protocol": protocol, "resource": resource, "target": target })
}

fn candidates(q: Value) -> Vec<Value> {
    let (st, v, _) = call("provider.candidates", "", q);
    assert_eq!(st, 0);
    v["data"]["candidates"].as_array().cloned().unwrap_or_default()
}

fn release(id: &str, q: &Value, mfa: bool, totp: bool) -> (i32, Value, Vec<u8>) {
    call(
        "provider.release",
        "",
        json!({
            "account_id": id, "protocol": q["protocol"], "resource": q["resource"], "target": q["target"],
            "needs": { "password": true, "totp": totp },
            "connect": { "mfa_verified": mfa, "transport": "direct" }
        }),
    )
}

fn rdp_q() -> Value {
    query("rdp", "server", Some("windows"), json!({ "host": "dc01.corp.example.com", "port": 3389 }))
}

// ── CRUD ────────────────────────────────────────────────────────────────

#[test]
#[serial]
fn crud_round_trip_never_returns_a_secret() {
    setup();
    let id = create(pw_account(json!({})));
    assert!(id.starts_with("sa_") && id.len() == 29);

    let mut every_response = Vec::new();
    let (_, v, raw) = call("read", &format!("v2/accounts/{id}"), json!({}));
    every_response.push(raw);
    assert_eq!(v["data"]["label"], "Domain admin");
    assert_eq!(v["data"]["has_secret"], true);
    assert_eq!(v["data"]["applies_to"]["targets"], json!(["*.corp.example.com", "10.20.0.0/16"]));

    let (_, v, raw) = call("list", "v2/accounts", json!({}));
    every_response.push(raw);
    assert_eq!(v["data"]["entries"].as_array().unwrap().len(), 1);
    assert!(v["data"].get("keys").is_none());

    let (_, _, raw) = call("write", &format!("v2/accounts/{id}"), json!({ "label": "Renamed" }));
    every_response.push(raw);
    for raw in every_response {
        assert!(!String::from_utf8_lossy(&raw).contains("hunter2-S3CRET"));
    }

    let (st, _, _) = call("delete", &format!("v2/accounts/{id}"), json!({}));
    assert_eq!(st, 0);
    assert_eq!(call("read", &format!("v2/accounts/{id}"), json!({})).0, 2);
    assert!(call("list", "v2/accounts", json!({})).1["data"]["entries"].as_array().unwrap().is_empty());
}

#[test]
#[serial]
fn metadata_key_never_holds_secret_bytes() {
    setup();
    let id = create(pw_account(json!({})));
    let meta = Host::new().storage_get(&format!("accounts/{id}/meta")).unwrap();
    assert!(!String::from_utf8_lossy(&meta).contains("hunter2-S3CRET"));
    let secret = Host::new().storage_get(&format!("accounts/{id}/secret")).unwrap();
    assert!(String::from_utf8_lossy(&secret).contains("hunter2-S3CRET"));
}

#[test]
#[serial]
fn update_preserves_the_secret_when_absent_or_empty() {
    setup();
    let id = create(pw_account(json!({})));
    let q = rdp_q();
    for body in [json!({ "label": "A" }), json!({ "label": "B", "password": "" })] {
        assert_eq!(call("write", &format!("v2/accounts/{id}"), body).0, 0);
        let (st, v, _) = release(&id, &q, true, false);
        assert_eq!(st, 0);
        assert_eq!(v["data"]["secret"]["password"], "hunter2-S3CRET");
    }
    assert_eq!(call("write", &format!("v2/accounts/{id}"), json!({ "password": "new-pw" })).0, 0);
    assert_eq!(release(&id, &q, true, false).1["data"]["secret"]["password"], "new-pw");
}

#[test]
#[serial]
fn changing_secret_kind_requires_the_new_secret() {
    setup();
    let id = create(pw_account(json!({ "protocols": "", "os_types": "", "targets": "" })));
    let (st, v, _) = call("write", &format!("v2/accounts/{id}"), json!({ "secret_kind": "ssh-key" }));
    assert_ne!(st, 0);
    assert!(v["error"].as_str().unwrap().contains("new secret"));
    let (st, _, raw) = call("write", &format!("v2/accounts/{id}"), json!({ "secret_kind": "ssh-key", "private_key": key() }));
    assert_eq!(st, 0, "{}", String::from_utf8_lossy(&raw));
    let q = query("ssh", "server", Some("windows"), json!({ "host": "h.example.com", "port": 22 }));
    assert_eq!(release(&id, &q, true, false).1["data"]["secret"]["kind"], "ssh-key");
}

#[test]
#[serial]
fn totp_seed_needs_admin_opt_in_and_can_be_cleared() {
    setup();
    let (st, v, _) = call("write", "v2/accounts", pw_account(json!({ "totp_seed": "JBSWY3DPEHPK3PXP" })));
    assert_ne!(st, 0);
    assert!(v["error"].as_str().unwrap().contains("disabled by the administrator"));

    host::set_config("allow_totp_seeds", "true");
    let id = create(pw_account(json!({ "totp_seed": "jbsw y3dp ehpk 3pxp" })));
    let web_q = query("web", "web_application", None, json!({ "origins": ["https://grafana.corp.example.com"] }));
    let id_web = create(pw_account(json!({
        "protocols": "web", "os_types": "", "resource_types": ["web_application"],
        "targets": "https://*.corp.example.com", "totp_seed": "JBSWY3DPEHPK3PXP"
    })));
    let (st, v, _) = release(&id_web, &web_q, true, true);
    assert_eq!(st, 0);
    assert_eq!(v["data"]["secret"]["totp_seed"], "JBSWY3DPEHPK3PXP");
    // Not asked for: not returned.
    let (_, v, _) = release(&id_web, &web_q, true, false);
    assert!(v["data"]["secret"].get("totp_seed").is_none());

    assert_eq!(call("delete", &format!("v2/accounts/{id_web}/totp"), json!({})).0, 0);
    assert_eq!(release(&id_web, &web_q, true, true).0, 4, "a recipe that needs a seed the account no longer has");
    assert_eq!(call("read", &format!("v2/accounts/{id}"), json!({})).1["data"]["has_totp"], true);
    assert_eq!(call("read", &format!("v2/accounts/{id_web}"), json!({})).1["data"]["has_totp"], false);
}

#[test]
#[serial]
fn admin_turning_totp_off_stops_releases_and_badges() {
    setup();
    host::set_config("allow_totp_seeds", "true");
    let id = create(pw_account(json!({
        "protocols": "web", "os_types": "", "resource_types": ["web_application"],
        "targets": "https://a.corp.example.com", "totp_seed": "JBSWY3DPEHPK3PXP"
    })));
    let q = query("web", "web_application", None, json!({ "origins": ["https://a.corp.example.com"] }));
    assert_eq!(candidates(q.clone())[0]["has_totp"], true);
    host::set_config("allow_totp_seeds", "false");
    assert_eq!(candidates(q.clone())[0]["has_totp"], false);
    assert_eq!(release(&id, &q, true, true).0, 4);
}

#[test]
#[serial]
fn per_user_cap_is_enforced() {
    setup();
    host::set_config("max_accounts_per_user", "2");
    create(pw_account(json!({})));
    create(pw_account(json!({})));
    let (st, v, _) = call("write", "v2/accounts", pw_account(json!({})));
    assert_ne!(st, 0);
    assert!(v["error"].as_str().unwrap().contains("limit of 2"));
}

#[test]
#[serial]
fn admin_settings_view_reports_effective_values() {
    setup();
    host::set_config("require_targets", "all");
    host::set_config("allowed_resource_types", "server, database");
    let (_, v, _) = call("read", "v2/settings", json!({}));
    assert_eq!(v["data"]["require_targets"], "all");
    assert_eq!(v["data"]["allowed_resource_types"], json!(["server", "database"]));
    assert_eq!(v["data"]["allow_totp_seeds"], false);
    assert_eq!(v["data"]["require_connect_mfa"], true);
}

#[test]
#[serial]
fn unknown_require_targets_value_fails_strict() {
    setup();
    host::set_config("require_targets", "sometimes");
    assert_eq!(call("read", "v2/settings", json!({})).1["data"]["require_targets"], "all");
}

#[test]
#[serial]
fn admin_resource_type_allowlist_is_enforced() {
    setup();
    host::set_config("allowed_resource_types", "server");
    let (st, v, _) = call("write", "v2/accounts", pw_account(json!({ "resource_types": ["database"] })));
    assert_ne!(st, 0);
    assert!(v["error"].as_str().unwrap().contains("not allowed"));
}

// ── malformed input ─────────────────────────────────────────────────────

#[test]
#[serial]
fn malformed_and_oversize_input_is_refused() {
    setup();
    let bad: Vec<Value> = vec![
        pw_account(json!({ "label": "" })),
        pw_account(json!({ "label": "x".repeat(65) })),
        pw_account(json!({ "username": "u".repeat(257) })),
        pw_account(json!({ "domain": "d".repeat(257) })),
        pw_account(json!({ "description": "d".repeat(513) })),
        pw_account(json!({ "password": "p".repeat(1025) })),
        pw_account(json!({ "password": "" })),
        pw_account(json!({ "label": "bad\u{0007}label" })),
        pw_account(json!({ "secret_kind": "token" })),
        pw_account(json!({ "resource_types": [] })),
        pw_account(json!({ "resource_types": ["Server!"] })),
        pw_account(json!({ "os_types": ["amiga"] })),
        pw_account(json!({ "protocols": ["telnet"] })),
        pw_account(json!({ "targets": "https://evil.example/path" })),
        pw_account(json!({ "targets": "*.com" })),
        pw_account(json!({ "targets": "a*b.example.com" })),
        pw_account(json!({ "targets": "10.0.0.0/33" })),
        pw_account(json!({ "label": 5 })),
        pw_account(json!({ "private_key": key() })),
        pw_account(json!({ "resource_types": (0..33).map(|i| format!("t{i}")).collect::<Vec<_>>() })),
    ];
    for (i, b) in bad.into_iter().enumerate() {
        let (st, v, _) = call("write", "v2/accounts", b);
        assert_ne!(st, 0, "case {i} should be refused");
        assert!(v["error"].is_string());
    }
    assert!(call("list", "v2/accounts", json!({})).1["data"]["entries"].as_array().unwrap().is_empty());
}

#[test]
#[serial]
fn ssh_key_validation() {
    setup();
    let key_acct = |pem: &str, extra: Value| {
        let mut base = json!({
            "label": "k", "username": "felipe", "secret_kind": "ssh-key", "private_key": pem,
            "resource_types": ["server"],
        });
        base.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
        base
    };
    assert_eq!(call("write", "v2/accounts", key_acct(key(), json!({}))).0, 0);
    for (pem, why) in [
        (encrypted_key(), "passphrase"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----", "valid OpenSSH"),
        ("not a key", "OpenSSH private key"),
        ("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----", "OpenSSH private key"),
    ] {
        let (st, v, _) = call("write", "v2/accounts", key_acct(pem, json!({})));
        assert_ne!(st, 0);
        assert!(v["error"].as_str().unwrap().contains(why), "{pem:?}: {v}");
    }
    let oversize = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----", "A".repeat(17 * 1024));
    assert_ne!(call("write", "v2/accounts", key_acct(&oversize, json!({}))).0, 0);
    // A key cannot be used over RDP or web.
    assert_ne!(call("write", "v2/accounts", key_acct(key(), json!({ "protocols": ["rdp"] }))).0, 0);
}

#[test]
#[serial]
fn admin_can_disable_ssh_keys() {
    setup();
    let id = {
        let (st, v, _) = call("write", "v2/accounts", json!({
            "label": "k", "username": "f", "secret_kind": "ssh-key", "private_key": key(), "resource_types": ["server"]
        }));
        assert_eq!(st, 0);
        v["data"]["id"].as_str().unwrap().to_string()
    };
    host::set_config("allow_ssh_keys", "false");
    let q = query("ssh", "server", None, json!({ "host": "h.example.com", "port": 22 }));
    assert!(candidates(q.clone()).is_empty());
    assert_eq!(release(&id, &q, true, false).0, 2);
    assert_ne!(call("write", "v2/accounts", json!({
        "label": "k2", "username": "f", "secret_kind": "ssh-key", "private_key": key(), "resource_types": ["server"]
    })).0, 0);
}

#[test]
#[serial]
fn bad_ids_never_reach_storage() {
    setup();
    create(pw_account(json!({})));
    for id in ["..", "../x", "sa_", "sa_UPPERCASEUPPERCASEUPPERC", "a/b", "sa_aaaaaaaaaaaaaaaaaaaaaaaaaa/../.."] {
        for op in ["read", "write", "delete"] {
            let (st, _, _) = call(op, &format!("v2/accounts/{id}"), json!({}));
            assert_ne!(st, 0, "{op} {id}");
        }
    }
}

#[test]
#[serial]
fn version_handling_reads_old_and_refuses_newer() {
    setup();
    let h = Host::new();
    let meta = |v: u32| {
        json!({
            "v": v, "id": "sa_aaaaaaaaaaaaaaaaaaaaaaaaaa", "label": "old", "username": "u",
            "secret_kind": "password", "has_totp": false,
            "applies_to": { "resource_types": ["server"] },
            "created_at": "t", "updated_at": "t"
        })
    };
    h.storage_put("accounts/sa_aaaaaaaaaaaaaaaaaaaaaaaaaa/meta", &serde_json::to_vec(&meta(1)).unwrap()).unwrap();
    assert_eq!(call("read", "v2/accounts/sa_aaaaaaaaaaaaaaaaaaaaaaaaaa", json!({})).0, 0);
    h.storage_put("accounts/sa_aaaaaaaaaaaaaaaaaaaaaaaaaa/meta", &serde_json::to_vec(&meta(2)).unwrap()).unwrap();
    assert_ne!(call("read", "v2/accounts/sa_aaaaaaaaaaaaaaaaaaaaaaaaaa", json!({})).0, 0);
    // A newer record is skipped in a listing, not allowed to hide the rest.
    create(pw_account(json!({})));
    assert_eq!(call("list", "v2/accounts", json!({})).1["data"]["entries"].as_array().unwrap().len(), 1);
}

// ── matching and release ────────────────────────────────────────────────

#[test]
#[serial]
fn candidates_match_type_os_protocol_and_target() {
    setup();
    create(pw_account(json!({})));
    assert_eq!(candidates(rdp_q()).len(), 1);
    // Wrong resource type, OS, protocol, host.
    assert!(candidates(query("rdp", "database", Some("windows"), json!({"host":"dc01.corp.example.com","port":3389}))).is_empty());
    assert!(candidates(query("rdp", "server", Some("linux"), json!({"host":"dc01.corp.example.com","port":3389}))).is_empty());
    assert!(candidates(query("rdp", "server", None, json!({"host":"dc01.corp.example.com","port":3389}))).is_empty());
    assert!(candidates(query("ssh", "server", Some("windows"), json!({"host":"dc01.corp.example.com","port":22}))).is_empty());
    assert!(candidates(query("rdp", "server", Some("windows"), json!({"host":"evil.example.org","port":3389}))).is_empty());
    // CIDR.
    assert_eq!(candidates(query("rdp", "server", Some("windows"), json!({"host":"10.20.33.4","port":3389}))).len(), 1);
    assert!(candidates(query("rdp", "server", Some("windows"), json!({"host":"10.21.0.1","port":3389}))).is_empty());
    // The candidate is metadata only.
    let c = &candidates(rdp_q())[0];
    assert!(c.get("password").is_none() && c.get("secret").is_none());
    assert_eq!(c["domain"], "CORP");
}

#[test]
#[serial]
fn web_requires_targets_by_default_and_all_origins_must_match() {
    setup();
    // No targets: fine to store, never offered for web.
    let (st, v, _) = call("write", "v2/accounts", pw_account(json!({
        "protocols": "web", "os_types": "", "resource_types": ["web_application"], "targets": ""
    })));
    assert_eq!(st, 0);
    assert!(v["warnings"][0].as_str().unwrap().contains("origin"));
    let one = query("web", "web_application", None, json!({ "origins": ["https://a.corp.example.com"] }));
    assert!(candidates(one.clone()).is_empty());

    create(pw_account(json!({
        "label": "Grafana", "protocols": "web", "os_types": "", "resource_types": ["web_application"],
        "targets": "https://*.corp.example.com"
    })));
    assert_eq!(candidates(one).len(), 1);
    let two = query("web", "web_application", None, json!({ "origins": ["https://a.corp.example.com", "https://login.vendor.example"] }));
    assert!(candidates(two).is_empty(), "every allowed origin must match");
    let http = query("web", "web_application", None, json!({ "origins": ["http://a.corp.example.com"] }));
    assert!(candidates(http).is_empty());
    let host_target = query("web", "web_application", None, json!({ "host": "a.corp.example.com", "port": 443 }));
    assert!(candidates(host_target).is_empty());
}

#[test]
#[serial]
fn require_targets_all_applies_to_ssh_and_rdp() {
    setup();
    create(pw_account(json!({ "targets": "", "protocols": "rdp" })));
    assert_eq!(candidates(rdp_q()).len(), 1);
    host::set_config("require_targets", "all");
    assert!(candidates(rdp_q()).is_empty());
}

#[test]
#[serial]
fn release_returns_only_what_was_asked_and_stamps_last_used() {
    setup();
    let id = create(pw_account(json!({})));
    let (st, v, raw) = release(&id, &rdp_q(), true, false);
    assert_eq!(st, 0);
    assert_eq!(v["data"]["username"], "felipe.adm");
    assert_eq!(v["data"]["domain"], "CORP");
    assert_eq!(v["data"]["secret"], json!({ "kind": "password", "password": "hunter2-S3CRET" }));
    assert!(String::from_utf8_lossy(&raw).contains("hunter2-S3CRET"));
    assert_eq!(candidates(rdp_q())[0]["last_used_at"], "2026-10-05T12:00:00Z");
    // Neither logs nor audit events carry the released bytes.
    for (_, line) in host::log_lines() {
        assert!(!String::from_utf8_lossy(&line).contains("hunter2-S3CRET"));
    }
    for ev in host::audit_events() {
        assert!(!String::from_utf8_lossy(&ev).contains("hunter2-S3CRET"));
    }
}

#[test]
#[serial]
fn release_refuses_forged_stale_and_unattested_requests() {
    setup();
    let id = create(pw_account(json!({})));
    // MFA.
    let (st, _, raw) = release(&id, &rdp_q(), false, false);
    assert_eq!(st, 3);
    assert!(!String::from_utf8_lossy(&raw).contains("hunter2"));
    host::set_config("require_connect_mfa", "false");
    assert_eq!(release(&id, &rdp_q(), false, false).0, 0);
    // A target the account does not apply to, a wrong type, an unknown id,
    // a malformed id.
    let other = query("rdp", "server", Some("windows"), json!({"host":"evil.example.org","port":3389}));
    assert_eq!(release(&id, &other, true, false).0, 2);
    let wrong_type = query("rdp", "database", Some("windows"), json!({"host":"dc01.corp.example.com","port":3389}));
    assert_eq!(release(&id, &wrong_type, true, false).0, 2);
    assert_eq!(release("sa_aaaaaaaaaaaaaaaaaaaaaaaaaa", &rdp_q(), true, false).0, 2);
    assert_eq!(release("../secret", &rdp_q(), true, false).0, 2);
}

#[test]
#[serial]
fn refusal_messages_carry_no_account_detail() {
    setup();
    let id = create(pw_account(json!({})));
    let other = query("rdp", "server", Some("windows"), json!({"host":"evil.example.org","port":3389}));
    let (_, _, raw) = release(&id, &other, true, false);
    let text = String::from_utf8_lossy(&raw).to_string();
    assert_eq!(text, "no matching account");
}

// ── audit ───────────────────────────────────────────────────────────────

#[test]
#[serial]
fn crud_emits_audit_events_without_secret_values() {
    setup();
    let id = create(pw_account(json!({})));
    call("write", &format!("v2/accounts/{id}"), json!({ "password": "another-S3CRET", "label": "L2" }));
    call("delete", &format!("v2/accounts/{id}"), json!({}));
    let events: Vec<Value> = host::audit_events().iter().map(|b| serde_json::from_slice(b).unwrap()).collect();
    let names: Vec<&str> = events.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert_eq!(names, ["self-accounts.account.created", "self-accounts.account.updated", "self-accounts.account.deleted"]);
    assert_eq!(events[1]["secret_changed"], true);
    assert_eq!(events[1]["changed"], json!(["label"]));
    assert_eq!(events[0]["entity_id"], "e1");
    let all = events.iter().map(|e| e.to_string()).collect::<String>();
    assert!(!all.contains("hunter2") && !all.contains("another-S3CRET"));
}

// ── first use on this target (Phase 5) ──────────────────────────────────

fn seen_raw(id: &str) -> Option<Vec<u8>> {
    Host::new().storage_get(&format!("accounts/{id}/seen")).ok()
}

fn rdp_to(host_name: &str) -> Value {
    query("rdp", "server", Some("windows"), json!({ "host": host_name, "port": 3389 }))
}

#[test]
#[serial]
fn first_use_flips_after_a_successful_release_only() {
    setup();
    let id = create(pw_account(json!({})));
    let fresh = &candidates(rdp_q())[0];
    assert_eq!(fresh["first_use_on_target"], true);
    assert!(fresh.get("last_used_on_target").is_none());

    // Listing candidates never records anything.
    candidates(rdp_q());
    assert!(seen_raw(&id).is_none(), "candidates must not write");

    // Refused releases never record: no MFA, a target the account does not
    // apply to, an unrequested TOTP.
    assert_eq!(release(&id, &rdp_q(), false, false).0, 3);
    assert_eq!(release(&id, &rdp_to("evil.example.org"), true, false).0, 2);
    assert_eq!(release(&id, &rdp_q(), true, true).0, 4);
    assert!(seen_raw(&id).is_none(), "a refused release must not make a target familiar");
    assert_eq!(candidates(rdp_q())[0]["first_use_on_target"], true);

    // A successful release does.
    assert_eq!(release(&id, &rdp_q(), true, false).0, 0);
    let after = &candidates(rdp_q())[0];
    assert_eq!(after["first_use_on_target"], false);
    assert_eq!(after["last_used_on_target"], "2026-10-05T12:00:00Z");
    // Another host the account applies to is still a first use, and the
    // same host spelled differently (or on another port) is not.
    assert_eq!(candidates(rdp_to("dc02.corp.example.com"))[0]["first_use_on_target"], true);
    let respelled = query("rdp", "server", Some("windows"), json!({ "host": "DC01.corp.example.com.", "port": 3390 }));
    assert_eq!(candidates(respelled)[0]["first_use_on_target"], false);
}

#[test]
#[serial]
fn the_release_response_is_unchanged_by_the_record() {
    setup();
    let id = create(pw_account(json!({})));
    for _ in 0..2 {
        let (st, v, _) = release(&id, &rdp_q(), true, false);
        assert_eq!(st, 0);
        let mut keys: Vec<&str> = v["data"].as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["domain", "secret", "username"]);
        assert_eq!(v["data"]["secret"], json!({ "kind": "password", "password": "hunter2-S3CRET" }));
    }
}

#[test]
#[serial]
fn seen_holds_digests_never_target_text() {
    setup();
    let id = create(pw_account(json!({})));
    for h in ["dc01.corp.example.com", "10.20.0.7", "srv.corp.example.com"] {
        assert_eq!(release(&id, &rdp_to(h), true, false).0, 0);
    }
    let raw = seen_raw(&id).expect("a seen record");
    let text = String::from_utf8_lossy(&raw);
    for needle in ["dc01", "corp", "example", "10.20", "srv", "rdp", "hunter2"] {
        assert!(!text.contains(needle), "{needle} leaked into seen: {text}");
    }
    let v: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v["v"], 1);
    let entries = v["targets"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    for e in entries {
        let h = e["h"].as_str().unwrap();
        assert!(h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()), "{h}");
        assert_eq!(e.as_object().unwrap().len(), 2, "digest and time only: {e}");
    }
    // `meta` and the listing stay free of it.
    let meta = String::from_utf8_lossy(&Host::new().storage_get(&format!("accounts/{id}/meta")).unwrap()).to_string();
    let (_, list, list_raw) = call("list", "v2/accounts", json!({}));
    assert!(list["data"]["entries"][0].get("seen").is_none());
    for e in entries {
        let h = e["h"].as_str().unwrap();
        assert!(!meta.contains(h) && !String::from_utf8_lossy(&list_raw).contains(h));
    }
}

#[test]
#[serial]
fn the_seen_set_is_capped_and_forgets_the_oldest_target() {
    setup();
    let id = create(pw_account(json!({ "targets": "10.20.0.0/16" })));
    let n = crate::seen::MAX_SEEN + 4;
    for i in 0..n {
        host::set_now_ms(Some(1_791_201_600_000 + i as i64 * 1_000));
        assert_eq!(release(&id, &rdp_to(&format!("10.20.0.{i}")), true, false).0, 0);
    }
    let v: Value = serde_json::from_slice(&seen_raw(&id).unwrap()).unwrap();
    assert_eq!(v["targets"].as_array().unwrap().len(), crate::seen::MAX_SEEN);
    // The four oldest are first uses again; the newest are remembered.
    for i in 0..4 {
        assert_eq!(candidates(rdp_to(&format!("10.20.0.{i}")))[0]["first_use_on_target"], true, "{i}");
    }
    assert_eq!(candidates(rdp_to(&format!("10.20.0.{}", n - 1)))[0]["first_use_on_target"], false);
    assert_eq!(candidates(rdp_to("10.20.0.4"))[0]["first_use_on_target"], false);
}

#[test]
#[serial]
fn web_targets_are_the_origin_set_in_any_order() {
    setup();
    let id = create(pw_account(json!({
        "protocols": "web", "os_types": "", "resource_types": ["web_application"],
        "targets": "https://*.corp.example.com"
    })));
    let q = |o: Value| query("web", "web_application", None, json!({ "origins": o }));
    let both = q(json!(["https://a.corp.example.com", "https://sso.corp.example.com"]));
    assert_eq!(release(&id, &both, true, false).0, 0);
    let reordered = q(json!(["https://sso.corp.example.com:443", "https://a.corp.example.com"]));
    assert_eq!(candidates(reordered)[0]["first_use_on_target"], false);
    // A subset is a different set of origins the recipe may fill.
    assert_eq!(candidates(q(json!(["https://a.corp.example.com"])))[0]["first_use_on_target"], true);
}

#[test]
#[serial]
fn deleting_an_account_removes_its_seen_record() {
    setup();
    let id = create(pw_account(json!({})));
    assert_eq!(release(&id, &rdp_q(), true, false).0, 0);
    assert!(seen_raw(&id).is_some());
    assert_eq!(call("delete", &format!("v2/accounts/{id}"), json!({})).0, 0);
    assert!(seen_raw(&id).is_none());
}

#[test]
#[serial]
fn a_newer_seen_record_is_left_alone_and_an_unreadable_one_replaced() {
    setup();
    let id = create(pw_account(json!({})));
    let newer = br#"{"v":9,"targets":[],"future":true}"#;
    Host::new().storage_put(&format!("accounts/{id}/seen"), newer).unwrap();
    assert_eq!(candidates(rdp_q())[0]["first_use_on_target"], true, "unreadable reads as never used");
    assert_eq!(release(&id, &rdp_q(), true, false).0, 0, "bookkeeping never fails a launch");
    assert_eq!(seen_raw(&id).unwrap(), newer.to_vec(), "a newer record must not be downgraded");

    Host::new().storage_put(&format!("accounts/{id}/seen"), b"garbage").unwrap();
    assert_eq!(release(&id, &rdp_q(), true, false).0, 0);
    assert_eq!(candidates(rdp_q())[0]["first_use_on_target"], false);
}
