//! End to end against the compiled `.wasm` in a real wasmtime instance, with the
//! testkit mirroring the host's ABI 1.3 behaviour (attested `caller` block,
//! entity-scoped storage). Needs the release wasm:
//!
//!   cd plugins-ext && cargo build --release --target wasm32-unknown-unknown -p bastion-plugin-self-accounts
//!
//! `wasm32-unknown-unknown`, not `wasm32-wasip1`: the host links only the `bv`
//! import module, so a build that imports `wasi_snapshot_preview1` cannot be
//! instantiated. A missing build fails with the exact command, never with an
//! os error.

use bastion_plugin_testkit::{TestCaller, TestHost, TestInvocation};
use serde_json::{json, Value};

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

fn wasm() -> Vec<u8> {
    // Deliberately not `locate_wasm`: it would also find a stale wasip1 build.
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32-unknown-unknown/release/bastion_plugin_self_accounts.wasm");
    std::fs::read(&p).unwrap_or_else(|_| {
        panic!(
            "{} is missing; build it with: cd plugins-ext && cargo build --release \
             --target wasm32-unknown-unknown -p bastion-plugin-self-accounts",
            p.display()
        )
    })
}

fn host() -> TestHost {
    TestHost::builder("self-accounts")
        .storage_prefix("")
        .audit_emit(true)
        .now_ms(1_791_201_600_000)
        .build()
}

fn run(h: &TestHost, w: &[u8], who: &str, op: &str, path: &str, data: Value) -> TestInvocation {
    h.invoke_as(w, &TestCaller::new(who), op, path, data).expect("invoke")
}

fn account() -> Value {
    json!({
        "label": "Domain admin", "username": "felipe.adm", "domain": "CORP",
        "secret_kind": "password", "password": "hunter2-S3CRET",
        "resource_types": ["server"], "os_types": ["windows"], "protocols": ["rdp"],
        "targets": "*.corp.example.com",
    })
}

fn rdp_query() -> Value {
    json!({
        "protocol": "rdp",
        "resource": { "type": "server", "os_type": "windows" },
        "target": { "host": "dc01.corp.example.com", "port": 3389 }
    })
}

fn release_body(id: &str, mfa: bool) -> Value {
    let q = rdp_query();
    json!({
        "account_id": id, "protocol": "rdp", "resource": q["resource"], "target": q["target"],
        "needs": { "password": true, "totp": false },
        "connect": { "mfa_verified": mfa, "transport": "direct" }
    })
}

fn id_of(inv: &TestInvocation) -> String {
    assert!(inv.is_success(), "{}", String::from_utf8_lossy(&inv.response));
    inv.response_json().unwrap()["data"]["id"].as_str().unwrap().to_string()
}

#[test]
fn full_flow_through_wasm_candidates_then_release() {
    let (h, w) = (host(), wasm());
    let id = id_of(&run(&h, &w, "alice", "write", "v2/accounts", account()));

    let c = run(&h, &w, "alice", "provider.candidates", "", rdp_query());
    assert!(c.is_success());
    let cands = c.response_json().unwrap()["data"]["candidates"].clone();
    assert_eq!(cands.as_array().unwrap().len(), 1);
    assert_eq!(cands[0]["id"], id.as_str());
    assert!(!String::from_utf8_lossy(&c.response).contains("hunter2"));

    let r = run(&h, &w, "alice", "provider.release", "", release_body(&id, true));
    assert!(r.is_success(), "{}", String::from_utf8_lossy(&r.response));
    let v = r.response_json().unwrap();
    assert_eq!(v["data"]["secret"]["password"], "hunter2-S3CRET");
    assert_eq!(v["data"]["domain"], "CORP");

    // Not without the MFA attestation.
    assert!(!run(&h, &w, "alice", "provider.release", "", release_body(&id, false)).is_success());
}

#[test]
fn another_entity_sees_and_releases_nothing() {
    let (h, w) = (host(), wasm());
    let id = id_of(&run(&h, &w, "alice", "write", "v2/accounts", account()));

    // Bob lists nothing, cannot read, update, delete or release alice's id.
    let list = run(&h, &w, "bob", "list", "v2/accounts", json!({}));
    assert!(list.response_json().unwrap()["data"]["entries"].as_array().unwrap().is_empty());
    assert!(!run(&h, &w, "bob", "read", &format!("v2/accounts/{id}"), json!({})).is_success());
    assert!(!run(&h, &w, "bob", "write", &format!("v2/accounts/{id}"), json!({"label":"x"})).is_success());
    assert!(!run(&h, &w, "bob", "delete", &format!("v2/accounts/{id}"), json!({})).is_success());
    assert!(!run(&h, &w, "bob", "provider.release", "", release_body(&id, true)).is_success());
    let c = run(&h, &w, "bob", "provider.candidates", "", rdp_query());
    assert!(c.response_json().unwrap()["data"]["candidates"].as_array().unwrap().is_empty());

    // Alice's record is untouched, in her own prefix only.
    assert!(run(&h, &w, "alice", "read", &format!("v2/accounts/{id}"), json!({})).is_success());
    assert!(h.entity_storage_dump("bob").is_empty());
    assert!(h.entity_storage_dump("alice").keys().any(|k| k.starts_with("accounts/")));
}

#[test]
fn two_entities_keep_independent_accounts_and_caps() {
    let h = TestHost::builder("self-accounts")
        .storage_prefix("")
        .config("max_accounts_per_user", "1")
        .build();
    let w = wasm();
    id_of(&run(&h, &w, "alice", "write", "v2/accounts", account()));
    id_of(&run(&h, &w, "bob", "write", "v2/accounts", account()));
    assert!(!run(&h, &w, "alice", "write", "v2/accounts", account()).is_success(), "alice is at her cap");
}

#[test]
fn storage_holds_secrets_only_under_the_secret_key() {
    let (h, w) = (host(), wasm());
    id_of(&run(&h, &w, "alice", "write", "v2/accounts", account()));
    let dump = h.entity_storage_dump("alice");
    for (k, v) in &dump {
        let has = String::from_utf8_lossy(v).contains("hunter2-S3CRET");
        assert_eq!(has, k.ends_with("/secret"), "{k}");
    }
    assert_eq!(dump.len(), 2);
    // Nothing the plugin logged or audited carries it either.
    for l in h.logs() {
        assert!(!l.line.contains("hunter2"));
    }
    for e in h.audit_events() {
        assert!(!e.to_string().contains("hunter2"));
    }
    assert_eq!(h.audit_events().len(), 1);
}

#[test]
fn ssh_key_account_parses_inside_the_fuel_budget() {
    let (h, w) = (host(), wasm());
    let inv = run(
        &h, &w, "alice", "write", "v2/accounts",
        json!({
            "label": "k", "username": "felipe", "secret_kind": "ssh-key", "private_key": key(),
            "resource_types": ["server"]
        }),
    );
    let id = id_of(&inv);
    eprintln!("ssh-key create consumed {} fuel", inv.fuel_consumed);
    let q = json!({
        "protocol": "ssh", "resource": { "type": "server" }, "target": { "host": "h.example.com", "port": 22 }
    });
    let r = run(&h, &w, "alice", "provider.release", "", json!({
        "account_id": id, "protocol": "ssh", "resource": q["resource"], "target": q["target"],
        "needs": { "password": false, "totp": false },
        "connect": { "mfa_verified": true, "transport": "rustion" }
    }));
    assert_eq!(r.response_json().unwrap()["data"]["secret"]["kind"], "ssh-key");
    assert!(r.response_json().unwrap()["data"]["secret"]["private_key"].as_str().unwrap().contains("OPENSSH"));
}

#[test]
fn a_caller_without_a_usable_entity_never_reaches_the_plugin() {
    let (h, w) = (host(), wasm());
    for bad in ["", "..", "a/b", "../alice"] {
        assert!(
            h.invoke_as(&w, &TestCaller::new(bad), "list", "v2/accounts", json!({})).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn plain_invocations_without_a_caller_fail_closed() {
    let (h, w) = (host(), wasm());
    let r = h.invoke(&w, "list", "v2/accounts", json!({})).unwrap();
    assert!(!r.is_success(), "a provider plugin must not serve an envelope with no caller");
}

#[test]
fn the_seen_record_is_per_entity_and_holds_no_target_text() {
    let (h, w) = (host(), wasm());
    let alice = id_of(&run(&h, &w, "alice", "write", "v2/accounts", account()));
    let bob = id_of(&run(&h, &w, "bob", "write", "v2/accounts", account()));
    let first = |who: &str| {
        let c = run(&h, &w, who, "provider.candidates", "", rdp_query());
        assert!(c.is_success());
        c.response_json().unwrap()["data"]["candidates"][0]["first_use_on_target"].clone()
    };
    assert_eq!(first("alice"), json!(true));
    assert_eq!(first("bob"), json!(true));

    // Alice connects; only her account stops being a first use there.
    assert!(run(&h, &w, "alice", "provider.release", "", release_body(&alice, true)).is_success());
    assert_eq!(first("alice"), json!(false));
    assert_eq!(first("bob"), json!(true), "bob's identical account has never been used there");

    // Physically: a digest under alice's prefix, nothing under bob's.
    let a = h.entity_storage_dump("alice");
    let seen = a.get(&format!("accounts/{alice}/seen")).expect("alice's seen record");
    let text = String::from_utf8_lossy(seen);
    assert!(!text.contains("dc01") && !text.contains("corp") && !text.contains("hunter2"), "{text}");
    assert!(!h.entity_storage_dump("bob").contains_key(&format!("accounts/{bob}/seen")));

    // A refused release by bob (no MFA attestation) records nothing.
    assert!(!run(&h, &w, "bob", "provider.release", "", release_body(&bob, false)).is_success());
    assert!(!h.entity_storage_dump("bob").keys().any(|k| k.ends_with("/seen")));
}
