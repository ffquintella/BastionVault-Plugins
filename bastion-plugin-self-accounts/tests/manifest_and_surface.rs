//! The shipped `plugin.toml` and `surface.json` are what an operator registers,
//! so they are tested as artefacts: they parse, validate, and say what the spec
//! says.

use std::collections::BTreeSet;

use bastion_plugin_sdk::surface::SurfaceManifest;
use bv_plugin_manifest::{PluginManifest, StorageScope};

fn manifest() -> PluginManifest {
    let text = include_str!("../plugin.toml");
    toml::from_str(text).expect("plugin.toml parses")
}

#[test]
fn manifest_validates_and_declares_the_provider_capabilities() {
    let m = manifest();
    m.validate().expect("plugin.toml validates");
    bv_plugin_manifest::check_abi_compatibility(&m.abi_version).expect("host accepts abi 1.3");
    assert_eq!(m.abi_version, "1.3");
    assert!(m.capabilities.caller_identity);
    assert_eq!(m.capabilities.storage_scope, StorageScope::Entity);
    let p = m.capabilities.credential_provider.as_ref().expect("provider block");
    assert_eq!(p.display_name, "Self-account");
    assert_eq!(p.protocols, ["ssh", "rdp", "web"]);
    assert_eq!(p.secret_kinds, ["password", "ssh-key"]);
}

#[test]
fn manifest_declares_no_network_capability() {
    let m = manifest();
    assert!(m.capabilities.app.net.is_none());
    assert!(m.capabilities.allowed_hosts.is_empty());
    assert!(!m.capabilities.app.is_declared());
}

#[test]
fn config_schema_defaults_match_the_spec() {
    let m = manifest();
    let get = |n: &str| m.config_schema.iter().find(|f| f.name == n).unwrap_or_else(|| panic!("{n}"));
    assert_eq!(get("allow_ssh_keys").default.as_deref(), Some("true"));
    assert_eq!(get("allow_totp_seeds").default.as_deref(), Some("false"));
    assert_eq!(get("max_accounts_per_user").default.as_deref(), Some("25"));
    assert_eq!(get("require_connect_mfa").default.as_deref(), Some("true"));
    assert_eq!(get("require_targets").default.as_deref(), Some("web"));
    assert_eq!(get("require_targets").options, ["web", "all"]);
    assert_eq!(m.config_schema.len(), 6);
}

fn surface() -> SurfaceManifest {
    serde_json::from_str(include_str!("../surface.json")).expect("surface.json parses")
}

#[test]
fn surface_validates_for_this_plugin() {
    surface().validate("self-accounts", &BTreeSet::new()).expect("surface validates");
}

#[test]
fn surface_binds_only_this_plugins_v2_paths() {
    let s = serde_json::to_string(&surface()).unwrap();
    for path in s.split("\"path\":\"").skip(1).map(|r| r.split('"').next().unwrap()) {
        assert!(path.starts_with("{mount}/v2/accounts"), "{path}");
    }
    assert!(!s.contains("/v1/"));
}

#[test]
fn password_and_key_forms_use_the_write_only_widgets() {
    let v: serde_json::Value = serde_json::from_str(include_str!("../surface.json")).unwrap();
    let forms: Vec<&serde_json::Value> = v["pages"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "form")
        .collect();
    assert_eq!(forms.len(), 2);
    let pw = &forms[0]["schema"]["properties"];
    assert_eq!(pw["password"]["format"], "password");
    assert_eq!(pw["totp_seed"]["format"], "password");
    let key = &forms[1]["schema"]["properties"];
    assert_eq!(key["private_key"]["format"], "secret-textarea");
    for f in &forms {
        assert_eq!(f["schema"]["properties"]["resource_types"]["x-bv-options"], "resource-types");
        assert_eq!(f["submit"]["binding"]["op"], "write");
    }
    // Only the delete row action, behind a confirm.
    let t = &v["pages"][0]["components"][0];
    assert_eq!(t["row_actions"].as_array().unwrap().len(), 1);
    assert_eq!(t["row_actions"][0]["confirm"], true);
}
