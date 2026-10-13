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
    let manifest = manifest();
    let declared = manifest.surface.expect("plugin.toml declares its management surface");
    let surface = surface();
    assert_eq!(declared.schema_version, surface.schema_version);
    assert_eq!(declared.sha256, "0".repeat(64), "the packer stamps the shipped bytes");
    assert_eq!(declared.size, 0, "the packer stamps the shipped bytes");
    surface.validate("self-accounts", &BTreeSet::new()).expect("surface validates");
}

#[test]
fn surface_binds_only_this_plugins_v2_paths() {
    let s = serde_json::to_string(&surface()).unwrap();
    for path in s.split("\"path\":\"").skip(1).map(|r| r.split('"').next().unwrap()) {
        assert!(path.starts_with("{mount}/v2/accounts"), "{path}");
    }
    assert!(!s.contains("/v1/"));
}

fn components() -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(include_str!("../surface.json")).unwrap();
    v["pages"][0]["components"].as_array().unwrap().clone()
}

fn form(id: &str) -> serde_json::Value {
    components()
        .into_iter()
        .find(|c| c["kind"] == "form" && c["id"] == id)
        .unwrap_or_else(|| panic!("form {id}"))
}

#[test]
fn password_and_key_forms_use_the_write_only_widgets() {
    let forms: Vec<serde_json::Value> = components().into_iter().filter(|c| c["kind"] == "form").collect();
    assert_eq!(forms.len(), 4);
    for f in &forms {
        let p = &f["schema"]["properties"];
        assert_eq!(p["resource_types"]["x-bv-options"], "resource-types", "{}", f["id"]);
        assert_eq!(f["submit"]["binding"]["op"], "write");
        // Every form is opened in a modal; nothing is rendered inline.
        assert_eq!(f["presentation"], "modal", "{}", f["id"]);
        if p.get("password").is_some() {
            assert_eq!(p["password"]["format"], "password");
            assert_eq!(p["totp_seed"]["format"], "password");
        }
        if p.get("private_key").is_some() {
            assert_eq!(p["private_key"]["format"], "secret-textarea");
        }
    }
    assert!(form("add-password")["schema"]["properties"]["password"].is_object());
    assert!(form("add-ssh-key")["schema"]["properties"]["private_key"].is_object());
}

#[test]
fn add_account_offers_a_kind_chooser() {
    let t = &components()[0];
    assert_eq!(t["kind"], "table");
    let actions = t["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["label"], "Add account");
    assert_eq!(actions[0]["forms"], serde_json::json!(["add-password", "add-ssh-key"]));
    for id in ["add-password", "add-ssh-key"] {
        assert_eq!(form(id)["submit"]["binding"]["path"], "{mount}/v2/accounts");
    }
    assert_eq!(form("add-password")["schema"]["properties"]["secret_kind"]["enum"], serde_json::json!(["password"]));
    assert_eq!(form("add-ssh-key")["schema"]["properties"]["secret_kind"]["enum"], serde_json::json!(["ssh-key"]));
}

#[test]
fn edit_opens_the_form_for_the_rows_kind_and_never_requires_or_changes_the_secret() {
    let t = &components()[0];
    let row_actions = t["row_actions"].as_array().unwrap();
    assert_eq!(row_actions.len(), 2);
    let edit = &row_actions[0];
    assert_eq!(edit["label"], "Edit");
    // The binding is the prefill read; the API never returns a secret on it.
    assert_eq!(edit["binding"], serde_json::json!({ "op": "read", "path": "{mount}/v2/accounts/{id}" }));
    assert_eq!(edit["open_form"]["select_by"], "secret_kind");
    let by_kind = &edit["open_form"]["forms_by_value"];
    // One edit form per secret kind the provider declares, so the kind is
    // fixed by the row.
    let declared = manifest().capabilities.credential_provider.unwrap().secret_kinds;
    assert_eq!(by_kind.as_object().unwrap().len(), declared.len());
    for kind in &declared {
        let f = form(by_kind[kind.as_str()].as_str().unwrap());
        assert_eq!(f["submit"]["binding"]["path"], "{mount}/v2/accounts/{id}");
        let props = f["schema"]["properties"].as_object().unwrap();
        assert!(!props.contains_key("secret_kind"), "{kind}: the kind cannot change on edit");
        let required: Vec<&str> =
            f["schema"]["required"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect();
        for secret in ["password", "private_key", "totp_seed"] {
            assert!(!required.contains(&secret), "{kind}: {secret} must stay optional on edit");
        }
    }
    // Delete is unchanged, behind a confirm.
    assert_eq!(row_actions[1]["label"], "Delete");
    assert_eq!(row_actions[1]["binding"]["op"], "delete");
    assert_eq!(row_actions[1]["confirm"], true);
}
