//! The plugin's own API (spec §3). No path names a user or an entity: the
//! host-attested caller decides whose records a request touches, by rebasing
//! storage before this code runs.

use bastion_plugin_sdk::provider::{Caller, LogicalOp};
use bastion_plugin_sdk::{Host, LogLevel, Response};
use serde_json::{json, Map, Value};

use crate::matching::parse_pattern;
use crate::model::*;
use crate::settings::Settings;
use crate::store;
use crate::timefmt::rfc3339;

const ACCOUNTS: &str = "v2/accounts";

fn reply(data: Value, warnings: Vec<String>) -> Response {
    let mut body = json!({ "data": data });
    if !warnings.is_empty() {
        body["warnings"] = json!(warnings);
    }
    Response::ok(serde_json::to_vec(&body).unwrap_or_default())
}

fn fail(status: i32, msg: &str) -> Response {
    Response::err(status, serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default())
}

fn invalid(e: Invalid) -> Response {
    fail(1, &e.0)
}

fn not_found() -> Response {
    fail(2, "account not found")
}

pub fn handle(caller: &Caller, op: LogicalOp, host: &Host) -> Response {
    let path = op.path.trim_matches('/');
    let settings = Settings::load(host);
    let segs: Vec<&str> = path.split('/').collect();
    match (op.op.as_str(), segs.as_slice()) {
        ("read", ["v2", "settings"]) => reply(json!(settings.view()), vec![]),
        ("list", ["v2", "accounts"]) => list(host),
        ("write", ["v2", "accounts"]) => create(caller, &op.data, &settings, host),
        ("read", ["v2", "accounts", id]) => read(host, id),
        ("write", ["v2", "accounts", id]) => update(caller, id, &op.data, &settings, host),
        ("delete", ["v2", "accounts", id]) => remove(caller, id, host),
        ("delete", ["v2", "accounts", id, "totp"]) => clear_totp(caller, id, host),
        _ if path == ACCOUNTS || path.starts_with("v2/") => fail(4, "unsupported operation or path"),
        _ => not_found(),
    }
}

// ── views ───────────────────────────────────────────────────────────────

fn view(meta: &AccountMeta) -> Value {
    let mut v = serde_json::to_value(meta).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        // Rows of the management table: flat strings for the row actions and
        // joined lists for the columns.
        o.insert("has_secret".into(), json!(true));
        o.insert("resource_types_text".into(), json!(meta.applies_to.resource_types.join(", ")));
        o.insert("targets_text".into(), json!(meta.applies_to.targets.join(", ")));
        o.insert("last_used_text".into(), json!(meta.last_used_at.clone().unwrap_or_default()));
    }
    v
}

fn list(host: &Host) -> Response {
    let ids = match store::list_ids(host) {
        Ok(i) => i,
        Err(e) => return invalid(e),
    };
    let mut entries = Vec::new();
    for id in ids {
        match store::load_meta(host, &id) {
            Ok(Some(m)) => entries.push(view(&m)),
            Ok(None) => {}
            Err(e) => host.log(LogLevel::Warn, &format!("skipping unreadable account {id}: {}", e.0)),
        }
    }
    entries.sort_by(|a, b| a["label"].as_str().cmp(&b["label"].as_str()));
    // `entries`, not `keys`: the management table prefers `keys` when present
    // and would then render bare ids.
    reply(json!({ "entries": entries }), vec![])
}

fn read(host: &Host, id: &str) -> Response {
    match store::load_meta(host, id) {
        Ok(Some(m)) => reply(view(&m), vec![]),
        Ok(None) => not_found(),
        Err(e) => invalid(e),
    }
}

// ── input parsing ───────────────────────────────────────────────────────

fn str_field<'a>(d: &'a Value, key: &str) -> Result<Option<&'a str>, Invalid> {
    match d.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(Invalid::new(format!("{key} must be a string"))),
    }
}

/// A list given as a JSON array, or as a comma/newline-separated string (what a
/// plain text form field submits).
fn list_field(d: &Value, key: &str) -> Result<Option<Vec<String>>, Invalid> {
    let items: Vec<String> = match d.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(|s| s.trim().to_string()).ok_or_else(|| Invalid::new(format!("{key} must be a list of strings"))))
            .collect::<Result<_, _>>()?,
        Some(Value::String(s)) => s
            .split(|c| c == ',' || c == '\n')
            .map(|p| p.trim().to_string())
            .collect(),
        Some(_) => return Err(Invalid::new(format!("{key} must be a list"))),
    };
    let mut out: Vec<String> = Vec::new();
    for i in items.into_iter().filter(|i| !i.is_empty()) {
        if i.chars().count() > MAX_ITEM {
            return Err(Invalid::new(format!("a {key} entry is longer than {MAX_ITEM} characters")));
        }
        if !out.contains(&i) {
            out.push(i);
        }
    }
    if out.len() > MAX_LIST {
        return Err(Invalid::new(format!("{key} has more than {MAX_LIST} entries")));
    }
    Ok(Some(out))
}

fn check_applies(a: &mut AppliesTo, kind: &str, settings: &Settings, warnings: &mut Vec<String>) -> Result<(), Invalid> {
    if a.resource_types.is_empty() {
        return Err(Invalid::new("resource_types needs at least one entry"));
    }
    for t in &a.resource_types {
        check_type_id(t)?;
        if !settings.allowed_resource_types.is_empty() && !settings.allowed_resource_types.contains(t) {
            return Err(Invalid::new(format!("resource type `{t}` is not allowed by the administrator")));
        }
    }
    for o in &mut a.os_types {
        *o = o.to_ascii_lowercase();
        if !OS_TYPES.contains(&o.as_str()) {
            return Err(Invalid::new("os_types entries must be one of linux, windows, macos, bsd, unix, other"));
        }
    }
    for p in &mut a.protocols {
        *p = p.to_ascii_lowercase();
        if !PROTOCOLS.contains(&p.as_str()) {
            return Err(Invalid::new("protocols entries must be one of ssh, rdp, web"));
        }
        if !compatible_protocols(kind).contains(&p.as_str()) {
            return Err(Invalid::new(format!("a {kind} account cannot be used over {p}")));
        }
    }
    let mut has_host = false;
    let mut has_origin = false;
    for t in &mut a.targets {
        let p = parse_pattern(t)?;
        *t = t.trim().to_ascii_lowercase();
        if p.is_origin() {
            has_origin = true;
        } else {
            has_host = true;
        }
    }
    // An account that can never be offered is a trap; say so at write time.
    let uses_web = a.protocols.is_empty() && kind == KIND_PASSWORD || a.protocols.iter().any(|p| p == "web");
    let uses_host = a.protocols.is_empty() || a.protocols.iter().any(|p| p == "ssh" || p == "rdp");
    if uses_web && !has_origin {
        warnings.push("No https:// origin in targets: this account is not offered for web logins while the administrator requires targets for them.".into());
    }
    if uses_host && !has_host && settings.require_targets == crate::settings::RequireTargets::All {
        warnings.push("No host target: this account is not offered for SSH or RDP while the administrator requires targets.".into());
    }
    Ok(())
}

struct SecretInput {
    password: Option<String>,
    private_key: Option<String>,
    totp_seed: Option<String>,
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.private_key.zeroize();
        self.totp_seed.zeroize();
    }
}

fn read_secret_input(d: &Value) -> Result<SecretInput, Invalid> {
    // Empty means "keep" on update and "absent" on create (write-preserve).
    let nz = |k: &str| -> Result<Option<String>, Invalid> {
        Ok(str_field(d, k)?.filter(|s| !s.is_empty()).map(|s| s.to_string()))
    };
    Ok(SecretInput { password: nz("password")?, private_key: nz("private_key")?, totp_seed: nz("totp_seed")? })
}

fn check_kind(kind: &str, settings: &Settings) -> Result<(), Invalid> {
    match kind {
        KIND_PASSWORD => Ok(()),
        KIND_SSH_KEY if settings.allow_ssh_keys => Ok(()),
        KIND_SSH_KEY => Err(Invalid::new("SSH-key accounts are disabled by the administrator")),
        _ => Err(Invalid::new("secret_kind must be `password` or `ssh-key`")),
    }
}

/// Validate and build the secret for `kind` from `input`, or `None` when the
/// input carries no secret (allowed on update only).
fn build_secret(kind: &str, input: &SecretInput, settings: &Settings, keep: Option<&AccountSecret>) -> Result<Option<AccountSecret>, Invalid> {
    match kind {
        KIND_PASSWORD => {
            if input.private_key.is_some() {
                return Err(Invalid::new("private_key is only valid for ssh-key accounts"));
            }
            let totp = match &input.totp_seed {
                Some(raw) => {
                    if !settings.allow_totp_seeds {
                        return Err(Invalid::new("TOTP seeds are disabled by the administrator"));
                    }
                    Some(normalise_totp_seed(raw)?)
                }
                None => None,
            };
            match (&input.password, keep) {
                (Some(pw), _) => {
                    check_text_secret("password", pw, MAX_PASSWORD)?;
                    Ok(Some(AccountSecret { v: CURRENT_VERSION, kind: KIND_PASSWORD.into(), password: Some(pw.clone()), totp_seed: totp.or_else(|| keep.and_then(|k| k.totp_seed.clone())), private_key: None }))
                }
                (None, Some(k)) if k.kind == KIND_PASSWORD => {
                    if totp.is_none() {
                        return Ok(None);
                    }
                    Ok(Some(AccountSecret { v: CURRENT_VERSION, kind: KIND_PASSWORD.into(), password: k.password.clone(), totp_seed: totp, private_key: None }))
                }
                _ => Err(Invalid::new("password is required")),
            }
        }
        KIND_SSH_KEY => {
            if input.password.is_some() || input.totp_seed.is_some() {
                return Err(Invalid::new("password and totp_seed are only valid for password accounts"));
            }
            match (&input.private_key, keep) {
                (Some(pem), _) => {
                    check_private_key(pem)?;
                    Ok(Some(AccountSecret { v: CURRENT_VERSION, kind: KIND_SSH_KEY.into(), password: None, totp_seed: None, private_key: Some(pem.clone()) }))
                }
                (None, Some(k)) if k.kind == KIND_SSH_KEY => Ok(None),
                _ => Err(Invalid::new("private_key is required")),
            }
        }
        _ => Err(Invalid::new("secret_kind must be `password` or `ssh-key`")),
    }
}

fn check_text_secret(field: &str, v: &str, max: usize) -> Result<(), Invalid> {
    if v.is_empty() {
        return Err(Invalid::new(format!("{field} is required")));
    }
    if v.len() > max {
        return Err(Invalid::new(format!("{field} is longer than {max} bytes")));
    }
    Ok(())
}

// ── mutations ───────────────────────────────────────────────────────────

fn audit(host: &Host, caller: &Caller, event: &str, meta: &AccountMeta, extra: Value) {
    let mut payload = json!({
        "event": event,
        "id": meta.id,
        "secret_kind": meta.secret_kind,
        "applies_to": meta.applies_to,
        "entity_id": caller.entity_id,
    });
    if let (Some(p), Some(e)) = (payload.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            p.insert(k.clone(), v.clone());
        }
    }
    let _ = host.audit_emit(&serde_json::to_vec(&payload).unwrap_or_default());
}

fn create(caller: &Caller, d: &Value, settings: &Settings, host: &Host) -> Response {
    match create_inner(caller, d, settings, host) {
        Ok(r) => r,
        Err(e) => invalid(e),
    }
}

fn create_inner(caller: &Caller, d: &Value, settings: &Settings, host: &Host) -> Result<Response, Invalid> {
    let mut warnings = Vec::new();
    let label = str_field(d, "label")?.unwrap_or("").trim().to_string();
    let username = str_field(d, "username")?.unwrap_or("").trim().to_string();
    let domain = str_field(d, "domain")?.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let description = str_field(d, "description")?.unwrap_or("").trim().to_string();
    check_text("label", &label, MAX_LABEL, true)?;
    check_text("username", &username, MAX_USERNAME, true)?;
    if let Some(dm) = &domain {
        check_text("domain", dm, MAX_DOMAIN, false)?;
    }
    check_text("description", &description, MAX_DESCRIPTION, false)?;
    let kind = str_field(d, "secret_kind")?.unwrap_or(KIND_PASSWORD).to_string();
    check_kind(&kind, settings)?;

    let mut applies = AppliesTo {
        resource_types: list_field(d, "resource_types")?.unwrap_or_default(),
        os_types: list_field(d, "os_types")?.unwrap_or_default(),
        protocols: list_field(d, "protocols")?.unwrap_or_default(),
        targets: list_field(d, "targets")?.unwrap_or_default(),
    };
    check_applies(&mut applies, &kind, settings, &mut warnings)?;

    let input = read_secret_input(d)?;
    let secret = build_secret(&kind, &input, settings, None)?.ok_or_else(|| Invalid::new("a secret is required"))?;

    if store::list_ids(host)?.len() >= settings.max_accounts_per_user {
        return Err(Invalid::new(format!("the limit of {} accounts per user is reached", settings.max_accounts_per_user)));
    }
    let now = rfc3339(host.now_unix_ms());
    let meta = AccountMeta {
        v: CURRENT_VERSION,
        id: store::new_id(host)?,
        label,
        username,
        domain,
        secret_kind: kind,
        has_totp: secret.totp_seed.is_some(),
        applies_to: applies,
        description,
        created_at: now.clone(),
        updated_at: now,
        last_used_at: None,
    };
    // Secret first: a record without a secret is invisible, a secret without a
    // record is unreachable and removed by the next delete of that id.
    store::save_secret(host, &meta.id, &secret)?;
    store::save_meta(host, &meta)?;
    audit(host, caller, "self-accounts.account.created", &meta, json!({}));
    Ok(reply(json!({ "id": meta.id }), warnings))
}

fn update(caller: &Caller, id: &str, d: &Value, settings: &Settings, host: &Host) -> Response {
    match update_inner(caller, id, d, settings, host) {
        Ok(r) => r,
        Err(e) => invalid(e),
    }
}

fn update_inner(caller: &Caller, id: &str, d: &Value, settings: &Settings, host: &Host) -> Result<Response, Invalid> {
    let Some(mut meta) = store::load_meta(host, id)? else {
        return Ok(not_found());
    };
    let before = meta.clone();
    let mut warnings = Vec::new();
    let mut changed: Vec<&str> = Vec::new();

    if let Some(s) = str_field(d, "label")? {
        meta.label = s.trim().to_string();
        check_text("label", &meta.label, MAX_LABEL, true)?;
    }
    if let Some(s) = str_field(d, "username")? {
        meta.username = s.trim().to_string();
        check_text("username", &meta.username, MAX_USERNAME, true)?;
    }
    if let Some(s) = str_field(d, "domain")? {
        let dm = s.trim().to_string();
        check_text("domain", &dm, MAX_DOMAIN, false)?;
        meta.domain = Some(dm).filter(|x| !x.is_empty());
    }
    if let Some(s) = str_field(d, "description")? {
        meta.description = s.trim().to_string();
        check_text("description", &meta.description, MAX_DESCRIPTION, false)?;
    }
    let new_kind = match str_field(d, "secret_kind")? {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => meta.secret_kind.clone(),
    };
    check_kind(&new_kind, settings)?;
    if let Some(v) = list_field(d, "resource_types")? { meta.applies_to.resource_types = v; }
    if let Some(v) = list_field(d, "os_types")? { meta.applies_to.os_types = v; }
    if let Some(v) = list_field(d, "protocols")? { meta.applies_to.protocols = v; }
    if let Some(v) = list_field(d, "targets")? { meta.applies_to.targets = v; }

    let input = read_secret_input(d)?;
    let kind_changed = new_kind != meta.secret_kind;
    let existing = if kind_changed { None } else { store::load_secret(host, id)? };
    let new_secret = build_secret(&new_kind, &input, settings, existing.as_ref())
        .map_err(|e| if kind_changed { Invalid::new(format!("changing secret_kind needs the new secret in the same write ({})", e.0)) } else { e })?;
    meta.secret_kind = new_kind;
    check_applies(&mut meta.applies_to, &meta.secret_kind, settings, &mut warnings)?;

    if let Some(s) = &new_secret {
        meta.has_totp = s.totp_seed.is_some();
    }
    if meta.label != before.label { changed.push("label"); }
    if meta.username != before.username { changed.push("username"); }
    if meta.domain != before.domain { changed.push("domain"); }
    if meta.description != before.description { changed.push("description"); }
    if meta.secret_kind != before.secret_kind { changed.push("secret_kind"); }
    if meta.applies_to != before.applies_to { changed.push("applies_to"); }
    if meta.has_totp != before.has_totp { changed.push("totp"); }

    meta.updated_at = rfc3339(host.now_unix_ms());
    if let Some(s) = &new_secret {
        store::save_secret(host, id, s)?;
    }
    store::save_meta(host, &meta)?;
    audit(host, caller, "self-accounts.account.updated", &meta, json!({ "changed": changed, "secret_changed": new_secret.is_some() }));
    Ok(reply(json!({ "id": meta.id }), warnings))
}

fn clear_totp(caller: &Caller, id: &str, host: &Host) -> Response {
    let r = (|| -> Result<Response, Invalid> {
        let Some(mut meta) = store::load_meta(host, id)? else { return Ok(not_found()); };
        if let Some(mut s) = store::load_secret(host, id)? {
            if s.totp_seed.is_some() {
                use zeroize::Zeroize;
                s.totp_seed.zeroize();
                s.totp_seed = None;
                store::save_secret(host, id, &s)?;
            }
        }
        meta.has_totp = false;
        meta.updated_at = rfc3339(host.now_unix_ms());
        store::save_meta(host, &meta)?;
        audit(host, caller, "self-accounts.account.updated", &meta, json!({ "changed": ["totp"], "secret_changed": true }));
        Ok(reply(Value::Object(Map::new()), vec![]))
    })();
    r.unwrap_or_else(invalid)
}

fn remove(caller: &Caller, id: &str, host: &Host) -> Response {
    let r = (|| -> Result<Response, Invalid> {
        let Some(meta) = store::load_meta(host, id)? else { return Ok(not_found()); };
        store::delete(host, id)?;
        audit(host, caller, "self-accounts.account.deleted", &meta, json!({}));
        Ok(reply(Value::Object(Map::new()), vec![]))
    })();
    r.unwrap_or_else(invalid)
}
