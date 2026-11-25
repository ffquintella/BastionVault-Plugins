//! The resource as `resource_sql_target` describes it, and the choice of the
//! profile that serves a session (features/sql-browser.md §5.1, §5.2).

use std::collections::BTreeSet;

use serde_json::Value;

use crate::api::ApiError;

/// The nine statement capabilities, in policy-language order. `sql_export`
/// and `sql_script` are vault-level endpoint grants and never part of a
/// login's ceiling comparison (§5.2).
pub const STATEMENT_CAPS: [&str; 9] = [
    "sql_select",
    "sql_insert",
    "sql_update",
    "sql_delete",
    "sql_alter",
    "sql_create",
    "sql_drop",
    "sql_execute",
    "sql_admin",
];

pub const ALL_CAPS: [&str; 11] = [
    "sql_select",
    "sql_insert",
    "sql_update",
    "sql_delete",
    "sql_alter",
    "sql_create",
    "sql_drop",
    "sql_execute",
    "sql_admin",
    "sql_export",
    "sql_script",
];

/// Map a capability name onto the static spelling (unknown → `None`).
pub fn cap_static(name: &str) -> Option<&'static str> {
    ALL_CAPS.iter().copied().find(|c| *c == name)
}

/// A step-up action as the host binds it (§8.3): the capabilities in
/// policy-language order, comma-separated (`sql_drop,sql_script`).
pub fn canonical_action(caps: &BTreeSet<&'static str>) -> String {
    ALL_CAPS.iter().copied().filter(|c| caps.contains(c)).collect::<Vec<_>>().join(",")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    VerifyFull,
    VerifyCa,
    Require,
    Disable,
}

impl TlsMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "verify-full" => Some(Self::VerifyFull),
            "verify-ca" => Some(Self::VerifyCa),
            "require" => Some(Self::Require),
            "disable" => Some(Self::Disable),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifyFull => "verify-full",
            Self::VerifyCa => "verify-ca",
            Self::Require => "require",
            Self::Disable => "disable",
        }
    }

    /// Whether the connection is encrypted at all (§5.4 weak-auth rule).
    pub fn encrypted(self) -> bool {
        self != Self::Disable
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    pub mode: TlsMode,
    pub server_name: Option<String>,
    pub ca_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    Secret {
        secret_id: String,
    },
    /// Phase 9 (T130, blocked by T62). Never selected here.
    Dynamic,
}

/// One strictly parsed `sql` profile, as the host's target view lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub label: String,
    /// `host:port` the credential is bound to; the only address dialled.
    pub endpoint: String,
    pub host: String,
    pub port: u16,
    pub catalog: Option<String>,
    /// SQL Server named instance (§5.1): the server must confirm it before
    /// the login is sent. The port is the profile's; SQL Browser is never
    /// asked.
    pub instance: Option<String>,
    pub tls: Tls,
    pub ceiling: BTreeSet<&'static str>,
    pub require_mfa: bool,
    /// Capabilities whose use needs a fresh step-up ticket bound to that
    /// action (§8.3), as the profile stated them when the session opened.
    pub step_up: BTreeSet<&'static str>,
    pub source: CredentialSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    DatabaseFirst,
    ClassifierOnly,
}

impl Enforcement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DatabaseFirst => "database-first",
            Self::ClassifierOnly => "classifier-only",
        }
    }
}

/// The host's answer to `resource_sql_target`.
#[derive(Debug, Clone)]
pub struct Target {
    pub namespace: String,
    pub resource: String,
    pub engine: String,
    pub enforcement: Enforcement,
    /// Capabilities the caller holds on `sql/server` (Display probe).
    pub server_caps: BTreeSet<&'static str>,
    pub profiles: Vec<Profile>,
    /// Profiles the host listed as invalid, with its reason.
    pub invalid: Vec<(String, String)>,
}

fn bad(m: &str) -> ApiError {
    ApiError::internal(format!("malformed resource_sql_target reply: {m}"))
}

fn text(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn caps(v: Option<&Value>) -> Result<BTreeSet<&'static str>, ()> {
    let list = v.and_then(Value::as_array).ok_or(())?;
    list.iter().map(|c| c.as_str().and_then(cap_static).ok_or(())).collect()
}

impl Profile {
    /// Parse one profile view. Any missing or wrongly typed field refuses
    /// the profile (it is then never selected).
    pub fn parse(v: &Value) -> Result<Self, String> {
        let req = |k: &str| text(v, k).filter(|s| !s.is_empty()).ok_or_else(|| format!("`{k}` missing"));
        let tls = v.get("tls").ok_or("`tls` missing")?;
        let mode = tls.get("mode").and_then(Value::as_str).and_then(TlsMode::parse).ok_or("bad `tls.mode`")?;
        let opt = |o: &Value, k: &str| -> Result<Option<String>, String> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
                _ => Err(format!("bad `{k}`")),
            }
        };
        let ceiling = caps(v.get("ceiling")).map_err(|_| "bad `ceiling`".to_string())?;
        if ceiling.is_empty() || ceiling.iter().any(|c| !STATEMENT_CAPS.contains(c)) {
            return Err("`ceiling` must list statement capabilities".into());
        }
        let source = match v.get("credential_source").and_then(|s| s.get("kind")).and_then(Value::as_str) {
            Some("secret") => CredentialSource::Secret {
                secret_id: v["credential_source"]
                    .get("secret_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or("bad `credential_source.secret_id`")?
                    .to_string(),
            },
            Some("dynamic") => CredentialSource::Dynamic,
            _ => return Err("bad `credential_source`".into()),
        };
        let port = v.get("port").and_then(Value::as_u64).filter(|p| (1..=65535).contains(p)).ok_or("bad `port`")?;
        // The host's view always lists `step_up` (T124); a missing or
        // malformed list fails the profile rather than reading as "none".
        let step_up = caps(v.get("step_up")).map_err(|_| "bad `step_up`".to_string())?;
        Ok(Self {
            id: req("id")?,
            label: text(v, "label").unwrap_or_default(),
            endpoint: req("endpoint")?,
            host: req("host")?,
            port: port as u16,
            catalog: opt(v, "catalog")?,
            instance: opt(v, "instance")?,
            tls: Tls { mode, server_name: opt(tls, "server_name")?, ca_pem: opt(tls, "ca_pem")? },
            ceiling,
            require_mfa: v.get("require_mfa").and_then(Value::as_bool).ok_or("bad `require_mfa`")?,
            step_up,
            source,
        })
    }
}

impl Target {
    pub fn parse(reply: &Value) -> Result<Self, ApiError> {
        let t = reply.get("target").ok_or_else(|| bad("no `target`"))?;
        let enforcement = match t.get("enforcement").and_then(Value::as_str) {
            Some("database-first") => Enforcement::DatabaseFirst,
            Some("classifier-only") => Enforcement::ClassifierOnly,
            // An unknown mode is never read as the weaker one.
            _ => return Err(bad("unknown enforcement mode")),
        };
        let mut profiles = Vec::new();
        let mut invalid = Vec::new();
        for p in t.get("profiles").and_then(Value::as_array).ok_or_else(|| bad("no `profiles`"))? {
            match Profile::parse(p) {
                Ok(p) => profiles.push(p),
                Err(e) => invalid.push((text(p, "id").unwrap_or_default(), e)),
            }
        }
        for p in t.get("invalid_profiles").and_then(Value::as_array).into_iter().flatten() {
            invalid.push((text(p, "id").unwrap_or_default(), text(p, "reason").unwrap_or_default()));
        }
        // Capabilities the host reports that this plugin does not know are
        // ignored rather than trusted.
        let server_caps = reply
            .get("privileges")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|c| c.as_str().and_then(cap_static)).collect())
            .unwrap_or_default();
        Ok(Self {
            namespace: text(reply, "namespace").unwrap_or_default().trim_matches('/').to_string(),
            resource: text(reply, "resource").ok_or_else(|| bad("no `resource`"))?,
            engine: text(t, "engine").ok_or_else(|| bad("no `engine`"))?,
            enforcement,
            server_caps,
            profiles,
            invalid,
        })
    }
}

/// The profile chosen for a session and what follows from it.
#[derive(Debug, Clone)]
pub struct Selection {
    pub profile: Profile,
    /// The caller's statement capabilities the selection was made for.
    pub grant: BTreeSet<&'static str>,
    /// `sql_select` only (optionally with export): the session is read-only
    /// at the database too (§5.3).
    pub read_only: bool,
    /// Capabilities the login can use but the vault alone refuses.
    pub vault_only: Vec<&'static str>,
    /// Every capability the caller holds is also all the login can do.
    pub db_enforced: bool,
    /// Capabilities the caller holds that the chosen login's ceiling does not
    /// reach: the session is clamped to refuse them (never silently
    /// widened), and the GUI shows them.
    pub narrowed_out: Vec<&'static str>,
}

/// §5.2: the smallest stored-secret profile whose ceiling covers the
/// caller's statement capabilities; a read-only grant is served only by an
/// exactly read-only login under `database-first`. `requested` narrows the
/// choice to one profile, which must itself qualify.
///
/// When no profile covers the whole grant, the session is *narrowed* to the
/// profile whose ceiling reaches the most of it (smallest ceiling on a tie):
/// the session's capabilities are the grant intersected with that ceiling,
/// the rest is listed in `narrowed_out` and refused by the session, and the
/// caller is never given more than the login can do. A profile that reaches
/// none of the grant never serves.
pub fn select(target: &Target, requested: Option<&str>) -> Result<Selection, ApiError> {
    let full: BTreeSet<&'static str> =
        target.server_caps.iter().copied().filter(|c| STATEMENT_CAPS.contains(c)).collect();
    if full.is_empty() {
        return Err(ApiError::refused(
            "no_sql_privilege",
            "the caller holds no statement capability (sql_select … sql_admin) on this resource's sql/server",
        ));
    }
    let candidates: Vec<&Profile> = target
        .profiles
        .iter()
        .filter(|p| requested.is_none_or(|r| p.id == r))
        .filter(|p| matches!(p.source, CredentialSource::Secret { .. }))
        .collect();
    if let Some(r) = requested {
        if candidates.is_empty() {
            return Err(ApiError::refused(
                "profile_not_found",
                format!("no usable `sql` profile `{r}` on this resource (dynamic profiles arrive with Phase 9)"),
            ));
        }
    }
    let database_first = target.enforcement == Enforcement::DatabaseFirst;
    // Whether `p` may serve `grant`: a read-only grant under `database-first`
    // needs an exactly read-only login, otherwise the ceiling must cover it.
    let serves = |p: &Profile, grant: &BTreeSet<&'static str>| -> bool {
        let read_only = grant.len() == 1 && grant.contains("sql_select");
        if read_only && database_first {
            p.ceiling.len() == 1 && p.ceiling.contains("sql_select")
        } else {
            grant.is_subset(&p.ceiling)
        }
    };
    let mut pick: Option<(&Profile, BTreeSet<&'static str>)> = candidates
        .iter()
        .copied()
        .filter(|p| serves(p, &full))
        .min_by_key(|p| p.ceiling.len())
        .map(|p| (p, full.clone()));
    if pick.is_none() {
        // Narrow: most of the grant reached first, then the smallest ceiling.
        pick = candidates
            .iter()
            .copied()
            .filter_map(|p| {
                let eff: BTreeSet<&'static str> = full.intersection(&p.ceiling).copied().collect();
                (!eff.is_empty() && serves(p, &eff)).then_some((p, eff))
            })
            .min_by_key(|(p, eff)| (std::cmp::Reverse(eff.len()), p.ceiling.len()));
    }
    let Some((profile, grant)) = pick else {
        let read_only = full.len() == 1 && full.contains("sql_select");
        let msg = if read_only && database_first {
            "this resource has no read-only SQL profile (ceiling exactly [\"sql_select\"]) for a read-only grant; \
             an administrator must add a read-only login, enable dynamic credentials, or set the resource to \
             classifier-only enforcement"
                .to_string()
        } else {
            format!(
                "no SQL profile's ceiling reaches any of the caller's grant [{}]",
                full.iter().copied().collect::<Vec<_>>().join(", ")
            )
        };
        return Err(ApiError::refused("no_profile_for_grant", msg));
    };
    let read_only = grant.len() == 1 && grant.contains("sql_select");
    let narrowed_out: Vec<&'static str> = full.difference(&grant).copied().collect();
    let vault_only: Vec<&'static str> = profile.ceiling.difference(&grant).copied().collect();
    Ok(Selection {
        profile: profile.clone(),
        db_enforced: vault_only.is_empty(),
        grant,
        read_only,
        vault_only,
        narrowed_out,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub fn profile_json(id: &str, ceiling: &[&str]) -> Value {
        json!({"id": id, "label": id, "endpoint": "10.0.0.5:5432", "host": "10.0.0.5", "port": 5432,
            "catalog": "app", "instance": null,
            "tls": {"mode": "verify-full", "server_name": null, "ca_pem": null},
            "ceiling": ceiling, "require_mfa": false, "step_up": [],
            "credential_source": {"kind": "secret", "secret_id": format!("{id}-secret")}})
    }

    pub fn target_json(enforcement: &str, privileges: &[&str], profiles: Vec<Value>) -> Value {
        json!({"namespace": "", "resource": "db", "privileges": privileges,
            "target": {"resource": "db", "type": "database", "engine": "postgresql", "default_port": 5432,
                "hostname": "db.internal", "ip_address": null, "database_name": "app",
                "enforcement": enforcement, "profiles": profiles, "invalid_profiles": []}})
    }

    fn sel(enf: &str, privs: &[&str], profiles: Vec<Value>, req: Option<&str>) -> Result<Selection, ApiError> {
        select(&Target::parse(&target_json(enf, privs, profiles)).unwrap(), req)
    }

    fn standard() -> Vec<Value> {
        vec![
            profile_json("admin", &STATEMENT_CAPS),
            profile_json("rw", &["sql_select", "sql_insert", "sql_update", "sql_delete"]),
            profile_json("ro", &["sql_select"]),
        ]
    }

    #[test]
    fn the_smallest_covering_profile_serves() {
        let s = sel("database-first", &["sql_select", "sql_update"], standard(), None).unwrap();
        assert_eq!(s.profile.id, "rw");
        assert!(!s.read_only && !s.db_enforced);
        assert_eq!(s.vault_only, vec!["sql_delete", "sql_insert"]);
        let s = sel("database-first", &["sql_select", "sql_insert", "sql_update", "sql_delete"], standard(), None);
        assert!(s.unwrap().db_enforced);
        assert_eq!(sel("database-first", &["sql_drop"], standard(), None).unwrap().profile.id, "admin");
    }

    #[test]
    fn a_read_only_grant_needs_an_exactly_read_only_login_under_database_first() {
        let s = sel("database-first", &["sql_select", "sql_export"], standard(), None).unwrap();
        assert_eq!(s.profile.id, "ro");
        assert!(s.read_only && s.db_enforced);
        let no_ro = vec![profile_json("admin", &STATEMENT_CAPS)];
        let e = sel("database-first", &["sql_select"], no_ro.clone(), None).unwrap_err();
        assert_eq!(e.code, "no_profile_for_grant");
        // classifier-only: the broader login may serve, flagged as not
        // database-enforced; never silently.
        let s = sel("classifier-only", &["sql_select"], no_ro, None).unwrap();
        assert_eq!(s.profile.id, "admin");
        assert!(s.read_only && !s.db_enforced);
    }

    #[test]
    fn a_requested_profile_must_qualify() {
        let e = sel("database-first", &["sql_select"], standard(), Some("admin")).unwrap_err();
        assert_eq!(e.code, "no_profile_for_grant", "a read-only caller cannot pick the admin login");
        assert_eq!(sel("database-first", &["sql_select"], standard(), Some("ro")).unwrap().profile.id, "ro");
        assert_eq!(
            sel("database-first", &["sql_select"], standard(), Some("nope")).unwrap_err().code,
            "profile_not_found"
        );
        // The request cannot widen or bypass: rw reaches select only, and a
        // narrowed read-only session still needs the exact read-only login.
        let e = sel("database-first", &["sql_select", "sql_admin"], standard(), Some("rw")).unwrap_err();
        assert_eq!(e.code, "no_profile_for_grant");
    }

    #[test]
    fn a_grant_above_every_ceiling_is_narrowed_to_the_best_profile() {
        let ro_only = vec![profile_json("ro", &["sql_select"])];
        // The reported case: every privilege, one read-only login, classifier-only.
        let s = sel("classifier-only", &STATEMENT_CAPS, ro_only.clone(), None).unwrap();
        assert_eq!(s.profile.id, "ro");
        assert_eq!(s.grant.iter().copied().collect::<Vec<_>>(), vec!["sql_select"]);
        assert!(s.read_only && s.db_enforced);
        assert_eq!(s.narrowed_out.len(), STATEMENT_CAPS.len() - 1);
        assert!(s.narrowed_out.contains(&"sql_admin") && !s.narrowed_out.contains(&"sql_select"));
        // The same under database-first: the narrowed session is exactly read-only.
        assert_eq!(sel("database-first", &STATEMENT_CAPS, ro_only, None).unwrap().profile.id, "ro");
        // The profile reaching the most of the grant wins over a smaller one.
        let s = sel("database-first", &["sql_select", "sql_update", "sql_admin"], standard()[1..].to_vec(), None);
        let s = s.unwrap();
        assert_eq!(s.profile.id, "rw");
        assert_eq!(s.narrowed_out, vec!["sql_admin"]);
        assert_eq!(s.vault_only, vec!["sql_delete", "sql_insert"]);
        // A full cover is never narrowed.
        assert!(sel("database-first", &STATEMENT_CAPS, standard(), None).unwrap().narrowed_out.is_empty());
        // A login that reaches none of the grant never serves.
        let e = sel("classifier-only", &["sql_drop"], vec![profile_json("ro", &["sql_select"])], None).unwrap_err();
        assert_eq!(e.code, "no_profile_for_grant");
        // Narrowing down to a read-only session under database-first still
        // needs an exactly read-only login: rw is not enough.
        let rw = vec![profile_json("rw", &["sql_select", "sql_insert"])];
        let s = sel("database-first", &["sql_select", "sql_drop"], rw, None);
        assert_eq!(s.unwrap_err().code, "no_profile_for_grant");
    }

    #[test]
    fn export_and_script_alone_open_nothing() {
        assert_eq!(sel("database-first", &["sql_export"], standard(), None).unwrap_err().code, "no_sql_privilege");
        assert_eq!(sel("database-first", &[], standard(), None).unwrap_err().code, "no_sql_privilege");
    }

    #[test]
    fn malformed_profiles_and_dynamic_sources_are_never_selected() {
        let mut broken = profile_json("ro", &["sql_select"]);
        broken["tls"]["mode"] = json!("prefer");
        let mut dynamic = profile_json("dyn", &["sql_select"]);
        dynamic["credential_source"] = json!({"kind": "dynamic", "mount": "db/", "role": "ro"});
        let mut extra_cap = profile_json("x", &["sql_select"]);
        extra_cap["ceiling"] = json!(["sql_select", "sql_export"]);
        let t =
            Target::parse(&target_json("database-first", &["sql_select"], vec![broken, dynamic, extra_cap])).unwrap();
        assert_eq!(t.profiles.len(), 1, "only the dynamic profile parses");
        assert_eq!(t.invalid.len(), 2);
        assert_eq!(select(&t, None).unwrap_err().code, "no_profile_for_grant");
    }

    #[test]
    fn step_up_lists_parse_strictly() {
        let mut p = profile_json("ro", &["sql_select"]);
        p["step_up"] = json!(["sql_script", "sql_drop"]);
        let parsed = Profile::parse(&p).unwrap();
        assert_eq!(canonical_action(&parsed.step_up), "sql_drop,sql_script");
        for bad in [json!(null), json!("sql_drop"), json!(["sql_nope"]), json!([1])] {
            let mut q = profile_json("ro", &["sql_select"]);
            q["step_up"] = bad.clone();
            assert!(Profile::parse(&q).is_err(), "{bad}");
        }
        let mut q = profile_json("ro", &["sql_select"]);
        q.as_object_mut().unwrap().remove("step_up");
        assert!(Profile::parse(&q).is_err(), "a missing step_up is not \"none\"");
        assert_eq!(canonical_action(&BTreeSet::new()), "");
    }

    #[test]
    fn an_unknown_enforcement_mode_is_refused() {
        let mut t = target_json("database-first", &["sql_select"], standard());
        t["target"]["enforcement"] = json!("vault-only");
        assert!(Target::parse(&t).is_err());
    }
}
