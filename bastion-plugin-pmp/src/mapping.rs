//! PMP → BastionVault translation: type lookup, slug, value
//! normalisation, asset-group derivation. Pure functions; the whole
//! module is exercised by the unit tests in `tests/`.

use std::collections::BTreeMap;

/// Sentinel strings the PMP exporter writes into otherwise-empty
/// cells. Anything matching one of these (case-insensitive, trimmed)
/// is treated as absent.
pub const EMPTY_SENTINELS: &[&str] = &["", "n/a", "na", "null", "none", "-"];

/// PMP `OS Type` row classification. Drives whether the row becomes
/// a Resource entry or a KV blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    /// Maps to a Resource (the `bv_type` is the BV resource type id).
    Resource,
    /// Maps to a KV blob under `secret/pmp-import/<batch>/<kind>/...`.
    /// `kind` is the trailing path segment (`generic-keys`,
    /// `application-passwords`, `license-store`).
    Kv,
    /// We didn't recognise the value; the wizard will prompt.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeMapping {
    pub kind: RowKind,
    /// BV resource type id when `kind == Resource`. KV kind slug when
    /// `kind == Kv` (`"generic-keys"` etc). Empty when `Unknown`.
    pub target: String,
    /// Pre-fills for the resource metadata the wizard renders.
    /// Examples: `engine=postgresql`, `vendor=fortinet`,
    /// `os_type=linux`. Always empty for KV rows.
    pub defaults: BTreeMap<String, String>,
}

impl TypeMapping {
    fn resource(ty: &str, defaults: &[(&str, &str)]) -> Self {
        Self {
            kind: RowKind::Resource,
            target: ty.into(),
            defaults: defaults.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect(),
        }
    }
    fn kv(kind: &str) -> Self {
        Self { kind: RowKind::Kv, target: kind.into(), defaults: BTreeMap::new() }
    }
    fn unknown() -> Self {
        Self { kind: RowKind::Unknown, target: String::new(), defaults: BTreeMap::new() }
    }
}

/// The fixed PMP `OS Type` → BV mapping. Match is case-insensitive
/// against the trimmed cell value. Unknown values (PMP custom
/// "Resource Types") return `RowKind::Unknown` so the wizard can
/// offer to register a custom BV type.
pub fn map_os_type(raw: &str) -> TypeMapping {
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "linux" => TypeMapping::resource("server", &[("os_type", "linux")]),
        "windows" => TypeMapping::resource("server", &[("os_type", "windows")]),
        "windowsdomain" | "windows domain" => {
            TypeMapping::resource("server", &[("os_type", "windows")])
        }
        "unix" => TypeMapping::resource("server", &[("os_type", "unix")]),
        "bsd" => TypeMapping::resource("server", &[("os_type", "bsd")]),
        "macos" | "mac os" | "darwin" => TypeMapping::resource("server", &[("os_type", "macos")]),
        "ms sql server" => TypeMapping::resource("database", &[("engine", "mssql")]),
        "mysql server" => TypeMapping::resource("database", &[("engine", "mysql")]),
        "postgresql" => TypeMapping::resource("database", &[("engine", "postgresql")]),
        "oracle db server" => TypeMapping::resource("database", &[("engine", "oracle")]),
        "cisco ios" => TypeMapping::resource("switch", &[("vendor", "cisco")]),
        "fortimanager" => TypeMapping::resource("firewall", &[("vendor", "fortinet")]),
        "web site accounts" => TypeMapping::resource("website", &[]),
        "generic keys" => TypeMapping::kv("generic-keys"),
        "application passwords" => TypeMapping::kv("application-passwords"),
        "license store" => TypeMapping::kv("license-store"),
        _ => TypeMapping::unknown(),
    }
}

/// Apply caller-supplied `type_overrides`. Override values are the BV
/// resource type id (`"firewall"`, `"network_device"`, …); they win
/// over the fixed table but we keep the `defaults` from the table so
/// `vendor=cisco` still pre-fills when an operator overrides
/// `Cisco IOS` from `switch` to `firewall`.
pub fn map_with_override(
    raw: &str,
    overrides: &BTreeMap<String, String>,
) -> TypeMapping {
    let mut m = map_os_type(raw);
    if let Some(v) = overrides.get(raw.trim()) {
        m.kind = RowKind::Resource;
        m.target = v.clone();
    }
    m
}

/// True when the trimmed lower-cased value should be treated as
/// absent. Used uniformly across every column.
pub fn is_empty(raw: &str) -> bool {
    let t = raw.trim().to_ascii_lowercase();
    EMPTY_SENTINELS.iter().any(|s| **s == t)
}

/// Normalise an optional cell — `None` for empty / sentinel values,
/// `Some(trimmed)` otherwise.
pub fn opt(raw: &str) -> Option<String> {
    if is_empty(raw) { None } else { Some(raw.trim().to_string()) }
}

/// Sanitise a name for use as a Resource or KV path segment. Allows
/// `[A-Za-z0-9._-]`; everything else collapses to `-`. Multiple
/// consecutive `-` collapse to one; leading/trailing `-` are
/// stripped. Empty input yields `unnamed`.
pub fn sanitise_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = false;
    for ch in raw.chars() {
        let keep = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
        if keep {
            out.push(ch);
            last_dash = ch == '-';
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() { "unnamed".into() } else { trimmed }
}

/// Slugify a department string into an asset-group name. Lower-cased,
/// `/` and whitespace collapsed to `-`. Unicode letters survive (BV
/// asset-group names accept Unicode).
pub fn slugify_department(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut last_dash = false;
    for ch in lower.chars() {
        if ch.is_whitespace() || ch == '/' || ch == '\\' || ch == '&' {
            if !last_dash {
                out.push('-');
                last_dash = true;
            }
        } else {
            out.push(ch);
            last_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_type_dispatches_to_the_right_bv_target() {
        assert_eq!(map_os_type("Linux").kind, RowKind::Resource);
        assert_eq!(map_os_type("Linux").target, "server");
        assert_eq!(map_os_type("Linux").defaults["os_type"], "linux");

        assert_eq!(map_os_type("MS SQL Server").target, "database");
        assert_eq!(map_os_type("MS SQL Server").defaults["engine"], "mssql");

        assert_eq!(map_os_type("Cisco IOS").target, "switch");
        assert_eq!(map_os_type("Cisco IOS").defaults["vendor"], "cisco");

        assert_eq!(map_os_type("Fortimanager").target, "firewall");
        assert_eq!(map_os_type("Fortimanager").defaults["vendor"], "fortinet");

        assert_eq!(map_os_type("Generic Keys").kind, RowKind::Kv);
        assert_eq!(map_os_type("Generic Keys").target, "generic-keys");

        assert_eq!(map_os_type("Application Passwords").target, "application-passwords");
        assert_eq!(map_os_type("License Store").target, "license-store");

        assert_eq!(map_os_type("Web Site Accounts").target, "website");

        assert_eq!(map_os_type("Arquivos de Incidentes").kind, RowKind::Unknown);
    }

    #[test]
    fn override_flips_target_but_keeps_defaults() {
        let mut o = BTreeMap::new();
        o.insert("Cisco IOS".into(), "firewall".into());
        let m = map_with_override("Cisco IOS", &o);
        assert_eq!(m.target, "firewall");
        assert_eq!(m.defaults["vendor"], "cisco");
    }

    #[test]
    fn empty_sentinels_are_treated_as_absent() {
        assert!(is_empty(""));
        assert!(is_empty("N/A"));
        assert!(is_empty("n/a"));
        assert!(is_empty("null"));
        assert!(is_empty("None"));
        assert!(is_empty(" - "));
        assert!(!is_empty("Produção"));
    }

    #[test]
    fn sanitise_name_keeps_safe_chars_and_dashifies_the_rest() {
        assert_eq!(sanitise_name("SRV-PSTDC1VDS0005"), "SRV-PSTDC1VDS0005");
        assert_eq!(sanitise_name("RDPDC2VDS0011 ( RDPDC1VDS0019 )"), "RDPDC2VDS0011-RDPDC1VDS0019");
        assert_eq!(sanitise_name("..."), "...");
        assert_eq!(sanitise_name("///"), "unnamed");
        assert_eq!(sanitise_name(""), "unnamed");
    }

    #[test]
    fn slugify_department_lowercases_and_collapses() {
        assert_eq!(slugify_department("TIC/INFRA"), "tic-infra");
        assert_eq!(slugify_department("EESP"), "eesp");
        assert_eq!(slugify_department("  Direção  Geral  "), "direção-geral");
        assert_eq!(slugify_department("Network & Security"), "network-security");
    }
}
