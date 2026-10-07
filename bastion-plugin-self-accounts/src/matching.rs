//! Target binding and candidate matching (spec §5).
//!
//! Why accounts carry `targets`: anyone who can edit a resource can point it at
//! any host and give it a self-account profile. Matching by resource type alone
//! cannot stop that, because the attacker chooses the type too. The host
//! supplies the target (computed from stored metadata) and this module decides.

use core::net::IpAddr;

use bastion_plugin_sdk::provider::{Resource, Target};

use crate::model::{compatible_protocols, AccountMeta, Invalid, PROTOCOLS};
use crate::settings::{RequireTargets, Settings};

/// One parsed `applies_to.targets` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// `dc01.corp.example.com`, exact, case-insensitive.
    Host(String),
    /// `*.corp.example.com`: exactly one label in place of the `*`.
    HostWildcard(String),
    /// A single IP address.
    Ip(IpAddr),
    /// `10.20.0.0/16`.
    Cidr(IpAddr, u8),
    /// `https://grafana.corp.example.com[:port]`.
    Origin { host: String, port: u16 },
    /// `https://*.corp.example.com[:port]`.
    OriginWildcard { suffix: String, port: u16 },
}

impl Pattern {
    pub fn is_origin(&self) -> bool {
        matches!(self, Pattern::Origin { .. } | Pattern::OriginWildcard { .. })
    }
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_dns(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.split('.').all(valid_label)
}

fn mask_len_ok(ip: &IpAddr, bits: u8) -> bool {
    match ip {
        IpAddr::V4(_) => bits <= 32,
        IpAddr::V6(_) => bits <= 128,
    }
}

fn split_port(authority: &str) -> Option<(&str, Option<u16>)> {
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h, Some(p.parse().ok()?))),
        Some(_) => None, // IPv6 literals are not accepted as origins
        None => Some((authority, None)),
    }
}

/// Parse one entry. The shape decides the kind: `https://…` is an origin,
/// `a.b.c.d/n` a CIDR, an IP literal an address, everything else a DNS name.
pub fn parse_pattern(raw: &str) -> Result<Pattern, Invalid> {
    let s = raw.trim().to_ascii_lowercase();
    let bad = || Invalid::new("targets entries must be a DNS name, a *.wildcard, an IP, a CIDR or an https:// origin");
    if s.is_empty() || s.len() > 256 {
        return Err(bad());
    }
    if let Some(rest) = s.strip_prefix("https://") {
        if rest.contains('/') || rest.contains('@') || rest.contains('?') || rest.contains('#') {
            return Err(Invalid::new("an origin target must be scheme://host[:port] with no path"));
        }
        let (host, port) = split_port(rest).ok_or_else(bad)?;
        let port = port.unwrap_or(443);
        if let Some(suffix) = host.strip_prefix("*.") {
            if !valid_dns(suffix) || !suffix.contains('.') {
                return Err(Invalid::new("a wildcard origin needs a registrable suffix, e.g. https://*.corp.example.com"));
            }
            return Ok(Pattern::OriginWildcard { suffix: suffix.to_string(), port });
        }
        if host.contains('*') || !valid_dns(host) {
            return Err(bad());
        }
        return Ok(Pattern::Origin { host: host.to_string(), port });
    }
    if s.contains("://") {
        return Err(Invalid::new("only https:// origins are accepted"));
    }
    if let Some((addr, bits)) = s.split_once('/') {
        let ip: IpAddr = addr.parse().map_err(|_| bad())?;
        let bits: u8 = bits.parse().map_err(|_| bad())?;
        if !mask_len_ok(&ip, bits) {
            return Err(bad());
        }
        return Ok(Pattern::Cidr(ip, bits));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Pattern::Ip(ip));
    }
    let s = s.trim_end_matches('.');
    if let Some(suffix) = s.strip_prefix("*.") {
        // A wildcard only as the whole left-most label, and never `*.com`.
        if !valid_dns(suffix) || !suffix.contains('.') {
            return Err(Invalid::new("a wildcard target needs a registrable suffix, e.g. *.corp.example.com"));
        }
        return Ok(Pattern::HostWildcard(suffix.to_string()));
    }
    if s.contains('*') || !valid_dns(s) {
        return Err(bad());
    }
    Ok(Pattern::Host(s.to_string()))
}

fn in_cidr(ip: &IpAddr, net: &IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (a, b) = (u32::from(*a), u32::from(*b));
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits as u32) };
            a & mask == b & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (a, b) = (u128::from(*a), u128::from(*b));
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits as u32) };
            a & mask == b & mask
        }
        _ => false,
    }
}

fn wildcard_matches(suffix: &str, host: &str) -> bool {
    // Exactly one label before the suffix: `a.corp.example.com` matches
    // `*.corp.example.com`; `corp.example.com` and `a.b.corp.example.com` do not.
    match host.strip_suffix(suffix).and_then(|h| h.strip_suffix('.')) {
        Some(label) => valid_label(label),
        None => false,
    }
}

/// Does a dialled host match a host-kind pattern? A DNS name is never matched
/// against a CIDR and an IP never against a DNS pattern: the plugin does not
/// resolve names.
pub fn host_matches(p: &Pattern, host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let ip = host.parse::<IpAddr>().ok();
    match p {
        Pattern::Host(h) => ip.is_none() && *h == host,
        Pattern::HostWildcard(suffix) => ip.is_none() && wildcard_matches(suffix, &host),
        Pattern::Ip(a) => ip.as_ref() == Some(a),
        Pattern::Cidr(net, bits) => ip.as_ref().is_some_and(|i| in_cidr(i, net, *bits)),
        Pattern::Origin { .. } | Pattern::OriginWildcard { .. } => false,
    }
}

/// Does an origin the recipe may fill match an origin pattern? HTTPS only.
pub fn origin_matches(p: &Pattern, origin: &str) -> bool {
    let origin = origin.trim().to_ascii_lowercase();
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    if rest.contains('/') || rest.contains('@') {
        return false;
    }
    let Some((host, port)) = split_port(rest) else {
        return false;
    };
    let port = port.unwrap_or(443);
    match p {
        Pattern::Origin { host: h, port: pp } => *h == host && *pp == port,
        Pattern::OriginWildcard { suffix, port: pp } => *pp == port && wildcard_matches(suffix, host),
        _ => false,
    }
}

/// The protocols an account applies to: its own list, or every protocol its
/// secret kind is compatible with when the list is empty.
pub fn effective_protocols(meta: &AccountMeta) -> Vec<&'static str> {
    let compatible = compatible_protocols(&meta.secret_kind);
    PROTOCOLS
        .iter()
        .copied()
        .filter(|p| compatible.contains(p))
        .filter(|p| meta.applies_to.protocols.is_empty() || meta.applies_to.protocols.iter().any(|x| x == p))
        .collect()
}

/// The single matching rule, shared by `provider.candidates` and
/// `provider.release` so that a forged or stale account id cannot be released
/// for a target it would not have been offered for.
pub fn account_matches(
    meta: &AccountMeta,
    settings: &Settings,
    protocol: &str,
    resource: &Resource,
    target: &Target,
) -> bool {
    if meta.secret_kind == crate::model::KIND_SSH_KEY && !settings.allow_ssh_keys {
        return false;
    }
    if !effective_protocols(meta).contains(&protocol) {
        return false;
    }
    if !meta.applies_to.resource_types.iter().any(|t| *t == resource.resource_type) {
        return false;
    }
    if !meta.applies_to.os_types.is_empty() {
        match &resource.os_type {
            Some(os) if meta.applies_to.os_types.iter().any(|o| o == os) => {}
            _ => return false,
        }
    }
    // Entries that no longer parse are dropped, which can only narrow the match.
    let patterns: Vec<Pattern> = meta
        .applies_to
        .targets
        .iter()
        .filter_map(|t| parse_pattern(t).ok())
        .collect();
    let (origins, hosts): (Vec<&Pattern>, Vec<&Pattern>) = patterns.iter().partition(|p| p.is_origin());

    if protocol == "web" {
        let Target::Origins { origins: wanted } = target else {
            return false;
        };
        if origins.is_empty() {
            return settings.require_targets == RequireTargets::None;
        }
        // The fill routine may run on any allowed origin, so every one must match.
        !wanted.is_empty() && wanted.iter().all(|o| origins.iter().any(|p| origin_matches(p, o)))
    } else {
        let Target::Host { host, .. } = target else {
            return false;
        };
        if hosts.is_empty() {
            return settings.require_targets != RequireTargets::All;
        }
        hosts.iter().any(|p| host_matches(p, host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Pattern {
        parse_pattern(s).unwrap_or_else(|e| panic!("{s}: {}", e.0))
    }

    #[test]
    fn dns_patterns() {
        assert!(host_matches(&p("dc01.corp.example.com"), "DC01.Corp.Example.com."));
        assert!(!host_matches(&p("dc01.corp.example.com"), "dc02.corp.example.com"));
        let w = p("*.corp.example.com");
        assert!(host_matches(&w, "a.corp.example.com"));
        assert!(!host_matches(&w, "corp.example.com"), "the apex is not a label under itself");
        assert!(!host_matches(&w, "a.b.corp.example.com"), "exactly one label");
        assert!(!host_matches(&w, "evilcorp.example.com"));
        assert!(!host_matches(&w, "a.corp.example.com.evil.org"));
    }

    #[test]
    fn wildcard_must_be_the_whole_leftmost_label_with_a_real_suffix() {
        for bad in ["*.com", "*", "a*.example.com", "*a.example.com", "a.*.example.com", "**.example.com", "*."] {
            assert!(parse_pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ip_and_cidr() {
        assert!(host_matches(&p("10.20.0.0/16"), "10.20.255.1"));
        assert!(!host_matches(&p("10.20.0.0/16"), "10.21.0.1"));
        assert!(host_matches(&p("0.0.0.0/0"), "8.8.8.8"));
        assert!(host_matches(&p("10.0.0.5"), "10.0.0.5"));
        assert!(!host_matches(&p("10.0.0.5"), "10.0.0.6"));
        assert!(host_matches(&p("fd00::/8"), "fd12::1"));
        assert!(!host_matches(&p("fd00::/8"), "fe80::1"));
        // The plugin never resolves names, in either direction.
        assert!(!host_matches(&p("10.20.0.0/16"), "dc01.corp.example.com"));
        assert!(!host_matches(&p("dc01.corp.example.com"), "10.20.0.1"));
        assert!(!host_matches(&p("*.corp.example.com"), "10.20.0.1"));
        // v4 net never matches a v6 address.
        assert!(!host_matches(&p("10.0.0.0/8"), "::ffff:10.0.0.1"));
        assert!(parse_pattern("10.0.0.0/33").is_err());
        assert!(parse_pattern("fd00::/129").is_err());
    }

    #[test]
    fn origins_are_https_only_and_port_exact() {
        let o = p("https://grafana.corp.example.com");
        assert!(origin_matches(&o, "https://grafana.corp.example.com"));
        assert!(origin_matches(&o, "https://grafana.corp.example.com:443"));
        assert!(!origin_matches(&o, "https://grafana.corp.example.com:8443"));
        assert!(!origin_matches(&o, "http://grafana.corp.example.com"));
        assert!(!origin_matches(&o, "https://grafana.corp.example.com.evil.org"));
        assert!(!origin_matches(&o, "https://user@grafana.corp.example.com"));
        assert!(!origin_matches(&o, "https://grafana.corp.example.com/login"));
        let w = p("https://*.corp.example.com");
        assert!(origin_matches(&w, "https://a.corp.example.com"));
        assert!(!origin_matches(&w, "https://corp.example.com"));
        assert!(!origin_matches(&w, "https://a.b.corp.example.com"));
        assert!(!origin_matches(&w, "https://a.corp.example.com:8443"));
        assert!(origin_matches(&p("https://x.example.com:8443"), "https://x.example.com:8443"));
    }

    #[test]
    fn origin_syntax_is_strict() {
        for bad in [
            "http://a.example.com",
            "ftp://a.example.com",
            "https://a.example.com/path",
            "https://a.example.com?x=1",
            "https://u@a.example.com",
            "https://*.com",
            "https://a.example.com:notaport",
            "https://[::1]:443",
            "",
        ] {
            assert!(parse_pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_patterns_never_match_origins_and_the_reverse() {
        assert!(!origin_matches(&p("dc01.corp.example.com"), "https://dc01.corp.example.com"));
        assert!(!host_matches(&p("https://dc01.corp.example.com"), "dc01.corp.example.com"));
    }
}
