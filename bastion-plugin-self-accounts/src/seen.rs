//! Where an account has been released (spec §5, Phase 5).
//!
//! The picker's "first use on this host" badge and its preselection of the
//! account last used on a target both read this record. It lives in its own
//! key, `accounts/<id>/seen`, so `meta` and the listing stay small, and it
//! holds **hashes only**: never the host or origin text, so the record says
//! nothing about where an operator connects to anyone who can read storage
//! (a backup, an administrator with barrier access) unless they already know
//! the target and test it.
//!
//! The badge is a hint, never a protection. An unfamiliar target is where a
//! hostile resource definition would try to harvest a credential, so the
//! picker says so; the protection is the target binding (`matching`).

use bastion_plugin_sdk::provider::Target;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SEEN_VERSION: u32 = 1;

/// Targets remembered per account. The oldest use is evicted past this.
pub const MAX_SEEN: usize = 64;

/// Domain separation: these digests must never collide with a digest of the
/// same text computed for any other purpose.
const DOMAIN: &[u8] = b"bastionvault/self-accounts/seen-target/v1";

/// One remembered target: its digest and the time of the last release there.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeenEntry {
    /// Lowercase hex SHA-256 from [`target_hash`].
    pub h: String,
    /// Unix milliseconds of the last release for this target.
    pub at: i64,
}

/// `accounts/<id>/seen`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seen {
    pub v: u32,
    #[serde(default)]
    pub targets: Vec<SeenEntry>,
}

impl Default for Seen {
    fn default() -> Self {
        Seen { v: SEEN_VERSION, targets: Vec::new() }
    }
}

/// Why a stored record could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeenProblem {
    /// Not JSON, or not this shape. Safe to replace.
    Unreadable,
    /// Written by a newer plugin. Must not be overwritten (read-old /
    /// write-new: a downgrade must not destroy what the newer version kept).
    Newer,
}

fn is_digest(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Seen {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SeenProblem> {
        let mut s: Seen = serde_json::from_slice(bytes).map_err(|_| SeenProblem::Unreadable)?;
        if s.v == 0 {
            return Err(SeenProblem::Unreadable);
        }
        if s.v > SEEN_VERSION {
            return Err(SeenProblem::Newer);
        }
        // Anything that is not a digest is dropped, so a damaged entry can
        // never be read back as target text.
        s.targets.retain(|e| is_digest(&e.h));
        s.v = SEEN_VERSION;
        s.enforce_cap();
        Ok(s)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// When the account was last released for the target with digest `h`.
    pub fn last_use(&self, h: &str) -> Option<i64> {
        self.targets.iter().find(|e| e.h == h).map(|e| e.at)
    }

    /// Note a release for `h` at `at`, evicting the oldest use past
    /// [`MAX_SEEN`].
    pub fn record(&mut self, h: String, at: i64) {
        match self.targets.iter_mut().find(|e| e.h == h) {
            Some(e) => e.at = at,
            None => self.targets.push(SeenEntry { h, at }),
        }
        self.enforce_cap();
    }

    fn enforce_cap(&mut self) {
        while self.targets.len() > MAX_SEEN {
            let oldest = self.targets.iter().enumerate().min_by_key(|(_, e)| e.at).map(|(i, _)| i).unwrap_or(0);
            self.targets.remove(oldest);
        }
    }
}

/// A dial host as the host computed it, in one spelling: no surrounding
/// whitespace, no trailing dot, lower case. The port is deliberately not
/// part of it: the credential reaches the same machine on any port.
pub fn canonical_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// An origin in one spelling: lower case, no trailing `/`, and no explicit
/// `:443` on an `https` origin.
pub fn canonical_origin(origin: &str) -> String {
    let o = origin.trim().trim_end_matches('/').to_ascii_lowercase();
    match o.strip_suffix(":443") {
        Some(base) if base.starts_with("https://") && !base["https://".len()..].contains(':') => base.to_string(),
        _ => o,
    }
}

fn update_framed(h: &mut Sha256, part: &[u8]) {
    // Length-prefixed, so no choice of parts can be re-split into another.
    h.update((part.len() as u64).to_be_bytes());
    h.update(part);
}

/// The digest of a target: SHA-256 over the domain tag, the target kind and
/// its canonical form. SSH and RDP share the `host` kind, so a host used over
/// one protocol is not a first use over the other. Web hashes the whole set of
/// origins the recipe may fill, order-insensitively.
pub fn target_hash(target: &Target) -> String {
    let mut h = Sha256::new();
    update_framed(&mut h, DOMAIN);
    match target {
        Target::Host { host, .. } => {
            update_framed(&mut h, b"host");
            update_framed(&mut h, canonical_host(host).as_bytes());
        }
        Target::Origins { origins } => {
            let mut set: Vec<String> = origins.iter().map(|o| canonical_origin(o)).collect();
            set.sort();
            set.dedup();
            update_framed(&mut h, b"origins");
            h.update((set.len() as u64).to_be_bytes());
            for o in &set {
                update_framed(&mut h, o.as_bytes());
            }
        }
    }
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(h: &str, port: u16) -> Target {
        Target::Host { host: h.into(), port }
    }
    fn origins(o: &[&str]) -> Target {
        Target::Origins { origins: o.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn the_digest_is_canonical_and_ignores_the_port() {
        let a = target_hash(&host("dc01.corp.example.com", 3389));
        assert_eq!(a, target_hash(&host(" DC01.Corp.Example.com. ", 22)));
        assert!(is_digest(&a));
        assert_ne!(a, target_hash(&host("dc02.corp.example.com", 3389)));
    }

    #[test]
    fn the_digest_is_domain_separated() {
        // Not a bare hash of the target text, nor of the text with the kind.
        let bare = Sha256::digest(b"dc01.corp.example.com");
        let bare_hex: String = bare.iter().map(|b| format!("{b:02x}")).collect();
        assert_ne!(target_hash(&host("dc01.corp.example.com", 22)), bare_hex);
        // A host and an origin set with the same text are different targets.
        assert_ne!(target_hash(&host("dc01.corp.example.com", 22)), target_hash(&origins(&["dc01.corp.example.com"])));
    }

    #[test]
    fn origin_sets_are_order_insensitive_and_unambiguous() {
        let a = target_hash(&origins(&["https://a.example.com", "https://b.example.com:443/"]));
        assert_eq!(
            a,
            target_hash(&origins(&["https://B.example.com", "https://a.example.com", "https://a.example.com"]))
        );
        assert_ne!(a, target_hash(&origins(&["https://a.example.com"])));
        assert_ne!(a, target_hash(&origins(&["https://a.example.com:8443", "https://b.example.com"])));
        // Framing: two origins never hash like one origin holding both.
        assert_ne!(
            target_hash(&origins(&["https://a.example.com", "https://b.example.com"])),
            target_hash(&origins(&["https://a.example.com\nhttps://b.example.com"]))
        );
    }

    #[test]
    fn the_set_is_capped_and_evicts_the_oldest_use() {
        let mut s = Seen::default();
        for i in 0..(MAX_SEEN as i64 + 6) {
            s.record(format!("{i:064x}"), 1_000 + i);
        }
        assert_eq!(s.targets.len(), MAX_SEEN);
        for i in 0..6 {
            assert_eq!(s.last_use(&format!("{i:064x}")), None, "{i} is among the oldest");
        }
        assert_eq!(s.last_use(&format!("{:064x}", 6)), Some(1_006));

        // A re-use refreshes the entry instead of growing the set, and saves
        // it from the next eviction.
        s.record(format!("{:064x}", 6), 9_999);
        assert_eq!(s.targets.len(), MAX_SEEN);
        s.record(format!("{:064x}", 500), 10_000);
        assert_eq!(s.last_use(&format!("{:064x}", 6)), Some(9_999));
        assert_eq!(s.last_use(&format!("{:064x}", 7)), None, "now the oldest");
    }

    #[test]
    fn reading_drops_non_digests_and_refuses_newer_versions() {
        let raw = br#"{"v":1,"targets":[{"h":"dc01.corp.example.com","at":1},{"h":"00000000000000000000000000000000000000000000000000000000000000aa","at":2}]}"#;
        let s = Seen::from_bytes(raw).unwrap();
        assert_eq!(s.targets.len(), 1);
        assert_eq!(Seen::from_bytes(br#"{"v":2,"targets":[]}"#), Err(SeenProblem::Newer));
        assert_eq!(Seen::from_bytes(b"not json"), Err(SeenProblem::Unreadable));
        assert_eq!(Seen::from_bytes(br#"{"v":0}"#), Err(SeenProblem::Unreadable));
    }
}
