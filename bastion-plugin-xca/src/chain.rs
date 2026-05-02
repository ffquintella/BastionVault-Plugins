//! Issuance-chain detection across the imported XCA cert set.
//!
//! The host's PKI engine partitions certs into two destinations:
//! issuers (which sign) and leaves (which don't). Until v0.1.8 the
//! plugin reported only `is_ca` (BasicConstraints `cA=true` or XCA's
//! own `certs.ca` column) and the GUI routed CA-flagged certs to the
//! issuer-import path. That over-classifies — a CA-flagged cert that
//! never actually signed anything in the file still landed on the
//! issuers tab.
//!
//! v0.1.9 walks the imported cert graph and reports, for each cert:
//!
//! - `signs_others` — true when at least one *other* cert in the same
//!   import set has this cert as its signer (matched by AKI/SKI when
//!   available, falling back to Issuer/Subject DN equality), OR when
//!   this is a self-signed cert whose `BasicConstraints.cA` is set
//!   (so an operator importing only a root-of-trust still gets it
//!   classed as an emitter).
//! - `signer_item_id` — the `items.id` of the parent cert in the same
//!   import set, when found. `None` for self-signed roots and for
//!   leaves whose issuer is off-set.
//! - `signer_subject` — the cert's Issuer DN as text, always populated
//!   so the GUI can render an emitter label even when the issuer
//!   isn't on this XCA file.
//!
//! Linking strategy:
//!
//! 1. **AuthorityKeyIdentifier → SubjectKeyIdentifier.** RFC 5280's
//!    canonical chain link. Reliable when both extensions are present
//!    and use the same hash.
//! 2. **Issuer DN → Subject DN.** Universal fallback; works on every
//!    cert because the DN fields are mandatory.
//!
//! Ambiguity (multiple parents share a Subject DN, or two certs share
//! an SKI hash collision) resolves first-match-wins. Real deployments
//! don't carry duplicates of the same CA across an XCA file.

use std::collections::BTreeMap;

use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::*;

/// Per-cert result of the chain walk. Keyed by `items.id` in the
/// caller. `signer_item_id` is the parent's id; `signer_subject` is
/// the human-readable issuer DN (always set, regardless of whether
/// the parent is in the import set).
#[derive(Debug, Clone)]
pub struct ChainInfo {
    pub signs_others: bool,
    pub signer_item_id: Option<i64>,
    pub signer_subject: String,
    /// Whether the cert is self-signed (Subject == Issuer or
    /// AKI == SKI). Surfaced here so future routing decisions don't
    /// have to re-parse the DER; today only the unit tests read it.
    #[allow(dead_code)]
    pub self_signed: bool,
}

/// Walk the cert graph defined by `(items.id, cert.der)` tuples and
/// return one [`ChainInfo`] per id. Order of the input vector is
/// preserved in the returned map only conceptually — callers iterate
/// by id.
pub fn analyze(certs: &[(i64, &[u8])]) -> BTreeMap<i64, ChainInfo> {
    // Pass 1 — extract per-cert features. Certs that fail to parse
    // are reported as a barebones `ChainInfo` so the caller can still
    // surface them in the preview.
    #[derive(Default)]
    struct Features {
        subject_dn: String,
        issuer_dn: String,
        subject_key_id: Option<Vec<u8>>,
        authority_key_id: Option<Vec<u8>>,
        is_ca_flagged: bool,
    }
    let mut features: BTreeMap<i64, Features> = BTreeMap::new();
    for (id, der) in certs {
        let mut f = Features::default();
        if let Ok((_, cert)) = X509Certificate::from_der(der) {
            f.subject_dn = cert.tbs_certificate.subject.to_string();
            f.issuer_dn = cert.tbs_certificate.issuer.to_string();
            for ext in cert.tbs_certificate.extensions() {
                match ext.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(ski) => {
                        f.subject_key_id = Some(ski.0.to_vec());
                    }
                    ParsedExtension::AuthorityKeyIdentifier(aki) => {
                        if let Some(kid) = &aki.key_identifier {
                            f.authority_key_id = Some(kid.0.to_vec());
                        }
                    }
                    ParsedExtension::BasicConstraints(bc) => {
                        f.is_ca_flagged = bc.ca;
                    }
                    _ => {}
                }
            }
        }
        features.insert(*id, f);
    }

    // Pass 2 — build the lookup tables for parent resolution.
    let mut by_subject_dn: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_subject_key_id: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
    for (id, f) in &features {
        if !f.subject_dn.is_empty() {
            by_subject_dn.entry(f.subject_dn.clone()).or_insert(*id);
        }
        if let Some(ski) = &f.subject_key_id {
            by_subject_key_id.entry(ski.clone()).or_insert(*id);
        }
    }

    // Pass 3 — resolve parents. Parent precedence: AKI → SKI match,
    // then Issuer DN → Subject DN. A cert that resolves itself as its
    // own parent is treated as self-signed.
    let mut parents: BTreeMap<i64, Option<i64>> = BTreeMap::new();
    let mut self_signed: BTreeMap<i64, bool> = BTreeMap::new();
    for (id, f) in &features {
        let parent = f
            .authority_key_id
            .as_ref()
            .and_then(|aki| by_subject_key_id.get(aki).copied())
            .or_else(|| {
                if !f.issuer_dn.is_empty() {
                    by_subject_dn.get(&f.issuer_dn).copied()
                } else {
                    None
                }
            });
        let is_self = match parent {
            Some(p) if p == *id => true,
            None => {
                // No parent in the set, but Subject == Issuer is the
                // canonical self-signed signal. We accept that even
                // when neither key-identifier extension was present.
                !f.subject_dn.is_empty() && f.subject_dn == f.issuer_dn
            }
            _ => false,
        };
        // Self-signed: don't carry a parent id. A cert is its own
        // signer; the caller doesn't need to wire that as a separate
        // entry in `signer_item_id`.
        let parent_for_link = match parent {
            Some(p) if p != *id => Some(p),
            _ => None,
        };
        parents.insert(*id, parent_for_link);
        self_signed.insert(*id, is_self);
    }

    // Pass 4 — figure out which certs signed at least one *other*
    // cert in the set.
    let mut signs_others_set: std::collections::BTreeSet<i64> =
        std::collections::BTreeSet::new();
    for (child_id, parent_id) in &parents {
        if let Some(p) = parent_id {
            if p != child_id {
                signs_others_set.insert(*p);
            }
        }
    }

    // Pass 5 — assemble the public ChainInfo per id. A self-signed
    // root with `BasicConstraints.cA = true` is reported as an
    // emitter even when nothing else in the set was signed by it,
    // so an operator importing a single trust-anchor cert still
    // gets it routed to the issuers tab.
    let mut out: BTreeMap<i64, ChainInfo> = BTreeMap::new();
    for (id, f) in features {
        let signer_item_id = parents.get(&id).copied().flatten();
        let is_self = *self_signed.get(&id).unwrap_or(&false);
        let signs_others = signs_others_set.contains(&id) || (is_self && f.is_ca_flagged);
        out.insert(
            id,
            ChainInfo {
                signs_others,
                signer_item_id,
                signer_subject: f.issuer_dn,
                self_signed: is_self,
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: a single self-signed cert with cA=true ends up as a
    /// signs_others=true root. Sibling leaves get parent ids.
    /// Built with rcgen so the test stays deterministic and doesn't
    /// require committed test fixtures.
    #[test]
    fn detects_root_and_leaves() {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
        };

        // Build a self-signed CA.
        let ca_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "TestRoot");
        ca_params.distinguished_name = dn;
        let ca = ca_params.self_signed(&ca_kp).unwrap();
        let ca_pem = ca.pem();
        let ca_der = ca.der().to_vec();
        let ca_issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_kp).unwrap();

        // Build a leaf signed by the CA.
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        let mut ldn = DistinguishedName::new();
        ldn.push(DnType::CommonName, "leaf.example");
        leaf_params.distinguished_name = ldn;
        let leaf = leaf_params.signed_by(&leaf_kp, &ca_issuer).unwrap();
        let leaf_der = leaf.der().to_vec();
        let result =
            analyze(&[(1, ca_der.as_slice()), (2, leaf_der.as_slice())]);
        let ca_info = &result[&1];
        let leaf_info = &result[&2];
        assert!(ca_info.signs_others, "CA must sign others");
        assert!(ca_info.self_signed);
        assert!(!leaf_info.signs_others, "leaf must not sign others");
        assert_eq!(leaf_info.signer_item_id, Some(1));
        assert!(!leaf_info.signer_subject.is_empty());
    }

    /// A CA-flagged cert that signed nothing in the import set is
    /// still a "root of trust" emitter when self-signed (e.g. an
    /// operator importing only a trust anchor).
    #[test]
    fn standalone_self_signed_ca_is_emitter() {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
            PKCS_ECDSA_P256_SHA256,
        };
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Lone");
        params.distinguished_name = dn;
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der().to_vec();
        let result = analyze(&[(7, der.as_slice())]);
        assert!(result[&7].signs_others);
        assert!(result[&7].self_signed);
    }

    /// A standalone leaf (no parent in set, not self-signed) is not
    /// an emitter and reports `signer_item_id = None` but still has
    /// a populated `signer_subject` (the issuer DN as text).
    #[test]
    fn standalone_leaf_has_only_issuer_text() {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
            PKCS_ECDSA_P256_SHA256,
        };
        let ca_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "OffSetCA");
        ca_params.distinguished_name = dn;
        let ca = ca_params.self_signed(&ca_kp).unwrap();
        let ca_pem = ca.pem();
        let ca_issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_kp).unwrap();

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["solo".into()]).unwrap();
        let mut ldn = DistinguishedName::new();
        ldn.push(DnType::CommonName, "solo");
        leaf_params.distinguished_name = ldn;
        let leaf = leaf_params.signed_by(&leaf_kp, &ca_issuer).unwrap();

        let der = leaf.der().to_vec();
        // Only the leaf is in the set — the CA stays out.
        let result = analyze(&[(11, der.as_slice())]);
        assert!(!result[&11].signs_others);
        assert!(!result[&11].self_signed);
        assert_eq!(result[&11].signer_item_id, None);
        assert!(!result[&11].signer_subject.is_empty());
    }
}
