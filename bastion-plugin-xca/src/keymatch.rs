//! Pair certs with their private keys by public-key fingerprint.
//!
//! XCA stores cert/key pairs without an explicit linkage column —
//! `items.pid` tracks the issuer chain, not the key. XCA matches at
//! runtime by comparing public keys, so we do the same.
//!
//! We compute a SHA-256 fingerprint of the algorithm-specific
//! "encoded public key bytes": exactly what the cert's
//! `SubjectPublicKeyInfo.subjectPublicKey` BIT STRING already
//! contains. For each algorithm, the same byte string is recoverable
//! from the (decrypted) PKCS#8 PrivateKeyInfo:
//!
//! - **RSA** (`rsaEncryption`): re-encode `RSAPublicKey { n, e }`
//!   from the inner `RSAPrivateKey`.
//! - **EC** (`ecPublicKey`): SEC1 `ECPrivateKey` carries a `[1]
//!   EXPLICIT publicKey BIT STRING` — its content is the encoded
//!   ECPoint, identical to what the cert's SPKI carries.
//! - **Ed25519 / Ed448** (RFC 8410): `OneAsymmetricKey` v2 carries
//!   `[1] IMPLICIT publicKey BIT STRING` — its content is the raw
//!   32 / 57-byte public key.
//!
//! Algorithms whose private-key encoding doesn't carry the public
//! half (Ed25519 v1 PKCS#8, etc.) yield `None`. The caller falls
//! back to no pairing for those rows.

use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// 32-byte SHA-256 of the algorithm's canonical public-key byte
/// string (the same bytes that live in the cert's SPKI BIT STRING).
pub type KeyFingerprint = [u8; 32];

/// Fingerprint a cert from its DER. Returns `None` for an
/// unparseable cert (we don't try to be clever — a cert that
/// doesn't parse can't pair with anything anyway).
pub fn fingerprint_cert(cert_der: &[u8]) -> Option<KeyFingerprint> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let spki = &cert.tbs_certificate.subject_pki;
    Some(sha256(spki.subject_public_key.data.as_ref()))
}

/// Fingerprint a decrypted PKCS#8 `PrivateKeyInfo`. Returns `None`
/// for algorithms whose private-key form doesn't include the public
/// half — caller should treat those as un-pairable.
pub fn fingerprint_private_key(pkcs8_der: &[u8]) -> Option<KeyFingerprint> {
    let pk = parse_pkcs8(pkcs8_der)?;
    if pk.alg_oid == OID_RSA_ENCRYPTION {
        let pubkey = rsa_public_from_private(pk.private_key)?;
        Some(sha256(&pubkey))
    } else if pk.alg_oid == OID_EC_PUBLIC_KEY {
        let bits = ec_public_from_private(pk.private_key)?;
        Some(sha256(&bits))
    } else if pk.alg_oid == OID_ED25519 || pk.alg_oid == OID_ED448 {
        // The optional [1] IMPLICIT publicKey BIT STRING is the only
        // path to a fingerprint here without doing curve math.
        let bits = pk.public_key?;
        Some(sha256(bits))
    } else {
        None
    }
}

fn sha256(bytes: &[u8]) -> KeyFingerprint {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// ── PKCS#8 PrivateKeyInfo / OneAsymmetricKey walker ────────────────

const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_ED448: &[u8] = &[0x2B, 0x65, 0x71];

struct Pkcs8<'a> {
    alg_oid: &'a [u8],
    /// Content of the privateKey OCTET STRING.
    private_key: &'a [u8],
    /// Content of the optional [1] IMPLICIT publicKey BIT STRING
    /// (already stripped of the leading "unused bits" octet).
    public_key: Option<&'a [u8]>,
}

fn parse_pkcs8(blob: &[u8]) -> Option<Pkcs8<'_>> {
    let (outer, _) = take_tlv(blob, 0x30)?; // SEQUENCE
    // version INTEGER
    let (_version, after_version) = take_tlv(outer, 0x02)?;
    // privateKeyAlgorithm SEQUENCE { OID, params }
    let (alg_seq, after_alg) = take_tlv(after_version, 0x30)?;
    let (alg_oid, _alg_rest) = take_tlv(alg_seq, 0x06)?;
    // privateKey OCTET STRING
    let (private_key_outer, after_pk) = take_tlv(after_alg, 0x04)?;
    // Optional [0] attributes / [1] publicKey
    let mut rest = after_pk;
    let mut public_key: Option<&[u8]> = None;
    while !rest.is_empty() {
        let tag = rest[0];
        let (body, next) = take_tlv(rest, tag)?;
        if tag == 0xA1 {
            // [1] IMPLICIT BIT STRING — body starts with unused-bits
            // octet, then the raw key bytes.
            if let Some((&_unused, key_bytes)) = body.split_first() {
                public_key = Some(key_bytes);
            }
        }
        rest = next;
    }
    Some(Pkcs8 {
        alg_oid,
        private_key: private_key_outer,
        public_key,
    })
}

/// Build the canonical `RSAPublicKey ::= SEQUENCE { n, e }` DER from
/// an `RSAPrivateKey`'s modulus + publicExponent.
fn rsa_public_from_private(rsa_priv: &[u8]) -> Option<Vec<u8>> {
    // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, ... }
    let (seq, _) = take_tlv(rsa_priv, 0x30)?;
    let (_version, after_v) = take_tlv(seq, 0x02)?;
    let (n_body, after_n) = take_tlv(after_v, 0x02)?;
    let (e_body, _) = take_tlv(after_n, 0x02)?;
    let n_tlv = encode_tlv(0x02, n_body);
    let e_tlv = encode_tlv(0x02, e_body);
    let mut inner = Vec::with_capacity(n_tlv.len() + e_tlv.len());
    inner.extend_from_slice(&n_tlv);
    inner.extend_from_slice(&e_tlv);
    Some(encode_tlv(0x30, &inner))
}

/// Pull the public-key bytes from an SEC1 `ECPrivateKey`'s optional
/// `[1] EXPLICIT publicKey BIT STRING`.
fn ec_public_from_private(ec_priv: &[u8]) -> Option<Vec<u8>> {
    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER,
    //   privateKey OCTET STRING,
    //   parameters [0] EXPLICIT ECParameters OPTIONAL,
    //   publicKey  [1] EXPLICIT BIT STRING OPTIONAL
    // }
    let (seq, _) = take_tlv(ec_priv, 0x30)?;
    let (_version, after_v) = take_tlv(seq, 0x02)?;
    let (_priv, after_priv) = take_tlv(after_v, 0x04)?;
    let mut rest = after_priv;
    while !rest.is_empty() {
        let tag = rest[0];
        let (body, next) = take_tlv(rest, tag)?;
        if tag == 0xA1 {
            // [1] EXPLICIT — inner is a real BIT STRING (tag 0x03)
            // whose body starts with the unused-bits octet.
            let (bs, _) = take_tlv(body, 0x03)?;
            let (&_unused, key_bytes) = bs.split_first()?;
            return Some(key_bytes.to_vec());
        }
        rest = next;
    }
    None
}

fn take_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if input.is_empty() || input[0] != expected_tag {
        return None;
    }
    let (len, header_len) = decode_length(&input[1..])?;
    let total = 1 + header_len + len;
    if input.len() < total {
        return None;
    }
    Some((&input[1 + header_len..total], &input[total..]))
}

fn decode_length(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || input.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &input[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

fn encode_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    encode_length_into(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn encode_length_into(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut buf = [0u8; 8];
    let mut n = len;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = (n & 0xff) as u8;
        n >>= 8;
    }
    let bytes = &buf[i..];
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(bytes);
}
