//! Random identifiers and keyed digests, on ring's vetted primitives.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// `n` random bytes from the OS, as lowercase hex. `None` when the OS
/// generator fails; callers refuse rather than fall back to a weaker source.
pub fn random_hex(n: usize) -> Option<String> {
    let mut buf = vec![0u8; n];
    SystemRandom::new().fill(&mut buf).ok()?;
    Some(hex(&buf))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// This process's instance prefix: every session id it mints starts with
/// it, so a request for a session served elsewhere is recognised (§6.5).
pub fn instance_id() -> String {
    random_hex(8).unwrap_or_else(|| "0000000000000000".into())
}

/// A session id: the instance prefix and 256 random bits (§6.1).
pub fn session_id(instance: &str) -> Option<String> {
    Some(format!("{instance}-{}", random_hex(32)?))
}

/// The instance prefix of a session id, when it is well formed.
pub fn instance_of(session_id: &str) -> Option<&str> {
    let (prefix, rest) = session_id.split_once('-')?;
    let well_formed = prefix.len() == 16
        && rest.len() == 64
        && prefix.bytes().chain(rest.bytes()).all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    well_formed.then_some(prefix)
}

/// HMAC-SHA256 under the plugin's digest key, hex. Statement and row-key
/// digests (§7, §11): comparable within a deployment, never reversible.
pub fn digest(key: &[u8], label: &str, data: &[u8]) -> String {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(label.as_bytes());
    ctx.update(&[0]);
    ctx.update(data);
    hex(ctx.sign().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_carry_the_instance_and_256_bits() {
        let inst = instance_id();
        let a = session_id(&inst).unwrap();
        let b = session_id(&inst).unwrap();
        assert_ne!(a, b);
        assert_eq!(instance_of(&a), Some(inst.as_str()));
        assert_eq!(a.len(), 16 + 1 + 64);
        for bad in ["", "x-y", &a[..a.len() - 1], &a.to_uppercase(), "0123456789abcdef-../etc"] {
            assert_eq!(instance_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn digests_are_keyed_and_labelled() {
        let d = digest(b"k1", "stmt", b"select 1");
        assert_eq!(d.len(), 64);
        assert_ne!(d, digest(b"k2", "stmt", b"select 1"));
        assert_ne!(d, digest(b"k1", "key", b"select 1"));
        assert_eq!(d, digest(b"k1", "stmt", b"select 1"));
    }
}
