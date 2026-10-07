//! Storage access. Every key is relative to the host-rebased entity scope
//! (`core/plugins/self-accounts/data/entity/<entity_id>/`), so this module
//! cannot name another user's records, and never writes an entity id.

use bastion_plugin_sdk::{Host, HostError};

use crate::model::{AccountMeta, AccountSecret, Invalid};
use crate::seen::{Seen, SeenProblem};

const PREFIX: &str = "accounts/";

/// `sa_` plus 26 base32 characters (128 random bits). Anything else is refused
/// before it can become part of a storage key.
pub fn valid_id(id: &str) -> bool {
    id.len() == 29
        && id.starts_with("sa_")
        && id[3..].chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
}

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn new_id(host: &Host) -> Result<String, Invalid> {
    let bytes = host
        .random_bytes(16)
        .map_err(|_| Invalid::new("the host could not supply random bytes"))?;
    let mut out = String::from("sa_");
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    Ok(out)
}

fn meta_key(id: &str) -> String {
    format!("{PREFIX}{id}/meta")
}
fn secret_key(id: &str) -> String {
    format!("{PREFIX}{id}/secret")
}
/// Digests of the targets this account was released for (`seen`). Never
/// target text.
fn seen_key(id: &str) -> String {
    format!("{PREFIX}{id}/seen")
}

fn io(_: HostError) -> Invalid {
    Invalid::new("storage is unavailable")
}

pub fn list_ids(host: &Host) -> Result<Vec<String>, Invalid> {
    let mut ids: Vec<String> = host
        .storage_list(PREFIX)
        .map_err(io)?
        .into_iter()
        // The barrier lists `sa_x/`; a flat store may list `sa_x/meta`.
        .map(|n| n.split('/').next().unwrap_or("").to_string())
        .filter(|n| valid_id(n))
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

pub fn load_meta(host: &Host, id: &str) -> Result<Option<AccountMeta>, Invalid> {
    if !valid_id(id) {
        return Ok(None);
    }
    match host.storage_get(&meta_key(id)) {
        Ok(b) => AccountMeta::from_bytes(&b).map(Some),
        Err(HostError::NotFound) => Ok(None),
        Err(e) => Err(io(e)),
    }
}

pub fn save_meta(host: &Host, meta: &AccountMeta) -> Result<(), Invalid> {
    let bytes = serde_json::to_vec(meta).map_err(|_| Invalid::new("could not encode the account"))?;
    host.storage_put(&meta_key(&meta.id), &bytes).map_err(io)
}

pub fn load_secret(host: &Host, id: &str) -> Result<Option<AccountSecret>, Invalid> {
    if !valid_id(id) {
        return Ok(None);
    }
    match host.storage_get(&secret_key(id)) {
        Ok(b) => {
            let b = zeroize::Zeroizing::new(b);
            AccountSecret::from_bytes(&b).map(Some)
        }
        Err(HostError::NotFound) => Ok(None),
        Err(e) => Err(io(e)),
    }
}

pub fn save_secret(host: &Host, id: &str, secret: &AccountSecret) -> Result<(), Invalid> {
    let bytes = secret.to_bytes();
    host.storage_put(&secret_key(id), &bytes).map_err(io)
}

/// The account's `seen` record; a missing one is an empty set.
pub fn load_seen(host: &Host, id: &str) -> Result<Seen, SeenProblem> {
    if !valid_id(id) {
        return Ok(Seen::default());
    }
    match host.storage_get(&seen_key(id)) {
        Ok(b) => Seen::from_bytes(&b),
        Err(HostError::NotFound) => Ok(Seen::default()),
        Err(_) => Err(SeenProblem::Unreadable),
    }
}

pub fn save_seen(host: &Host, id: &str, seen: &Seen) -> Result<(), Invalid> {
    host.storage_put(&seen_key(id), &seen.to_bytes()).map_err(io)
}

pub fn delete(host: &Host, id: &str) -> Result<(), Invalid> {
    // Secret first: if a later delete fails, what remains is metadata only.
    // `seen` holds digests only, and the meta goes last so a half-deleted
    // account stays visible (and deletable) rather than orphaned.
    let _ = host.storage_delete(&secret_key(id));
    let _ = host.storage_delete(&seen_key(id));
    host.storage_delete(&meta_key(id)).map_err(io)
}
