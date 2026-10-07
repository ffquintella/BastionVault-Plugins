//! Stored records and their validation (spec §2). Metadata and secret live in
//! separate keys so that listing and candidate matching never deserialise
//! secret material.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const CURRENT_VERSION: u32 = 1;

pub const MAX_LABEL: usize = 64;
pub const MAX_USERNAME: usize = 256;
pub const MAX_DOMAIN: usize = 256;
pub const MAX_DESCRIPTION: usize = 512;
pub const MAX_PASSWORD: usize = 1024;
pub const MAX_PRIVATE_KEY: usize = 16 * 1024;
pub const MAX_LIST: usize = 32;
pub const MAX_ITEM: usize = 256;

pub const KIND_PASSWORD: &str = "password";
pub const KIND_SSH_KEY: &str = "ssh-key";

pub const PROTOCOLS: [&str; 3] = ["ssh", "rdp", "web"];
pub const OS_TYPES: [&str; 6] = ["linux", "windows", "macos", "bsd", "unix", "other"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliesTo {
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub os_types: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub targets: Vec<String>,
}

/// `accounts/<id>/meta`. Never contains secret material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountMeta {
    pub v: u32,
    pub id: String,
    pub label: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub secret_kind: String,
    #[serde(default)]
    pub has_totp: bool,
    pub applies_to: AppliesTo,
    #[serde(default)]
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// `accounts/<id>/secret`. No `Debug`, wiped on drop.
#[derive(Serialize, Deserialize)]
pub struct AccountSecret {
    pub v: u32,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

impl Drop for AccountSecret {
    fn drop(&mut self) {
        self.password.zeroize();
        self.totp_seed.zeroize();
        self.private_key.zeroize();
    }
}

/// A refusal that is the caller's fault. The message names the offending
/// field, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

impl Invalid {
    pub fn new(msg: impl Into<String>) -> Self {
        Invalid(msg.into())
    }
}

impl AccountMeta {
    /// Readers accept every version up to the current one; a newer record was
    /// written by a newer plugin and must not be misread.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Invalid> {
        let m: AccountMeta = serde_json::from_slice(bytes)
            .map_err(|_| Invalid::new("stored account record is unreadable"))?;
        if m.v == 0 || m.v > CURRENT_VERSION {
            return Err(Invalid::new("stored account record has an unsupported version"));
        }
        Ok(m)
    }
}

impl AccountSecret {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Invalid> {
        let s: AccountSecret = serde_json::from_slice(bytes)
            .map_err(|_| Invalid::new("stored account secret is unreadable"))?;
        if s.v == 0 || s.v > CURRENT_VERSION {
            return Err(Invalid::new("stored account secret has an unsupported version"));
        }
        Ok(s)
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(serde_json::to_vec(self).unwrap_or_default())
    }
}

/// The protocols a secret kind can be used with (spec §2 table).
pub fn compatible_protocols(kind: &str) -> &'static [&'static str] {
    match kind {
        KIND_PASSWORD => &["ssh", "rdp", "web"],
        KIND_SSH_KEY => &["ssh"],
        _ => &[],
    }
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

pub fn check_text(field: &str, v: &str, max: usize, required: bool) -> Result<(), Invalid> {
    if required && v.trim().is_empty() {
        return Err(Invalid::new(format!("{field} is required")));
    }
    if v.chars().count() > max {
        return Err(Invalid::new(format!("{field} is longer than {max} characters")));
    }
    if has_control(v) {
        return Err(Invalid::new(format!("{field} contains control characters")));
    }
    Ok(())
}

/// A resource-type id as the Resources page stores it.
pub fn check_type_id(v: &str) -> Result<(), Invalid> {
    let ok = !v.is_empty()
        && v.len() <= 64
        && v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(Invalid::new("resource_types entries must be lowercase ids (a-z, 0-9, _ and -)"))
    }
}

/// Base32 (RFC 4648) TOTP seed, spaces and `=` padding tolerated.
pub fn normalise_totp_seed(raw: &str) -> Result<String, Invalid> {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if s.is_empty() || s.len() > MAX_PASSWORD {
        return Err(Invalid::new("totp_seed must be 1-1024 base32 characters"));
    }
    if !s.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        return Err(Invalid::new("totp_seed must be base32 (A-Z, 2-7)"));
    }
    Ok(s)
}

/// Accepts an unencrypted OpenSSH private key. A PKCS#8 PEM is recognised by its
/// armour so that it can be refused with a precise message: this version stores
/// OpenSSH keys only, because the SSH session path reads that form.
pub fn check_private_key(pem: &str) -> Result<(), Invalid> {
    if pem.is_empty() {
        return Err(Invalid::new("private_key is required"));
    }
    if pem.len() > MAX_PRIVATE_KEY {
        return Err(Invalid::new("private_key is larger than 16 KiB"));
    }
    if pem.contains("ENCRYPTED") {
        return Err(Invalid::new(
            "passphrase-protected private keys are not supported; store an unencrypted key",
        ));
    }
    if !pem.contains("BEGIN OPENSSH PRIVATE KEY") {
        return Err(Invalid::new("private_key must be an OpenSSH private key (BEGIN OPENSSH PRIVATE KEY)"));
    }
    let key = ssh_key::PrivateKey::from_openssh(pem)
        .map_err(|_| Invalid::new("private_key is not a valid OpenSSH private key"))?;
    if key.is_encrypted() {
        return Err(Invalid::new(
            "passphrase-protected private keys are not supported; store an unencrypted key",
        ));
    }
    Ok(())
}
