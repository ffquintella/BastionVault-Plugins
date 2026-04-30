//! XCA database reader — opens the SQLite file, walks the `items`
//! table, and returns a typed list of certs / private keys / CSRs /
//! CRLs / templates. Decryption of `private_keys.private` is gated on
//! the operator-supplied password and surfaced per-row so the GUI can
//! show "this key needs a per-key password" inline.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use x509_parser::prelude::*;

use crate::crypto;

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    PrivateKey,
    Cert,
    Request,
    Crl,
    Template,
    PublicKey,
    Authority,
    Other,
}

impl ItemType {
    fn from_xca(code: i64) -> Self {
        match code {
            1 => ItemType::PrivateKey,
            2 => ItemType::Cert,
            3 => ItemType::Request,
            4 => ItemType::Crl,
            5 => ItemType::Template,
            6 => ItemType::PublicKey,
            7 => ItemType::Authority,
            _ => ItemType::Other,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ItemMeta {
    pub id: i64,
    pub item_type: ItemType,
    pub parent: i64,
    pub name: String,
    pub comment: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptStatus {
    /// Not encrypted in the file — surfaced as plaintext.
    NotEncrypted,
    /// Decrypted with the supplied password.
    Ok,
    /// Operator didn't supply a password and one is required.
    MissingPassword,
    /// Wrong password / corrupt blob.
    WrongPassword,
    /// Format is something we don't recognise (smartcard pointer, etc.).
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct PreviewItem {
    pub meta: ItemMeta,
    /// PEM-encoded body if we have one (cert, CSR, CRL, public key
    /// always; private key only when decryption succeeded).
    pub pem: Option<String>,
    /// For certs / CSRs: subject DN. For private keys: empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    /// For certs only: serial number as uppercase hex.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub serial_hex: String,
    /// For certs only: not_after (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after_unix: Option<i64>,
    /// Decryption result for private keys; always `NotEncrypted` for
    /// other item types.
    pub decrypt: DecryptStatus,
    /// True when `private_keys.ownPass` was non-empty for this row.
    pub has_own_pass: bool,
}

#[derive(Debug, Serialize)]
pub struct PreviewSummary {
    pub format_version: String,
    pub issuer_count: usize,
    pub leaf_count: usize,
    pub csr_count: usize,
    pub crl_count: usize,
    pub template_count: usize,
    pub key_count: usize,
    pub skipped: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Preview {
    pub summary: PreviewSummary,
    pub items: Vec<PreviewItem>,
    pub decryption_failures: Vec<DecryptionFailure>,
    pub ownpass_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DecryptionFailure {
    pub name: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct OpenError(pub String);

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpenError {}

/// Cheap up-front sniff. Returns the schema version + whether any
/// row in `private_keys.private` looks encrypted.
#[derive(Debug, Serialize)]
pub struct ValidateResult {
    pub ok: bool,
    pub format_version: String,
    pub requires_password: bool,
    pub ownpass_keys: Vec<String>,
}

pub fn validate(path: &Path) -> Result<ValidateResult, OpenError> {
    let conn = open_readonly(path)?;
    let format_version = read_format_version(&conn).unwrap_or_else(|_| "unknown".into());
    let requires_password = scan_requires_password(&conn).unwrap_or(false);
    let ownpass_keys = scan_ownpass_keys(&conn).unwrap_or_default();
    Ok(ValidateResult {
        ok: true,
        format_version,
        requires_password,
        ownpass_keys,
    })
}

/// Full preview pass. Decrypts what it can with the supplied
/// `master_password`; per-row `ownPass` overrides come from
/// `per_key_passwords` keyed by item name.
pub fn preview(
    path: &Path,
    master_password: Option<&str>,
    per_key_passwords: &BTreeMap<String, String>,
) -> Result<Preview, OpenError> {
    let conn = open_readonly(path)?;
    let format_version = read_format_version(&conn).unwrap_or_else(|_| "unknown".into());

    // Load all `items` rows once so we can join in memory.
    let item_rows = read_items(&conn)?;

    let mut items: Vec<PreviewItem> = Vec::with_capacity(item_rows.len());
    let mut decryption_failures: Vec<DecryptionFailure> = Vec::new();
    let mut ownpass_keys: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut summary = PreviewSummary {
        format_version: format_version.clone(),
        issuer_count: 0,
        leaf_count: 0,
        csr_count: 0,
        crl_count: 0,
        template_count: 0,
        key_count: 0,
        skipped: Vec::new(),
    };

    for meta in item_rows {
        match meta.item_type {
            ItemType::Cert => {
                if let Ok(Some(item)) = read_cert_item(&conn, &meta) {
                    if item.is_ca {
                        summary.issuer_count += 1;
                    } else {
                        summary.leaf_count += 1;
                    }
                    items.push(item.into_preview(meta));
                }
            }
            ItemType::Request => {
                summary.csr_count += 1;
                if let Ok(Some(p)) = read_request_item(&conn, &meta) {
                    items.push(p);
                }
            }
            ItemType::Crl => {
                summary.crl_count += 1;
                if let Ok(Some(p)) = read_crl_item(&conn, &meta) {
                    items.push(p);
                }
            }
            ItemType::Template => {
                summary.template_count += 1;
                if let Ok(Some(p)) = read_template_item(&conn, &meta) {
                    items.push(p);
                }
            }
            ItemType::PrivateKey => {
                summary.key_count += 1;
                let row = read_private_key_row(&conn, &meta);
                match row {
                    Ok(Some((blob, has_own_pass))) => {
                        if has_own_pass {
                            ownpass_keys.push(meta.name.clone());
                        }
                        let pw = per_key_passwords
                            .get(&meta.name)
                            .map(|s| s.as_str())
                            .or(master_password);
                        match try_decrypt_key(&blob, pw) {
                            Ok((pem, status)) => items.push(PreviewItem {
                                pem: pem,
                                subject: String::new(),
                                serial_hex: String::new(),
                                not_after_unix: None,
                                decrypt: status,
                                has_own_pass,
                                meta,
                            }),
                            Err(reason) => {
                                decryption_failures.push(DecryptionFailure {
                                    name: meta.name.clone(),
                                    reason: reason.clone(),
                                });
                                items.push(PreviewItem {
                                    pem: None,
                                    subject: String::new(),
                                    serial_hex: String::new(),
                                    not_after_unix: None,
                                    decrypt: classify_failure(&reason),
                                    has_own_pass,
                                    meta,
                                });
                            }
                        }
                    }
                    Ok(None) => skipped.push(format!("missing-private-blob:{}", meta.name)),
                    Err(e) => skipped.push(format!("private-key-row-error:{e}")),
                }
            }
            ItemType::PublicKey => {
                if let Ok(Some(p)) = read_public_key_item(&conn, &meta) {
                    items.push(p);
                }
            }
            ItemType::Authority => {
                skipped.push(format!("authority-config:{}", meta.name));
            }
            ItemType::Other => {
                skipped.push(format!("unknown-type:{}", meta.name));
            }
        }
    }

    summary.skipped = skipped;
    Ok(Preview {
        summary,
        items,
        decryption_failures,
        ownpass_keys,
    })
}

/// Return the first candidate column name that exists on `table`, or
/// `None` if none do. Uses `PRAGMA table_info` so we don't have to
/// keep up with every XCA schema bump.
fn pick_column(conn: &Connection, table: &str, candidates: &[&'static str]) -> Option<&'static str> {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql).ok()?;
    let mut rows = stmt.query([]).ok()?;
    let mut cols: Vec<String> = Vec::new();
    while let Ok(Some(r)) = rows.next() {
        if let Ok(name) = r.get::<_, String>(1) {
            cols.push(name);
        }
    }
    candidates.iter().copied().find(|c| cols.iter().any(|n| n.eq_ignore_ascii_case(c)))
}

fn open_readonly(path: &Path) -> Result<Connection, OpenError> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| OpenError(format!("open {}: {e}", path.display())))
}

fn read_format_version(conn: &Connection) -> rusqlite::Result<String> {
    // XCA writes its schema version into the `settings` table under
    // key `schema`. We don't try to reconcile it across XCA releases
    // here — the value is reported back to the GUI for display.
    let row: rusqlite::Result<String> = conn.query_row(
        "SELECT value FROM settings WHERE key_ = 'schema' LIMIT 1",
        [],
        |r| r.get(0),
    );
    match row {
        Ok(s) => Ok(s),
        Err(_) => Ok("unknown".into()),
    }
}

fn scan_requires_password(conn: &Connection) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare("SELECT private FROM private_keys WHERE private IS NOT NULL")?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let blob: Vec<u8> = r.get(0)?;
        if crypto::detect_format(&blob).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn scan_ownpass_keys(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT items.name FROM items \
         JOIN private_keys ON private_keys.item = items.id \
         WHERE private_keys.ownPass IS NOT NULL AND private_keys.ownPass != ''",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        out.push(r.get::<_, String>(0)?);
    }
    Ok(out)
}

fn read_items(conn: &Connection) -> Result<Vec<ItemMeta>, OpenError> {
    // XCA renamed the parent-id column from `parent` to `pid` somewhere
    // around the 2.x line. Probe the schema and pick whichever exists;
    // fall back to NULL so the query at least runs on exotic forks.
    let parent_expr = pick_column(conn, "items", &["pid", "parent"]).unwrap_or("NULL");
    let sql = format!(
        "SELECT id, type, {parent_expr} AS parent, name, comment FROM items ORDER BY id ASC"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| OpenError(format!("prepare items: {e}")))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| OpenError(format!("query items: {e}")))?;
    let mut out = Vec::new();
    while let Some(r) = rows
        .next()
        .map_err(|e| OpenError(format!("walk items: {e}")))?
    {
        let id: i64 = r.get(0).map_err(|e| OpenError(e.to_string()))?;
        let type_code: i64 = r.get(1).map_err(|e| OpenError(e.to_string()))?;
        let parent: i64 = r.get::<_, Option<i64>>(2).unwrap_or_default().unwrap_or(0);
        let name: String = r.get(3).map_err(|e| OpenError(e.to_string()))?;
        let comment: String = r.get::<_, Option<String>>(4).unwrap_or_default().unwrap_or_default();
        out.push(ItemMeta {
            id,
            item_type: ItemType::from_xca(type_code),
            parent,
            name,
            comment,
        });
    }
    Ok(out)
}

struct CertRow {
    der: Vec<u8>,
    is_ca: bool,
}

impl CertRow {
    fn into_preview(self, meta: ItemMeta) -> PreviewItem {
        let mut subject = String::new();
        let mut serial_hex = String::new();
        let mut not_after_unix: Option<i64> = None;
        if let Ok((_, c)) = X509Certificate::from_der(&self.der) {
            subject = c.subject().to_string();
            serial_hex = format_serial_hex(&c.tbs_certificate.serial.to_bytes_be());
            not_after_unix = Some(c.tbs_certificate.validity.not_after.timestamp());
        }
        PreviewItem {
            pem: Some(pem_wrap("CERTIFICATE", &self.der)),
            subject,
            serial_hex,
            not_after_unix,
            decrypt: DecryptStatus::NotEncrypted,
            has_own_pass: false,
            meta,
        }
    }
}

fn read_cert_item(conn: &Connection, meta: &ItemMeta) -> rusqlite::Result<Option<CertRow>> {
    let row: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT cert, ca FROM certs WHERE item = ?1",
            [meta.id],
            |r| Ok((r.get(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))),
        )
        .ok();
    Ok(row.map(|(der, ca)| CertRow {
        der,
        is_ca: ca != 0,
    }))
}

fn read_request_item(conn: &Connection, meta: &ItemMeta) -> rusqlite::Result<Option<PreviewItem>> {
    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT request FROM requests WHERE item = ?1",
            [meta.id],
            |r| r.get(0),
        )
        .ok();
    Ok(row.map(|der| {
        let mut subject = String::new();
        if let Ok((_, csr)) = X509CertificationRequest::from_der(&der) {
            subject = csr.certification_request_info.subject.to_string();
        }
        PreviewItem {
            pem: Some(pem_wrap("CERTIFICATE REQUEST", &der)),
            subject,
            serial_hex: String::new(),
            not_after_unix: None,
            decrypt: DecryptStatus::NotEncrypted,
            has_own_pass: false,
            meta: ItemMeta {
                id: meta.id,
                item_type: meta.item_type,
                parent: meta.parent,
                name: meta.name.clone(),
                comment: meta.comment.clone(),
            },
        }
    }))
}

fn read_crl_item(conn: &Connection, meta: &ItemMeta) -> rusqlite::Result<Option<PreviewItem>> {
    let row: Option<Vec<u8>> = conn
        .query_row("SELECT crl FROM crls WHERE item = ?1", [meta.id], |r| {
            r.get(0)
        })
        .ok();
    Ok(row.map(|der| PreviewItem {
        pem: Some(pem_wrap("X509 CRL", &der)),
        subject: String::new(),
        serial_hex: String::new(),
        not_after_unix: None,
        decrypt: DecryptStatus::NotEncrypted,
        has_own_pass: false,
        meta: ItemMeta {
            id: meta.id,
            item_type: meta.item_type,
            parent: meta.parent,
            name: meta.name.clone(),
            comment: meta.comment.clone(),
        },
    }))
}

fn read_template_item(
    conn: &Connection,
    meta: &ItemMeta,
) -> rusqlite::Result<Option<PreviewItem>> {
    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT template FROM templates WHERE item = ?1",
            [meta.id],
            |r| r.get(0),
        )
        .ok();
    // Templates are XCA's internal blob format; we round-trip them
    // base64-tagged inside the PEM body so the operator can re-import
    // them later or hand-translate to a `pki/role`.
    Ok(row.map(|blob| PreviewItem {
        pem: Some(pem_wrap("XCA TEMPLATE", &blob)),
        subject: String::new(),
        serial_hex: String::new(),
        not_after_unix: None,
        decrypt: DecryptStatus::NotEncrypted,
        has_own_pass: false,
        meta: ItemMeta {
            id: meta.id,
            item_type: meta.item_type,
            parent: meta.parent,
            name: meta.name.clone(),
            comment: meta.comment.clone(),
        },
    }))
}

fn read_public_key_item(
    conn: &Connection,
    meta: &ItemMeta,
) -> rusqlite::Result<Option<PreviewItem>> {
    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT key FROM public_keys WHERE item = ?1",
            [meta.id],
            |r| r.get(0),
        )
        .ok();
    Ok(row.map(|der| PreviewItem {
        pem: Some(pem_wrap("PUBLIC KEY", &der)),
        subject: String::new(),
        serial_hex: String::new(),
        not_after_unix: None,
        decrypt: DecryptStatus::NotEncrypted,
        has_own_pass: false,
        meta: ItemMeta {
            id: meta.id,
            item_type: meta.item_type,
            parent: meta.parent,
            name: meta.name.clone(),
            comment: meta.comment.clone(),
        },
    }))
}

fn read_private_key_row(
    conn: &Connection,
    meta: &ItemMeta,
) -> rusqlite::Result<Option<(Vec<u8>, bool)>> {
    let row: Option<(Vec<u8>, Option<String>)> = conn
        .query_row(
            "SELECT private, ownPass FROM private_keys WHERE item = ?1",
            [meta.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    Ok(row.map(|(blob, op)| (blob, op.map(|s| !s.is_empty()).unwrap_or(false))))
}

fn try_decrypt_key(blob: &[u8], password: Option<&str>) -> Result<(Option<String>, DecryptStatus), String> {
    match crypto::detect_format(blob) {
        None => {
            // Treat as plaintext PKCS#8 / SEC1 DER and pass through.
            let pem = pem_wrap("PRIVATE KEY", blob);
            Ok((Some(pem), DecryptStatus::NotEncrypted))
        }
        Some(_) => {
            let Some(pw) = password else {
                return Err("missing password".into());
            };
            match crypto::decrypt_auto(blob, pw) {
                Ok(plain) => Ok((Some(pem_wrap("PRIVATE KEY", &plain)), DecryptStatus::Ok)),
                Err(e) => Err(e.0),
            }
        }
    }
}

fn classify_failure(reason: &str) -> DecryptStatus {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("missing password") {
        DecryptStatus::MissingPassword
    } else if lower.contains("wrong password") || lower.contains("decrypt failed") {
        DecryptStatus::WrongPassword
    } else if lower.contains("malformed") || lower.contains("unsupported") {
        DecryptStatus::Unsupported
    } else {
        DecryptStatus::Unsupported
    }
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    // Hand-rolled PEM (RFC 7468). The `pem` crate's API has shifted
    // between minor releases and we only need the single happy-path
    // shape — base64-with-line-breaks-at-64 wrapped in BEGIN/END
    // armour. Trivially unit-testable, zero risk of upstream churn.
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let mut i = 0;
    while i < body.len() {
        let end = (i + 64).min(body.len());
        out.push_str(&body[i..end]);
        out.push('\n');
        i = end;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn format_serial_hex(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}
