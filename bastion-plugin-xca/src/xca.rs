//! XCA database reader — opens the SQLite file, walks the `items`
//! table, and returns a typed list of certs / private keys / CSRs /
//! CRLs / templates. Decryption of `private_keys.private` is gated on
//! the operator-supplied password and surfaced per-row so the GUI can
//! show "this key needs a per-key password" inline.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use x509_parser::prelude::*;

use crate::crypto;
use crate::keymatch::{self, KeyFingerprint};

/// XCA stores DER blobs (certs, CSRs, CRLs, templates, keys, encrypted
/// private blobs) as base64 ASCII inside `VARCHAR` columns rather than
/// as raw `BLOB`. Read the column as text, strip any whitespace XCA may
/// have emitted, and decode. If the value somehow already arrives as a
/// blob (older XCA forks did this), fall back to the raw bytes.
fn read_xca_blob_column(
    conn: &Connection,
    sql: &str,
    item_id: i64,
) -> rusqlite::Result<Option<Vec<u8>>> {
    let raw = match conn.query_row(sql, [item_id], |r| {
        r.get::<_, rusqlite::types::Value>(0)
    }) {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };
    let bytes = match raw {
        rusqlite::types::Value::Text(s) => decode_xca_b64(&s),
        rusqlite::types::Value::Blob(b) => b,
        rusqlite::types::Value::Null => return Ok(None),
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected XCA blob column type: {other:?}"),
                )),
            ))
        }
    };
    Ok(Some(bytes))
}

fn decode_xca_b64(s: &str) -> Vec<u8> {
    // XCA emits a single line of standard base64. Be lenient against
    // wrapped lines / stray whitespace just in case.
    let trimmed: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(trimmed.as_bytes())
        .unwrap_or_else(|_| s.as_bytes().to_vec())
}

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
        // Modern XCA pkitype enum (schema >= 8): asym_key=1, x509req=2,
        // x509=3, crl=4, tmpl=5. Earlier internal docs of this plugin had
        // 2/3 swapped; the live schema-8 file the user shipped proved the
        // ordering above. 6/7 are reserved for codes XCA hasn't shipped on
        // disk; we map them defensively but never index off them.
        match code {
            1 => ItemType::PrivateKey,
            2 => ItemType::Request,
            3 => ItemType::Cert,
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
    /// `items.id` of the paired counterpart, when the plugin matched
    /// a cert with its private key (or vice versa) by public-key
    /// fingerprint. `None` when no match was possible (algorithm
    /// without an extractable public key, decryption failed, no
    /// counterpart exists in the file).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paired_item_id: Option<i64>,
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
    // Public-key fingerprints, keyed by `items.id`. We compute one
    // for every cert (from its SPKI) and every successfully-decrypted
    // private key (from its PKCS#8). Cert↔key pairs are then resolved
    // by equal fingerprint after the per-row pass.
    let mut cert_fingerprints: BTreeMap<i64, KeyFingerprint> = BTreeMap::new();
    let mut key_fingerprints: BTreeMap<i64, KeyFingerprint> = BTreeMap::new();
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
            ItemType::Cert => match read_cert_item(&conn, &meta) {
                Ok(Some(item)) => {
                    if item.is_ca {
                        summary.issuer_count += 1;
                    } else {
                        summary.leaf_count += 1;
                    }
                    if let Some(fp) = keymatch::fingerprint_cert(&item.der) {
                        cert_fingerprints.insert(meta.id, fp);
                    }
                    items.push(item.into_preview(meta));
                }
                Ok(None) => skipped.push(format!("cert-row-missing:{}", meta.name)),
                Err(e) => skipped.push(format!("cert-row-error:{}: {e}", meta.name)),
            },
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
                            Ok((pem, der_opt, status)) => {
                                if let Some(der) = der_opt.as_deref() {
                                    if let Some(fp) = keymatch::fingerprint_private_key(der) {
                                        key_fingerprints.insert(meta.id, fp);
                                    }
                                }
                                items.push(PreviewItem {
                                    pem,
                                    subject: String::new(),
                                    serial_hex: String::new(),
                                    not_after_unix: None,
                                    decrypt: status,
                                    has_own_pass,
                                    paired_item_id: None,
                                    meta,
                                });
                            }
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
                                    paired_item_id: None,
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

    // Pair certs with private keys by public-key fingerprint. XCA
    // doesn't store an explicit cert↔key linkage column, so we rely
    // on the same property XCA itself uses at runtime: matching
    // public keys. A cert and a key share a `paired_item_id` when
    // their fingerprints are equal. If multiple keys collide on the
    // same fingerprint (rare — would mean duplicated key material),
    // the first one wins on each side.
    let mut fp_to_cert: BTreeMap<KeyFingerprint, i64> = BTreeMap::new();
    for (id, fp) in &cert_fingerprints {
        fp_to_cert.entry(*fp).or_insert(*id);
    }
    let mut fp_to_key: BTreeMap<KeyFingerprint, i64> = BTreeMap::new();
    for (id, fp) in &key_fingerprints {
        fp_to_key.entry(*fp).or_insert(*id);
    }
    for item in &mut items {
        item.paired_item_id = match item.meta.item_type {
            ItemType::Cert => cert_fingerprints
                .get(&item.meta.id)
                .and_then(|fp| fp_to_key.get(fp).copied()),
            ItemType::PrivateKey => key_fingerprints
                .get(&item.meta.id)
                .and_then(|fp| fp_to_cert.get(fp).copied()),
            _ => None,
        };
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
        let val: rusqlite::types::Value = r.get(0)?;
        let blob = match val {
            rusqlite::types::Value::Text(s) => decode_xca_b64(&s),
            rusqlite::types::Value::Blob(b) => b,
            _ => continue,
        };
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
            paired_item_id: None,
            meta,
        }
    }
}

/// Pull the cert blob from whichever column name this XCA build uses,
/// then derive `is_ca` from the certificate's own BasicConstraints
/// extension. Earlier code keyed off a `certs.ca` column that doesn't
/// exist in every schema version, which silently dropped every cert.
fn read_cert_item(conn: &Connection, meta: &ItemMeta) -> rusqlite::Result<Option<CertRow>> {
    let col = pick_column(conn, "certs", &["cert", "der"]).unwrap_or("cert");
    // Pull `ca` separately so we can fall back to BasicConstraints when
    // the column is absent. Schema 8 has it; some older forks don't.
    let has_ca_col = pick_column(conn, "certs", &["ca"]).is_some();
    let der_sql = format!("SELECT {col} FROM certs WHERE item = ?1");
    let der = match read_xca_blob_column(conn, &der_sql, meta.id)? {
        Some(b) => b,
        None => return Ok(None),
    };
    let ca_flag: Option<i64> = if has_ca_col {
        conn.query_row("SELECT ca FROM certs WHERE item = ?1", [meta.id], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .ok()
        .flatten()
    } else {
        None
    };
    let is_ca = ca_flag.map(|v| v != 0).unwrap_or_else(|| is_ca_cert(&der));
    Ok(Some(CertRow { der, is_ca }))
}

fn is_ca_cert(der: &[u8]) -> bool {
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return false;
    };
    match cert.basic_constraints() {
        Ok(Some(bc)) => bc.value.ca,
        _ => false,
    }
}

fn read_request_item(conn: &Connection, meta: &ItemMeta) -> rusqlite::Result<Option<PreviewItem>> {
    let col = pick_column(conn, "requests", &["request", "csr", "der"]).unwrap_or("request");
    let sql = format!("SELECT {col} FROM requests WHERE item = ?1");
    let row = read_xca_blob_column(conn, &sql, meta.id)?;
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
            paired_item_id: None,
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
    let col = pick_column(conn, "crls", &["crl", "der"]).unwrap_or("crl");
    let sql = format!("SELECT {col} FROM crls WHERE item = ?1");
    let row = read_xca_blob_column(conn, &sql, meta.id)?;
    Ok(row.map(|der| PreviewItem {
        pem: Some(pem_wrap("X509 CRL", &der)),
        subject: String::new(),
        serial_hex: String::new(),
        not_after_unix: None,
        decrypt: DecryptStatus::NotEncrypted,
        has_own_pass: false,
        paired_item_id: None,
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
    let col = pick_column(conn, "templates", &["template", "data"]).unwrap_or("template");
    let sql = format!("SELECT {col} FROM templates WHERE item = ?1");
    let row = read_xca_blob_column(conn, &sql, meta.id)?;
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
        paired_item_id: None,
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
    let col = pick_column(conn, "public_keys", &["key", "public", "der"]).unwrap_or("key");
    let sql = format!("SELECT {col} FROM public_keys WHERE item = ?1");
    let row = read_xca_blob_column(conn, &sql, meta.id)?;
    Ok(row.map(|der| PreviewItem {
        pem: Some(pem_wrap("PUBLIC KEY", &der)),
        subject: String::new(),
        serial_hex: String::new(),
        not_after_unix: None,
        decrypt: DecryptStatus::NotEncrypted,
        has_own_pass: false,
        paired_item_id: None,
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
    let blob = match read_xca_blob_column(
        conn,
        "SELECT private FROM private_keys WHERE item = ?1",
        meta.id,
    )? {
        Some(b) => b,
        None => return Ok(None),
    };
    let own_pass: Option<String> = conn
        .query_row(
            "SELECT ownPass FROM private_keys WHERE item = ?1",
            [meta.id],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten();
    let has_own_pass = own_pass.map(|s| !s.is_empty()).unwrap_or(false);
    Ok(Some((blob, has_own_pass)))
}

fn try_decrypt_key(
    blob: &[u8],
    password: Option<&str>,
) -> Result<(Option<String>, Option<Vec<u8>>, DecryptStatus), String> {
    match crypto::detect_format(blob) {
        None => {
            // Treat as plaintext PKCS#8 / SEC1 DER and pass through.
            let pem = pem_wrap("PRIVATE KEY", blob);
            Ok((Some(pem), Some(blob.to_vec()), DecryptStatus::NotEncrypted))
        }
        Some(_) => {
            let Some(pw) = password else {
                return Err("missing password".into());
            };
            match crypto::decrypt_auto(blob, pw) {
                Ok(plain) => Ok((
                    Some(pem_wrap("PRIVATE KEY", &plain)),
                    Some(plain),
                    DecryptStatus::Ok,
                )),
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
