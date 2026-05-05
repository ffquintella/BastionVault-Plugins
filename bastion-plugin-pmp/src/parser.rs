//! Spreadsheet reader. `calamine` opens `.xls` (BIFF) and `.xlsx`
//! (OOXML) transparently — we pick the sheet, normalise the header,
//! and return a `Vec<RawRow>` keyed by the original header names.
//! Empty cells stay as empty strings — the mapping layer applies
//! the `EMPTY_SENTINELS` rule uniformly.

use std::collections::BTreeMap;
use std::path::Path;

use calamine::{open_workbook_auto, Data, Reader};

/// Canonical PMP `ExportPasswordView` columns. The reader requires
/// `Resource Name`, `User Account`, and `Password` — the rest are
/// optional. Anything in the sheet header that isn't on this list
/// becomes an `unknown_columns[]` entry the wizard surfaces.
pub const KNOWN_COLUMNS: &[&str] = &[
    "Resource Name",
    "User Account",
    "Password",
    "Last Accessed Time",
    "Description",
    "DNS Name",
    "Department",
    "Location",
    "OS Type",
    "Resource URL",
    "Notes",
];

pub const REQUIRED_COLUMNS: &[&str] = &[
    "Resource Name",
    "User Account",
    "Password",
    "OS Type",
];

#[derive(Debug, Clone)]
pub struct RawRow {
    /// 1-based row number in the sheet (header is row 1, first data
    /// row is 2). Surfaces in skip reasons.
    pub row_number: usize,
    pub cells: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ParsedSheet {
    pub format: String,
    pub sheet: String,
    pub columns: Vec<String>,
    pub missing_required: Vec<String>,
    pub unknown_columns: Vec<String>,
    pub rows: Vec<RawRow>,
}

/// Open the workbook and parse the PMP sheet. Tries
/// `ExportPasswordView` first; falls back to the first sheet whose
/// header row contains every required column. Encrypted PMP exports
/// (recent versions can wrap the workbook in a per-export password)
/// are detected on open and rejected with a clear message rather
/// than surfacing the underlying calamine error.
pub fn parse(path: &Path) -> Result<ParsedSheet, String> {
    let format = match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase) {
        Some(ref e) if e == "xlsx" => "xlsx".to_string(),
        Some(ref e) if e == "xls" => "xls".to_string(),
        _ => "xls".to_string(),
    };

    if let Some(reason) = sniff_encrypted(path) {
        return Err(format!(
            "Encrypted PMP exports are not supported ({reason}). \
             Re-export from PMP without per-export encryption and try again."
        ));
    }

    let mut book = open_workbook_auto(path).map_err(|e| {
        // calamine's error strings sometimes leak through the
        // OLE-CFB layer; promote the obvious encryption signals to
        // the same friendly message as `sniff_encrypted`.
        let raw = e.to_string();
        if raw.to_ascii_lowercase().contains("encrypt")
            || raw.to_ascii_lowercase().contains("password-protected")
        {
            return format!(
                "Encrypted PMP exports are not supported (calamine: {raw}). \
                 Re-export from PMP without per-export encryption and try again."
            );
        }
        format!("open workbook: {raw}")
    })?;
    let sheet_names = book.sheet_names().to_vec();
    if sheet_names.is_empty() {
        return Err("workbook has no sheets".into());
    }

    let preferred = "ExportPasswordView";
    let pick: String = if sheet_names.iter().any(|n| n == preferred) {
        preferred.into()
    } else {
        // Fall back to the first sheet that has every required column
        // in its header row.
        let mut chosen = None;
        for n in &sheet_names {
            if let Ok(range) = book.worksheet_range(n) {
                let header = header_row(&range);
                if REQUIRED_COLUMNS.iter().all(|c| header.iter().any(|h| h == c)) {
                    chosen = Some(n.clone());
                    break;
                }
            }
        }
        chosen.unwrap_or_else(|| sheet_names[0].clone())
    };

    let range = book.worksheet_range(&pick).map_err(|e| format!("read sheet {pick:?}: {e}"))?;
    let header = header_row(&range);
    if header.is_empty() {
        return Err(format!("sheet {pick:?} is empty"));
    }

    let missing_required: Vec<String> = REQUIRED_COLUMNS
        .iter()
        .filter(|c| !header.iter().any(|h| h == *c))
        .map(|c| (*c).to_string())
        .collect();

    let unknown_columns: Vec<String> = header
        .iter()
        .filter(|h| !KNOWN_COLUMNS.contains(&h.as_str()))
        .cloned()
        .collect();

    let mut rows = Vec::new();
    for (idx, row) in range.rows().enumerate().skip(1) {
        let mut cells = BTreeMap::new();
        for (col_idx, h) in header.iter().enumerate() {
            let v = row.get(col_idx).map(cell_to_string).unwrap_or_default();
            cells.insert(h.clone(), v);
        }
        if cells.values().all(|v| v.trim().is_empty()) {
            continue;
        }
        rows.push(RawRow { row_number: idx + 1, cells });
    }

    Ok(ParsedSheet {
        format,
        sheet: pick,
        columns: header,
        missing_required,
        unknown_columns,
        rows,
    })
}

fn header_row(range: &calamine::Range<Data>) -> Vec<String> {
    range
        .rows()
        .next()
        .map(|row| row.iter().map(cell_to_string).collect())
        .unwrap_or_default()
}

/// Cheap signature sniff for password-protected workbooks. Both
/// `.xls` and `.xlsx` use OLE-CFB compound files for encryption,
/// with two well-known stream patterns:
///
/// - **`.xlsx`** (OOXML password-protect): the file is a CFB
///   container — header `D0 CF 11 E0 A1 B1 1A E1` — wrapping an
///   `EncryptedPackage` stream and an `EncryptionInfo` header.
/// - **`.xls`** (BIFF password-protect): same CFB container, but
///   the workbook stream begins with a `FilePass` record (opcode
///   `0x002F`) rather than a `BOF`.
///
/// Detecting either reliably means parsing the CFB; for the cheap
/// sniff we look for the literal ASCII strings `EncryptedPackage`
/// and `EncryptionInfo` in the first 8 KiB. Both names are stored
/// as UTF-16LE entries inside the CFB directory, so the bytes show
/// up as `E\0n\0c\0r\0y\0p\0t\0e\0d\0P\0a\0c\0k\0a\0g\0e\0`
/// — search for that pattern. False-positive risk is negligible
/// (the literal "EncryptedPackage" never appears in unencrypted
/// PMP exports). Returns `Some(reason)` when we're confident the
/// workbook is encrypted; `None` otherwise.
fn sniff_encrypted(path: &Path) -> Option<String> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; 8 * 1024];
    let n = f.read(&mut buf).ok()?;
    let head = &buf[..n];

    let cfb_magic = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    let is_cfb = head.starts_with(&cfb_magic);

    let needle_pkg = utf16le_bytes("EncryptedPackage");
    let needle_inf = utf16le_bytes("EncryptionInfo");
    let pkg = window_contains(head, &needle_pkg);
    let inf = window_contains(head, &needle_inf);

    // `.xlsx` encryption: ZIP magic `PK\x03\x04` would be the
    // unencrypted case; encrypted .xlsx is wrapped in a CFB.
    let is_zip = head.starts_with(b"PK\x03\x04");
    if is_zip {
        return None;
    }
    if pkg && inf {
        return Some("EncryptedPackage stream found in CFB container".into());
    }
    if is_cfb && (pkg || inf) {
        return Some("OLE-CFB container with encryption metadata".into());
    }
    None
}

fn utf16le_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for ch in s.encode_utf16() {
        out.push((ch & 0xff) as u8);
        out.push((ch >> 8) as u8);
    }
    out
}

fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn cell_to_string(d: &Data) -> String {
    match d {
        Data::Empty => String::new(),
        Data::String(s) => s.clone(),
        Data::Float(f) => {
            // PMP exports integers as integers in .xlsx; preserve that
            // shape so a port column comes out as "5432" not "5432.0".
            if f.fract() == 0.0 && f.is_finite() {
                format!("{}", *f as i64)
            } else {
                format!("{f}")
            }
        }
        Data::Int(i) => i.to_string(),
        Data::Bool(b) => b.to_string(),
        Data::Error(e) => format!("#{e:?}"),
        Data::DateTime(dt) => dt.to_string(),
        Data::DateTimeIso(s) | Data::DurationIso(s) => s.clone(),
    }
}
