//! PostgreSQL binary result values to JSON cells (features/sql-browser.md
//! §6.3). Integers that always fit ±2^53 are numbers; `bigint`, `numeric`
//! and every other wide number is a decimal string, so precision is never
//! lost. Binary is base64. A type this module cannot decode is returned as
//! base64 with kind `binary`, never guessed.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use tokio_postgres::types::{FromSql, Kind, Type};

/// A cell over this many bytes is truncated (`truncated` / `full_length`).
pub const MAX_CELL_BYTES: usize = 64 * 1024;

/// Nesting depth for arrays and composites; deeper values are binary.
const MAX_DEPTH: usize = 8;

/// The JSON kind a column's values have.
pub fn kind(ty: &Type) -> &'static str {
    match ty.kind() {
        Kind::Domain(base) => return kind(base),
        Kind::Enum(_) => return "string",
        Kind::Array(_) | Kind::Composite(_) => return "json",
        _ => {}
    }
    match *ty {
        Type::BOOL => "boolean",
        Type::INT2 | Type::INT4 | Type::OID | Type::FLOAT4 | Type::FLOAT8 => "number",
        Type::BYTEA => "binary",
        Type::JSON | Type::JSONB => "json",
        Type::DATE | Type::TIME | Type::TIMETZ | Type::TIMESTAMP | Type::TIMESTAMPTZ => "datetime",
        Type::INT8 | Type::NUMERIC | Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::CHAR => "string",
        Type::UNKNOWN | Type::XML | Type::UUID | Type::INET | Type::CIDR | Type::MACADDR | Type::INTERVAL => "string",
        _ if is_texty(ty) => "string",
        _ => "binary",
    }
}

/// A database number (integer, float or `numeric`), through domains. Its
/// cells are numbers or decimal strings the server produced, never text a
/// user typed: exports write them as is (§8.1 formula guard).
pub fn is_numeric(ty: &Type) -> bool {
    if let Kind::Domain(base) = ty.kind() {
        return is_numeric(base);
    }
    matches!(*ty, Type::INT2 | Type::INT4 | Type::INT8 | Type::OID | Type::FLOAT4 | Type::FLOAT8 | Type::NUMERIC)
}

/// `bytea`, through domains: its cells are base64.
pub fn is_bytea(ty: &Type) -> bool {
    match ty.kind() {
        Kind::Domain(base) => is_bytea(base),
        _ => *ty == Type::BYTEA,
    }
}

/// Types whose binary form is their text (`citext` and other extension
/// text types are recognised by name).
fn is_texty(ty: &Type) -> bool {
    matches!(*ty, Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN | Type::XML)
        || ty.name() == "citext"
}

/// One decoded cell. `FromSql` for every type, so a row can be read
/// column by column whatever the result shape.
#[derive(Debug, Clone, PartialEq)]
pub struct Cell(pub Value);

impl<'a> FromSql<'a> for Cell {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Cell(decode(ty, raw, 0)))
    }

    fn from_sql_null(_: &Type) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Cell(Value::Null))
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

fn binary(raw: &[u8]) -> Value {
    Value::String(B64.encode(raw))
}

fn be<const N: usize>(raw: &[u8]) -> Option<[u8; N]> {
    raw.get(..N)?.try_into().ok().filter(|_| raw.len() == N)
}

/// Decode `raw` (binary format) as `ty`. Malformed input decodes to base64,
/// never panics.
pub fn decode(ty: &Type, raw: &[u8], depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return binary(raw);
    }
    match ty.kind() {
        Kind::Domain(base) => return decode(base, raw, depth + 1),
        Kind::Enum(_) => return text(raw),
        Kind::Array(elem) => return array(elem, raw, depth).unwrap_or_else(|| binary(raw)),
        Kind::Composite(fields) => {
            let types: Vec<(&str, &Type)> = fields.iter().map(|f| (f.name(), f.type_())).collect();
            return composite(&types, raw, depth).unwrap_or_else(|| binary(raw));
        }
        _ => {}
    }
    let v = match *ty {
        Type::BOOL => be::<1>(raw).map(|b| json!(b[0] != 0)),
        Type::INT2 => be::<2>(raw).map(|b| json!(i16::from_be_bytes(b))),
        Type::INT4 => be::<4>(raw).map(|b| json!(i32::from_be_bytes(b))),
        Type::OID => be::<4>(raw).map(|b| json!(u32::from_be_bytes(b))),
        Type::INT8 => be::<8>(raw).map(|b| json!(i64::from_be_bytes(b).to_string())),
        Type::FLOAT4 => be::<4>(raw).map(|b| float(f32::from_be_bytes(b) as f64)),
        Type::FLOAT8 => be::<8>(raw).map(|b| float(f64::from_be_bytes(b))),
        Type::NUMERIC => numeric(raw).map(Value::String),
        Type::CHAR => be::<1>(raw).map(|b| json!(String::from_utf8_lossy(&b).to_string())),
        Type::BYTEA => Some(binary(raw)),
        Type::JSON => Some(text(raw)),
        Type::JSONB => raw.split_first().filter(|(v, _)| **v == 1).map(|(_, rest)| text(rest)),
        Type::UUID => be::<16>(raw).map(|b| json!(uuid(&b))),
        Type::DATE => be::<4>(raw).map(|b| json!(date(i32::from_be_bytes(b)))),
        Type::TIME => be::<8>(raw).map(|b| json!(time_of_day(i64::from_be_bytes(b)))),
        Type::TIMETZ => timetz(raw).map(Value::String),
        Type::TIMESTAMP => be::<8>(raw).map(|b| json!(timestamp(i64::from_be_bytes(b), ""))),
        Type::TIMESTAMPTZ => be::<8>(raw).map(|b| json!(timestamp(i64::from_be_bytes(b), "+00"))),
        Type::INTERVAL => interval(raw).map(Value::String),
        Type::INET | Type::CIDR => inet(raw).map(Value::String),
        Type::MACADDR => {
            be::<6>(raw).map(|b| json!(b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")))
        }
        _ if is_texty(ty) => Some(text(raw)),
        _ => None,
    };
    v.unwrap_or_else(|| binary(raw))
}

fn text(raw: &[u8]) -> Value {
    match std::str::from_utf8(raw) {
        Ok(s) => Value::String(s.to_string()),
        Err(_) => binary(raw),
    }
}

fn float(f: f64) -> Value {
    if f.is_finite() {
        serde_json::Number::from_f64(f).map(Value::Number).unwrap_or_else(|| json!(f.to_string()))
    } else if f.is_nan() {
        json!("NaN")
    } else if f > 0.0 {
        json!("Infinity")
    } else {
        json!("-Infinity")
    }
}

fn numeric(raw: &[u8]) -> Option<String> {
    let rd = |i: usize| raw.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let (ndigits, weight, sign, dscale) = (rd(0)? as usize, rd(2)? as i16, rd(4)?, rd(6)? as usize);
    if raw.len() != 8 + 2 * ndigits {
        return None;
    }
    match sign {
        0xC000 => return Some("NaN".into()),
        0xD000 => return Some("Infinity".into()),
        0xF000 => return Some("-Infinity".into()),
        0x0000 | 0x4000 => {}
        _ => return None,
    }
    let digits: Vec<u16> = (0..ndigits).map(|i| rd(8 + 2 * i)).collect::<Option<_>>()?;
    if digits.iter().any(|d| *d > 9999) || dscale > 16383 {
        return None;
    }
    let mut int_part = String::new();
    for i in 0..=(weight.max(-1) as i32) {
        let d = digits.get(i as usize).copied().unwrap_or(0);
        if int_part.is_empty() {
            if d != 0 {
                int_part = d.to_string();
            }
        } else {
            int_part.push_str(&format!("{d:04}"));
        }
    }
    if int_part.is_empty() {
        int_part.push('0');
    }
    let mut frac = String::new();
    let mut i = weight as i32 + 1;
    while frac.len() < dscale {
        let d = if i < 0 { 0 } else { digits.get(i as usize).copied().unwrap_or(0) };
        frac.push_str(&format!("{d:04}"));
        i += 1;
    }
    frac.truncate(dscale);
    let neg = sign == 0x4000 && (int_part != "0" || frac.bytes().any(|b| b != b'0'));
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    out.push_str(&int_part);
    if dscale > 0 {
        out.push('.');
        out.push_str(&frac);
    }
    Some(out)
}

fn uuid(b: &[u8; 16]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// PostgreSQL's epoch (2000-01-01) in days after 1970-01-01.
const PG_EPOCH_DAYS: i64 = 10_957;
const USECS_PER_DAY: i64 = 86_400_000_000;

fn ymd(days_since_pg_epoch: i64) -> String {
    let (y, m, d) = civil(days_since_pg_epoch + PG_EPOCH_DAYS);
    if y <= 0 {
        format!("{:04}-{m:02}-{d:02} BC", 1 - y)
    } else {
        format!("{y:04}-{m:02}-{d:02}")
    }
}

fn date(days: i32) -> String {
    match days {
        i32::MAX => "infinity".into(),
        i32::MIN => "-infinity".into(),
        d => ymd(d as i64),
    }
}

fn time_of_day(usecs: i64) -> String {
    let (s, us) = (usecs.div_euclid(1_000_000), usecs.rem_euclid(1_000_000));
    let base = format!("{:02}:{:02}:{:02}", s / 3_600, (s / 60) % 60, s % 60);
    if us == 0 {
        base
    } else {
        format!("{base}.{:06}", us).trim_end_matches('0').to_string()
    }
}

fn timetz(raw: &[u8]) -> Option<String> {
    let t: [u8; 12] = be(raw)?;
    let usecs = i64::from_be_bytes(t[..8].try_into().ok()?);
    // The zone is stored as seconds *west* of UTC.
    let west = i32::from_be_bytes(t[8..].try_into().ok()?);
    let east = -west;
    let (sign, abs) = if east < 0 { ('-', -east) } else { ('+', east) };
    let zone = if abs % 3_600 == 0 {
        format!("{sign}{:02}", abs / 3_600)
    } else {
        format!("{sign}{:02}:{:02}", abs / 3_600, (abs / 60) % 60)
    };
    Some(format!("{}{zone}", time_of_day(usecs)))
}

fn timestamp(usecs: i64, zone: &str) -> String {
    match usecs {
        i64::MAX => "infinity".into(),
        i64::MIN => "-infinity".into(),
        u => {
            let (days, tod) = (u.div_euclid(USECS_PER_DAY), u.rem_euclid(USECS_PER_DAY));
            let date = ymd(days);
            match date.strip_suffix(" BC") {
                Some(d) => format!("{d} {}{zone} BC", time_of_day(tod)),
                None => format!("{date} {}{zone}", time_of_day(tod)),
            }
        }
    }
}

fn interval(raw: &[u8]) -> Option<String> {
    let b: [u8; 16] = be(raw)?;
    let usecs = i64::from_be_bytes(b[..8].try_into().ok()?);
    let days = i32::from_be_bytes(b[8..12].try_into().ok()?);
    let months = i32::from_be_bytes(b[12..].try_into().ok()?);
    let mut parts = Vec::new();
    let (y, mo) = (months / 12, months % 12);
    if y != 0 {
        parts.push(format!("{y} year{}", if y.abs() == 1 { "" } else { "s" }));
    }
    if mo != 0 {
        parts.push(format!("{mo} mon{}", if mo.abs() == 1 { "" } else { "s" }));
    }
    if days != 0 {
        parts.push(format!("{days} day{}", if days.abs() == 1 { "" } else { "s" }));
    }
    if usecs != 0 || parts.is_empty() {
        let sign = if usecs < 0 { "-" } else { "" };
        let a = usecs.unsigned_abs();
        let (s, us) = (a / 1_000_000, a % 1_000_000);
        let mut t = format!("{sign}{:02}:{:02}:{:02}", s / 3_600, (s / 60) % 60, s % 60);
        if us != 0 {
            t = format!("{t}.{us:06}").trim_end_matches('0').to_string();
        }
        parts.push(t);
    }
    Some(parts.join(" "))
}

fn inet(raw: &[u8]) -> Option<String> {
    let (&family, rest) = raw.split_first()?;
    let (&bits, rest) = rest.split_first()?;
    let (&is_cidr, rest) = rest.split_first()?;
    let (&nb, addr) = rest.split_first()?;
    if addr.len() != nb as usize {
        return None;
    }
    let ip: std::net::IpAddr = match (family, nb) {
        (2, 4) => std::net::IpAddr::from(<[u8; 4]>::try_from(addr).ok()?),
        (3, 16) => std::net::IpAddr::from(<[u8; 16]>::try_from(addr).ok()?),
        _ => return None,
    };
    let full = if ip.is_ipv4() { 32 } else { 128 };
    Some(if is_cidr == 0 && bits == full { ip.to_string() } else { format!("{ip}/{bits}") })
}

fn read_i32(raw: &[u8], at: &mut usize) -> Option<i32> {
    let b = raw.get(*at..*at + 4)?;
    *at += 4;
    Some(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn array(elem: &Type, raw: &[u8], depth: usize) -> Option<Value> {
    let mut at = 0;
    let ndim = read_i32(raw, &mut at)?;
    let _flags = read_i32(raw, &mut at)?;
    let _oid = read_i32(raw, &mut at)?;
    if ndim == 0 {
        return Some(json!([]));
    }
    if !(1..=6).contains(&ndim) {
        return None;
    }
    let mut dims = Vec::new();
    for _ in 0..ndim {
        let len = read_i32(raw, &mut at)?;
        let _lbound = read_i32(raw, &mut at)?;
        dims.push(usize::try_from(len).ok()?);
    }
    let total = dims.iter().try_fold(1usize, |a, d| a.checked_mul(*d))?;
    if total > raw.len() {
        return None;
    }
    let mut flat = Vec::with_capacity(total);
    for _ in 0..total {
        let len = read_i32(raw, &mut at)?;
        if len < 0 {
            flat.push(Value::Null);
        } else {
            let bytes = raw.get(at..at + len as usize)?;
            at += len as usize;
            flat.push(decode(elem, bytes, depth + 1));
        }
    }
    if at != raw.len() {
        return None;
    }
    fn nest(flat: &mut std::vec::IntoIter<Value>, dims: &[usize]) -> Value {
        match dims.split_first() {
            Some((n, [])) => Value::Array(flat.take(*n).collect()),
            Some((n, rest)) => Value::Array((0..*n).map(|_| nest(flat, rest)).collect()),
            None => Value::Null,
        }
    }
    Some(nest(&mut flat.into_iter(), &dims))
}

fn composite(fields: &[(&str, &Type)], raw: &[u8], depth: usize) -> Option<Value> {
    let mut at = 0;
    let count = usize::try_from(read_i32(raw, &mut at)?).ok()?;
    if count != fields.len() {
        return None;
    }
    let mut out = Map::new();
    for (name, ty) in fields {
        let _oid = read_i32(raw, &mut at)?;
        let len = read_i32(raw, &mut at)?;
        let v = if len < 0 {
            Value::Null
        } else {
            let bytes = raw.get(at..at + len as usize)?;
            at += len as usize;
            decode(ty, bytes, depth + 1)
        };
        out.insert(name.to_string(), v);
    }
    (at == raw.len()).then_some(Value::Object(out))
}

/// Cap a cell at [`MAX_CELL_BYTES`]: a long string is cut on a character
/// boundary; a long array or object is replaced by the start of its JSON
/// text. Returns the cell and, when cut, its full length in bytes.
pub fn cap(v: Value) -> (Value, Option<usize>) {
    match v {
        Value::String(s) if s.len() > MAX_CELL_BYTES => {
            let full = s.len();
            let mut end = MAX_CELL_BYTES;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            (Value::String(s[..end].to_string()), Some(full))
        }
        Value::Array(_) | Value::Object(_) => {
            let text = v.to_string();
            if text.len() > MAX_CELL_BYTES {
                let (cut, full) = cap(Value::String(text));
                (cut, full)
            } else {
                (v, None)
            }
        }
        other => (other, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric_bytes(ndigits: u16, weight: i16, sign: u16, dscale: u16, digits: &[u16]) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [ndigits, weight as u16, sign, dscale] {
            v.extend_from_slice(&x.to_be_bytes());
        }
        for d in digits {
            v.extend_from_slice(&d.to_be_bytes());
        }
        v
    }

    #[test]
    fn numbers_keep_their_precision() {
        assert_eq!(decode(&Type::INT8, &i64::MAX.to_be_bytes(), 0), json!("9223372036854775807"));
        assert_eq!(decode(&Type::INT4, &(-5i32).to_be_bytes(), 0), json!(-5));
        // 12345.6789 = digits [1, 2345, 6789], weight 1, dscale 4
        assert_eq!(decode(&Type::NUMERIC, &numeric_bytes(3, 1, 0, 4, &[1, 2345, 6789]), 0), json!("12345.6789"));
        // -0.05 = digits [500], weight -1, dscale 2
        assert_eq!(decode(&Type::NUMERIC, &numeric_bytes(1, -1, 0x4000, 2, &[500]), 0), json!("-0.05"));
        // 10000 = digits [1], weight 1, dscale 0
        assert_eq!(decode(&Type::NUMERIC, &numeric_bytes(1, 1, 0, 0, &[1]), 0), json!("10000"));
        assert_eq!(decode(&Type::NUMERIC, &numeric_bytes(0, 0, 0xC000, 0, &[]), 0), json!("NaN"));
        assert_eq!(decode(&Type::FLOAT8, &f64::NAN.to_be_bytes(), 0), json!("NaN"));
        assert_eq!(decode(&Type::FLOAT8, &1.5f64.to_be_bytes(), 0), json!(1.5));
        assert_eq!(kind(&Type::INT8), "string");
        assert_eq!(kind(&Type::INT4), "number");
    }

    #[test]
    fn dates_and_times_are_iso() {
        assert_eq!(decode(&Type::DATE, &0i32.to_be_bytes(), 0), json!("2000-01-01"));
        assert_eq!(decode(&Type::DATE, &(-1i32).to_be_bytes(), 0), json!("1999-12-31"));
        assert_eq!(decode(&Type::DATE, &i32::MAX.to_be_bytes(), 0), json!("infinity"));
        let ts = (USECS_PER_DAY + 3_723_000_500i64).to_be_bytes();
        assert_eq!(decode(&Type::TIMESTAMPTZ, &ts, 0), json!("2000-01-02 01:02:03.0005+00"));
        assert_eq!(decode(&Type::TIMESTAMP, &0i64.to_be_bytes(), 0), json!("2000-01-01 00:00:00"));
        let mut iv = 3_600_000_000i64.to_be_bytes().to_vec();
        iv.extend_from_slice(&2i32.to_be_bytes());
        iv.extend_from_slice(&14i32.to_be_bytes());
        assert_eq!(decode(&Type::INTERVAL, &iv, 0), json!("1 year 2 mons 2 days 01:00:00"));
    }

    #[test]
    fn text_binary_and_arrays() {
        assert_eq!(decode(&Type::TEXT, "héllo".as_bytes(), 0), json!("héllo"));
        assert_eq!(decode(&Type::BYTEA, &[0, 1, 2], 0), json!("AAEC"));
        assert_eq!(decode(&Type::JSONB, b"\x01{\"a\":1}", 0), json!("{\"a\":1}"));
        let mut arr = Vec::new();
        for x in [1i32, 0, 23, 2, 1] {
            arr.extend_from_slice(&x.to_be_bytes());
        }
        for (len, val) in [(4i32, Some(7i32)), (-1, None)] {
            arr.extend_from_slice(&len.to_be_bytes());
            if let Some(v) = val {
                arr.extend_from_slice(&v.to_be_bytes());
            }
        }
        assert_eq!(decode(&Type::INT4_ARRAY, &arr, 0), json!([7, null]));
    }

    #[test]
    fn malformed_values_never_panic() {
        for ty in [Type::INT4, Type::NUMERIC, Type::INT4_ARRAY, Type::TIMETZ, Type::INET, Type::JSONB, Type::UUID] {
            for raw in [&b""[..], &b"\x00"[..], &b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]] {
                let _ = decode(&ty, raw, 0);
            }
        }
        assert_eq!(decode(&Type::INT4, &[1, 2], 0), json!("AQI="), "a wrong length is base64, not a guess");
    }

    #[test]
    fn long_cells_are_capped() {
        let (v, full) = cap(json!("é".repeat(MAX_CELL_BYTES)));
        assert_eq!(full, Some(2 * MAX_CELL_BYTES));
        assert!(v.as_str().unwrap().len() <= MAX_CELL_BYTES);
        assert_eq!(cap(json!("short")), (json!("short"), None));
    }
}
