//! Oracle result values to JSON cells (features/sql-browser.md §6.3).
//! `NUMBER` is a decimal string unless the column is an integer of at most
//! 15 digits (always within ±2^53); binary floats are numbers; `RAW` is
//! base64; dates, timestamps and intervals are ISO-style text. LOBs, BFILEs,
//! objects, cursors and vectors are shown as a placeholder, never read.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use oraclemcp_driver_cx_protocol::oson::OsonValue;
use oraclemcp_driver_cx_protocol::thin::{ColumnMetadata, QueryValue};
use serde_json::{Map, Number, Value};

/// What a result column is, as the grid and the exporters need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColMeta {
    pub name: String,
    pub type_name: &'static str,
    /// `string | number | boolean | null | binary | json | datetime` (§6.3).
    pub kind: &'static str,
    /// A database number (exports write it as is, never formula-guarded).
    pub numeric: bool,
}

impl ColMeta {
    pub fn new(c: &ColumnMetadata) -> Self {
        let (type_name, kind, numeric) = describe(c);
        Self { name: c.name().to_string(), type_name, kind, numeric }
    }

    pub fn binary(&self) -> bool {
        self.kind == "binary"
    }

    pub fn json(&self) -> Value {
        serde_json::json!({"name": self.name, "type": self.type_name, "kind": self.kind})
    }
}

/// Oracle's internal type numbers (`ora_type_num`) and character form.
fn describe(c: &ColumnMetadata) -> (&'static str, &'static str, bool) {
    let national = c.csfrm() == 2;
    match c.ora_type_num() {
        1 if national => ("NVARCHAR2", "string", false),
        1 => ("VARCHAR2", "string", false),
        96 if national => ("NCHAR", "string", false),
        96 => ("CHAR", "string", false),
        8 => ("LONG", "string", false),
        2 | 3 if c.scale() == 0 && (1..=15).contains(&c.precision()) => ("NUMBER", "number", true),
        2 | 3 => ("NUMBER", "string", true),
        100 => ("BINARY_FLOAT", "number", true),
        101 => ("BINARY_DOUBLE", "number", true),
        12 => ("DATE", "datetime", false),
        180 => ("TIMESTAMP", "datetime", false),
        181 => ("TIMESTAMP WITH TIME ZONE", "datetime", false),
        231 => ("TIMESTAMP WITH LOCAL TIME ZONE", "datetime", false),
        182 => ("INTERVAL YEAR TO MONTH", "string", false),
        183 => ("INTERVAL DAY TO SECOND", "string", false),
        23 => ("RAW", "binary", false),
        24 => ("LONG RAW", "binary", false),
        104 | 208 => ("ROWID", "string", false),
        252 => ("BOOLEAN", "boolean", false),
        119 => ("JSON", "json", false),
        112 if national => ("NCLOB", "string", false),
        112 => ("CLOB", "string", false),
        113 => ("BLOB", "binary", false),
        114 => ("BFILE", "string", false),
        127 => ("VECTOR", "string", false),
        _ => ("OTHER", "string", false),
    }
}

/// The largest integer a JSON number carries exactly.
const SAFE: i64 = 1 << 53;

fn float_text(text: &str) -> Value {
    text.parse::<f64>()
        .ok()
        .and_then(Number::from_f64)
        .map(Value::Number)
        .unwrap_or_else(|| Value::String(text.to_string()))
}

fn datetime(y: i32, mo: u8, d: u8, h: u8, mi: u8, s: u8, ns: u32) -> String {
    let mut out = format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}");
    if ns > 0 {
        let frac = format!("{ns:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    out
}

fn interval_ds(days: i32, h: i32, m: i32, s: i32, fs: i32) -> String {
    let neg = days < 0 || h < 0 || m < 0 || s < 0 || fs < 0;
    let mut out = format!(
        "{}{} {:02}:{:02}:{:02}",
        if neg { "-" } else { "+" },
        days.unsigned_abs(),
        h.unsigned_abs(),
        m.unsigned_abs(),
        s.unsigned_abs()
    );
    if fs != 0 {
        out.push_str(&format!(".{:09}", fs.unsigned_abs()));
    }
    out
}

fn oson(v: &OsonValue, depth: usize) -> Value {
    if depth > 64 {
        return Value::String("[nested too deep]".into());
    }
    match v {
        OsonValue::Null => Value::Null,
        OsonValue::Bool(b) => Value::Bool(*b),
        OsonValue::Number(t) => match t.parse::<i64>() {
            Ok(n) if (-SAFE..=SAFE).contains(&n) => Value::from(n),
            _ => Value::String(t.clone()),
        },
        OsonValue::BinaryFloat(f) => Number::from_f64(f64::from(*f)).map(Value::Number).unwrap_or(Value::Null),
        OsonValue::BinaryDouble(f) => Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
        OsonValue::String(s) => Value::String(s.clone()),
        OsonValue::Raw(b) => Value::String(B64.encode(b)),
        OsonValue::DateTime { year, month, day, hour, minute, second, nanosecond } => {
            Value::String(datetime(*year, *month, *day, *hour, *minute, *second, *nanosecond))
        }
        OsonValue::IntervalDS { days, hours, minutes, seconds, fseconds } => {
            Value::String(interval_ds(*days, *hours, *minutes, *seconds, *fseconds))
        }
        OsonValue::Array(items) => Value::Array(items.iter().map(|i| oson(i, depth + 1)).collect()),
        OsonValue::Object(fields) => {
            Value::Object(fields.iter().map(|(k, v)| (k.clone(), oson(v, depth + 1))).collect::<Map<_, _>>())
        }
        _ => Value::String("[unsupported JSON value]".into()),
    }
}

/// One cell. Malformed input never panics.
pub fn cell(meta: &ColMeta, v: Option<&QueryValue>) -> Value {
    let Some(v) = v else { return Value::Null };
    match v {
        QueryValue::Text(s) => Value::String(s.clone()),
        QueryValue::TextRaw { bytes, .. } => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        QueryValue::Raw(b) => Value::String(B64.encode(b)),
        QueryValue::Rowid(r) => Value::String(r.clone()),
        QueryValue::Number(n) => {
            let text = n.to_canonical_string();
            match n.to_i64() {
                Some(i) if meta.kind == "number" && (-SAFE..=SAFE).contains(&i) => Value::from(i),
                _ => Value::String(text),
            }
        }
        QueryValue::BinaryDouble(t) => float_text(t),
        QueryValue::Boolean(b) => Value::Bool(*b),
        QueryValue::DateTime { year, month, day, hour, minute, second, nanosecond } => {
            Value::String(datetime(*year, *month, *day, *hour, *minute, *second, *nanosecond))
        }
        QueryValue::TimestampTz { year, month, day, hour, minute, second, nanosecond, offset_minutes } => {
            let sign = if *offset_minutes < 0 { '-' } else { '+' };
            let off = offset_minutes.unsigned_abs();
            Value::String(format!(
                "{}{sign}{:02}:{:02}",
                datetime(*year, *month, *day, *hour, *minute, *second, *nanosecond),
                off / 60,
                off % 60
            ))
        }
        QueryValue::IntervalDS { days, hours, minutes, seconds, fseconds } => {
            Value::String(interval_ds(*days, *hours, *minutes, *seconds, *fseconds))
        }
        QueryValue::IntervalYM { years, months } => {
            let neg = *years < 0 || *months < 0;
            Value::String(format!(
                "{}{}-{:02}",
                if neg { "-" } else { "+" },
                years.unsigned_abs(),
                months.unsigned_abs()
            ))
        }
        QueryValue::Json(j) => oson(j, 0),
        QueryValue::Array(items) => Value::Array(items.iter().map(|i| cell(meta, i.as_ref())).collect()),
        QueryValue::Lob(_) => Value::String(format!("[{}]", meta.type_name)),
        QueryValue::Cursor(_) => Value::String("[CURSOR]".into()),
        QueryValue::Object(_) => Value::String("[OBJECT]".into()),
        QueryValue::Vector(_) => Value::String("[VECTOR]".into()),
        _ => Value::String("[unsupported value]".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(kind: &'static str) -> ColMeta {
        ColMeta { name: "c".into(), type_name: "NUMBER", kind, numeric: true }
    }

    #[test]
    fn numbers_keep_their_precision() {
        let small = QueryValue::number_from_text("42", true);
        assert_eq!(cell(&meta("number"), Some(&small)), Value::from(42));
        assert_eq!(cell(&meta("string"), Some(&small)), Value::String("42".into()));
        let big = QueryValue::number_from_text("9007199254740993", true);
        assert_eq!(cell(&meta("number"), Some(&big)), Value::String("9007199254740993".into()));
        let dec = QueryValue::number_from_text("10.5", false);
        assert_eq!(cell(&meta("string"), Some(&dec)), Value::String("10.5".into()));
        assert_eq!(cell(&meta("string"), None), Value::Null);
        assert_eq!(float_text("1.5"), Value::from(1.5));
        assert_eq!(float_text("Inf"), Value::String("Inf".into()));
    }

    #[test]
    fn temporal_values_are_iso_text() {
        assert_eq!(datetime(2026, 1, 2, 3, 4, 5, 0), "2026-01-02 03:04:05");
        assert_eq!(datetime(2026, 1, 2, 3, 4, 5, 120_000_000), "2026-01-02 03:04:05.12");
        assert_eq!(interval_ds(1, 2, 3, 4, 0), "+1 02:03:04");
        assert_eq!(interval_ds(-1, 0, 0, 0, 0), "-1 00:00:00");
        let raw = QueryValue::Raw(vec![0xde, 0xad]);
        let m = ColMeta { name: "r".into(), type_name: "RAW", kind: "binary", numeric: false };
        assert_eq!(cell(&m, Some(&raw)), Value::String("3q0=".into()));
    }
}
