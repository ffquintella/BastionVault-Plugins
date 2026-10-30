//! MySQL / MariaDB result values to JSON cells (features/sql-browser.md
//! §6.3), for both protocols: the text protocol returns every value as
//! bytes, the binary protocol (prepared statements) typed values. Integers
//! of types that always fit ±2^53 are numbers; `BIGINT` and `DECIMAL` are
//! decimal strings, so precision is never lost. Binary is base64.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use mysql_async::consts::ColumnType;
use mysql_async::{Column, Value as My};
use serde_json::{Number, Value};

/// The `binary` character set id: a string column with it holds bytes.
const BINARY_CHARSET: u16 = 63;

/// What a result column is, as the grid and the exporters need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColMeta {
    pub name: String,
    pub type_name: &'static str,
    /// `string | number | boolean | null | binary | json | datetime` (§6.3).
    pub kind: &'static str,
    ty: ColumnType,
}

impl ColMeta {
    pub fn new(c: &Column) -> Self {
        let ty = c.column_type();
        // BINARY_FLAG alone is set on binary collations of text too; only
        // the `binary` character set means bytes.
        let (type_name, kind) = describe(ty, c.character_set() == BINARY_CHARSET);
        Self { name: c.name_str().into_owned(), type_name, kind, ty }
    }

    /// A database number (exports write it as is, never formula-guarded).
    pub fn numeric(&self) -> bool {
        self.kind == "number"
            || matches!(
                self.ty,
                ColumnType::MYSQL_TYPE_LONGLONG | ColumnType::MYSQL_TYPE_DECIMAL | ColumnType::MYSQL_TYPE_NEWDECIMAL
            )
    }

    pub fn binary(&self) -> bool {
        self.kind == "binary"
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({"name": self.name, "type": self.type_name, "kind": self.kind})
    }
}

fn describe(ty: ColumnType, binary_charset: bool) -> (&'static str, &'static str) {
    use ColumnType::*;
    match ty {
        MYSQL_TYPE_TINY => ("tinyint", "number"),
        MYSQL_TYPE_SHORT => ("smallint", "number"),
        MYSQL_TYPE_INT24 => ("mediumint", "number"),
        MYSQL_TYPE_LONG => ("int", "number"),
        MYSQL_TYPE_YEAR => ("year", "number"),
        MYSQL_TYPE_FLOAT => ("float", "number"),
        MYSQL_TYPE_DOUBLE => ("double", "number"),
        MYSQL_TYPE_LONGLONG => ("bigint", "string"),
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => ("decimal", "string"),
        MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE => ("date", "datetime"),
        MYSQL_TYPE_DATETIME | MYSQL_TYPE_DATETIME2 => ("datetime", "datetime"),
        MYSQL_TYPE_TIMESTAMP | MYSQL_TYPE_TIMESTAMP2 => ("timestamp", "datetime"),
        MYSQL_TYPE_TIME | MYSQL_TYPE_TIME2 => ("time", "datetime"),
        MYSQL_TYPE_JSON => ("json", "json"),
        MYSQL_TYPE_BIT => ("bit", "binary"),
        MYSQL_TYPE_GEOMETRY => ("geometry", "binary"),
        MYSQL_TYPE_ENUM => ("enum", "string"),
        MYSQL_TYPE_SET => ("set", "string"),
        MYSQL_TYPE_NULL => ("null", "null"),
        MYSQL_TYPE_VARCHAR | MYSQL_TYPE_VAR_STRING if binary_charset => ("varbinary", "binary"),
        MYSQL_TYPE_STRING if binary_charset => ("binary", "binary"),
        MYSQL_TYPE_VARCHAR | MYSQL_TYPE_VAR_STRING => ("varchar", "string"),
        MYSQL_TYPE_STRING => ("char", "string"),
        MYSQL_TYPE_TINY_BLOB | MYSQL_TYPE_MEDIUM_BLOB | MYSQL_TYPE_LONG_BLOB | MYSQL_TYPE_BLOB if binary_charset => {
            ("blob", "binary")
        }
        MYSQL_TYPE_TINY_BLOB | MYSQL_TYPE_MEDIUM_BLOB | MYSQL_TYPE_LONG_BLOB | MYSQL_TYPE_BLOB => ("text", "string"),
        // Anything newer (VECTOR, …) is bytes until it is reviewed.
        _ => ("unknown", "binary"),
    }
}

/// The largest integer a JSON number carries exactly.
const SAFE: i64 = 1 << 53;

fn number_or_string(text: String) -> Value {
    if let Ok(i) = text.parse::<i64>() {
        if (-SAFE..=SAFE).contains(&i) {
            return Value::Number(i.into());
        }
    }
    Value::String(text)
}

fn float(f: f64) -> Value {
    Number::from_f64(f).map(Value::Number).unwrap_or_else(|| Value::String(f.to_string()))
}

fn utf8_or_base64(bytes: Vec<u8>) -> Value {
    match String::from_utf8(bytes) {
        Ok(s) => Value::String(s),
        Err(e) => Value::String(B64.encode(e.into_bytes())),
    }
}

/// `(year, month, day, hour, minute, second, microsecond)`.
type DateParts = (u16, u8, u8, u8, u8, u8, u32);

fn date(meta: &ColMeta, (y, mo, d, h, mi, s, us): DateParts) -> String {
    if matches!(meta.ty, ColumnType::MYSQL_TYPE_DATE | ColumnType::MYSQL_TYPE_NEWDATE) {
        return format!("{y:04}-{mo:02}-{d:02}");
    }
    let mut out = format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}");
    if us != 0 {
        out.push_str(&format!(".{us:06}"));
    }
    out
}

fn time(neg: bool, days: u32, h: u8, mi: u8, s: u8, us: u32) -> String {
    let hours = u64::from(days) * 24 + u64::from(h);
    let mut out = format!("{}{hours:02}:{mi:02}:{s:02}", if neg { "-" } else { "" });
    if us != 0 {
        out.push_str(&format!(".{us:06}"));
    }
    out
}

/// One cell. Malformed input decodes to base64, never panics.
pub fn cell(meta: &ColMeta, v: My) -> Value {
    match v {
        My::NULL => Value::Null,
        My::Int(i) if meta.kind == "number" && (-SAFE..=SAFE).contains(&i) => Value::Number(i.into()),
        My::Int(i) => Value::String(i.to_string()),
        My::UInt(u) if meta.kind == "number" && u <= SAFE as u64 => Value::Number(u.into()),
        My::UInt(u) => Value::String(u.to_string()),
        My::Float(f) => float(f64::from(f)),
        My::Double(f) => float(f),
        My::Date(y, mo, d, h, mi, s, us) => Value::String(date(meta, (y, mo, d, h, mi, s, us))),
        My::Time(neg, days, h, mi, s, us) => Value::String(time(neg, days, h, mi, s, us)),
        My::Bytes(b) => match meta.kind {
            "binary" => Value::String(B64.encode(&b)),
            "number" => match String::from_utf8(b) {
                Ok(text) if matches!(meta.ty, ColumnType::MYSQL_TYPE_FLOAT | ColumnType::MYSQL_TYPE_DOUBLE) => {
                    text.parse::<f64>().map(float).unwrap_or(Value::String(text))
                }
                Ok(text) => number_or_string(text),
                Err(e) => Value::String(B64.encode(e.into_bytes())),
            },
            "json" => match serde_json::from_slice::<Value>(&b) {
                Ok(v) => v,
                Err(_) => utf8_or_base64(b),
            },
            _ => utf8_or_base64(b),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(ty: ColumnType) -> ColMeta {
        let (type_name, kind) = describe(ty, false);
        ColMeta { name: "c".into(), type_name, kind, ty }
    }

    #[test]
    fn integers_numbers_and_wide_numbers_strings() {
        assert_eq!(cell(&meta(ColumnType::MYSQL_TYPE_LONG), My::Int(7)), Value::from(7));
        assert_eq!(cell(&meta(ColumnType::MYSQL_TYPE_LONG), My::Bytes(b"-12".to_vec())), Value::from(-12));
        assert_eq!(cell(&meta(ColumnType::MYSQL_TYPE_LONGLONG), My::Int(7)), Value::from("7"));
        assert_eq!(
            cell(&meta(ColumnType::MYSQL_TYPE_LONGLONG), My::Bytes(b"9007199254740993".to_vec())),
            Value::from("9007199254740993")
        );
        assert_eq!(cell(&meta(ColumnType::MYSQL_TYPE_NEWDECIMAL), My::Bytes(b"10.50".to_vec())), Value::from("10.50"));
        assert_eq!(cell(&meta(ColumnType::MYSQL_TYPE_DOUBLE), My::Bytes(b"1.5".to_vec())), Value::from(1.5));
        assert_eq!(cell(&meta(ColumnType::MYSQL_TYPE_DOUBLE), My::Double(2.25)), Value::from(2.25));
        assert!(meta(ColumnType::MYSQL_TYPE_LONGLONG).numeric() && meta(ColumnType::MYSQL_TYPE_NEWDECIMAL).numeric());
    }

    #[test]
    fn null_is_distinct_from_the_empty_string() {
        let m = meta(ColumnType::MYSQL_TYPE_VAR_STRING);
        assert_eq!(cell(&m, My::NULL), Value::Null);
        assert_eq!(cell(&m, My::Bytes(Vec::new())), Value::from(""));
    }

    #[test]
    fn dates_times_json_and_binary() {
        let d = meta(ColumnType::MYSQL_TYPE_DATE);
        assert_eq!(cell(&d, My::Date(2026, 10, 30, 0, 0, 0, 0)), Value::from("2026-10-30"));
        let dt = meta(ColumnType::MYSQL_TYPE_DATETIME);
        assert_eq!(cell(&dt, My::Date(2026, 1, 2, 3, 4, 5, 6)), Value::from("2026-01-02 03:04:05.000006"));
        let t = meta(ColumnType::MYSQL_TYPE_TIME);
        assert_eq!(cell(&t, My::Time(true, 1, 2, 3, 4, 0)), Value::from("-26:03:04"));
        let j = meta(ColumnType::MYSQL_TYPE_JSON);
        assert_eq!(cell(&j, My::Bytes(br#"{"a":1}"#.to_vec())), serde_json::json!({"a": 1}));
        let bit = meta(ColumnType::MYSQL_TYPE_BIT);
        assert_eq!(cell(&bit, My::Bytes(vec![0xff])), Value::from("/w=="));
        let (_, kind) = describe(ColumnType::MYSQL_TYPE_BLOB, true);
        assert_eq!(kind, "binary");
        let (_, kind) = describe(ColumnType::MYSQL_TYPE_BLOB, false);
        assert_eq!(kind, "string");
        // Bytes that are not UTF-8 in a text column are never guessed.
        assert_eq!(cell(&meta(ColumnType::MYSQL_TYPE_VAR_STRING), My::Bytes(vec![0xff, 0xfe])), Value::from("//4="));
    }
}
