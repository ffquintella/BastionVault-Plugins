//! SQL Server result values to JSON cells (features/sql-browser.md §6.3).
//! Integers that always fit ±2^53 are numbers; `bigint`, `decimal`,
//! `numeric` and `money` are strings, so precision is never lost (money as
//! the server rounds it to four places). Binary is base64; dates and times
//! are ISO-style text.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{Number, Value};
use tiberius::time::{Date, DateTime2, Time};
use tiberius::{Column, ColumnData, ColumnType};

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
        let (type_name, kind) = describe(c.column_type());
        Self { name: c.name().to_string(), type_name, kind, ty: c.column_type() }
    }

    /// A database number (exports write it as is, never formula-guarded).
    pub fn numeric(&self) -> bool {
        self.kind == "number"
            || matches!(
                self.ty,
                ColumnType::Int8 | ColumnType::Decimaln | ColumnType::Numericn | ColumnType::Money | ColumnType::Money4
            )
    }

    pub fn binary(&self) -> bool {
        self.kind == "binary"
    }

    pub fn json(&self) -> Value {
        serde_json::json!({"name": self.name, "type": self.type_name, "kind": self.kind})
    }
}

fn describe(ty: ColumnType) -> (&'static str, &'static str) {
    use ColumnType::*;
    match ty {
        Null => ("null", "null"),
        Bit | Bitn => ("bit", "boolean"),
        Int1 => ("tinyint", "number"),
        Int2 => ("smallint", "number"),
        Int4 => ("int", "number"),
        // Intn is int-family of a width only the value tells: a 64-bit
        // value is written as a string.
        Intn => ("int", "number"),
        Int8 => ("bigint", "string"),
        Float4 | Float8 | Floatn => ("float", "number"),
        Decimaln | Numericn => ("decimal", "string"),
        Money | Money4 => ("money", "string"),
        Guid => ("uniqueidentifier", "string"),
        Datetime | Datetimen => ("datetime", "datetime"),
        Datetime4 => ("smalldatetime", "datetime"),
        Daten => ("date", "datetime"),
        Timen => ("time", "datetime"),
        Datetime2 => ("datetime2", "datetime"),
        DatetimeOffsetn => ("datetimeoffset", "datetime"),
        BigVarChar | BigChar | Text => ("varchar", "string"),
        NVarchar | NChar | NText => ("nvarchar", "string"),
        Xml => ("xml", "string"),
        BigVarBin | BigBinary | Image => ("varbinary", "binary"),
        // sql_variant, CLR types and anything newer: bytes until reviewed.
        Udt | SSVariant => ("unknown", "binary"),
    }
}

/// The largest integer a JSON number carries exactly.
const SAFE: i64 = 1 << 53;

fn float(f: f64) -> Value {
    Number::from_f64(f).map(Value::Number).unwrap_or_else(|| Value::String(f.to_string()))
}

/// Proleptic Gregorian date from a day count since 0001-01-01.
fn civil(days_since_0001: i64) -> (i64, u32, u32) {
    // Shift to days since 1970-01-01, then Howard Hinnant's civil_from_days.
    let z = days_since_0001 - 719_162 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn date_text(days_since_0001: i64) -> String {
    let (y, m, d) = civil(days_since_0001);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `hh:mm:ss[.fffffff]` from a count of `10^-scale` second increments.
fn time_text(increments: u64, scale: u8) -> String {
    let unit = 10u64.pow(u32::from(scale.min(7)));
    let secs = increments / unit;
    let frac = increments % unit;
    let mut out = format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60);
    if scale > 0 {
        out.push_str(&format!(".{:0width$}", frac, width = usize::from(scale.min(7))));
    }
    out
}

/// Days from 0001-01-01 to 1900-01-01 (the `datetime` epoch).
const DAYS_TO_1900: i64 = 693_595;

fn datetime2_text(dt: DateTime2) -> String {
    format!("{} {}", date_text(i64::from(dt.date().days())), time_text(dt.time().increments(), dt.time().scale()))
}

fn date(d: Date) -> String {
    date_text(i64::from(d.days()))
}

fn time(t: Time) -> String {
    time_text(t.increments(), t.scale())
}

/// One cell. Malformed input never panics.
pub fn cell(meta: &ColMeta, v: &ColumnData<'_>) -> Value {
    match v {
        ColumnData::U8(Some(n)) => Value::from(*n),
        ColumnData::I16(Some(n)) => Value::from(*n),
        ColumnData::I32(Some(n)) => Value::from(*n),
        ColumnData::I64(Some(n))
            if meta.kind == "number" && (-SAFE..=SAFE).contains(n) && meta.ty != ColumnType::Intn =>
        {
            Value::from(*n)
        }
        ColumnData::I64(Some(n)) => Value::String(n.to_string()),
        ColumnData::F32(Some(f)) => float(f64::from(*f)),
        ColumnData::F64(Some(f)) if matches!(meta.ty, ColumnType::Money | ColumnType::Money4) => {
            Value::String(format!("{f:.4}"))
        }
        ColumnData::F64(Some(f)) => float(*f),
        ColumnData::Bit(Some(b)) => Value::Bool(*b),
        ColumnData::String(Some(s)) => Value::String(s.to_string()),
        ColumnData::Guid(Some(g)) => Value::String(g.to_string()),
        ColumnData::Binary(Some(b)) => Value::String(B64.encode(b)),
        ColumnData::Numeric(Some(n)) => Value::String(n.to_string()),
        ColumnData::Xml(Some(x)) => Value::String(x.to_string()),
        ColumnData::DateTime(Some(dt)) => {
            // 1/300 s ticks since midnight, days since 1900-01-01.
            let ms = u64::from(dt.seconds_fragments()) * 10 / 3;
            let text = format!(
                "{} {}.{:03}",
                date_text(DAYS_TO_1900 + i64::from(dt.days())),
                time_text(ms / 1000, 0),
                ms % 1000
            );
            Value::String(text)
        }
        ColumnData::SmallDateTime(Some(dt)) => {
            let mins = u64::from(dt.seconds_fragments());
            Value::String(format!("{} {}", date_text(DAYS_TO_1900 + i64::from(dt.days())), time_text(mins * 60, 0)))
        }
        ColumnData::Date(Some(d)) => Value::String(date(*d)),
        ColumnData::Time(Some(t)) => Value::String(time(*t)),
        ColumnData::DateTime2(Some(dt)) => Value::String(datetime2_text(*dt)),
        ColumnData::DateTimeOffset(Some(o)) => {
            // Stored in UTC; shown in the value's own offset.
            let dt = o.datetime2();
            let scale = dt.time().scale().min(7);
            let unit = 10i128.pow(u32::from(scale));
            let total = i128::from(dt.date().days()) * 86_400 * unit
                + i128::from(dt.time().increments())
                + i128::from(o.offset()) * 60 * unit;
            let days = total.div_euclid(86_400 * unit);
            let rest = total.rem_euclid(86_400 * unit) as u64;
            let off = o.offset();
            let sign = if off < 0 { '-' } else { '+' };
            Value::String(format!(
                "{} {} {sign}{:02}:{:02}",
                date_text(days as i64),
                time_text(rest, scale),
                off.unsigned_abs() / 60,
                off.unsigned_abs() % 60
            ))
        }
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiberius::numeric::Numeric;
    use tiberius::time::{DateTime, DateTimeOffset};

    fn meta(ty: ColumnType) -> ColMeta {
        let (type_name, kind) = describe(ty);
        ColMeta { name: "c".into(), type_name, kind, ty }
    }

    #[test]
    fn integers_numbers_and_wide_numbers_strings() {
        assert_eq!(cell(&meta(ColumnType::Int4), &ColumnData::I32(Some(7))), Value::from(7));
        assert_eq!(cell(&meta(ColumnType::Int8), &ColumnData::I64(Some(7))), Value::from("7"));
        assert_eq!(
            cell(&meta(ColumnType::Intn), &ColumnData::I64(Some(9_007_199_254_740_993))),
            Value::from("9007199254740993")
        );
        assert_eq!(cell(&meta(ColumnType::Intn), &ColumnData::I32(Some(-3))), Value::from(-3));
        assert_eq!(
            cell(&meta(ColumnType::Decimaln), &ColumnData::Numeric(Some(Numeric::new_with_scale(1050, 2)))),
            Value::from("10.50")
        );
        assert_eq!(cell(&meta(ColumnType::Money), &ColumnData::F64(Some(12.5))), Value::from("12.5000"));
        assert_eq!(cell(&meta(ColumnType::Floatn), &ColumnData::F64(Some(1.5))), Value::from(1.5));
        assert!(meta(ColumnType::Int8).numeric() && meta(ColumnType::Money).numeric());
    }

    #[test]
    fn null_is_distinct_from_the_empty_string_and_binary_is_base64() {
        let m = meta(ColumnType::NVarchar);
        assert_eq!(cell(&m, &ColumnData::String(None)), Value::Null);
        assert_eq!(cell(&m, &ColumnData::String(Some("".into()))), Value::from(""));
        assert_eq!(
            cell(&meta(ColumnType::BigVarBin), &ColumnData::Binary(Some(vec![0xff].into()))),
            Value::from("/w==")
        );
        assert_eq!(cell(&meta(ColumnType::Bitn), &ColumnData::Bit(Some(true))), Value::Bool(true));
    }

    #[test]
    fn dates_and_times() {
        assert_eq!(date_text(0), "0001-01-01");
        assert_eq!(date_text(DAYS_TO_1900), "1900-01-01");
        assert_eq!(date_text(739_918), "2026-10-30");
        let dt = ColumnData::DateTime(Some(DateTime::new(0, 300 * 3661 + 150)));
        assert_eq!(cell(&meta(ColumnType::Datetimen), &dt), Value::from("1900-01-01 01:01:01.500"));
        let d2 = DateTime2::new(Date::new(739_918), Time::new(452_961_234_567, 7));
        assert_eq!(
            cell(&meta(ColumnType::Datetime2), &ColumnData::DateTime2(Some(d2))),
            Value::from("2026-10-30 12:34:56.1234567")
        );
        // 23:00 UTC at -03:00 is 20:00 local the same day.
        let utc = DateTime2::new(Date::new(739_918), Time::new(23 * 3600, 0));
        let v =
            cell(&meta(ColumnType::DatetimeOffsetn), &ColumnData::DateTimeOffset(Some(DateTimeOffset::new(utc, -180))));
        assert_eq!(v, Value::from("2026-10-30 20:00:00 -03:00"));
        // 01:00 UTC at -03:00 is the previous day.
        let utc = DateTime2::new(Date::new(739_918), Time::new(3600, 0));
        let v =
            cell(&meta(ColumnType::DatetimeOffsetn), &ColumnData::DateTimeOffset(Some(DateTimeOffset::new(utc, -180))));
        assert_eq!(v, Value::from("2026-10-29 22:00:00 -03:00"));
    }
}
