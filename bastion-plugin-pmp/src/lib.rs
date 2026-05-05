//! Library surface for `bastion-plugin-pmp`. The bin entrypoint
//! (`main.rs`) calls into `validate` / `preview`; tests under
//! `tests/` import the same functions.

pub mod mapping;
pub mod parser;
pub mod plan;

use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ValidateReport {
    pub ok: bool,
    pub format: String,
    pub sheet: String,
    pub row_count: usize,
    pub columns: Vec<String>,
    pub missing_required: Vec<String>,
    pub unknown_columns: Vec<String>,
}

pub fn validate(path: &Path) -> Result<ValidateReport, String> {
    let p = parser::parse(path)?;
    Ok(ValidateReport {
        ok: p.missing_required.is_empty(),
        format: p.format,
        sheet: p.sheet,
        row_count: p.rows.len(),
        columns: p.columns,
        missing_required: p.missing_required,
        unknown_columns: p.unknown_columns,
    })
}

pub fn preview(path: &Path, opts: &plan::PlanOptions) -> Result<plan::ImportPlan, String> {
    let sheet = parser::parse(path)?;
    if !sheet.missing_required.is_empty() {
        return Err(format!(
            "spreadsheet is missing required columns: {}",
            sheet.missing_required.join(", ")
        ));
    }
    Ok(plan::build(&sheet, opts))
}

/// Test-only helper: construct a `ParsedSheet` from a header + row
/// matrix without hitting `calamine`. Lets the version-matrix tests
/// cover layout permutations (column reorder, missing optionals,
/// extra custom columns, sheet-name fallback) without committing
/// per-PMP-version `.xls` fixtures to the repo.
pub fn build_synthetic_sheet(
    sheet: &str,
    headers: &[&str],
    rows: &[Vec<&str>],
) -> parser::ParsedSheet {
    use std::collections::BTreeMap;

    let header_vec: Vec<String> = headers.iter().map(|s| (*s).to_string()).collect();
    let missing_required: Vec<String> = parser::REQUIRED_COLUMNS
        .iter()
        .filter(|c| !header_vec.iter().any(|h| h == *c))
        .map(|c| (*c).to_string())
        .collect();
    let unknown_columns: Vec<String> = header_vec
        .iter()
        .filter(|h| !parser::KNOWN_COLUMNS.contains(&h.as_str()))
        .cloned()
        .collect();
    let mut out_rows = Vec::new();
    for (idx, r) in rows.iter().enumerate() {
        let mut cells = BTreeMap::new();
        for (i, h) in header_vec.iter().enumerate() {
            cells.insert(h.clone(), r.get(i).copied().unwrap_or("").to_string());
        }
        out_rows.push(parser::RawRow { row_number: idx + 2, cells });
    }
    parser::ParsedSheet {
        format: "synthetic".into(),
        sheet: sheet.into(),
        columns: header_vec,
        missing_required,
        unknown_columns,
        rows: out_rows,
    }
}
