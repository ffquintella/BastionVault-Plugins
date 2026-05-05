//! Build the import plan from the parsed sheet. The plan is what
//! `op = "preview"` and `op = "import"` both return; the GUI walks
//! it via the existing Resource / KV / Asset Group Tauri commands.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::mapping::{self, RowKind};
use crate::parser::{ParsedSheet, RawRow, KNOWN_COLUMNS};

/// Inputs from the GUI's `preview` / `import` request that
/// influence the plan shape (vs. the parser's pure mechanical job).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PlanOptions {
    /// Slug applied to KV paths and to the `pmp-import:<batch-id>`
    /// tag. The wizard generates this once per import run; if
    /// missing, we fall back to a `YYYYMMDDhhmmss`-shaped value
    /// derived from the local clock.
    #[serde(default)]
    pub batch_id: Option<String>,
    /// Operator-supplied `OS Type` value → BV resource type id.
    /// Empty entries are ignored.
    #[serde(default)]
    pub type_overrides: BTreeMap<String, String>,
    /// `name_collision_policy` is informational here — the plan
    /// doesn't enforce it (the GUI does, against existing state).
    /// We round-trip it so the wizard can echo it back to the user.
    #[serde(default)]
    pub name_collision_policy: Option<String>,
    /// Custom-column policy.
    #[serde(default)]
    pub preserve_unknown_columns: bool,
    /// Custom columns the GUI marked as "use as tag". Their values
    /// land in `resource.tags` (and the KV blob's `metadata.tags`).
    #[serde(default)]
    pub tag_columns: Vec<String>,
    /// The wizard fetches `list_asset_groups` and passes the names
    /// down so the plan can mark each derived department-group with
    /// `exists: true|false`.
    #[serde(default)]
    pub existing_asset_groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceSecret {
    pub name: String,
    pub value_b64: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourcePlan {
    pub name: String,
    #[serde(rename = "type")]
    pub bv_type: String,
    pub metadata: BTreeMap<String, String>,
    pub asset_groups: Vec<String>,
    pub tags: Vec<String>,
    pub secrets: Vec<ResourceSecret>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KvBlobPlan {
    pub kind: String,
    pub path: String,
    pub data: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetGroupPlan {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub members: Vec<String>,
    pub secrets: Vec<String>,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkipEntry {
    pub row: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanSummary {
    pub resource_count: usize,
    pub secret_count: usize,
    pub kv_blob_count: usize,
    pub asset_group_count: usize,
    pub skipped: Vec<SkipEntry>,
    pub type_distribution: BTreeMap<String, usize>,
    pub kv_distribution: BTreeMap<String, usize>,
    pub asset_groups_new: Vec<String>,
    pub asset_groups_existing: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportPlan {
    pub batch_id: String,
    pub summary: PlanSummary,
    pub asset_groups: Vec<AssetGroupPlan>,
    pub resources: Vec<ResourcePlan>,
    pub kv_blobs: Vec<KvBlobPlan>,
}

pub fn build(sheet: &ParsedSheet, opts: &PlanOptions) -> ImportPlan {
    let batch_id = opts.batch_id.clone().unwrap_or_else(default_batch_id);
    let existing: BTreeSet<&str> =
        opts.existing_asset_groups.iter().map(String::as_str).collect();
    let tag_cols: BTreeSet<&str> = opts.tag_columns.iter().map(String::as_str).collect();

    // Collect resources keyed by sanitised name so multi-row rows
    // collapse. Insertion order matters for stable output, so we
    // also remember the order each name was first seen.
    let mut resources: BTreeMap<String, ResourcePlan> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut kv_blobs: Vec<KvBlobPlan> = Vec::new();
    let mut groups: BTreeMap<String, AssetGroupPlan> = BTreeMap::new();
    let mut skipped: Vec<SkipEntry> = Vec::new();

    for row in &sheet.rows {
        let resource_name_raw = row.cells.get("Resource Name").cloned().unwrap_or_default();
        if mapping::is_empty(&resource_name_raw) {
            skipped.push(SkipEntry {
                row: row.row_number,
                reason: "missing Resource Name".into(),
            });
            continue;
        }
        let os_type_raw = row.cells.get("OS Type").cloned().unwrap_or_default();
        if mapping::is_empty(&os_type_raw) {
            skipped.push(SkipEntry {
                row: row.row_number,
                reason: "missing OS Type".into(),
            });
            continue;
        }
        let user_raw = row.cells.get("User Account").cloned().unwrap_or_default();
        let password_raw = row.cells.get("Password").cloned().unwrap_or_default();

        let mapping_ = mapping::map_with_override(&os_type_raw, &opts.type_overrides);
        let department = row.cells.get("Department").and_then(|d| mapping::opt(d));
        let dep_group = department.as_deref().map(mapping::slugify_department).filter(|s| !s.is_empty());

        match mapping_.kind {
            RowKind::Kv => {
                if mapping::is_empty(&password_raw) {
                    skipped.push(SkipEntry {
                        row: row.row_number,
                        reason: "missing Password".into(),
                    });
                    continue;
                }
                let res_segment = mapping::sanitise_name(&resource_name_raw);
                let acct_segment = if mapping::is_empty(&user_raw) {
                    "default".to_string()
                } else {
                    mapping::sanitise_name(&user_raw)
                };
                let path = format!(
                    "secret/pmp-import/{batch_id}/{kind}/{res_segment}/{acct_segment}",
                    kind = mapping_.target,
                );
                let mut data = BTreeMap::new();
                data.insert(
                    "value_b64".into(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(password_raw.as_bytes()),
                    ),
                );
                data.insert(
                    "pmp_resource_name".into(),
                    serde_json::Value::String(resource_name_raw.clone()),
                );
                if !mapping::is_empty(&user_raw) {
                    data.insert(
                        "pmp_account".into(),
                        serde_json::Value::String(user_raw.trim().to_string()),
                    );
                }
                data.insert(
                    "pmp_os_type".into(),
                    serde_json::Value::String(os_type_raw.trim().to_string()),
                );
                inject_envelope_metadata(&mut data, row, &opts.tag_columns, opts.preserve_unknown_columns, sheet);
                if let Some(dep) = &department {
                    data.insert("department".into(), serde_json::Value::String(dep.clone()));
                }
                let mut tags: Vec<String> = vec![format!("pmp-import:{batch_id}")];
                for col in &opts.tag_columns {
                    if let Some(v) = row.cells.get(col).and_then(|v| mapping::opt(v)) {
                        tags.push(v);
                    }
                }
                data.insert(
                    "tags".into(),
                    serde_json::Value::Array(
                        tags.into_iter().map(serde_json::Value::String).collect(),
                    ),
                );
                if let Some(slug) = &dep_group {
                    let g = groups.entry(slug.clone()).or_insert_with(|| AssetGroupPlan {
                        name: slug.clone(),
                        display_name: department.clone().unwrap_or_default(),
                        description: department
                            .as_ref()
                            .map(|d| format!("Imported from PMP department \"{d}\""))
                            .unwrap_or_default(),
                        members: Vec::new(),
                        secrets: Vec::new(),
                        exists: existing.contains(slug.as_str()),
                    });
                    if !g.secrets.contains(&path) {
                        g.secrets.push(path.clone());
                    }
                }
                kv_blobs.push(KvBlobPlan { kind: mapping_.target.clone(), path, data });
            }
            RowKind::Resource => {
                if mapping::is_empty(&user_raw) {
                    skipped.push(SkipEntry {
                        row: row.row_number,
                        reason: "missing User Account".into(),
                    });
                    continue;
                }
                if mapping::is_empty(&password_raw) {
                    skipped.push(SkipEntry {
                        row: row.row_number,
                        reason: "missing Password".into(),
                    });
                    continue;
                }
                let bv_type = mapping_.target.clone();
                let res_name = mapping::sanitise_name(&resource_name_raw);
                let entry = resources.entry(res_name.clone()).or_insert_with(|| {
                    order.push(res_name.clone());
                    ResourcePlan {
                        name: res_name.clone(),
                        bv_type: bv_type.clone(),
                        metadata: build_metadata(
                            &resource_name_raw,
                            row,
                            &mapping_.defaults,
                            &tag_cols,
                            opts.preserve_unknown_columns,
                            sheet,
                        ),
                        asset_groups: Vec::new(),
                        tags: Vec::new(),
                        secrets: Vec::new(),
                    }
                });
                // For repeated rows merge defaults non-destructively
                // so the first row wins on conflict.
                for (k, v) in &mapping_.defaults {
                    entry.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                }
                if let Some(dep) = &department {
                    entry.metadata.entry("department".into()).or_insert_with(|| dep.clone());
                }
                for col in &opts.tag_columns {
                    if let Some(v) = row.cells.get(col).and_then(|v| mapping::opt(v)) {
                        if !entry.tags.contains(&v) {
                            entry.tags.push(v);
                        }
                    }
                }
                if let Some(slug) = &dep_group {
                    if !entry.asset_groups.contains(slug) {
                        entry.asset_groups.push(slug.clone());
                    }
                    let g = groups.entry(slug.clone()).or_insert_with(|| AssetGroupPlan {
                        name: slug.clone(),
                        display_name: department.clone().unwrap_or_default(),
                        description: department
                            .as_ref()
                            .map(|d| format!("Imported from PMP department \"{d}\""))
                            .unwrap_or_default(),
                        members: Vec::new(),
                        secrets: Vec::new(),
                        exists: existing.contains(slug.as_str()),
                    });
                    if !g.members.contains(&entry.name) {
                        g.members.push(entry.name.clone());
                    }
                }
                let mut sec_meta = BTreeMap::new();
                if let Some(t) = row.cells.get("Last Accessed Time").and_then(|v| mapping::opt(v)) {
                    sec_meta.insert("pmp_last_accessed".into(), t);
                }
                entry.secrets.push(ResourceSecret {
                    name: mapping::sanitise_name(&user_raw),
                    value_b64: base64::engine::general_purpose::STANDARD.encode(password_raw.as_bytes()),
                    metadata: sec_meta,
                });
            }
        }
    }

    // Stable resource order (insertion order from `order`).
    // Defence-in-depth: any resource whose secrets[] is empty (would
    // happen if every row contributing to it was skipped for a
    // missing User Account or Password) gets dropped here so the
    // wizard never tries to create a resource without accounts.
    let mut resources_vec: Vec<ResourcePlan> = Vec::new();
    for n in order {
        if let Some(r) = resources.remove(&n) {
            if r.secrets.is_empty() {
                skipped.push(SkipEntry {
                    row: 0,
                    reason: format!("resource {} dropped — no accounts after row filtering", r.name),
                });
                continue;
            }
            resources_vec.push(r);
        }
    }

    let mut type_distribution: BTreeMap<String, usize> = BTreeMap::new();
    for r in &resources_vec {
        *type_distribution.entry(r.bv_type.clone()).or_default() += 1;
    }
    let mut kv_distribution: BTreeMap<String, usize> = BTreeMap::new();
    for k in &kv_blobs {
        *kv_distribution.entry(k.kind.clone()).or_default() += 1;
    }
    let groups_vec: Vec<AssetGroupPlan> = groups.into_values().collect();
    let asset_groups_new: Vec<String> = groups_vec
        .iter()
        .filter(|g| !g.exists)
        .map(|g| g.name.clone())
        .collect();
    let asset_groups_existing: Vec<String> = groups_vec
        .iter()
        .filter(|g| g.exists)
        .map(|g| g.name.clone())
        .collect();
    let secret_count: usize = resources_vec.iter().map(|r| r.secrets.len()).sum();

    ImportPlan {
        batch_id: batch_id.clone(),
        summary: PlanSummary {
            resource_count: resources_vec.len(),
            secret_count,
            kv_blob_count: kv_blobs.len(),
            asset_group_count: groups_vec.len(),
            skipped,
            type_distribution,
            kv_distribution,
            asset_groups_new,
            asset_groups_existing,
        },
        asset_groups: groups_vec,
        resources: resources_vec,
        kv_blobs,
    }
}

fn build_metadata(
    resource_name_raw: &str,
    row: &RawRow,
    defaults: &BTreeMap<String, String>,
    tag_cols: &BTreeSet<&str>,
    preserve_unknown: bool,
    sheet: &ParsedSheet,
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(v) = row.cells.get("DNS Name").and_then(|v| mapping::opt(v)) {
        m.insert("hostname".into(), v.to_lowercase());
    }
    if let Some(v) = row.cells.get("Description").and_then(|v| mapping::opt(v)) {
        m.insert("description".into(), v);
    }
    if let Some(v) = row.cells.get("Location").and_then(|v| mapping::opt(v)) {
        m.insert("location".into(), v);
    }
    if let Some(v) = row.cells.get("Notes").and_then(|v| mapping::opt(v)) {
        m.insert("notes".into(), v);
    }
    if let Some(v) = row.cells.get("Resource URL").and_then(|v| mapping::opt(v)) {
        // PMP exports cloud-console rows with `Resource URL`
        // sometimes filled and sometimes empty. We always preserve
        // it under both keys so a `website` resource can read `url`
        // and an `application` resource can read `console_url`.
        m.insert("url".into(), v.clone());
        m.insert("console_url".into(), v);
    }
    for (k, v) in defaults {
        m.insert(k.clone(), v.clone());
    }
    // Preserve the original resource name even after sanitisation,
    // since the sanitiser is lossy.
    if mapping::sanitise_name(resource_name_raw) != resource_name_raw {
        m.insert("pmp_resource_name".into(), resource_name_raw.to_string());
    }
    if preserve_unknown {
        for h in &sheet.columns {
            if KNOWN_COLUMNS.contains(&h.as_str()) {
                continue;
            }
            if tag_cols.contains(h.as_str()) {
                continue; // tag columns surface via `tags`, not metadata.
            }
            if let Some(v) = row.cells.get(h).and_then(|v| mapping::opt(v)) {
                m.insert(h.to_ascii_lowercase().replace([' ', '/'], "_"), v);
            }
        }
    }
    m
}

fn inject_envelope_metadata(
    data: &mut BTreeMap<String, serde_json::Value>,
    row: &RawRow,
    tag_cols: &[String],
    preserve_unknown: bool,
    sheet: &ParsedSheet,
) {
    if let Some(v) = row.cells.get("Description").and_then(|v| mapping::opt(v)) {
        data.insert("description".into(), serde_json::Value::String(v));
    }
    if let Some(v) = row.cells.get("Notes").and_then(|v| mapping::opt(v)) {
        data.insert("notes".into(), serde_json::Value::String(v));
    }
    if let Some(v) = row.cells.get("Location").and_then(|v| mapping::opt(v)) {
        data.insert("location".into(), serde_json::Value::String(v));
    }
    if let Some(v) = row.cells.get("Last Accessed Time").and_then(|v| mapping::opt(v)) {
        data.insert("pmp_last_accessed".into(), serde_json::Value::String(v));
    }
    if preserve_unknown {
        for h in &sheet.columns {
            if KNOWN_COLUMNS.contains(&h.as_str()) {
                continue;
            }
            if tag_cols.iter().any(|c| c == h) {
                continue;
            }
            if let Some(v) = row.cells.get(h).and_then(|v| mapping::opt(v)) {
                data.insert(
                    h.to_ascii_lowercase().replace([' ', '/'], "_"),
                    serde_json::Value::String(v),
                );
            }
        }
    }
}

fn default_batch_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}
