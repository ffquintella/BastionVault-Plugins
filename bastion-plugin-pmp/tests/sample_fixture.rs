//! End-to-end test against the operator-supplied PMP export fixture.
//! Skipped when the fixture isn't present so the suite still runs in
//! environments that don't have the (private) sample on disk.

use std::path::PathBuf;

use bastion_plugin_pmp::{plan::PlanOptions, preview, validate};

fn fixture_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BV_PMP_FIXTURE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let default = PathBuf::from("/Users/felipe/Desktop/ExportResources-Teste.xls");
    if default.exists() {
        Some(default)
    } else {
        None
    }
}

#[test]
fn validate_matches_pmp_export_view() {
    let Some(path) = fixture_path() else { eprintln!("fixture missing — skipping"); return };
    let r = validate(&path).expect("validate");
    assert!(r.ok, "missing required columns: {:?}", r.missing_required);
    assert_eq!(r.sheet, "ExportPasswordView");
    for required in &["Resource Name", "User Account", "Password", "OS Type"] {
        assert!(r.columns.iter().any(|c| c == *required), "missing {required}");
    }
    assert!(r.row_count > 0);
    assert!(
        r.unknown_columns.iter().any(|c| c == "Ambiente"),
        "expected Ambiente in unknown_columns: {:?}",
        r.unknown_columns
    );
}

#[test]
fn preview_groups_multi_account_resources_and_routes_kv_kinds() {
    let Some(path) = fixture_path() else { eprintln!("fixture missing — skipping"); return };
    let opts = PlanOptions {
        batch_id: Some("test-batch".into()),
        preserve_unknown_columns: true,
        tag_columns: vec!["Ambiente".into()],
        ..Default::default()
    };
    let plan = preview(&path, &opts).expect("preview");

    // Sanity: no resources have an empty type id.
    assert!(plan.resources.iter().all(|r| !r.bv_type.is_empty()));

    // Multi-account collapse: at least one resource carries >1 secret
    // (the operator's sample has ~10 such rows).
    assert!(
        plan.resources.iter().any(|r| r.secrets.len() > 1),
        "no multi-account resource detected — collapse rule didn't fire"
    );

    // Type distribution honours the new firewall/switch/database mappings.
    let td = &plan.summary.type_distribution;
    assert!(td.get("server").copied().unwrap_or(0) > 0);
    assert!(td.get("database").copied().unwrap_or(0) > 0);
    // The fixture has Cisco IOS + Fortimanager rows.
    assert!(td.get("switch").copied().unwrap_or(0) > 0 || td.get("firewall").copied().unwrap_or(0) > 0);

    // KV routing: Generic Keys / License Store / Application Passwords
    // land in `kv_blobs`, not `resources`.
    let kv = &plan.summary.kv_distribution;
    let total_kv: usize = kv.values().sum();
    assert_eq!(total_kv, plan.kv_blobs.len());
    assert!(plan.kv_blobs.iter().all(|b| b.path.starts_with("secret/pmp-import/test-batch/")));

    // Department → asset group derivation.
    assert!(plan.summary.asset_group_count > 0);
    for g in &plan.asset_groups {
        assert!(!g.name.contains('/'), "slug must collapse `/` (got {})", g.name);
        assert!(g.name == g.name.to_lowercase());
    }

    // Every resource carries at least one account secret. The
    // wizard skips resources without accounts, but the planner
    // should also defend against the case — if a row is dropped for
    // a missing User Account or Password, its resource only stays
    // when at least one sibling row contributed an account.
    for r in &plan.resources {
        assert!(
            !r.secrets.is_empty(),
            "resource {} reached the plan with no accounts",
            r.name
        );
    }

    // Account count = sum of `secrets[]` lengths matches the
    // `summary.secret_count`. This is the property the migration
    // most depends on: every PMP (resource, account) row → exactly
    // one BV resource_secret under the right resource.
    let total_accounts: usize = plan.resources.iter().map(|r| r.secrets.len()).sum();
    assert_eq!(total_accounts, plan.summary.secret_count);

    // Multi-account resources retain DISTINCT account names — no
    // collisions from sanitisation collapsing two PMP usernames
    // into one BV key.
    for r in &plan.resources {
        let mut names: Vec<&str> = r.secrets.iter().map(|s| s.name.as_str()).collect();
        names.sort();
        let unique_count = {
            let mut s = names.clone();
            s.dedup();
            s.len()
        };
        assert_eq!(
            unique_count,
            r.secrets.len(),
            "resource {} has duplicate account keys: {:?}",
            r.name,
            names
        );
    }

    // Owner field is *not* present on any resource or KV blob.
    for r in &plan.resources {
        assert!(!r.metadata.contains_key("owner"), "resource {} carries owner field", r.name);
    }
    for b in &plan.kv_blobs {
        assert!(!b.data.contains_key("owner"), "kv blob {} carries owner field", b.path);
    }
}
