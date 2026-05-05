//! Phase 5: cover the column-layout drift between PMP versions
//! without committing per-version `.xls` / `.xlsx` fixtures to the
//! repo. We construct `ParsedSheet`s synthetically — the parser
//! has its own real-fixture coverage in `sample_fixture.rs`; here
//! we exercise the planner against the layout permutations we know
//! PMP ships.

use bastion_plugin_pmp::{build_synthetic_sheet, plan, validate};

fn opts() -> plan::PlanOptions {
    plan::PlanOptions {
        batch_id: Some("matrix".into()),
        preserve_unknown_columns: true,
        ..Default::default()
    }
}

#[test]
fn pmp_v11_minimal_layout() {
    // PMP 11.x — minimum-effort export, only the required columns
    // plus DNS Name and Description. No Department, no custom
    // columns, no Last Accessed Time.
    let sheet = build_synthetic_sheet(
        "ExportPasswordView",
        &[
            "Resource Name",
            "User Account",
            "Password",
            "OS Type",
            "DNS Name",
            "Description",
        ],
        &[
            vec!["web01", "root", "p1", "Linux", "web01.example.com", "Web server"],
            vec!["web01", "deploy", "p2", "Linux", "web01.example.com", "Web server"],
            vec!["fw-edge", "admin", "p3", "Fortimanager", "fw-edge.example.com", ""],
        ],
    );
    let plan = plan::build(&sheet, &opts());

    assert_eq!(plan.summary.resource_count, 2);
    assert_eq!(plan.summary.secret_count, 3);
    assert_eq!(plan.summary.kv_blob_count, 0);
    assert_eq!(plan.summary.asset_group_count, 0); // no Department column

    let web = plan.resources.iter().find(|r| r.name == "web01").unwrap();
    assert_eq!(web.bv_type, "server");
    assert_eq!(web.metadata.get("os_type").map(String::as_str), Some("linux"));
    assert_eq!(web.secrets.len(), 2);

    let fw = plan.resources.iter().find(|r| r.name == "fw-edge").unwrap();
    assert_eq!(fw.bv_type, "firewall");
    assert_eq!(fw.metadata.get("vendor").map(String::as_str), Some("fortinet"));
}

#[test]
fn pmp_v12_full_layout_with_department_and_custom_cols() {
    // PMP 12.x — operator's typical export with Department + a
    // few custom columns. Verifies department→asset-group + the
    // preserve_unknown_columns path.
    let sheet = build_synthetic_sheet(
        "ExportPasswordView",
        &[
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
            "Ambiente",
            "AWS Account",
        ],
        &[
            vec![
                "db-prod-01",
                "postgres",
                "pw1",
                "2026-01-02 03:04:05",
                "Primary",
                "db-prod-01.fgv.br",
                "TIC/INFRA",
                "DC-1",
                "PostgreSQL",
                "",
                "",
                "Produção",
                "",
            ],
            vec![
                "sw-core-a",
                "admin",
                "pw2",
                "",
                "",
                "sw-core-a.fgv.br",
                "DO-TIC-INFRA",
                "DC-1 Rack A1",
                "Cisco IOS",
                "",
                "",
                "Produção",
                "",
            ],
        ],
    );
    let plan = plan::build(&sheet, &opts());

    assert_eq!(plan.summary.resource_count, 2);
    assert_eq!(plan.summary.asset_group_count, 2);
    let groups: Vec<&str> = plan.asset_groups.iter().map(|g| g.name.as_str()).collect();
    assert!(groups.contains(&"tic-infra"));
    assert!(groups.contains(&"do-tic-infra"));

    let db = plan.resources.iter().find(|r| r.name == "db-prod-01").unwrap();
    assert_eq!(db.bv_type, "database");
    assert_eq!(db.metadata.get("engine").map(String::as_str), Some("postgresql"));
    assert_eq!(db.asset_groups, vec!["tic-infra".to_string()]);

    let sw = plan.resources.iter().find(|r| r.name == "sw-core-a").unwrap();
    assert_eq!(sw.bv_type, "switch");
    assert_eq!(sw.metadata.get("vendor").map(String::as_str), Some("cisco"));
    assert_eq!(sw.metadata.get("department").map(String::as_str), Some("DO-TIC-INFRA"));

    // Custom column preserved as resource metadata.
    assert_eq!(db.metadata.get("aws_account"), None);
    // `Ambiente` was preserved (not promoted to a tag because we
    // didn't pass `tag_columns` in this test).
    assert_eq!(db.metadata.get("ambiente").map(String::as_str), Some("Produção"));
}

#[test]
fn pmp_v13_xlsx_with_kv_kinds_and_reordered_columns() {
    // PMP 13.x — newer export rearranges columns, includes the
    // KV-bound row types. Sheet name keeps `ExportPasswordView`.
    let sheet = build_synthetic_sheet(
        "ExportPasswordView",
        &[
            "OS Type",        // moved to the front in some PMP 13 builds
            "Resource Name",
            "User Account",
            "Password",
            "Description",
            "DNS Name",
            "Department",
        ],
        &[
            vec!["Generic Keys", "vendor-api-key", "default", "k1", "Vendor token", "", "TIC"],
            vec!["License Store", "vmware-licenses", "vmware-vsphere-7", "k2", "vSphere 7 license", "", "TIC"],
            vec!["Application Passwords", "splunk-svc", "indexer", "k3", "Splunk indexer", "", ""],
            vec!["Linux", "srv-app01", "root", "p1", "App server", "srv-app01.example.com", ""],
        ],
    );
    let plan = plan::build(&sheet, &opts());

    assert_eq!(plan.summary.resource_count, 1);
    assert_eq!(plan.summary.kv_blob_count, 3);
    let dist = &plan.summary.kv_distribution;
    assert_eq!(dist.get("generic-keys"), Some(&1));
    assert_eq!(dist.get("license-store"), Some(&1));
    assert_eq!(dist.get("application-passwords"), Some(&1));

    // KV blobs land under the right kind in the path.
    for b in &plan.kv_blobs {
        assert!(b.path.starts_with(&format!("secret/pmp-import/matrix/{}/", b.kind)));
    }

    // Asset group derived from the KV row's Department too.
    assert!(plan.asset_groups.iter().any(|g| g.name == "tic"));
}

#[test]
fn rejects_when_required_column_is_absent() {
    let sheet = build_synthetic_sheet(
        "ExportPasswordView",
        &["Resource Name", "User Account", "Password"], // OS Type missing
        &[vec!["x", "y", "z"]],
    );
    assert!(sheet.missing_required.contains(&"OS Type".to_string()));
}

#[test]
fn unknown_pmp_os_type_falls_back_to_a_slugged_custom_type() {
    let sheet = build_synthetic_sheet(
        "ExportPasswordView",
        &[
            "Resource Name", "User Account", "Password", "OS Type",
        ],
        &[vec!["mystery-box", "admin", "pw", "Arquivos de Incidentes"]],
    );
    let plan = plan::build(&sheet, &opts());
    assert_eq!(plan.summary.resource_count, 1);
    assert_eq!(plan.resources[0].bv_type, "arquivos-de-incidentes");
}

#[test]
fn missing_password_drops_the_row_with_a_skip_reason() {
    let sheet = build_synthetic_sheet(
        "ExportPasswordView",
        &[
            "Resource Name", "User Account", "Password", "OS Type",
        ],
        &[
            vec!["srv01", "root", "", "Linux"],
            vec!["srv02", "root", "good", "Linux"],
        ],
    );
    let plan = plan::build(&sheet, &opts());
    assert_eq!(plan.summary.resource_count, 1);
    assert_eq!(plan.resources[0].name, "srv02");
    assert!(plan
        .summary
        .skipped
        .iter()
        .any(|s| s.row == 2 && s.reason.contains("Password")));
}

#[test]
fn rejects_encrypted_pmp_export_with_friendly_message() {
    use std::io::Write;
    // CFB magic + a UTF-16LE EncryptedPackage marker, padded to
    // make the sniffer's first-8-KiB scan find it. This is a
    // minimal synthetic envelope — we only need the sniffer to
    // identify the signature; calamine never gets called.
    let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    bytes.resize(512, 0);
    for ch in "EncryptedPackage".encode_utf16() {
        bytes.push((ch & 0xff) as u8);
        bytes.push((ch >> 8) as u8);
    }
    for ch in "EncryptionInfo".encode_utf16() {
        bytes.push((ch & 0xff) as u8);
        bytes.push((ch >> 8) as u8);
    }
    bytes.resize(2048, 0);

    let dir = std::env::temp_dir();
    let path = dir.join(format!("bv-pmp-encrypted-{}.xls", std::process::id()));
    {
        let mut f = std::fs::File::create(&path).expect("create temp");
        f.write_all(&bytes).expect("write temp");
    }

    let err = validate(&path).expect_err("expected encrypted detection");
    assert!(
        err.to_lowercase().contains("encrypt"),
        "expected the friendly encryption message, got: {err}"
    );

    let _ = std::fs::remove_file(&path);
}
