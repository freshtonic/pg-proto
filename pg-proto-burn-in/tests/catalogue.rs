//! Process-level tests for authoritative catalogue closure.

use std::{fs, process::Command};

#[test]
fn catalogue_reports_every_uncovered_generated_and_supplemental_entry() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["catalogue", "--as-of", "2026-08-16", "--output-dir"])
        .arg(artifacts.path())
        .output()
        .expect("run catalogue audit");

    assert!(
        !output.status.success(),
        "an empty evidence set cannot close the catalogue"
    );
    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("result.json")).expect("catalogue result"),
    )
    .expect("valid catalogue result");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["generated_entries"], 220);
    assert_eq!(result["supplemental_entries"], 37);
    assert_eq!(result["catalogue_entries"], 257);
    assert_eq!(result["disposed_entries"], 0);
    assert_eq!(result["missing_entries"], result["catalogue_entries"]);
    assert_eq!(result["success"], false);
    let missing = result["missing"].as_array().expect("missing IDs");
    assert!(missing.iter().any(|id| id == "frontend.Ready.Query"));
    assert!(missing.iter().any(|id| id == "async.notice"));
}

#[test]
fn catalogue_rejects_unknown_and_duplicate_evidence() {
    let directory = tempfile::tempdir().expect("test directory");
    let unknown = directory.path().join("unknown.json");
    fs::write(
        &unknown,
        br#"{"coverage":{"real_postgres":["not.in.catalogue"]}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["catalogue", "--as-of", "2026-08-16", "--input"])
        .arg(&unknown)
        .args(["--output-dir"])
        .arg(directory.path().join("unknown-artifacts"))
        .output()
        .expect("run unknown evidence audit");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown coverage ID"));

    let duplicate = directory.path().join("duplicate.json");
    fs::write(
        &duplicate,
        br#"{"coverage":{"real_postgres":["backend.Ready.Query"],"scripted":["backend.Ready.Query"]}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["catalogue", "--as-of", "2026-08-16", "--input"])
        .arg(&duplicate)
        .args(["--output-dir"])
        .arg(directory.path().join("duplicate-artifacts"))
        .output()
        .expect("run duplicate evidence audit");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate coverage disposition"));

    let unreviewed = directory.path().join("unreviewed-exemption.json");
    fs::write(
        &unreviewed,
        br#"{"coverage":{"exempted":["frontend.Ready.Query"]}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["catalogue", "--as-of", "2026-08-16", "--input"])
        .arg(&unreviewed)
        .args(["--output-dir"])
        .arg(directory.path().join("unreviewed-artifacts"))
        .output()
        .expect("run unreviewed exemption audit");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("artifact exemptions are not authoritative")
    );
}

#[test]
fn approved_catalogue_has_exactly_one_reviewed_disposition_per_entry() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args([
            "catalogue",
            "--approved",
            "--as-of",
            "2026-08-17",
            "--output-dir",
        ])
        .arg(artifacts.path())
        .output()
        .expect("run approved catalogue audit");

    assert!(
        output.status.success(),
        "approved catalogue failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("result.json")).expect("catalogue result"),
    )
    .expect("valid catalogue result");
    assert_eq!(result["catalogue_entries"], 257);
    assert_eq!(result["disposed_entries"], 257);
    assert_eq!(result["missing_entries"], 0);
    assert_eq!(result["success"], true);
    assert!(
        result["dispositions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["id"] == "frontend.Ready.Query" && entry["kind"] == "indirect" })
    );
    assert!(
        result["dispositions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["id"] == "async.notice" && entry["kind"] == "real-postgres" })
    );
}
