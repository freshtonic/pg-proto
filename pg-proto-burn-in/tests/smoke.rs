use std::{fs, process::Command};

#[test]
#[ignore = "requires Docker"]
fn smoke_profile_crosses_a_real_intermediary_and_writes_artifacts() {
    let artifacts = tempfile::tempdir().expect("create artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["conformance", "--profile", "smoke", "--artifacts"])
        .arg(artifacts.path())
        .output()
        .expect("run smoke profile");

    assert!(
        output.status.success(),
        "smoke profile failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("result.json")).expect("read JSON artifact"),
    )
    .expect("parse JSON artifact");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "conformance");
    assert_eq!(result["profile"], "smoke");
    assert_eq!(result["postgres_version"], "18");
    assert_eq!(result["scenario"]["name"], "extended-select-scalar");
    assert_eq!(result["scenario"]["value"], 42);
    assert_eq!(result["success"], true);
    assert_eq!(
        result["coverage"]["observed_ids"]
            .as_array()
            .expect("coverage IDs")
            .len(),
        15
    );
    assert_eq!(result["coverage"]["stages"].as_array().unwrap().len(), 7);
    assert_eq!(
        result["coverage"]["real_postgres"]
            .as_array()
            .unwrap()
            .len(),
        15
    );
    for disposition in ["scripted", "indirect", "missing", "exempted"] {
        assert!(result["coverage"][disposition].is_array());
    }

    let summary =
        fs::read_to_string(artifacts.path().join("summary.md")).expect("read Markdown artifact");
    assert!(summary.contains("extended-select-scalar"));
    assert!(summary.contains("42"));
    assert!(summary.contains("PASS"));
}
