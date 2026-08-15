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
    assert_eq!(result["fixtures"]["version"], 1);
    assert_eq!(
        result["fixtures"]["expected_checksum"],
        "214b809aeff4f6934f7e091a05051fa0"
    );
    assert_eq!(result["fixtures"]["checksum_verified"], true);
    assert_eq!(
        result["fixtures"]["actual_checksum"],
        result["fixtures"]["expected_checksum"]
    );
    let scenarios = result["data_scenarios"]
        .as_array()
        .expect("data scenario results");
    for (name, rows) in [
        ("zero-rows", 0),
        ("one-typed-row", 1),
        ("small-narrow", 7),
        ("medium-nullable", 128),
        ("commerce-join", 64),
        ("large-streamed", 4096),
    ] {
        let scenario = scenarios
            .iter()
            .find(|scenario| scenario["name"] == name)
            .unwrap_or_else(|| panic!("missing {name} scenario"));
        assert_eq!(scenario["rows"], rows);
        assert_eq!(scenario["validated"], true);
    }
    let large = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "large-streamed")
        .expect("large streamed result");
    assert_eq!(large["bytes"], 1_784_970);
    assert_eq!(large["nulls"], 819);
    assert_eq!(
        large["digest"],
        "191b550a26addc17754b296d2f0e554dcfb7e666030f2c9ecc35d7d1b41b80d3"
    );
    assert_eq!(
        result["coverage"]["observed_ids"]
            .as_array()
            .expect("coverage IDs")
            .len(),
        16
    );
    assert_eq!(result["coverage"]["stages"].as_array().unwrap().len(), 7);
    assert_eq!(
        result["coverage"]["real_postgres"]
            .as_array()
            .unwrap()
            .len(),
        16
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
