use std::{fs, process::Command};

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn soak_requires_a_bounded_budget_and_records_a_replayable_schedule() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args([
            "soak",
            "--seed",
            "8675309",
            "--iterations",
            "0",
            "--artifacts",
        ])
        .arg(artifacts.path())
        .output()
        .expect("run bounded soak");

    assert!(
        output.status.success(),
        "soak planning failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("result.json")).expect("result artifact"),
    )
    .expect("valid soak artifact");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "soak");
    assert_eq!(result["seed"], 8_675_309);
    assert_eq!(result["budget"], serde_json::json!({"iterations": 0}));

    let sequence = result["sequence"].as_array().expect("recorded sequence");
    assert_eq!(sequence.len(), 9, "three canonical scenarios per phase");
    assert!(sequence.iter().all(|entry| entry["canonical"] == true));
    assert_eq!(sequence[0]["phase"], "long-lived");
    assert_eq!(sequence[3]["phase"], "connection-churn");
    assert_eq!(sequence[6]["phase"], "bounded-concurrency");
    assert_eq!(
        result["replay_command"],
        "pg-proto-burn-in replay --input result.json --artifacts replay"
    );
}

#[test]
fn soak_rejects_an_unbounded_run() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["soak", "--seed", "1", "--artifacts"])
        .arg(artifacts.path())
        .output()
        .expect("run unbounded soak");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly one budget"));
}
