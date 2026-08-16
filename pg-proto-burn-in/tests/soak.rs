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

    let checkpoints = result["resource_checkpoints"]
        .as_array()
        .expect("resource checkpoints");
    assert_eq!(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint["stage"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "startup-drained",
            "long-lived-drained",
            "connection-churn-drained",
            "bounded-concurrency-drained",
            "abrupt-termination-drained",
            "teardown",
        ]
    );
    for checkpoint in &checkpoints[..5] {
        assert_eq!(checkpoint["quiescent"], true);
        if cfg!(target_os = "linux") {
            assert!(checkpoint["intermediary"]["sampling_gap"].is_null());
            assert!(checkpoint["driver"]["sampling_gap"].is_null());
            assert!(checkpoint["postgres"]["sampling_gap"].is_null());
        } else {
            assert!(checkpoint["intermediary"]["sampling_gap"].is_string());
            assert!(checkpoint["driver"]["sampling_gap"].is_string());
            assert!(checkpoint["postgres"]["sampling_gap"].is_null());
        }
        assert_eq!(checkpoint["postgres"]["connections"], 0);
        assert_eq!(checkpoint["postgres"]["locks"], 0);
    }
    assert_eq!(checkpoints[2]["termination"], "graceful-restart");
    assert_eq!(checkpoints[4]["termination"], "abrupt-termination");
    assert_eq!(checkpoints[5]["termination"], "graceful-teardown");
    assert_eq!(result["lifecycle_evidence"]["graceful_restart"], true);
    assert_eq!(result["lifecycle_evidence"]["abrupt_termination"], true);
    assert_eq!(result["lifecycle_evidence"]["teardown"], true);
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
