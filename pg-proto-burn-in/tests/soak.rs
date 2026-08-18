//! Process-level tests for bounded soak execution and replay.

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
            "--output-dir",
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
    assert_eq!(result["scenario_catalogue"].as_array().unwrap().len(), 3);
    assert_eq!(result["scenario_catalogue"][0]["id"], "scalar");
    assert_eq!(result["scenario_catalogue"][0]["weight"], 3);
    assert_eq!(
        result["scenario_catalogue"][0]["postgres_versions"],
        "14-18"
    );
    assert!(
        result["scenario_catalogue"]
            .as_array()
            .unwrap()
            .iter()
            .all(
                |scenario| !scenario["prerequisites"].as_array().unwrap().is_empty()
                    && !scenario["expected_coverage"].as_array().unwrap().is_empty()
                    && !scenario["assertions"].as_array().unwrap().is_empty()
            )
    );
    assert_eq!(result["admission_policy"]["expected_failure_budget"], 2);
    assert_eq!(
        result["admission_policy"]["invariant_failure_action"],
        "stop-admission-immediately"
    );

    let sequence = result["sequence"].as_array().expect("recorded sequence");
    assert_eq!(sequence.len(), 9, "three canonical scenarios per phase");
    assert!(sequence.iter().all(|entry| entry["canonical"] == true));
    assert_eq!(sequence[0]["phase"], "long-lived");
    assert_eq!(sequence[3]["phase"], "connection-churn");
    assert_eq!(sequence[6]["phase"], "bounded-concurrency");
    assert_eq!(
        result["replay_command"],
        "pg-proto-burn-in replay --input result.json --output-dir replay"
    );
    assert_eq!(result["trace_policy"]["mode"], "redacted");
    assert_eq!(result["trace_policy"]["capacity"], 64);
    assert_eq!(result["trace_policy"]["payloads"], false);
    assert!(result["recent_trace"].as_array().unwrap().len() <= 64);
    assert!(
        result["recent_trace"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["parameters"].as_object().unwrap().is_empty())
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

    let gates = &result["resource_gates"];
    assert_eq!(gates["passed"], true);
    assert_eq!(gates["baseline_stage"], "startup-drained");
    assert_eq!(gates["checked_stages"], 4);
    assert_eq!(gates["postgres_connections_after_drain"], 0);
    assert_eq!(gates["postgres_locks_after_drain"], 0);
    if cfg!(target_os = "linux") {
        assert_eq!(gates["authoritative"], true);
        assert_eq!(gates["intermediary_task_growth"], 0);
        assert_eq!(gates["intermediary_descriptor_growth"], 0);
        assert!(gates["gaps"].as_array().unwrap().is_empty());
    } else {
        assert_eq!(gates["authoritative"], false);
        assert!(!gates["gaps"].as_array().unwrap().is_empty());
    }
    let summary = fs::read_to_string(artifacts.path().join("summary.md")).expect("summary");
    assert!(summary.contains("Trace policy: redacted"));
}

#[test]
fn soak_rejects_an_unbounded_run() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["soak", "--seed", "1", "--output-dir"])
        .arg(artifacts.path())
        .output()
        .expect("run unbounded soak");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--iterations"));
    assert!(stderr.contains("--duration-seconds"));
}

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn soak_duration_is_a_wall_clock_budget() {
    let output_dir = tempfile::tempdir().expect("output directory");
    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args([
            "soak",
            "--seed",
            "7",
            "--duration-seconds",
            "3",
            "--output-dir",
        ])
        .arg(output_dir.path())
        .output()
        .expect("run duration-bounded soak");
    assert!(
        output.status.success(),
        "duration soak failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(3));
    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.path().join("result.json")).expect("result artifact"),
    )
    .expect("valid result");
    assert_eq!(result["budget"], serde_json::json!({"duration-seconds": 3}));
    assert_eq!(result["sequence"].as_array().unwrap().len(), 3);
    assert_eq!(result["completed"], 3);
}

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn replay_reproduces_a_captured_failure_and_preserves_original_evidence() {
    let capture = tempfile::tempdir().expect("capture artifact directory");
    let replay = tempfile::tempdir().expect("replay artifact directory");
    let schedule = capture.path().join("schedule.json");
    fs::write(
        &schedule,
        serde_json::to_vec_pretty(&serde_json::json!([{
            "ordinal": 0,
            "phase": "long-lived",
            "scenario": "scalar",
            "canonical": false,
            "parameters": {
                "expected": 41,
                "password": 123456,
                "tls_secret": 234567,
                "cancellation_key": 345678
            }
        }]))
        .expect("encode schedule"),
    )
    .expect("write schedule");

    let captured = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["soak", "--seed", "91", "--iterations", "0", "--schedule"])
        .arg(&schedule)
        .arg("--capture-payloads")
        .arg("--output-dir")
        .arg(capture.path())
        .output()
        .expect("capture deterministic failure");
    assert!(!captured.status.success(), "mismatched oracle must fail");

    let captured_bytes = fs::read(capture.path().join("result.json")).expect("captured result");
    let captured_result: serde_json::Value =
        serde_json::from_slice(&captured_bytes).expect("valid captured result");
    assert_eq!(captured_result["success"], false);
    assert_eq!(captured_result["failure"]["kind"], "assertion-mismatch");
    assert_eq!(captured_result["trace_policy"]["mode"], "diagnostic");
    assert_eq!(captured_result["trace_policy"]["payloads"], true);
    let persisted = String::from_utf8(captured_bytes.clone()).expect("UTF-8 result");
    for secret in ["123456", "234567", "345678"] {
        assert!(
            !persisted.contains(secret),
            "artifact leaked secret {secret}"
        );
    }
    for field in ["password", "tls_secret", "cancellation_key"] {
        assert_eq!(
            captured_result["recent_trace"][0]["parameters"][field],
            "<redacted>"
        );
    }
    assert_eq!(captured_result["failure_bundle"]["seed"], 91);
    assert_eq!(
        captured_result["failure_bundle"]["replay_command"],
        captured_result["replay_command"]
    );
    assert!(captured_result["failure_bundle"]["recent_trace"].is_array());
    assert!(captured_result["failure_bundle"]["resource_stages"].is_array());
    assert_eq!(
        captured_result["failure_bundle"]["child_logs"],
        serde_json::json!(["child diagnostics redacted; correlate with failure fingerprint"])
    );
    let summary = fs::read_to_string(capture.path().join("summary.md")).expect("summary");
    assert!(summary.contains("Failure bundle: recorded"));
    assert!(summary.contains("Trace policy: diagnostic"));

    let replayed = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["replay", "--input"])
        .arg(capture.path().join("result.json"))
        .arg("--output-dir")
        .arg(replay.path())
        .output()
        .expect("replay captured failure");
    assert!(
        !replayed.status.success(),
        "reproduced failure remains a failure"
    );

    assert_eq!(
        fs::read(replay.path().join("original.json")).expect("preserved original"),
        captured_bytes
    );
    let replay_result: serde_json::Value = serde_json::from_slice(
        &fs::read(replay.path().join("result.json")).expect("replay result"),
    )
    .expect("valid replay result");
    assert_eq!(replay_result["command"], "replay");
    assert_eq!(replay_result["failure"], captured_result["failure"]);
    assert_eq!(replay_result["reproduced_failure"], true);
}
