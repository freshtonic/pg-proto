use std::{fs, process::Command};

#[test]
fn performance_evidence_emits_corrected_histograms_and_advisory_candidate_drift() {
    let workspace = tempfile::tempdir().expect("workspace");
    let input = workspace.path().join("measurements.json");
    let baseline = workspace.path().join("baseline.json");
    let artifacts = workspace.path().join("artifacts");
    fs::write(
        &input,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "warm_up": {"closed_loop_micros": [100, 110], "open_loop_micros": [100, 100]},
            "measurement": {
                "closed_loop": {
                    "elapsed_micros": 1_000_000,
                    "latencies_micros": [100, 110, 120, 130]
                },
                "open_loop": {
                    "elapsed_micros": 1_000_000,
                    "scheduled_interval_micros": 100,
                    "queue_micros": [10, 20, 30, 40],
                    "execution_micros": [80, 80, 80, 80],
                    "end_to_end_micros": [90, 200, 300, 400]
                }
            },
            "windows": [
                {"throughput_per_second": 4.0, "p95_micros": 130, "p99_micros": 130},
                {"throughput_per_second": 3.8, "p95_micros": 135, "p99_micros": 140}
            ],
            "evidence": {
                "soak_result": "soak/result.json",
                "resource_checkpoints": 6,
                "copy_scenarios": 6
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &baseline,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "key": {
                "runner": "linux-x86_64-stable-01",
                "postgres_version": "18",
                "profile": "controlled",
                "build_mode": "optimized"
            },
            "throughput_per_second": 4.2,
            "p95_micros": 120,
            "p99_micros": 125,
            "promoted": true,
            "version": 3
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args([
            "performance",
            "--input",
            input.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
            "--output-dir",
            artifacts.to_str().unwrap(),
            "--runner",
            "github-hosted",
            "--postgres-version",
            "18",
            "--build-mode",
            "optimized",
        ])
        .output()
        .expect("evaluate performance evidence");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let result: serde_json::Value =
        serde_json::from_slice(&fs::read(artifacts.join("performance.json")).unwrap()).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["build"]["mode"], "optimized");
    assert_eq!(
        result["phases"]["warm_up"]["included_in_measurement"],
        false
    );
    assert_eq!(result["phases"]["closed_loop"]["operations"], 4);
    assert_eq!(
        result["phases"]["open_loop"]["achieved_rate_per_second"],
        4.0
    );
    assert!(
        result["phases"]["open_loop"]["end_to_end_corrected"]["count"]
            .as_u64()
            .unwrap()
            > 4
    );
    assert!(result["phases"]["open_loop"]["queue"]["p95_micros"].is_number());
    assert!(result["phases"]["open_loop"]["execution"]["p99_micros"].is_number());
    assert_eq!(result["comparison"]["baseline_version"], 3);
    assert_eq!(
        result["comparison"]["thresholds"]["throughput_percent"],
        -10.0
    );
    assert_eq!(result["comparison"]["thresholds"]["latency_percent"], 20.0);
    assert_eq!(result["comparison"]["disposition"], "advisory");
    assert_eq!(result["comparison"]["candidate_baseline_written"], true);
    assert_eq!(result["evidence"]["resource_checkpoints"], 6);
    assert_eq!(result["evidence"]["copy_scenarios"], 6);
    assert!(artifacts.join("candidate-baseline.json").exists());
    assert!(
        fs::read_to_string(artifacts.join("summary.md"))
            .unwrap()
            .contains("ADVISORY")
    );
}

#[test]
fn hosted_runners_cannot_enable_performance_gates() {
    let workspace = tempfile::tempdir().expect("workspace");
    let input = workspace.path().join("measurements.json");
    fs::write(&input, r#"{"schema_version":1}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args([
            "performance",
            "--input",
            input.to_str().unwrap(),
            "--output-dir",
            workspace.path().to_str().unwrap(),
            "--runner",
            "github-hosted",
            "--postgres-version",
            "18",
            "--build-mode",
            "optimized",
            "--enforce",
        ])
        .output()
        .expect("reject hosted gate");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("performance gates require an explicitly stable Linux runner")
    );
}

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn controlled_profile_captures_real_intermediary_measurements_before_evaluation() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args([
            "performance",
            "--profile",
            "controlled",
            "--seed",
            "42",
            "--duration-seconds",
            "1",
            "--output-dir",
            artifacts.path().to_str().unwrap(),
        ])
        .output()
        .expect("capture controlled performance");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let measurements: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("measurements.json")).expect("capture artifact"),
    )
    .unwrap();
    assert!(
        !measurements["warm_up"]["closed_loop_micros"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !measurements["measurement"]["closed_loop"]["latencies_micros"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let open = &measurements["measurement"]["open_loop"];
    assert_eq!(
        open["queue_micros"].as_array().unwrap().len(),
        open["execution_micros"].as_array().unwrap().len()
    );
    assert_eq!(
        open["queue_micros"].as_array().unwrap().len(),
        open["end_to_end_micros"].as_array().unwrap().len()
    );
    assert!(measurements["windows"].as_array().unwrap().len() >= 2);
    assert_eq!(measurements["evidence"]["resource_checkpoints"], 2);
    assert_eq!(measurements["evidence"]["copy_scenarios"], 1);
    assert!(artifacts.path().join("performance.json").exists());
}
