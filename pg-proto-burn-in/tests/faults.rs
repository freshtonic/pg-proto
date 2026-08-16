use std::{fs, process::Command};

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn disposable_fault_profiles_record_recovery_without_performance_evidence() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["faults", "--artifacts"])
        .arg(artifacts.path())
        .output()
        .expect("run fault profiles");

    assert!(
        output.status.success(),
        "fault profiles failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("result.json")).expect("result artifact"),
    )
    .expect("valid result JSON");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "faults");
    assert_eq!(result["postgres_version"], "18");
    assert_eq!(result["isolated_containers"], 5);
    assert_eq!(result["performance_evidence_included"], false);
    assert_eq!(result["success"], true);

    let scenarios = result["scenarios"].as_array().expect("fault scenarios");
    for (id, contract) in [
        ("backend-termination", "new-session-recovers"),
        ("resource-exhaustion", "same-session-recovers"),
        ("interrupted-copy", "new-session-recovers"),
        ("deadlock", "both-sessions-recover"),
        ("postgres-restart", "topology-terminates"),
    ] {
        let scenario = scenarios
            .iter()
            .find(|scenario| scenario["id"] == id)
            .unwrap_or_else(|| panic!("missing {id} scenario"));
        assert_eq!(scenario["contract"], contract);
        assert_eq!(scenario["fault_observed"], true);
        assert_eq!(scenario["contract_satisfied"], true);
        assert_eq!(scenario["isolated"], true);
        assert_eq!(scenario["performance_evidence_included"], false);
        assert!(
            scenario["evidence"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }

    let summary =
        fs::read_to_string(artifacts.path().join("summary.md")).expect("Markdown artifact");
    assert!(summary.contains("Fault injection: PASS"));
    assert!(summary.contains("Performance evidence included: no"));
}
