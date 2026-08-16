use std::{fs, process::Command};

#[test]
fn smoke_profile_rejects_versions_outside_the_compatibility_contract() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args([
            "conformance",
            "--profile",
            "smoke",
            "--postgres-version",
            "13",
            "--artifacts",
        ])
        .arg(artifacts.path())
        .output()
        .expect("run rejected compatibility version");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported PostgreSQL version: 13"));
}

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
    let error_scenarios = result["error_scenarios"]
        .as_array()
        .expect("SQL error scenario results");
    for (name, sqlstate) in [
        ("syntax", "42601"),
        ("missing-table", "42P01"),
        ("type", "42883"),
        ("arithmetic", "22012"),
        ("constraint", "23505"),
        ("permission", "42501"),
        ("failed-transaction", "25P02"),
        ("timeout", "57014"),
        ("serialization", "40001"),
        ("deadlock", "40P01"),
        ("invalidated-prepare", "0A000"),
    ] {
        let outcome = error_scenarios
            .iter()
            .find(|outcome| outcome["name"] == name)
            .unwrap_or_else(|| panic!("missing {name} SQL error scenario"));
        assert_eq!(outcome["expected_sqlstate"], sqlstate);
        assert_eq!(outcome["actual_sqlstate"], sqlstate);
        assert_eq!(outcome["protocol_ready"], true);
        assert_eq!(outcome["connection_clean"], true);
    }
    let lifecycle = result["query_lifecycle"]
        .as_array()
        .expect("query lifecycle results");
    for scenario in [
        "simple-query",
        "unnamed-extended",
        "named-statement-and-portal",
        "binary-formats",
        "portal-suspension",
        "pipelined-extended",
        "flush-and-sync",
    ] {
        let outcome = lifecycle
            .iter()
            .find(|outcome| outcome["name"] == scenario)
            .unwrap_or_else(|| panic!("missing {scenario} lifecycle scenario"));
        assert_eq!(outcome["ready_after"], true);
        assert_eq!(outcome["validated"], true);
    }
    let copy = result["copy_scenarios"]
        .as_array()
        .expect("COPY scenario results");
    for (name, direction, completed, aborted, failed) in [
        ("copy-in-small-chunked", "in", true, false, false),
        ("copy-in-large-backpressured", "in", true, false, false),
        ("copy-in-malformed-failure", "in", false, false, true),
        ("copy-out-small", "out", true, false, false),
        ("copy-out-large-slow-consumer", "out", true, false, false),
        ("copy-out-early-abort", "out", false, true, false),
    ] {
        let outcome = copy
            .iter()
            .find(|outcome| outcome["name"] == name)
            .unwrap_or_else(|| panic!("missing {name} COPY scenario"));
        assert_eq!(outcome["direction"], direction);
        assert_eq!(outcome["completed"], completed);
        assert_eq!(outcome["aborted"], aborted);
        assert_eq!(outcome["failed"], failed);
        assert_eq!(outcome["recovered"], true);
        assert_eq!(outcome["validated"], true);
        assert!(outcome["chunks"].as_u64().unwrap() > 0);
        assert!(outcome["payload_bytes"].as_u64().unwrap() > 0);
    }
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
    assert_eq!(result["async_traffic"]["notice_message"], "burn-in notice");
    assert_eq!(
        result["async_traffic"]["notification_channel"],
        "burn_in_events"
    );
    assert_eq!(
        result["async_traffic"]["notification_payload"],
        "fixture-ready"
    );
    assert_eq!(
        result["async_traffic"]["parameter_status"],
        serde_json::json!({
            "name": "application_name",
            "value": "pg-proto-burn-in-async"
        })
    );
    assert_eq!(result["async_traffic"]["backend_key_forwarded"], true);
    assert_eq!(
        result["async_traffic"]["causally_unattributed"],
        serde_json::json!(["backend-key", "notice", "notification", "parameter-status"])
    );
    assert_eq!(
        result["cancellation"],
        serde_json::json!({
            "selected_sqlstate": "57014",
            "selected_session_survived": true,
            "unaffected_value": 7,
            "unaffected_session_survived": true,
            "all_keys_rewritten": true,
            "mappings_after_teardown": 0
        })
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
    let observed_ids = result["coverage"]["observed_ids"]
        .as_array()
        .expect("coverage IDs");
    assert!(
        (37..=38).contains(&observed_ids.len()),
        "expected required coverage with at most one optional transition"
    );
    assert_eq!(result["coverage"]["stages"].as_array().unwrap().len(), 7);
    assert_eq!(
        result["coverage"]["real_postgres"].as_array().unwrap(),
        observed_ids
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

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn authentication_profile_writes_versioned_security_evidence() {
    let artifacts = tempfile::tempdir().expect("artifact directory");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["conformance", "--profile", "authentication", "--artifacts"])
        .arg(artifacts.path())
        .output()
        .expect("run authentication profile");

    assert!(
        output.status.success(),
        "authentication profile failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(
        &std::fs::read(artifacts.path().join("result.json")).expect("result artifact"),
    )
    .expect("valid result JSON");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["profile"], "authentication");
    let profiles = result["authentication_profiles"]
        .as_array()
        .expect("authentication profile evidence");
    let stable_ids: Vec<_> = profiles
        .iter()
        .map(|profile| profile["id"].as_str().expect("stable profile ID"))
        .collect();
    assert_eq!(
        stable_ids,
        [
            "auth.plaintext.trust",
            "auth.plaintext.cleartext-password",
            "auth.plaintext.md5",
            "auth.plaintext.scram-sha-256",
            "auth.tls.scram-sha-256-plus",
            "auth.tls.negotiation",
            "auth.tls.rejection",
        ]
    );
    assert!(
        profiles
            .iter()
            .all(|profile| profile["postgres_versions"] == "14-18")
    );
    assert!(
        profiles
            .iter()
            .all(|profile| profile["evidence"].as_str().is_some())
    );
}
