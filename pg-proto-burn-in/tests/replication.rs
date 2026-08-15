use std::{fs, process::Command};

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn physical_replication_profile_records_wal_feedback_and_teardown() {
    let artifacts = tempfile::tempdir().expect("create artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["conformance", "--profile", "replication", "--artifacts"])
        .arg(artifacts.path())
        .output()
        .expect("run physical replication profile");

    assert!(
        output.status.success(),
        "replication profile failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("result.json")).expect("read JSON artifact"),
    )
    .expect("parse JSON artifact");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["profile"], "replication");
    assert_eq!(result["postgres_version"], "18");
    assert_eq!(result["success"], true);

    let replication = &result["replication"];
    assert_eq!(replication["wal_received"], true);
    assert_eq!(replication["standby_status_sent"], true);
    assert_eq!(replication["cancelled"], true);
    assert_eq!(replication["sqlstate"], "57014");
    assert_eq!(replication["teardown_complete"], true);
    assert_eq!(
        replication["scripted_half_close_orders"],
        serde_json::json!(["client-first", "server-first"])
    );
}
