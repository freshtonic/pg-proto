use std::{fs, process::Command};

#[test]
fn scripted_profile_covers_exceptional_paths_without_claiming_real_postgres() {
    let artifacts = tempfile::tempdir().expect("create artifact directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["conformance", "--profile", "scripted", "--output-dir"])
        .arg(artifacts.path())
        .output()
        .expect("run scripted profile");

    assert!(
        output.status.success(),
        "scripted profile failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.path().join("result.json")).expect("read JSON artifact"),
    )
    .expect("parse JSON artifact");
    assert_eq!(result["profile"], "scripted");
    assert_eq!(result["success"], true);
    assert_eq!(result["coverage"]["real_postgres"], serde_json::json!([]));
    assert_eq!(
        result["coverage"]["scripted"],
        serde_json::json!([
            "scripted.authentication.gss",
            "scripted.authentication.gss-continue",
            "scripted.authentication.kerberos-v5",
            "scripted.authentication.sspi",
            "scripted.copy-both.client-half-close-first",
            "scripted.copy-both.server-half-close-first",
            "scripted.copy-fail.exact",
            "scripted.encryption.gss-request",
            "scripted.encryption.legacy-error",
            "scripted.function-call",
            "scripted.illegal.copy-data-while-ready",
            "scripted.malformed.invalid-encoding",
            "scripted.malformed.invalid-length",
            "scripted.malformed.truncated-frame",
            "scripted.malformed.unknown-tag"
        ])
    );
    let diagnostics = result["scripted_diagnostics"]
        .as_array()
        .expect("scripted diagnostic evidence");
    assert_eq!(diagnostics.len(), 5);
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic["id"].as_str().expect("stable diagnostic ID"))
            .collect::<Vec<_>>(),
        [
            "scripted.malformed.invalid-length",
            "scripted.malformed.truncated-frame",
            "scripted.malformed.unknown-tag",
            "scripted.malformed.invalid-encoding",
            "scripted.illegal.copy-data-while-ready",
        ]
    );
    for diagnostic in diagnostics {
        assert_eq!(diagnostic["rejected"], true);
        assert_eq!(diagnostic["teardown_complete"], true);
        assert_eq!(diagnostic["transport_capacity_bytes"], 256);
        assert_eq!(diagnostic["frame_limit_bytes"], 256);
        assert!(
            !diagnostic["diagnostic"]
                .as_str()
                .expect("stable rejection diagnostic")
                .is_empty()
        );
    }
}
