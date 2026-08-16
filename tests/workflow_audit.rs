//! Structural checks for required GitHub Actions status names.

use std::{fs, path::PathBuf};

#[test]
fn reused_ci_still_expands_every_required_fuzz_check() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let fuzz = workflow
        .split_once("\n  fuzz:\n")
        .expect("CI workflow defines the fuzz job")
        .1;
    let (job, steps) = fuzz
        .split_once("    steps:\n")
        .expect("fuzz job defines steps");

    assert!(job.contains("    if: always()"));
    assert!(
        !job.contains("needs.reuse-pr-ci.outputs.tested != 'true'"),
        "the reuse predicate at job level prevents GitHub from expanding matrix check names"
    );
    assert!(
        steps.contains("needs.reuse-pr-ci.outputs.tested != 'true'"),
        "expensive fuzz steps must remain conditional when CI is reused"
    );
    for target in [
        "pre_startup",
        "scram",
        "frontend_codec",
        "runtime_fsm",
        "backend_codec",
    ] {
        assert!(
            fuzz.contains(target),
            "missing required fuzz check {target}"
        );
    }
}

#[test]
fn burn_in_workflows_separate_portable_evidence_from_stable_runner_enforcement() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("conformance --profile smoke --postgres-version 18"));

    let compatibility =
        fs::read_to_string(root.join(".github/workflows/postgres-compatibility.yml")).unwrap();
    assert!(compatibility.contains("version: [14, 15, 16, 17, 18]"));
    assert!(
        compatibility
            .contains("conformance --profile smoke --postgres-version ${{ matrix.version }}")
    );

    let burn_in = fs::read_to_string(root.join(".github/workflows/burn-in.yml")).unwrap();
    assert!(burn_in.contains("schedule:"));
    assert!(burn_in.contains("workflow_dispatch:"));

    let hosted = burn_in
        .split_once("  hosted-soak:")
        .expect("hosted soak job")
        .1
        .split_once("  stable-performance:")
        .expect("stable performance follows hosted soak")
        .0;
    assert!(hosted.contains("runs-on: ubuntu-latest"));
    assert!(hosted.contains("continue-on-error: true"));
    assert!(hosted.contains("soak --profile diagnostic"));
    assert!(!hosted.contains("performance --profile"));

    let stable = burn_in
        .split_once("  stable-performance:")
        .expect("stable performance job")
        .1;
    assert!(stable.contains("runs-on: [self-hosted, linux, pg-proto-stable]"));
    assert!(stable.contains("soak --profile \"$BURN_IN_PROFILE\""));
    assert!(stable.contains("performance --profile"));
    assert!(!stable.contains("continue-on-error: true"));
    assert!(stable.contains("Performance command is not integrated yet"));
}
