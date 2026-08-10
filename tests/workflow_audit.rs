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
