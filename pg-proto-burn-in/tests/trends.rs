//! Process-level tests for historical performance trend reports.

use std::{fs, path::Path, process::Command};

fn write_report(root: &Path, name: &str, throughput: f64) {
    let performance = root.join(name).join("performance-controlled");
    fs::create_dir_all(&performance).expect("create performance directory");
    fs::write(
        performance.join("performance.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "drift": { "median_throughput_per_second": throughput }
        }))
        .expect("encode performance artifact"),
    )
    .expect("write performance artifact");
}

#[test]
fn trends_orders_reports_and_embeds_a_labelled_svg_with_an_improvement_summary() {
    let history = tempfile::tempdir().expect("history directory");
    write_report(history.path(), "abcdef2-20260818T120000Z", 120.0);
    write_report(history.path(), "abcdef1-20260817T120000Z", 100.0);
    write_report(history.path(), "not-a-report", 1_000_000.0);

    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["trends", "--dir"])
        .arg(history.path())
        .output()
        .expect("generate trends");
    assert!(
        output.status.success(),
        "trends failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let markdown = fs::read_to_string(history.path().join("TRENDS.md")).expect("read trends");
    assert!(markdown.contains("![Throughput trend](throughput.svg)"));
    assert!(markdown.contains("performance improved"));
    assert!(markdown.contains("+20.00%"));

    let svg = fs::read_to_string(history.path().join("throughput.svg")).expect("read chart");
    assert!(svg.contains(">throughput<"), "missing Y-axis label");
    assert!(svg.contains(">report<"), "missing X-axis label");
    assert!(svg.contains("<polyline"));
    let first = svg
        .find("abcdef1-20260817T120000Z")
        .expect("first report label");
    let second = svg
        .find("abcdef2-20260818T120000Z")
        .expect("second report label");
    assert!(first < second, "reports are not chronological");
    assert!(!svg.contains("not-a-report"));
}

#[test]
fn trends_reports_holding_and_regressed_and_requires_two_reports() {
    for (latest, expected) in [
        (104.0, "performance holding"),
        (90.0, "performance regressed"),
    ] {
        let history = tempfile::tempdir().expect("history directory");
        write_report(history.path(), "abcdef1-20260817T120000Z", 100.0);
        write_report(history.path(), "abcdef2-20260818T120000Z", latest);
        let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
            .args(["trends", "--dir"])
            .arg(history.path())
            .output()
            .expect("generate trends");
        assert!(output.status.success());
        let markdown = fs::read_to_string(history.path().join("TRENDS.md")).expect("read trends");
        assert!(markdown.contains(expected), "missing summary {expected}");
    }

    let history = tempfile::tempdir().expect("history directory");
    write_report(history.path(), "abcdef1-20260817T120000Z", 100.0);
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["trends", "--dir"])
        .arg(history.path())
        .output()
        .expect("reject insufficient history");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least two"));
}
