use std::{fs, process::Command};

#[test]
fn help_describes_every_public_command_and_output_directory() {
    let binary = env!("CARGO_BIN_EXE_pg-proto-burn-in");
    let help = Command::new(binary)
        .arg("--help")
        .output()
        .expect("show top-level help");
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).expect("UTF-8 help");
    for command in [
        "conformance",
        "soak",
        "replay",
        "catalogue",
        "performance",
        "faults",
        "make-report",
        "trends",
    ] {
        assert!(
            help.contains(command),
            "missing command {command} from help"
        );
    }
    assert!(help.contains("--run-all"));
    assert!(help.contains("--soak-duration-seconds"));

    for command in ["conformance", "soak", "catalogue", "faults"] {
        let help = Command::new(binary)
            .args([command, "--help"])
            .output()
            .expect("show command help");
        assert!(help.status.success(), "{command} --help failed");
        let help = String::from_utf8(help.stdout).expect("UTF-8 help");
        assert!(help.contains("--output-dir"));
        assert!(
            help.contains("Directory"),
            "{command} option lacks a description"
        );
        assert!(!help.contains("--artifacts"));
    }
}

#[test]
fn run_all_requires_a_soak_duration_and_output_directory() {
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .arg("--run-all")
        .output()
        .expect("validate run-all arguments");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--soak-duration-seconds"));
    assert!(stderr.contains("--output-dir"));
}

#[test]
fn soak_does_not_accept_a_profile_option() {
    let binary = env!("CARGO_BIN_EXE_pg-proto-burn-in");
    let help = Command::new(binary)
        .args(["soak", "--help"])
        .output()
        .expect("show soak help");
    assert!(help.status.success());
    assert!(!String::from_utf8_lossy(&help.stdout).contains("--profile"));

    let output = Command::new(binary)
        .args([
            "soak",
            "--profile",
            "overnight",
            "--seed",
            "1",
            "--iterations",
            "0",
            "--output-dir",
            "unused",
        ])
        .output()
        .expect("reject removed soak profile");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--profile'"));
}

#[test]
#[ignore = "requires a Docker-compatible container runtime"]
fn run_all_executes_every_conventional_run_and_writes_the_report() {
    let output_dir = tempfile::tempdir().expect("output directory");
    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .args(["--run-all", "--soak-duration-seconds", "1", "--output-dir"])
        .arg(output_dir.path())
        .output()
        .expect("run every burn-in permutation");
    assert!(
        output.status.success(),
        "run-all failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for directory in [
        "smoke-pg14",
        "smoke-pg15",
        "smoke-pg16",
        "smoke-pg17",
        "smoke-pg18",
        "authentication",
        "replication",
        "rewrites",
        "scripted",
        "faults",
        "soak",
        "catalogue",
    ] {
        assert!(
            output_dir
                .path()
                .join(directory)
                .join("result.json")
                .is_file(),
            "missing {directory} result"
        );
    }
    for profile in ["controlled", "scheduled-soak", "overnight", "diagnostic"] {
        let directory = format!("performance-{profile}");
        assert!(
            output_dir
                .path()
                .join(&directory)
                .join("performance.json")
                .is_file(),
            "missing {directory} result"
        );
    }
    assert!(output_dir.path().join("REPORT.md").is_file());
}

#[test]
fn make_report_links_artifacts_from_recognized_run_directories() {
    let root = tempfile::tempdir().expect("report directory");
    for directory in [
        "smoke-pg14",
        "authentication",
        "performance-controlled",
        "soak",
        "catalogue",
    ] {
        let run = root.path().join(directory);
        fs::create_dir(&run).expect("create run directory");
        fs::write(run.join("result.json"), b"{}").expect("write JSON artifact");
        fs::write(run.join("summary.md"), b"# Summary\n").expect("write Markdown artifact");
    }
    fs::create_dir(root.path().join("unrecognized")).expect("create unrelated directory");
    fs::write(root.path().join("unrecognized/result.json"), b"{}").expect("write unrelated file");

    let output = Command::new(env!("CARGO_BIN_EXE_pg-proto-burn-in"))
        .arg("make-report")
        .arg("--dir")
        .arg(root.path())
        .output()
        .expect("make report");
    assert!(
        output.status.success(),
        "make-report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = fs::read_to_string(root.path().join("REPORT.md")).expect("read report");
    for link in [
        "[result.json](smoke-pg14/result.json)",
        "[summary.md](authentication/summary.md)",
        "[result.json](performance-controlled/result.json)",
        "[result.json](soak/result.json)",
        "[summary.md](catalogue/summary.md)",
    ] {
        assert!(report.contains(link), "missing report link {link}");
    }
    assert!(!report.contains("unrecognized"));
    assert!(
        report.contains("smoke-pg15"),
        "absent conventional runs remain visible"
    );
}
