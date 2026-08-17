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
    ] {
        assert!(
            help.contains(command),
            "missing command {command} from help"
        );
    }

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
fn make_report_links_artifacts_from_recognized_run_directories() {
    let root = tempfile::tempdir().expect("report directory");
    for directory in ["smoke-pg14", "authentication", "soak", "catalogue"] {
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
