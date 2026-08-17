use std::{error::Error, path::Path};

use crate::{atomic_write, option};

const RUN_DIRECTORIES: &[&str] = &[
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
];

pub(crate) async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let directory = Path::new(option(arguments, "--dir")?);
    if !directory.is_dir() {
        return Err(format!("report directory does not exist: {}", directory.display()).into());
    }

    let mut report = String::from("# pg-proto burn-in report\n\n");
    for run_name in RUN_DIRECTORIES {
        report.push_str(&format!("## `{run_name}`\n\n"));
        let run_directory = directory.join(run_name);
        if !run_directory.is_dir() {
            report.push_str("Not run.\n\n");
            continue;
        }
        let mut artifacts = Vec::new();
        let mut entries = tokio::fs::read_dir(&run_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                artifacts.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        artifacts.sort();
        if artifacts.is_empty() {
            report.push_str("No artifacts found.\n\n");
        } else {
            for artifact in artifacts {
                report.push_str(&format!("- [{artifact}]({run_name}/{artifact})\n"));
            }
            report.push('\n');
        }
    }
    atomic_write(&directory.join("REPORT.md"), report.as_bytes()).await
}
