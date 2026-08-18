//! Delegation of performance commands to a profile-optimized executable.

use std::{error::Error, path::PathBuf};

use tokio::process::Command;

const DELEGATED: &str = "PG_PROTO_BURN_IN_PERFORMANCE_DELEGATED";
const PERFORMANCE_BINARY: &str = "pg-proto-burn-in-performance";

pub(crate) async fn run_if_needed(arguments: &[String]) -> Result<bool, Box<dyn Error>> {
    if arguments.get(1).map(String::as_str) != Some("performance")
        || std::env::var_os(DELEGATED).is_some()
    {
        return Ok(false);
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("burn-in package has no workspace parent")?
        .to_owned();
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || workspace.join("target"),
        |value| {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                workspace.join(path)
            }
        },
    );
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let build_mode = arguments
        .windows(2)
        .find_map(|pair| (pair[0] == "--build-mode").then_some(pair[1].as_str()))
        .unwrap_or("optimized");
    let profile = match build_mode {
        "optimized" => "burn-in",
        "allocator-diagnostic" => "burn-in-diagnostic",
        value => return Err(format!("unsupported performance build mode: {value}").into()),
    };
    let status = Command::new(cargo)
        .current_dir(&workspace)
        .args([
            "build",
            "--locked",
            "--profile",
            profile,
            "-p",
            "pg-proto-burn-in",
            "--bin",
            PERFORMANCE_BINARY,
        ])
        .env("PG_PROTO_REQUESTED_PROFILE", profile)
        .status()
        .await?;
    if !status.success() {
        return Err(format!("failed to build optimized performance binary: {status}").into());
    }

    let executable = target.join(profile).join(format!(
        "{PERFORMANCE_BINARY}{}",
        std::env::consts::EXE_SUFFIX
    ));
    let status = Command::new(&executable)
        .args(&arguments[1..])
        .env(DELEGATED, "1")
        .status()
        .await
        .map_err(|error| {
            format!(
                "failed to execute optimized performance binary {}: {error}",
                executable.display()
            )
        })?;
    if status.success() {
        Ok(true)
    } else {
        Err(format!("optimized performance binary failed: {status}").into())
    }
}
