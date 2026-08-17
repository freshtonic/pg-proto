use std::{error::Error, path::PathBuf, time::SystemTime};

use tokio::process::Command;

use crate::option;

pub(crate) async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let executable = arguments.first().ok_or("missing executable path")?;
    let output_dir = PathBuf::from(option(arguments, "--output-dir")?);
    let soak_duration = option(arguments, "--soak-duration-seconds")?;
    if soak_duration.parse::<u64>()? == 0 {
        return Err("--soak-duration-seconds must be positive".into());
    }

    for version in ["14", "15", "16", "17", "18"] {
        run_command(
            executable,
            &[
                "conformance",
                "--profile",
                "smoke",
                "--postgres-version",
                version,
                "--output-dir",
                &path(&output_dir, &format!("smoke-pg{version}")),
            ],
        )
        .await?;
    }
    for profile in ["authentication", "replication", "rewrites", "scripted"] {
        run_command(
            executable,
            &[
                "conformance",
                "--profile",
                profile,
                "--output-dir",
                &path(&output_dir, profile),
            ],
        )
        .await?;
    }
    run_command(
        executable,
        &["faults", "--output-dir", &path(&output_dir, "faults")],
    )
    .await?;
    run_command(
        executable,
        &[
            "soak",
            "--profile",
            "overnight",
            "--seed",
            "8675309",
            "--duration-seconds",
            soak_duration,
            "--output-dir",
            &path(&output_dir, "soak"),
        ],
    )
    .await?;
    let as_of = utc_date(SystemTime::now())?;
    run_command(
        executable,
        &[
            "catalogue",
            "--approved",
            "--as-of",
            &as_of,
            "--output-dir",
            &path(&output_dir, "catalogue"),
        ],
    )
    .await?;
    run_command(
        executable,
        &["make-report", "--dir", &output_dir.to_string_lossy()],
    )
    .await
}

async fn run_command(executable: &str, arguments: &[&str]) -> Result<(), Box<dyn Error>> {
    eprintln!("running: pg-proto-burn-in {}", arguments.join(" "));
    let status = Command::new(executable).args(arguments).status().await?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "burn-in command failed with {status}: pg-proto-burn-in {}",
            arguments.join(" ")
        )
        .into())
    }
}

fn path(root: &std::path::Path, child: &str) -> String {
    root.join(child).to_string_lossy().into_owned()
}

fn utc_date(now: SystemTime) -> Result<String, Box<dyn Error>> {
    let days = i64::try_from(now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() / 86_400)?;
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_date_formats_epoch_and_known_leap_day() {
        assert_eq!(utc_date(SystemTime::UNIX_EPOCH).unwrap(), "1970-01-01");
        assert_eq!(
            utc_date(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_709_164_800))
                .unwrap(),
            "2024-02-29"
        );
    }
}
