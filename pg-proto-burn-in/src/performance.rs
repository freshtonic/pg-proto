use std::{cmp::Ordering, error::Error, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{atomic_write, option};

#[derive(Debug, Deserialize)]
struct Input {
    schema_version: u32,
    warm_up: WarmUpInput,
    measurement: MeasurementInput,
    windows: Vec<Window>,
    evidence: Evidence,
}

#[derive(Debug, Deserialize)]
struct WarmUpInput {
    closed_loop_micros: Vec<u64>,
    open_loop_micros: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct MeasurementInput {
    closed_loop: ClosedLoopInput,
    open_loop: OpenLoopInput,
}

#[derive(Debug, Deserialize)]
struct ClosedLoopInput {
    elapsed_micros: u64,
    latencies_micros: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct OpenLoopInput {
    elapsed_micros: u64,
    scheduled_interval_micros: u64,
    queue_micros: Vec<u64>,
    execution_micros: Vec<u64>,
    end_to_end_micros: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Window {
    throughput_per_second: f64,
    p95_micros: u64,
    p99_micros: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Evidence {
    soak_result: String,
    resource_checkpoints: usize,
    copy_scenarios: usize,
}

#[derive(Debug, Deserialize)]
struct Baseline {
    schema_version: u32,
    key: BaselineKey,
    throughput_per_second: f64,
    p95_micros: u64,
    p99_micros: u64,
    promoted: bool,
    version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct BaselineKey {
    runner: String,
    postgres_version: String,
    profile: String,
    build_mode: String,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    environment: Environment,
    build: Build,
    phases: Phases,
    drift: Drift,
    comparison: Comparison,
    evidence: Evidence,
}

#[derive(Debug, Serialize)]
struct Environment {
    runner: String,
    postgres_version: String,
    operating_system: &'static str,
    architecture: &'static str,
}

#[derive(Debug, Serialize)]
struct Build {
    mode: String,
    cargo_profile: String,
    allocator: String,
    compiler: String,
    target: String,
    features: &'static str,
    lockfile_sha256: String,
    binary_sha256: String,
    reproducible_settings: &'static str,
}

#[derive(Debug, Serialize)]
struct Phases {
    warm_up: WarmUp,
    closed_loop: ClosedLoop,
    open_loop: OpenLoop,
}

#[derive(Debug, Serialize)]
struct WarmUp {
    included_in_measurement: bool,
    closed_loop_operations: usize,
    open_loop_operations: usize,
}

#[derive(Debug, Serialize)]
struct ClosedLoop {
    operations: usize,
    throughput_per_second: f64,
    latency: Histogram,
}

#[derive(Debug, Serialize)]
struct OpenLoop {
    operations: usize,
    achieved_rate_per_second: f64,
    scheduled_interval_micros: u64,
    queue: Histogram,
    execution: Histogram,
    end_to_end_raw: Histogram,
    end_to_end_corrected: Histogram,
}

#[derive(Clone, Debug, Serialize)]
struct Histogram {
    count: usize,
    min_micros: u64,
    p50_micros: u64,
    p95_micros: u64,
    p99_micros: u64,
    max_micros: u64,
    logarithmic_buckets: Vec<Bucket>,
}

#[derive(Clone, Debug, Serialize)]
struct Bucket {
    upper_bound_micros: u64,
    count: usize,
}

#[derive(Debug, Serialize)]
struct Drift {
    windows: Vec<Window>,
    median_throughput_per_second: f64,
    median_p95_micros: u64,
    median_p99_micros: u64,
    first_to_last_throughput_percent: f64,
}

#[derive(Debug, Serialize)]
struct Comparison {
    baseline_version: Option<u32>,
    thresholds: Thresholds,
    throughput_change_percent: Option<f64>,
    p95_change_percent: Option<f64>,
    p99_change_percent: Option<f64>,
    threshold_exceeded: bool,
    disposition: &'static str,
    candidate_baseline_written: bool,
}

#[derive(Debug, Serialize)]
struct Thresholds {
    throughput_percent: f64,
    latency_percent: f64,
}

pub(crate) async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let runner = option(arguments, "--runner")?;
    let enforce = arguments.iter().any(|argument| argument == "--enforce");
    let stable_runner = arguments
        .iter()
        .any(|argument| argument == "--stable-runner");
    if enforce && (!stable_runner || runner == "github-hosted" || !cfg!(target_os = "linux")) {
        return Err("performance gates require an explicitly stable Linux runner".into());
    }
    let input_path = PathBuf::from(option(arguments, "--input")?);
    let artifacts = PathBuf::from(option(arguments, "--artifacts")?);
    let postgres_version = option(arguments, "--postgres-version")?;
    let build_mode = option(arguments, "--build-mode")?;
    if !matches!(build_mode, "optimized" | "allocator-diagnostic") {
        return Err("--build-mode must be optimized or allocator-diagnostic".into());
    }
    let input: Input = serde_json::from_slice(&tokio::fs::read(input_path).await?)?;
    validate_input(&input)?;
    let baseline = match option(arguments, "--baseline") {
        Ok(path) => Some(serde_json::from_slice::<Baseline>(
            &tokio::fs::read(path).await?,
        )?),
        Err(_) => None,
    };
    let key = BaselineKey {
        runner: runner.into(),
        postgres_version: postgres_version.into(),
        profile: "controlled".into(),
        build_mode: build_mode.into(),
    };
    if let Some(value) = &baseline {
        if value.schema_version != 1 || !value.promoted {
            return Err("baseline must be a promoted schema-version 1 artifact".into());
        }
        // Hosted evidence is deliberately not baseline-compatible. It may still be
        // compared for visibility, but never gates or promotes automatically.
        if runner != "github-hosted" && value.key != key {
            return Err("baseline key does not match runner, PostgreSQL, profile and build".into());
        }
    }

    let report = build_report(
        input,
        baseline.as_ref(),
        build_mode,
        enforce,
        runner,
        postgres_version,
    )?;
    tokio::fs::create_dir_all(&artifacts).await?;
    atomic_write(
        &artifacts.join("performance.json"),
        &serde_json::to_vec_pretty(&report)?,
    )
    .await?;
    let candidate = serde_json::json!({
        "schema_version": 1,
        "key": key,
        "throughput_per_second": report.drift.median_throughput_per_second,
        "p95_micros": report.drift.median_p95_micros,
        "p99_micros": report.drift.median_p99_micros,
        "promoted": false,
        "version": baseline.map_or(1, |value| value.version + 1),
        "review_required": true
    });
    atomic_write(
        &artifacts.join("candidate-baseline.json"),
        &serde_json::to_vec_pretty(&candidate)?,
    )
    .await?;
    let status = if report.comparison.disposition == "enforced-pass" {
        "PASS"
    } else {
        "ADVISORY"
    };
    let summary = format!(
        "# Controlled performance\n\n{status}: {:.2} operations/s; p95 {} us; p99 {} us.\n\nWarm-up samples are excluded. Candidate baseline requires review and was not promoted.\n",
        report.drift.median_throughput_per_second,
        report.drift.median_p95_micros,
        report.drift.median_p99_micros,
    );
    atomic_write(&artifacts.join("summary.md"), summary.as_bytes()).await?;
    if enforce && report.comparison.threshold_exceeded {
        return Err("promoted performance threshold exceeded".into());
    }
    Ok(())
}

fn validate_input(input: &Input) -> Result<(), Box<dyn Error>> {
    if input.schema_version != 1 {
        return Err("unsupported performance input schema".into());
    }
    let open = &input.measurement.open_loop;
    if input.measurement.closed_loop.elapsed_micros == 0
        || open.elapsed_micros == 0
        || open.scheduled_interval_micros == 0
        || open.queue_micros.len() != open.execution_micros.len()
        || open.queue_micros.len() != open.end_to_end_micros.len()
        || input.windows.is_empty()
    {
        return Err("performance input contains incomplete controlled phases".into());
    }
    if input.evidence.resource_checkpoints == 0 || input.evidence.copy_scenarios == 0 {
        return Err("performance input must reference soak resources and COPY evidence".into());
    }
    Ok(())
}

fn build_report(
    input: Input,
    baseline: Option<&Baseline>,
    build_mode: &str,
    enforce: bool,
    runner: &str,
    postgres_version: &str,
) -> Result<Report, Box<dyn Error>> {
    let closed_rate = rate(
        input.measurement.closed_loop.latencies_micros.len(),
        input.measurement.closed_loop.elapsed_micros,
    );
    let open_rate = rate(
        input.measurement.open_loop.end_to_end_micros.len(),
        input.measurement.open_loop.elapsed_micros,
    );
    let corrected = coordinated_omission_correct(
        &input.measurement.open_loop.end_to_end_micros,
        input.measurement.open_loop.scheduled_interval_micros,
    );
    let throughput = median_f64(
        &input
            .windows
            .iter()
            .map(|window| window.throughput_per_second)
            .collect::<Vec<_>>(),
    );
    let p95 = median_u64(
        &input
            .windows
            .iter()
            .map(|window| window.p95_micros)
            .collect::<Vec<_>>(),
    );
    let p99 = median_u64(
        &input
            .windows
            .iter()
            .map(|window| window.p99_micros)
            .collect::<Vec<_>>(),
    );
    let throughput_change =
        baseline.map(|value| percent_change(throughput, value.throughput_per_second));
    let p95_change = baseline.map(|value| percent_change(p95 as f64, value.p95_micros as f64));
    let p99_change = baseline.map(|value| percent_change(p99 as f64, value.p99_micros as f64));
    let exceeded = throughput_change.is_some_and(|change| change < -10.0)
        || p95_change.is_some_and(|change| change > 20.0)
        || p99_change.is_some_and(|change| change > 20.0);
    let first = input.windows.first().unwrap().throughput_per_second;
    let last = input.windows.last().unwrap().throughput_per_second;
    let compiler = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_else(
            || "unavailable".into(),
            |output| String::from_utf8_lossy(&output.stdout).trim().into(),
        );
    let binary_sha256 = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::read(path).ok())
        .map_or_else(|| "unavailable".into(), |bytes| sha256(&bytes));
    Ok(Report {
        schema_version: 1,
        environment: Environment {
            runner: runner.into(),
            postgres_version: postgres_version.into(),
            operating_system: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
        },
        build: Build {
            mode: build_mode.into(),
            cargo_profile: if build_mode == "optimized" {
                "burn-in"
            } else {
                "burn-in-diagnostic"
            }
            .into(),
            allocator: if build_mode == "optimized" {
                "production-system"
            } else {
                "instrumented-required"
            }
            .into(),
            compiler,
            target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            features: "default",
            lockfile_sha256: sha256(include_bytes!("../../Cargo.lock")),
            binary_sha256,
            reproducible_settings: "locked dependencies; debug symbols; lto=fat; codegen-units=1",
        },
        phases: Phases {
            warm_up: WarmUp {
                included_in_measurement: false,
                closed_loop_operations: input.warm_up.closed_loop_micros.len(),
                open_loop_operations: input.warm_up.open_loop_micros.len(),
            },
            closed_loop: ClosedLoop {
                operations: input.measurement.closed_loop.latencies_micros.len(),
                throughput_per_second: closed_rate,
                latency: histogram(&input.measurement.closed_loop.latencies_micros)?,
            },
            open_loop: OpenLoop {
                operations: input.measurement.open_loop.end_to_end_micros.len(),
                achieved_rate_per_second: open_rate,
                scheduled_interval_micros: input.measurement.open_loop.scheduled_interval_micros,
                queue: histogram(&input.measurement.open_loop.queue_micros)?,
                execution: histogram(&input.measurement.open_loop.execution_micros)?,
                end_to_end_raw: histogram(&input.measurement.open_loop.end_to_end_micros)?,
                end_to_end_corrected: histogram(&corrected)?,
            },
        },
        drift: Drift {
            windows: input.windows,
            median_throughput_per_second: throughput,
            median_p95_micros: p95,
            median_p99_micros: p99,
            first_to_last_throughput_percent: percent_change(last, first),
        },
        comparison: Comparison {
            baseline_version: baseline.map(|value| value.version),
            thresholds: Thresholds {
                throughput_percent: -10.0,
                latency_percent: 20.0,
            },
            throughput_change_percent: throughput_change,
            p95_change_percent: p95_change,
            p99_change_percent: p99_change,
            threshold_exceeded: exceeded,
            disposition: if enforce {
                if exceeded {
                    "enforced-fail"
                } else {
                    "enforced-pass"
                }
            } else {
                "advisory"
            },
            candidate_baseline_written: true,
        },
        evidence: input.evidence,
    })
}

fn rate(operations: usize, elapsed_micros: u64) -> f64 {
    operations as f64 * 1_000_000.0 / elapsed_micros as f64
}

fn coordinated_omission_correct(values: &[u64], interval: u64) -> Vec<u64> {
    let mut corrected = Vec::new();
    for &value in values {
        corrected.push(value);
        let mut synthetic = value.saturating_sub(interval);
        while synthetic >= interval {
            corrected.push(synthetic);
            synthetic = synthetic.saturating_sub(interval);
        }
    }
    corrected
}

fn histogram(values: &[u64]) -> Result<Histogram, Box<dyn Error>> {
    if values.is_empty() {
        return Err("histogram requires at least one sample".into());
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let max = *sorted.last().unwrap();
    let mut upper = 1_u64;
    let mut buckets = Vec::new();
    while upper < max {
        buckets.push(Bucket {
            upper_bound_micros: upper,
            count: sorted.iter().filter(|&&value| value <= upper).count(),
        });
        upper = upper.saturating_mul(2);
    }
    buckets.push(Bucket {
        upper_bound_micros: upper,
        count: sorted.len(),
    });
    Ok(Histogram {
        count: sorted.len(),
        min_micros: sorted[0],
        p50_micros: percentile(&sorted, 50),
        p95_micros: percentile(&sorted, 95),
        p99_micros: percentile(&sorted, 99),
        max_micros: max,
        logarithmic_buckets: buckets,
    })
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let rank = (percentile * sorted.len()).div_ceil(100).saturating_sub(1);
    sorted[rank]
}

fn median_u64(values: &[u64]) -> u64 {
    let mut values = values.to_vec();
    values.sort_unstable();
    values[values.len() / 2]
}

fn median_f64(values: &[f64]) -> f64 {
    let mut values = values.to_vec();
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(Ordering::Equal));
    values[values.len() / 2]
}

fn percent_change(candidate: f64, baseline: f64) -> f64 {
    (candidate - baseline) * 100.0 / baseline
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
