//! Controlled performance capture, evaluation, and artifact generation.

use std::{
    cmp::Ordering,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::Stdio,
    time::Duration,
};

use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt, runners::AsyncRunner},
};
use tokio::{process::Command, time::Instant};

use crate::{ChildEvent, atomic_write, option, read_event, wait_success};

#[derive(Debug, Deserialize, Serialize)]
struct Input {
    schema_version: u32,
    warm_up: WarmUpInput,
    measurement: MeasurementInput,
    windows: Vec<Window>,
    evidence: Evidence,
}

#[derive(Debug, Deserialize, Serialize)]
struct WarmUpInput {
    closed_loop_micros: Vec<u64>,
    open_loop_micros: Vec<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MeasurementInput {
    closed_loop: ClosedLoopInput,
    open_loop: OpenLoopInput,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClosedLoopInput {
    elapsed_micros: u64,
    latencies_micros: Vec<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
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
    hardware: Hardware,
}

#[derive(Debug, Serialize)]
struct Hardware {
    manufacturer: String,
    model: String,
    cpu: String,
    memory_bytes: Option<u64>,
    summary: String,
    gaps: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Build {
    mode: String,
    cargo_profile: String,
    base_profile: String,
    optimization_level: String,
    performance_optimized: bool,
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
    let runner = option(arguments, "--runner")
        .ok()
        .map(str::to_owned)
        .or_else(|| std::env::var("RUNNER_NAME").ok())
        .unwrap_or_else(|| "local-or-unspecified".into());
    let enforce = arguments.iter().any(|argument| argument == "--enforce");
    let stable_runner = arguments
        .iter()
        .any(|argument| argument == "--stable-runner");
    if enforce && (!stable_runner || runner == "github-hosted" || !cfg!(target_os = "linux")) {
        return Err("performance gates require an explicitly stable Linux runner".into());
    }
    let artifacts = PathBuf::from(option(arguments, "--output-dir")?);
    let postgres_version = option(arguments, "--postgres-version").unwrap_or("18");
    let build_mode = option(arguments, "--build-mode").unwrap_or("optimized");
    if !matches!(build_mode, "optimized" | "allocator-diagnostic") {
        return Err("--build-mode must be optimized or allocator-diagnostic".into());
    }
    let input = if let Ok(input_path) = option(arguments, "--input") {
        serde_json::from_slice(&tokio::fs::read(input_path).await?)?
    } else {
        let profile = option(arguments, "--profile")?;
        if !matches!(
            profile,
            "controlled" | "scheduled-soak" | "overnight" | "diagnostic"
        ) {
            return Err(
                "performance --profile must be controlled, scheduled-soak, overnight or diagnostic"
                    .into(),
            );
        }
        let seed = option(arguments, "--seed")?.parse()?;
        let duration = option(arguments, "--duration-seconds")?.parse()?;
        let executable = arguments.first().ok_or("missing executable path")?;
        let captured = capture(executable, seed, duration, postgres_version).await?;
        tokio::fs::create_dir_all(&artifacts).await?;
        atomic_write(
            &artifacts.join("measurements.json"),
            &serde_json::to_vec_pretty(&captured)?,
        )
        .await?;
        captured
    };
    validate_input(&input)?;
    let baseline = match option(arguments, "--baseline") {
        Ok(path) => Some(serde_json::from_slice::<Baseline>(
            &tokio::fs::read(path).await?,
        )?),
        Err(_) => None,
    };
    let key = BaselineKey {
        runner: runner.clone(),
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
        &runner,
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
        "# Controlled performance\n\n{status}: {:.2} operations/s; p95 {} us; p99 {} us.\n\nHardware: {}.\n\nWarm-up samples are excluded. Candidate baseline requires review and was not promoted.\n",
        report.drift.median_throughput_per_second,
        report.drift.median_p95_micros,
        report.drift.median_p99_micros,
        report.environment.hardware.summary,
    );
    atomic_write(&artifacts.join("summary.md"), summary.as_bytes()).await?;
    if enforce && report.comparison.threshold_exceeded {
        return Err("promoted performance threshold exceeded".into());
    }
    Ok(())
}

async fn capture(
    executable: &str,
    seed: u64,
    duration_seconds: u64,
    postgres_version: &str,
) -> Result<Input, Box<dyn Error>> {
    if duration_seconds == 0 {
        return Err("performance capture requires a positive --duration-seconds".into());
    }
    if postgres_version != "18" {
        return Err("performance capture currently requires PostgreSQL 18".into());
    }
    let container = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );
    let mut intermediary = Command::new(executable)
        .args(["intermediary-child", "--address", &upstream.to_string()])
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ChildEvent::Ready { listen_addr, .. } = read_event(&mut intermediary).await? else {
        return Err("expected performance intermediary ready event".into());
    };
    let mut config = tokio_postgres::Config::new();
    config
        .host(listen_addr.ip().to_string())
        .port(listen_addr.port())
        .user("postgres")
        .dbname("postgres");
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    let connection_task = tokio::spawn(connection);

    resource_checkpoint(&client).await?;
    let copy_bytes = client
        .copy_out("COPY (SELECT generate_series(1, 16)) TO STDOUT")
        .await?
        .try_fold(
            0_usize,
            |total, bytes| async move { Ok(total + bytes.len()) },
        )
        .await?;
    if copy_bytes == 0 {
        return Err("performance COPY evidence was empty".into());
    }

    let warm_up_duration = Duration::from_millis((duration_seconds * 100).clamp(100, 5_000));
    let warm_closed = run_closed_loop(&client, warm_up_duration, seed).await?;
    let warm_open_interval = Duration::from_micros(1_000);
    let warm_open = run_open_loop(&client, warm_up_duration, warm_open_interval, seed).await?;

    let measurement_duration = Duration::from_secs(duration_seconds);
    let closed_started = Instant::now();
    let closed = run_closed_loop(&client, measurement_duration, seed ^ 0xa5a5).await?;
    let closed_elapsed = elapsed_micros(closed_started.elapsed());
    let saturation = rate(closed.len(), closed_elapsed);
    let target_rate = (saturation * 0.8).clamp(1.0, 1_000.0);
    let scheduled_interval = Duration::from_secs_f64(1.0 / target_rate);
    let open_started = Instant::now();
    let open = run_open_loop(
        &client,
        measurement_duration,
        scheduled_interval,
        seed ^ 0x5a5a,
    )
    .await?;
    let open_elapsed = elapsed_micros(open_started.elapsed());
    resource_checkpoint(&client).await?;

    let windows = measurement_windows(&closed, closed_elapsed, &open, open_elapsed);
    let input = Input {
        schema_version: 1,
        warm_up: WarmUpInput {
            closed_loop_micros: warm_closed,
            open_loop_micros: warm_open
                .iter()
                .map(|sample| sample.end_to_end_micros)
                .collect(),
        },
        measurement: MeasurementInput {
            closed_loop: ClosedLoopInput {
                elapsed_micros: closed_elapsed,
                latencies_micros: closed,
            },
            open_loop: OpenLoopInput {
                elapsed_micros: open_elapsed,
                scheduled_interval_micros: elapsed_micros(scheduled_interval),
                queue_micros: open.iter().map(|sample| sample.queue_micros).collect(),
                execution_micros: open.iter().map(|sample| sample.execution_micros).collect(),
                end_to_end_micros: open.iter().map(|sample| sample.end_to_end_micros).collect(),
            },
        },
        windows,
        evidence: Evidence {
            soak_result: "measurements.json#controlled-public-intermediary".into(),
            resource_checkpoints: 2,
            copy_scenarios: 1,
        },
    };
    drop(client);
    connection_task.await??;
    let ChildEvent::Completed { .. } = read_event(&mut intermediary).await? else {
        return Err("expected performance intermediary completion event".into());
    };
    wait_success(&mut intermediary, "performance intermediary").await?;
    drop(container);
    Ok(input)
}

#[derive(Clone, Copy)]
struct OpenSample {
    queue_micros: u64,
    execution_micros: u64,
    end_to_end_micros: u64,
}

async fn run_closed_loop(
    client: &tokio_postgres::Client,
    duration: Duration,
    seed: u64,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let deadline = Instant::now() + duration;
    let mut samples = Vec::new();
    let mut ordinal = seed;
    while samples.is_empty() || Instant::now() < deadline {
        let started = Instant::now();
        let expected = i64::try_from(ordinal % 31 + 1)?;
        let actual: i64 = client
            .query_one("SELECT $1::int8", &[&expected])
            .await?
            .get(0);
        if actual != expected {
            return Err("controlled closed-loop result mismatch".into());
        }
        samples.push(elapsed_micros(started.elapsed()));
        ordinal = ordinal.wrapping_add(1);
    }
    Ok(samples)
}

async fn run_open_loop(
    client: &tokio_postgres::Client,
    duration: Duration,
    interval: Duration,
    seed: u64,
) -> Result<Vec<OpenSample>, Box<dyn Error>> {
    let phase_started = Instant::now();
    let deadline = phase_started + duration;
    let mut scheduled = phase_started;
    let mut ordinal = seed;
    let mut samples = Vec::new();
    while samples.is_empty() || scheduled < deadline {
        tokio::time::sleep_until(scheduled).await;
        let execution_started = Instant::now();
        let queue = execution_started.saturating_duration_since(scheduled);
        let expected = i64::try_from(ordinal % 31 + 1)?;
        let actual: i64 = client
            .query_one("SELECT $1::int8", &[&expected])
            .await?
            .get(0);
        if actual != expected {
            return Err("controlled open-loop result mismatch".into());
        }
        let completed = Instant::now();
        samples.push(OpenSample {
            queue_micros: elapsed_micros(queue),
            execution_micros: elapsed_micros(completed.duration_since(execution_started)),
            end_to_end_micros: elapsed_micros(completed.duration_since(scheduled)),
        });
        scheduled += interval;
        ordinal = ordinal.wrapping_add(1);
    }
    Ok(samples)
}

async fn resource_checkpoint(client: &tokio_postgres::Client) -> Result<(), Box<dyn Error>> {
    let row = client
        .query_one(
            "SELECT count(*)::bigint FROM pg_stat_activity WHERE backend_type = 'client backend'",
            &[],
        )
        .await?;
    let connections: i64 = row.get(0);
    if connections < 1 {
        return Err("performance resource checkpoint lost its PostgreSQL session".into());
    }
    Ok(())
}

fn measurement_windows(
    closed: &[u64],
    closed_elapsed: u64,
    open: &[OpenSample],
    open_elapsed: u64,
) -> Vec<Window> {
    let window_count = 2_usize.min(closed.len()).min(open.len()).max(1);
    (0..window_count)
        .map(|index| {
            let closed_start = index * closed.len() / window_count;
            let closed_end = (index + 1) * closed.len() / window_count;
            let open_start = index * open.len() / window_count;
            let open_end = (index + 1) * open.len() / window_count;
            let mut latencies = closed[closed_start..closed_end].to_vec();
            latencies.extend(
                open[open_start..open_end]
                    .iter()
                    .map(|sample| sample.end_to_end_micros),
            );
            latencies.sort_unstable();
            let elapsed = closed_elapsed / u64::try_from(window_count).unwrap()
                + open_elapsed / u64::try_from(window_count).unwrap();
            Window {
                throughput_per_second: rate(latencies.len(), elapsed),
                p95_micros: percentile(&latencies, 95),
                p99_micros: percentile(&latencies, 99),
            }
        })
        .collect()
}

fn elapsed_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros())
        .unwrap_or(u64::MAX)
        .max(1)
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
            hardware: capture_hardware(),
        },
        build: Build {
            mode: build_mode.into(),
            cargo_profile: env!("PG_PROTO_CARGO_PROFILE").into(),
            base_profile: env!("PG_PROTO_BASE_PROFILE").into(),
            optimization_level: env!("PG_PROTO_OPT_LEVEL").into(),
            performance_optimized: matches!(
                env!("PG_PROTO_CARGO_PROFILE"),
                "burn-in" | "burn-in-diagnostic"
            ) && env!("PG_PROTO_OPT_LEVEL") != "0",
            allocator: if build_mode == "optimized" {
                "production-system"
            } else {
                "instrumented-required"
            }
            .into(),
            compiler,
            target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            features: "default",
            lockfile_sha256: workspace_lockfile_sha256(),
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

#[cfg(target_os = "macos")]
fn capture_hardware() -> Hardware {
    let profiler = std::process::Command::new("system_profiler")
        .arg("SPHardwareDataType")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
    let field = |name: &str| {
        profiler.as_deref().and_then(|output| {
            output.lines().find_map(|line| {
                let (key, value) = line.trim().split_once(':')?;
                (key == name).then(|| value.trim().to_owned())
            })
        })
    };
    let model = field("Model Name")
        .or_else(|| command_value("sysctl", &["-n", "hw.model"]))
        .unwrap_or_else(|| "unavailable".into());
    let cpu = field("Chip")
        .or_else(|| field("Processor Name"))
        .or_else(|| command_value("sysctl", &["-n", "machdep.cpu.brand_string"]))
        .unwrap_or_else(|| std::env::consts::ARCH.into());
    let memory_bytes = field("Memory")
        .as_deref()
        .and_then(parse_human_memory)
        .or_else(|| {
            command_value("sysctl", &["-n", "hw.memsize"]).and_then(|value| value.parse().ok())
        });
    hardware("Apple", &model, &cpu, memory_bytes)
}

#[cfg(target_os = "linux")]
fn capture_hardware() -> Hardware {
    let manufacturer = read_trimmed("/sys/devices/virtual/dmi/id/sys_vendor")
        .unwrap_or_else(|| "unavailable".into());
    let model = read_trimmed("/sys/devices/virtual/dmi/id/product_name")
        .unwrap_or_else(|| "unavailable".into());
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "model name").then(|| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| std::env::consts::ARCH.into());
    let memory_bytes = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let value = line.strip_prefix("MemTotal:")?;
                value
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
                    .and_then(|kib| kib.checked_mul(1024))
            })
        });
    hardware(&manufacturer, &model, &cpu, memory_bytes)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn capture_hardware() -> Hardware {
    hardware("unavailable", "unavailable", std::env::consts::ARCH, None)
}

fn hardware(manufacturer: &str, model: &str, cpu: &str, memory_bytes: Option<u64>) -> Hardware {
    let memory = memory_bytes.map_or_else(|| "memory unavailable".into(), format_memory);
    let mut gaps = Vec::new();
    if manufacturer == "unavailable" {
        gaps.push("manufacturer unavailable".into());
    }
    if model == "unavailable" {
        gaps.push("model unavailable".into());
    }
    if memory_bytes.is_none() {
        gaps.push("physical memory unavailable".into());
    }
    Hardware {
        manufacturer: manufacturer.into(),
        model: model.into(),
        cpu: cpu.into(),
        memory_bytes,
        summary: format!("{manufacturer} {model} / {cpu} / {memory}"),
        gaps,
    }
}

fn format_memory(bytes: u64) -> String {
    let gib = bytes as f64 / (1024_u64.pow(3) as f64);
    if (gib - gib.round()).abs() < 0.05 {
        format!("{:.0} GB", gib.round())
    } else {
        format!("{gib:.1} GB")
    }
}

#[cfg(target_os = "macos")]
fn command_value(command: &str, arguments: &[&str]) -> Option<String> {
    std::process::Command::new(command)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn parse_human_memory(value: &str) -> Option<u64> {
    let mut fields = value.split_whitespace();
    let amount = fields.next()?.parse::<u64>().ok()?;
    let multiplier = match fields.next()? {
        "TB" => 1024_u64.pow(4),
        "GB" => 1024_u64.pow(3),
        "MB" => 1024_u64.pow(2),
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn workspace_lockfile_sha256() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|directory| {
            directory
                .ancestors()
                .map(|ancestor| ancestor.join("Cargo.lock"))
                .find(|candidate| candidate.is_file())
        })
        .and_then(|path| std::fs::read(path).ok())
        .map_or_else(|| "unavailable".into(), |bytes| sha256(&bytes))
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
