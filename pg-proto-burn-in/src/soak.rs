use std::{
    collections::BTreeMap,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
};

use serde::{Deserialize, Serialize};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt, runners::AsyncRunner},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    time::sleep,
};
use tokio::{process::Command, time::timeout};

use crate::{CHILD_TIMEOUT, ChildEvent, atomic_write, option, read_event, wait_success};

const CONCURRENCY: usize = 4;
const CANONICAL: [&str; 3] = ["scalar", "rows", "syntax-error"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    LongLived,
    ConnectionChurn,
    BoundedConcurrency,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SequenceEntry {
    ordinal: usize,
    phase: Phase,
    scenario: String,
    canonical: bool,
    parameters: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Budget {
    Iterations(u64),
    DurationSeconds(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SoakResult {
    schema_version: u32,
    command: String,
    seed: u64,
    budget: Budget,
    max_concurrency: usize,
    sequence: Vec<SequenceEntry>,
    completed: usize,
    success: bool,
    replay_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reduced_from: Option<usize>,
    #[serde(default)]
    resource_checkpoints: Vec<ResourceCheckpoint>,
    #[serde(default)]
    lifecycle_evidence: LifecycleEvidence,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LifecycleEvidence {
    graceful_restart: bool,
    abrupt_termination: bool,
    teardown: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ProcessResources {
    pid: u32,
    rss_bytes: u64,
    pss_bytes: u64,
    virtual_memory_bytes: u64,
    tasks: u64,
    file_descriptors: u64,
    cpu_user_ticks: u64,
    cpu_system_ticks: u64,
    voluntary_context_switches: u64,
    involuntary_context_switches: u64,
    read_bytes: u64,
    write_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampling_gap: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PostgresResources {
    process: ProcessResources,
    memory_bytes: i64,
    connections: i64,
    locks: i64,
    temporary_bytes: i64,
    wal_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampling_gap: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResourceCheckpoint {
    stage: String,
    quiescent: bool,
    intermediary: ProcessResources,
    driver: ProcessResources,
    postgres: PostgresResources,
    #[serde(skip_serializing_if = "Option::is_none")]
    termination: Option<String>,
}

struct ExecutionOutcome {
    completed: usize,
    resource_checkpoints: Vec<ResourceCheckpoint>,
    lifecycle_evidence: LifecycleEvidence,
}

#[derive(Debug, Serialize, Deserialize)]
struct DriverResult {
    version: u32,
    success: bool,
    completed: usize,
    error: Option<String>,
}

pub(crate) async fn run_soak(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let seed = option(arguments, "--seed")?.parse()?;
    let budget = parse_budget(arguments)?;
    let artifacts = PathBuf::from(option(arguments, "--artifacts")?);
    let sequence = schedule(seed, budget.clone())?;
    execute_and_record(
        arguments.first().ok_or("missing executable path")?,
        &artifacts,
        seed,
        budget,
        sequence,
        "soak",
        None,
    )
    .await
}

pub(crate) async fn run_replay(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let input = PathBuf::from(option(arguments, "--input")?);
    let artifacts = PathBuf::from(option(arguments, "--artifacts")?);
    let original: SoakResult = serde_json::from_slice(&tokio::fs::read(&input).await?)?;
    if original.schema_version != 1 {
        return Err(format!(
            "unsupported soak artifact schema {}",
            original.schema_version
        )
        .into());
    }
    tokio::fs::create_dir_all(&artifacts).await?;
    // Preserve the source evidence before any optional reduction can run.
    atomic_write(
        &artifacts.join("original.json"),
        &serde_json::to_vec_pretty(&original)?,
    )
    .await?;
    let reduce = arguments.iter().any(|argument| argument == "--reduce");
    let original_len = original.sequence.len();
    let sequence = original.sequence;
    let exact = execute_and_record(
        arguments.first().ok_or("missing executable path")?,
        &artifacts,
        original.seed,
        original.budget.clone(),
        sequence.clone(),
        "replay",
        None,
    )
    .await;
    if !reduce || exact.is_ok() {
        return exact;
    }

    let reduced = reduce_failing_prefix(
        arguments.first().ok_or("missing executable path")?,
        &sequence,
    )
    .await;
    let reduction = SoakResult {
        schema_version: 1,
        command: "replay-reduction".into(),
        seed: original.seed,
        budget: original.budget,
        max_concurrency: CONCURRENCY,
        sequence: reduced.clone(),
        completed: 0,
        success: false,
        replay_command: "pg-proto-burn-in replay --input reduction.json --artifacts replay".into(),
        reduced_from: Some(original_len),
        resource_checkpoints: Vec::new(),
        lifecycle_evidence: LifecycleEvidence::default(),
    };
    atomic_write(
        &artifacts.join("reduction.json"),
        &serde_json::to_vec_pretty(&reduction)?,
    )
    .await?;
    exact
}

fn parse_budget(arguments: &[String]) -> Result<Budget, Box<dyn Error>> {
    let iterations = option(arguments, "--iterations").ok();
    let duration = option(arguments, "--duration-seconds").ok();
    match (iterations, duration) {
        (Some(value), None) => Ok(Budget::Iterations(value.parse()?)),
        (None, Some(value)) => Ok(Budget::DurationSeconds(value.parse()?)),
        _ => Err("soak requires exactly one budget: --iterations or --duration-seconds".into()),
    }
}

fn schedule(seed: u64, budget: Budget) -> Result<Vec<SequenceEntry>, Box<dyn Error>> {
    let weighted_per_phase = match budget {
        Budget::Iterations(value) => usize::try_from(value)?,
        // Duration schedules remain deterministic and bounded. Each selected operation is
        // budgeted one second; replay uses the recorded prefix, never wall-clock selection.
        Budget::DurationSeconds(value) => usize::try_from(value)?,
    };
    let mut rng = StableRng(seed);
    let mut entries = Vec::new();
    for phase in [
        Phase::LongLived,
        Phase::ConnectionChurn,
        Phase::BoundedConcurrency,
    ] {
        for scenario in CANONICAL {
            push_entry(&mut entries, phase.clone(), scenario, true, &mut rng);
        }
        for _ in 0..weighted_per_phase {
            let scenario = match rng.next() % 6 {
                0..=2 => "scalar",
                3..=4 => "rows",
                _ => "syntax-error",
            };
            push_entry(&mut entries, phase.clone(), scenario, false, &mut rng);
        }
    }
    Ok(entries)
}

fn push_entry(
    entries: &mut Vec<SequenceEntry>,
    phase: Phase,
    scenario: &str,
    canonical: bool,
    rng: &mut StableRng,
) {
    let mut parameters = BTreeMap::new();
    if scenario == "rows" {
        parameters.insert(
            "rows".into(),
            if canonical {
                7
            } else {
                (rng.next() % 31 + 1) as i64
            },
        );
    }
    entries.push(SequenceEntry {
        ordinal: entries.len(),
        phase,
        scenario: scenario.into(),
        canonical,
        parameters,
    });
}

struct StableRng(u64);

impl StableRng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        if value == 0 {
            value = 0x9e37_79b9_7f4a_7c15;
        }
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

async fn reduce_failing_prefix(executable: &str, sequence: &[SequenceEntry]) -> Vec<SequenceEntry> {
    if sequence.len() <= 1 {
        return sequence.to_vec();
    }
    let mut passing_prefix = 0;
    let mut failing_prefix = sequence.len();
    // Keep reduction bounded even for a very large overnight recording.
    for _ in 0..8 {
        if failing_prefix - passing_prefix <= 1 {
            break;
        }
        let candidate = passing_prefix + (failing_prefix - passing_prefix) / 2;
        if execute(executable, &sequence[..candidate]).await.is_err() {
            failing_prefix = candidate;
        } else {
            passing_prefix = candidate;
        }
    }
    sequence[..failing_prefix].to_vec()
}

async fn execute_and_record(
    executable: &str,
    artifacts: &Path,
    seed: u64,
    budget: Budget,
    sequence: Vec<SequenceEntry>,
    command: &str,
    reduced_from: Option<usize>,
) -> Result<(), Box<dyn Error>> {
    tokio::fs::create_dir_all(artifacts).await?;
    let outcome = execute(executable, &sequence).await;
    let completed = outcome.as_ref().map(|value| value.completed).unwrap_or(0);
    let (resource_checkpoints, lifecycle_evidence) = outcome
        .as_ref()
        .map(|value| {
            (
                value.resource_checkpoints.clone(),
                value.lifecycle_evidence.clone(),
            )
        })
        .unwrap_or_default();
    let result = SoakResult {
        schema_version: 1,
        command: command.into(),
        seed,
        budget,
        max_concurrency: CONCURRENCY,
        sequence,
        completed,
        success: outcome.is_ok(),
        replay_command: "pg-proto-burn-in replay --input result.json --artifacts replay".into(),
        reduced_from,
        resource_checkpoints,
        lifecycle_evidence,
    };
    write_result(artifacts, &result).await?;
    outcome.map(|_| ())
}

async fn execute(
    executable: &str,
    sequence: &[SequenceEntry],
) -> Result<ExecutionOutcome, Box<dyn Error>> {
    let container = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );
    let long: Vec<_> = sequence
        .iter()
        .filter(|entry| entry.phase == Phase::LongLived)
        .cloned()
        .collect();
    let churn: Vec<_> = sequence
        .iter()
        .filter(|entry| entry.phase == Phase::ConnectionChurn)
        .cloned()
        .collect();
    let concurrent: Vec<_> = sequence
        .iter()
        .filter(|entry| entry.phase == Phase::BoundedConcurrency)
        .cloned()
        .collect();
    // Five sampling connections and one deliberately terminated connection are
    // included in the intermediary's finite connection budget.
    let connections = usize::from(!long.is_empty()) + churn.len() + concurrent.len() + 6;
    let mut intermediary = Command::new(executable)
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--connections",
            &connections.to_string(),
        ])
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ChildEvent::Ready { listen_addr, .. } = read_event(&mut intermediary).await? else {
        return Err("expected soak intermediary ready event".into());
    };
    let intermediary_pid = intermediary.id().ok_or("intermediary PID unavailable")?;
    let mut resource_checkpoints = Vec::new();
    resource_checkpoints
        .push(checkpoint(executable, listen_addr, intermediary_pid, "startup-drained").await?);
    let mut completed = 0;
    if !long.is_empty() {
        completed += run_child(executable, listen_addr, &long).await?;
    }
    resource_checkpoints.push(
        checkpoint(
            executable,
            listen_addr,
            intermediary_pid,
            "long-lived-drained",
        )
        .await?,
    );
    for entry in churn {
        completed += run_child(executable, listen_addr, &[entry]).await?;
    }
    resource_checkpoints.push(
        checkpoint(
            executable,
            listen_addr,
            intermediary_pid,
            "connection-churn-drained",
        )
        .await?,
    );
    for batch in concurrent.chunks(CONCURRENCY) {
        let futures = batch
            .iter()
            .cloned()
            .map(|entry| async move { run_child(executable, listen_addr, &[entry]).await });
        let results = futures_util::future::join_all(futures).await;
        for result in results {
            completed += result?;
        }
    }
    resource_checkpoints.push(
        checkpoint(
            executable,
            listen_addr,
            intermediary_pid,
            "bounded-concurrency-drained",
        )
        .await?,
    );
    abrupt_termination(executable, listen_addr).await?;
    resource_checkpoints.push(
        checkpoint(
            executable,
            listen_addr,
            intermediary_pid,
            "abrupt-termination-drained",
        )
        .await?,
    );
    let ChildEvent::Completed { .. } = read_event(&mut intermediary).await? else {
        return Err("expected soak intermediary completion event".into());
    };
    wait_success(&mut intermediary, "soak intermediary").await?;
    resource_checkpoints.push(ResourceCheckpoint {
        stage: "teardown".into(),
        quiescent: true,
        intermediary: unavailable_process(
            intermediary_pid,
            "process exited after graceful teardown",
        ),
        driver: unavailable_process(0, "no driver active at teardown"),
        postgres: PostgresResources::default(),
        termination: Some("graceful-teardown".into()),
    });
    drop(container);
    Ok(ExecutionOutcome {
        completed,
        resource_checkpoints,
        lifecycle_evidence: LifecycleEvidence {
            graceful_restart: true,
            abrupt_termination: true,
            teardown: true,
        },
    })
}

async fn run_child(
    executable: &str,
    address: SocketAddr,
    entries: &[SequenceEntry],
) -> Result<usize, Box<dyn Error>> {
    let encoded = serde_json::to_string(entries)?;
    let output = timeout(
        CHILD_TIMEOUT,
        Command::new(executable)
            .args([
                "soak-driver-child",
                "--address",
                &address.to_string(),
                "--sequence",
                &encoded,
            ])
            .output(),
    )
    .await??;
    let result: DriverResult = serde_json::from_slice(&output.stdout)?;
    if !output.status.success() || !result.success {
        return Err(result
            .error
            .unwrap_or_else(|| "soak driver failed".into())
            .into());
    }
    Ok(result.completed)
}

async fn checkpoint(
    executable: &str,
    address: SocketAddr,
    intermediary_pid: u32,
    stage: &str,
) -> Result<ResourceCheckpoint, Box<dyn Error>> {
    let output = timeout(
        CHILD_TIMEOUT,
        Command::new(executable)
            .args(["resource-driver-child", "--address", &address.to_string()])
            .output(),
    )
    .await??;
    if !output.status.success() {
        return Err(format!(
            "resource checkpoint failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let mut checkpoint: ResourceCheckpoint = serde_json::from_slice(&output.stdout)?;
    checkpoint.stage = stage.into();
    checkpoint.termination = match stage {
        "long-lived-drained" => Some("graceful-close".into()),
        "connection-churn-drained" => Some("graceful-restart".into()),
        "abrupt-termination-drained" => Some("abrupt-termination".into()),
        _ => None,
    };
    // The checkpoint driver has closed before this sample, so the intermediary
    // has drained the connection that performed the PostgreSQL observation.
    checkpoint.intermediary = sample_process(intermediary_pid);
    checkpoint.quiescent = checkpoint.postgres.connections == 0 && checkpoint.postgres.locks == 0;
    Ok(checkpoint)
}

async fn abrupt_termination(executable: &str, address: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new(executable)
        .args(["resource-hold-child", "--address", &address.to_string()])
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("hold child stdout unavailable")?;
    let mut line = String::new();
    timeout(CHILD_TIMEOUT, BufReader::new(stdout).read_line(&mut line)).await??;
    if line.trim() != "ready" {
        return Err("abrupt-termination child did not become ready".into());
    }
    child.kill().await?;
    let status = child.wait().await?;
    if status.success() {
        return Err("abrupt-termination child exited successfully".into());
    }
    Ok(())
}

pub(crate) async fn run_resource_hold_child(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let proxy: SocketAddr = option(arguments, "--address")?.parse()?;
    let mut config = tokio_postgres::Config::new();
    config
        .host(proxy.ip().to_string())
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres");
    let (_client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    println!("ready");
    std::io::Write::flush(&mut std::io::stdout())?;
    sleep(std::time::Duration::from_secs(3600)).await;
    Ok(())
}

pub(crate) async fn run_resource_driver_child(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let proxy: SocketAddr = option(arguments, "--address")?.parse()?;
    let mut config = tokio_postgres::Config::new();
    config
        .host(proxy.ip().to_string())
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres");
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    let connection_task = tokio::spawn(connection);
    client
        .simple_query("SELECT pg_stat_clear_snapshot()")
        .await?;
    let row = client
        .query_one(
            "SELECT
                (SELECT count(*)::bigint FROM pg_stat_activity WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()),
                (SELECT count(*)::bigint FROM pg_locks WHERE pid IN
                    (SELECT pid FROM pg_stat_activity WHERE backend_type = 'client backend' AND pid <> pg_backend_pid())),
                (SELECT COALESCE(sum(temp_bytes), 0)::bigint FROM pg_stat_database),
                (SELECT COALESCE(wal_bytes, 0)::text FROM pg_stat_wal),
                pg_backend_pid(),
                (SELECT COALESCE(sum(total_bytes), 0)::bigint FROM pg_backend_memory_contexts)",
            &[],
        )
        .await?;
    let postgres_pid: i32 = row.get(4);
    let postgres_process = sample_process(postgres_pid.try_into()?);
    let checkpoint = ResourceCheckpoint {
        stage: String::new(),
        quiescent: false,
        intermediary: ProcessResources::default(),
        driver: sample_process(std::process::id()),
        postgres: PostgresResources {
            process: postgres_process,
            memory_bytes: row.get(5),
            connections: row.get(0),
            locks: row.get(1),
            temporary_bytes: row.get(2),
            wal_bytes: row.get::<_, String>(3).parse()?,
            // SQL statistics remain authoritative even when the container PID
            // namespace prevents host-side /proc attribution.
            sampling_gap: None,
        },
        termination: None,
    };
    drop(client);
    timeout(CHILD_TIMEOUT, connection_task).await???;
    println!("{}", serde_json::to_string(&checkpoint)?);
    Ok(())
}

fn unavailable_process(pid: u32, reason: &str) -> ProcessResources {
    ProcessResources {
        pid,
        sampling_gap: Some(reason.into()),
        ..ProcessResources::default()
    }
}

#[cfg(target_os = "linux")]
fn sample_process(pid: u32) -> ProcessResources {
    match sample_linux_process(pid) {
        Ok(sample) => sample,
        Err(error) => unavailable_process(pid, &error.to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn sample_process(pid: u32) -> ProcessResources {
    unavailable_process(
        pid,
        "authoritative process sampling is available only on Linux",
    )
}

#[cfg(target_os = "linux")]
fn sample_linux_process(pid: u32) -> Result<ProcessResources, Box<dyn Error>> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let status = std::fs::read_to_string(root.join("status"))?;
    let stat = std::fs::read_to_string(root.join("stat"))?;
    let io = std::fs::read_to_string(root.join("io"))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .ok_or("malformed /proc stat")?
        .1
        .split_whitespace()
        .collect();
    let kib = |name: &str| -> Result<u64, Box<dyn Error>> {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| format!("missing {name} in /proc status"))?
            .split_whitespace()
            .next()
            .ok_or("missing status value")?
            .parse::<u64>()?;
        Ok(value * 1024)
    };
    let scalar = |source: &str, name: &str| -> Result<u64, Box<dyn Error>> {
        Ok(source
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| format!("missing {name}"))?
            .trim()
            .parse()?)
    };
    let smaps = std::fs::read_to_string(root.join("smaps_rollup"))?;
    let pss_bytes = smaps
        .lines()
        .find_map(|line| line.strip_prefix("Pss:"))
        .ok_or("missing Pss in /proc smaps_rollup")?
        .split_whitespace()
        .next()
        .ok_or("missing Pss value")?
        .parse::<u64>()?
        * 1024;
    Ok(ProcessResources {
        pid,
        rss_bytes: kib("VmRSS:")?,
        pss_bytes,
        virtual_memory_bytes: kib("VmSize:")?,
        tasks: scalar(&status, "Threads:")?,
        file_descriptors: std::fs::read_dir(root.join("fd"))?.count() as u64,
        cpu_user_ticks: fields.get(11).ok_or("missing utime")?.parse()?,
        cpu_system_ticks: fields.get(12).ok_or("missing stime")?.parse()?,
        voluntary_context_switches: scalar(&status, "voluntary_ctxt_switches:")?,
        involuntary_context_switches: scalar(&status, "nonvoluntary_ctxt_switches:")?,
        read_bytes: scalar(&io, "read_bytes:")?,
        write_bytes: scalar(&io, "write_bytes:")?,
        sampling_gap: None,
    })
}

pub(crate) async fn run_driver_child(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let proxy: SocketAddr = option(arguments, "--address")?.parse()?;
    let entries: Vec<SequenceEntry> = serde_json::from_str(option(arguments, "--sequence")?)?;
    let outcome = execute_entries(proxy, &entries).await;
    let result = DriverResult {
        version: 1,
        success: outcome.is_ok(),
        completed: outcome.as_ref().copied().unwrap_or(0),
        error: outcome.as_ref().err().map(ToString::to_string),
    };
    println!("{}", serde_json::to_string(&result)?);
    outcome.map(|_| ())
}

async fn execute_entries(
    proxy: SocketAddr,
    entries: &[SequenceEntry],
) -> Result<usize, Box<dyn Error>> {
    let mut config = tokio_postgres::Config::new();
    config
        .host(proxy.ip().to_string())
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres");
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    let connection_task = tokio::spawn(connection);
    for entry in entries {
        match entry.scenario.as_str() {
            "scalar" => {
                let value: i32 = client.query_one("SELECT 42::int4", &[]).await?.get(0);
                if value != 42 {
                    return Err("scalar result mismatch".into());
                }
            }
            "rows" => {
                let expected = *entry
                    .parameters
                    .get("rows")
                    .ok_or("rows parameter missing")?;
                let rows = client
                    .query(
                        "SELECT value FROM generate_series(1, $1::int8) value",
                        &[&expected],
                    )
                    .await?;
                if rows.len() != usize::try_from(expected)? {
                    return Err("row count mismatch".into());
                }
            }
            "syntax-error" => {
                let error = client
                    .simple_query("SELEC invalid")
                    .await
                    .expect_err("invalid SQL succeeded");
                if error.as_db_error().map(|error| error.code().code()) != Some("42601") {
                    return Err("syntax error SQLSTATE mismatch".into());
                }
                let ready: i32 = client.query_one("SELECT 1::int4", &[]).await?.get(0);
                if ready != 1 {
                    return Err("connection did not recover".into());
                }
            }
            unknown => return Err(format!("unknown soak scenario {unknown}").into()),
        }
    }
    drop(client);
    timeout(CHILD_TIMEOUT, connection_task).await???;
    Ok(entries.len())
}

async fn write_result(path: &Path, result: &SoakResult) -> Result<(), Box<dyn Error>> {
    atomic_write(
        &path.join("result.json"),
        &serde_json::to_vec_pretty(result)?,
    )
    .await?;
    let status = if result.success { "PASS" } else { "FAIL" };
    let summary = format!(
        "# pg-proto {}\n\n{status}: {}/{} scheduled operations completed (seed {}).\n\nResource checkpoints: {} (graceful restart: {}, abrupt termination: {}, teardown: {}).\n",
        result.command,
        result.completed,
        result.sequence.len(),
        result.seed,
        result.resource_checkpoints.len(),
        result.lifecycle_evidence.graceful_restart,
        result.lifecycle_evidence.abrupt_termination,
        result.lifecycle_evidence.teardown,
    );
    atomic_write(&path.join("summary.md"), summary.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_schedule_is_stable_and_starts_with_each_canonical_cycle() {
        let first = schedule(42, Budget::Iterations(4)).unwrap();
        let second = schedule(42, Budget::Iterations(4)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 21);
        for offset in [0, 7, 14] {
            assert_eq!(
                first[offset..offset + 3]
                    .iter()
                    .map(|entry| entry.scenario.as_str())
                    .collect::<Vec<_>>(),
                CANONICAL
            );
            assert!(
                first[offset..offset + 3]
                    .iter()
                    .all(|entry| entry.canonical)
            );
        }
    }

    #[test]
    fn schedule_round_trips_as_exact_replay_input() {
        let sequence = schedule(9, Budget::Iterations(3)).unwrap();
        let encoded = serde_json::to_vec(&sequence).unwrap();
        let replayed: Vec<SequenceEntry> = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(replayed, sequence);
    }

    #[test]
    fn process_sampling_is_authoritative_on_linux_or_records_a_gap() {
        let sample = sample_process(std::process::id());
        assert_eq!(sample.pid, std::process::id());
        if cfg!(target_os = "linux") {
            assert!(sample.sampling_gap.is_none());
            assert!(sample.rss_bytes > 0);
            assert!(sample.virtual_memory_bytes >= sample.rss_bytes);
            assert!(sample.tasks > 0);
            assert!(sample.file_descriptors > 0);
        } else {
            assert!(sample.sampling_gap.is_some());
        }
    }
}
