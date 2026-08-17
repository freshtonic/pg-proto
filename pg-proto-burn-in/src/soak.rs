use std::{
    collections::BTreeMap,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
const EXPECTED_FAILURE_BUDGET: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ScenarioId {
    Scalar,
    Rows,
    SyntaxError,
}

struct ScenarioDefinition {
    id: ScenarioId,
    weight: u64,
    prerequisites: &'static [&'static str],
    expected_coverage: &'static [&'static str],
    assertions: &'static [&'static str],
    postgres_versions: &'static str,
    replay_parameters: &'static [&'static str],
}

const SCENARIOS: [ScenarioDefinition; 3] = [
    ScenarioDefinition {
        id: ScenarioId::Scalar,
        weight: 3,
        prerequisites: &["authenticated-ready-session"],
        expected_coverage: &[
            "backend.Ready.Parse",
            "backend.ParseResponse.Complete",
            "backend.Building.Describe",
            "backend.DescribeResponse.ParameterDescription",
            "backend.DescribeResponse.RowDescription",
            "backend.Building.Bind",
            "backend.BindResponse.Complete",
            "backend.Building.Execute",
            "backend.ExecuteResponse.Continue",
            "backend.ExecuteResponse.CommandComplete",
            "backend.Building.Sync",
            "backend.SyncResponse.Ready",
        ],
        assertions: &["value-equals-42"],
        postgres_versions: "14-18",
        replay_parameters: &["expected"],
    },
    ScenarioDefinition {
        id: ScenarioId::Rows,
        weight: 2,
        prerequisites: &["authenticated-ready-session"],
        expected_coverage: &[
            "backend.Ready.Parse",
            "backend.ParseResponse.Complete",
            "backend.Building.Describe",
            "backend.DescribeResponse.ParameterDescription",
            "backend.DescribeResponse.RowDescription",
            "backend.Building.Bind",
            "backend.BindResponse.Complete",
            "backend.Building.Execute",
            "backend.ExecuteResponse.Continue",
            "backend.ExecuteResponse.CommandComplete",
            "backend.Building.Sync",
            "backend.SyncResponse.Ready",
        ],
        assertions: &["row-count-equals-rows-parameter"],
        postgres_versions: "14-18",
        replay_parameters: &["rows"],
    },
    ScenarioDefinition {
        id: ScenarioId::SyntaxError,
        weight: 1,
        prerequisites: &["authenticated-ready-session"],
        expected_coverage: &[
            "backend.Ready.Query",
            "backend.Simple.Error",
            "backend.SimpleError.Ready",
        ],
        assertions: &["sqlstate-42601", "connection-recovers"],
        postgres_versions: "14-18",
        replay_parameters: &[],
    },
];

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ScenarioMetadata {
    id: ScenarioId,
    weight: u64,
    prerequisites: Vec<String>,
    expected_coverage: Vec<String>,
    assertions: Vec<String>,
    postgres_versions: String,
    replay_parameters: Vec<String>,
}

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
    scenario: ScenarioId,
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
    scenario_catalogue: Vec<ScenarioMetadata>,
    admission_policy: AdmissionPolicy,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure: Option<FailureEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reproduced_failure: Option<bool>,
    #[serde(default)]
    resource_gates: ResourceGates,
    #[serde(default)]
    trace_policy: TracePolicy,
    #[serde(default)]
    recent_trace: Vec<TraceEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure_bundle: Option<FailureBundle>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AdmissionPolicy {
    expected_failure_budget: usize,
    expected_failure_action: String,
    invariant_failure_action: String,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            expected_failure_budget: EXPECTED_FAILURE_BUDGET,
            expected_failure_action: "continue-until-budget-exhausted".into(),
            invariant_failure_action: "stop-admission-immediately".into(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct TracePolicy {
    mode: String,
    capacity: usize,
    payloads: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TraceEntry {
    ordinal: usize,
    phase: Phase,
    scenario: String,
    parameter_names: Vec<String>,
    parameters: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FailureBundle {
    seed: u64,
    scenario_prefix: Vec<TraceEntry>,
    configuration: FailureConfiguration,
    coverage: Vec<String>,
    resource_stages: Vec<String>,
    recent_trace: Vec<TraceEntry>,
    child_logs: Vec<String>,
    replay_command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FailureConfiguration {
    budget: Budget,
    max_concurrency: usize,
    payload_capture: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FailureEvidence {
    kind: String,
    fingerprint: String,
    message: String,
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ResourceGates {
    authoritative: bool,
    passed: bool,
    baseline_stage: String,
    checked_stages: usize,
    intermediary_task_growth: u64,
    intermediary_descriptor_growth: u64,
    postgres_connections_after_drain: i64,
    postgres_locks_after_drain: i64,
    gaps: Vec<String>,
}

struct ExecutionOutcome {
    completed: usize,
    resource_checkpoints: Vec<ResourceCheckpoint>,
    lifecycle_evidence: LifecycleEvidence,
}

struct RecordRequest<'a> {
    artifacts: &'a Path,
    seed: u64,
    budget: Budget,
    command: &'a str,
    reduced_from: Option<usize>,
    expected_failure: Option<FailureEvidence>,
    payload_capture: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct DriverResult {
    version: u32,
    success: bool,
    completed: usize,
    expected_failures: Vec<String>,
    admission_stopped: bool,
    error: Option<String>,
}

struct DriverExecution {
    completed: usize,
    admission: FailureAdmission,
}

#[derive(Default)]
struct FailureAdmission {
    expected_failures: Vec<String>,
    stopped: bool,
}

impl FailureAdmission {
    fn record_expected(&mut self, failure: String) {
        self.expected_failures.push(failure);
        self.stopped = self.expected_failures.len() > EXPECTED_FAILURE_BUDGET;
    }

    fn stop_for_invariant(&mut self) {
        self.stopped = true;
    }
}

pub(crate) async fn run_soak(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let seed = option(arguments, "--seed")?.parse()?;
    let budget = parse_budget(arguments)?;
    let artifacts = PathBuf::from(option(arguments, "--output-dir")?);
    let payload_capture = arguments
        .iter()
        .any(|argument| argument == "--capture-payloads");
    let sequence = if let Some(path) = optional_option(arguments, "--schedule") {
        serde_json::from_slice(&tokio::fs::read(path).await?)?
    } else {
        schedule(seed, budget.clone())?
    };
    execute_and_record(
        arguments.first().ok_or("missing executable path")?,
        sequence,
        RecordRequest {
            artifacts: &artifacts,
            seed,
            budget,
            command: "soak",
            reduced_from: None,
            expected_failure: None,
            payload_capture,
        },
    )
    .await
}

pub(crate) async fn run_replay(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let input = PathBuf::from(option(arguments, "--input")?);
    let artifacts = PathBuf::from(option(arguments, "--output-dir")?);
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
    let original_failure = original.failure.clone();
    let sequence = original.sequence;
    let exact = execute_and_record(
        arguments.first().ok_or("missing executable path")?,
        sequence.clone(),
        RecordRequest {
            artifacts: &artifacts,
            seed: original.seed,
            budget: original.budget.clone(),
            command: "replay",
            reduced_from: None,
            expected_failure: original_failure,
            payload_capture: original.trace_policy.payloads,
        },
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
        scenario_catalogue: scenario_catalogue(),
        admission_policy: AdmissionPolicy::default(),
        sequence: reduced.clone(),
        completed: 0,
        success: false,
        replay_command: "pg-proto-burn-in replay --input reduction.json --output-dir replay".into(),
        reduced_from: Some(original_len),
        resource_checkpoints: Vec::new(),
        lifecycle_evidence: LifecycleEvidence::default(),
        failure: None,
        reproduced_failure: None,
        resource_gates: ResourceGates::default(),
        trace_policy: TracePolicy::default(),
        recent_trace: Vec::new(),
        failure_bundle: None,
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
    if let Budget::DurationSeconds(value) = budget {
        return duration_schedule(seed, usize::try_from(value)?);
    }
    let Budget::Iterations(value) = budget else {
        unreachable!()
    };
    let weighted_per_phase = usize::try_from(value)?;
    let mut rng = StableRng(seed);
    let mut entries = Vec::new();
    for phase in [
        Phase::LongLived,
        Phase::ConnectionChurn,
        Phase::BoundedConcurrency,
    ] {
        for scenario in &SCENARIOS {
            push_entry(&mut entries, phase.clone(), scenario.id, true, &mut rng);
        }
        for _ in 0..weighted_per_phase {
            let scenario = weighted_scenario(rng.next());
            push_entry(&mut entries, phase.clone(), scenario, false, &mut rng);
        }
    }
    Ok(entries)
}

fn duration_schedule(seed: u64, slots: usize) -> Result<Vec<SequenceEntry>, Box<dyn Error>> {
    if slots == 0 {
        return Err("--duration-seconds must be positive".into());
    }
    let mut rng = StableRng(seed);
    let mut entries = Vec::with_capacity(slots);
    let phases = [
        Phase::LongLived,
        Phase::ConnectionChurn,
        Phase::BoundedConcurrency,
    ];
    for (phase_index, phase) in phases.into_iter().enumerate() {
        let phase_slots = slots / 3 + usize::from(phase_index < slots % 3);
        for slot in 0..phase_slots {
            let canonical_scenario = SCENARIOS.get(slot);
            let canonical = canonical_scenario.is_some();
            let scenario = canonical_scenario
                .map(|definition| definition.id)
                .unwrap_or_else(|| weighted_scenario(rng.next()));
            push_entry(&mut entries, phase.clone(), scenario, canonical, &mut rng);
        }
    }
    Ok(entries)
}

fn push_entry(
    entries: &mut Vec<SequenceEntry>,
    phase: Phase,
    scenario: ScenarioId,
    canonical: bool,
    rng: &mut StableRng,
) {
    let mut parameters = BTreeMap::new();
    if scenario == ScenarioId::Rows {
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
        scenario,
        canonical,
        parameters,
    });
}

fn weighted_scenario(random: u64) -> ScenarioId {
    let total = SCENARIOS
        .iter()
        .map(|scenario| scenario.weight)
        .sum::<u64>();
    let mut selected = random % total;
    for scenario in &SCENARIOS {
        if selected < scenario.weight {
            return scenario.id;
        }
        selected -= scenario.weight;
    }
    unreachable!("scenario weights are non-empty and positive")
}

fn scenario_name(scenario: ScenarioId) -> &'static str {
    match scenario {
        ScenarioId::Scalar => "scalar",
        ScenarioId::Rows => "rows",
        ScenarioId::SyntaxError => "syntax-error",
    }
}

fn scenario_catalogue() -> Vec<ScenarioMetadata> {
    SCENARIOS
        .iter()
        .map(|definition| ScenarioMetadata {
            id: definition.id,
            weight: definition.weight,
            prerequisites: definition
                .prerequisites
                .iter()
                .map(|value| (*value).into())
                .collect(),
            expected_coverage: definition
                .expected_coverage
                .iter()
                .map(|value| (*value).into())
                .collect(),
            assertions: definition
                .assertions
                .iter()
                .map(|value| (*value).into())
                .collect(),
            postgres_versions: definition.postgres_versions.into(),
            replay_parameters: definition
                .replay_parameters
                .iter()
                .map(|value| (*value).into())
                .collect(),
        })
        .collect()
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
        if execute(executable, &sequence[..candidate], None)
            .await
            .is_err()
        {
            failing_prefix = candidate;
        } else {
            passing_prefix = candidate;
        }
    }
    sequence[..failing_prefix].to_vec()
}

async fn execute_and_record(
    executable: &str,
    sequence: Vec<SequenceEntry>,
    request: RecordRequest<'_>,
) -> Result<(), Box<dyn Error>> {
    tokio::fs::create_dir_all(request.artifacts).await?;
    let pace = match request.budget {
        Budget::DurationSeconds(seconds) => Some(std::time::Duration::from_secs_f64(
            seconds as f64 / sequence.len() as f64,
        )),
        Budget::Iterations(_) => None,
    };
    let outcome = execute(executable, &sequence, pace).await;
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
    let resource_gates = evaluate_resource_gates(&resource_checkpoints);
    let gate_failure = outcome.is_ok() && !resource_gates.passed;
    let failure = outcome
        .as_ref()
        .err()
        .map(|error| classify_failure(error.as_ref()))
        .or_else(|| gate_failure.then(|| resource_gate_failure(&resource_gates)));
    let reproduced_failure = request
        .expected_failure
        .as_ref()
        .map(|expected| failure.as_ref() == Some(expected));
    let trace_policy = TracePolicy {
        mode: if request.payload_capture {
            "diagnostic".into()
        } else {
            "redacted".into()
        },
        capacity: 64,
        payloads: request.payload_capture,
    };
    let full_trace = trace_entries(&sequence, request.payload_capture);
    let recent_trace = full_trace
        .iter()
        .rev()
        .take(trace_policy.capacity)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let replay_command =
        "pg-proto-burn-in replay --input result.json --output-dir replay".to_owned();
    let failure_bundle = failure.as_ref().map(|_| FailureBundle {
        seed: request.seed,
        scenario_prefix: full_trace
            .iter()
            .take(completed.saturating_add(1).min(full_trace.len()))
            .cloned()
            .collect(),
        configuration: FailureConfiguration {
            budget: request.budget.clone(),
            max_concurrency: CONCURRENCY,
            payload_capture: request.payload_capture,
        },
        // Transition coverage remains owned by conformance artifacts; do not invent soak IDs.
        coverage: Vec::new(),
        resource_stages: resource_checkpoints
            .iter()
            .map(|checkpoint| checkpoint.stage.clone())
            .collect(),
        recent_trace: recent_trace.clone(),
        child_logs: vec!["child diagnostics redacted; correlate with failure fingerprint".into()],
        replay_command: replay_command.clone(),
    });
    let result = SoakResult {
        schema_version: 1,
        command: request.command.into(),
        seed: request.seed,
        budget: request.budget,
        max_concurrency: CONCURRENCY,
        scenario_catalogue: scenario_catalogue(),
        admission_policy: AdmissionPolicy::default(),
        sequence: redact_sensitive_sequence(sequence),
        completed,
        success: outcome.is_ok() && !gate_failure,
        replay_command,
        reduced_from: request.reduced_from,
        resource_checkpoints,
        lifecycle_evidence,
        failure,
        reproduced_failure,
        resource_gates,
        trace_policy,
        recent_trace,
        failure_bundle,
    };
    write_result(request.artifacts, &result).await?;
    if gate_failure {
        Err("resource-growth: a quiescent resource gate failed".into())
    } else {
        outcome.map(|_| ())
    }
}

fn trace_entries(sequence: &[SequenceEntry], payload_capture: bool) -> Vec<TraceEntry> {
    sequence
        .iter()
        .map(|entry| TraceEntry {
            ordinal: entry.ordinal,
            phase: entry.phase.clone(),
            scenario: scenario_name(entry.scenario).into(),
            parameter_names: entry.parameters.keys().cloned().collect(),
            parameters: if payload_capture {
                entry
                    .parameters
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            if sensitive_name(name) {
                                "<redacted>".into()
                            } else {
                                value.to_string()
                            },
                        )
                    })
                    .collect()
            } else {
                BTreeMap::new()
            },
        })
        .collect()
}

fn redact_sensitive_sequence(mut sequence: Vec<SequenceEntry>) -> Vec<SequenceEntry> {
    for entry in &mut sequence {
        for (name, value) in &mut entry.parameters {
            if sensitive_name(name) {
                *value = 0;
            }
        }
    }
    sequence
}

fn sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "password",
        "secret",
        "credential",
        "tls",
        "cancellation",
        "token",
    ]
    .iter()
    .any(|sensitive| name.contains(sensitive))
}

fn evaluate_resource_gates(checkpoints: &[ResourceCheckpoint]) -> ResourceGates {
    let operational: Vec<_> = checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.stage != "teardown")
        .collect();
    let Some(baseline) = operational.first() else {
        return ResourceGates {
            gaps: vec!["no quiescent resource checkpoints were recorded".into()],
            ..ResourceGates::default()
        };
    };
    let checked = &operational[1..];
    let mut gaps = Vec::new();
    for checkpoint in &operational {
        if let Some(gap) = &checkpoint.intermediary.sampling_gap {
            gaps.push(format!("{}: {gap}", checkpoint.stage));
        }
    }
    let authoritative = gaps.is_empty();
    let intermediary_task_growth = checked
        .iter()
        .map(|checkpoint| {
            checkpoint
                .intermediary
                .tasks
                .saturating_sub(baseline.intermediary.tasks)
        })
        .max()
        .unwrap_or(0);
    let intermediary_descriptor_growth = checked
        .iter()
        .map(|checkpoint| {
            checkpoint
                .intermediary
                .file_descriptors
                .saturating_sub(baseline.intermediary.file_descriptors)
        })
        .max()
        .unwrap_or(0);
    let postgres_connections_after_drain = operational
        .iter()
        .map(|checkpoint| checkpoint.postgres.connections)
        .max()
        .unwrap_or_default();
    let postgres_locks_after_drain = operational
        .iter()
        .map(|checkpoint| checkpoint.postgres.locks)
        .max()
        .unwrap_or_default();
    let passed = postgres_connections_after_drain == 0
        && postgres_locks_after_drain == 0
        && (!authoritative
            || (intermediary_task_growth == 0 && intermediary_descriptor_growth == 0));
    ResourceGates {
        authoritative,
        passed,
        baseline_stage: baseline.stage.clone(),
        checked_stages: checked.len(),
        intermediary_task_growth,
        intermediary_descriptor_growth,
        postgres_connections_after_drain,
        postgres_locks_after_drain,
        gaps,
    }
}

fn resource_gate_failure(gates: &ResourceGates) -> FailureEvidence {
    let message = format!(
        "resource-growth: tasks +{}, descriptors +{}, PostgreSQL connections {}, locks {}",
        gates.intermediary_task_growth,
        gates.intermediary_descriptor_growth,
        gates.postgres_connections_after_drain,
        gates.postgres_locks_after_drain,
    );
    classify_failure(&message)
}

fn classify_failure(error: &dyn std::fmt::Display) -> FailureEvidence {
    let raw_message = error.to_string();
    let kind = if raw_message.starts_with("assertion-mismatch:") {
        "assertion-mismatch"
    } else if raw_message.starts_with("resource-growth:") {
        "resource-growth"
    } else {
        "execution-error"
    }
    .to_owned();
    let message = if matches!(kind.as_str(), "assertion-mismatch" | "resource-growth") {
        raw_message.clone()
    } else {
        "execution details redacted; use the fingerprint and child logs for diagnosis".into()
    };
    FailureEvidence {
        kind,
        fingerprint: Sha256::digest(raw_message.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        message,
    }
}

fn optional_option<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .map(String::as_str)
}

async fn execute(
    executable: &str,
    sequence: &[SequenceEntry],
    pace: Option<std::time::Duration>,
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
    // Five sampling connections, one deliberately terminated connection, and
    // one final graceful teardown connection are included in the
    // intermediary's finite connection budget. Keeping teardown distinct
    // prevents the last checkpoint from racing process exit on Linux.
    let connections = usize::from(!long.is_empty()) + churn.len() + concurrent.len() + 7;
    let mut intermediary = Command::new(executable)
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--connections",
            &connections.to_string(),
            "--allow-abrupt-disconnects",
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
        completed += run_child(executable, listen_addr, &long, pace).await?;
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
        completed += run_child(executable, listen_addr, &[entry], pace).await?;
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
        let futures = batch.iter().cloned().map(|entry| {
            let batch_pace = pace.map(|value| value * u32::try_from(batch.len()).unwrap());
            async move { run_child(executable, listen_addr, &[entry], batch_pace).await }
        });
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
    run_child(executable, listen_addr, &[], None).await?;
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
    pace: Option<std::time::Duration>,
) -> Result<usize, Box<dyn Error>> {
    let encoded = serde_json::to_string(entries)?;
    let mut arguments = vec![
        "soak-driver-child".to_owned(),
        "--address".to_owned(),
        address.to_string(),
        "--sequence".to_owned(),
        encoded,
    ];
    if let Some(pace) = pace {
        arguments.push("--pace-millis".into());
        arguments.push(pace.as_millis().to_string());
    }
    let child_timeout = pace
        .and_then(|value| value.checked_mul(u32::try_from(entries.len()).ok()?))
        .unwrap_or_default()
        .saturating_add(CHILD_TIMEOUT);
    let output = timeout(
        child_timeout,
        Command::new(executable).args(arguments).output(),
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
    let pace = option(arguments, "--pace-millis")
        .ok()
        .map(str::parse::<u64>)
        .transpose()?
        .map(std::time::Duration::from_millis);
    let outcome = execute_entries(proxy, &entries, pace).await;
    let expected_failures = outcome
        .as_ref()
        .map(|execution| execution.admission.expected_failures.clone())
        .unwrap_or_default();
    let admission_stopped = outcome
        .as_ref()
        .map(|execution| execution.admission.stopped)
        .unwrap_or(true);
    let recoverable_failure = expected_failures.first().cloned();
    let result = DriverResult {
        version: 1,
        success: outcome.is_ok() && recoverable_failure.is_none(),
        completed: outcome
            .as_ref()
            .map(|execution| execution.completed)
            .unwrap_or(0),
        expected_failures,
        admission_stopped,
        error: outcome
            .as_ref()
            .err()
            .map(ToString::to_string)
            .or(recoverable_failure),
    };
    println!("{}", serde_json::to_string(&result)?);
    match outcome {
        Ok(execution) if execution.admission.expected_failures.is_empty() => Ok(()),
        Ok(execution) => Err(execution.admission.expected_failures[0].clone().into()),
        Err(error) => Err(error),
    }
}

async fn execute_entries(
    proxy: SocketAddr,
    entries: &[SequenceEntry],
    pace: Option<std::time::Duration>,
) -> Result<DriverExecution, Box<dyn Error>> {
    let mut config = tokio_postgres::Config::new();
    config
        .host(proxy.ip().to_string())
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres");
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    let connection_task = tokio::spawn(connection);
    let mut completed = 0;
    let mut admission = FailureAdmission::default();
    for entry in entries {
        match entry.scenario {
            ScenarioId::Scalar => {
                let value: i32 = client.query_one("SELECT 42::int4", &[]).await?.get(0);
                let expected = entry.parameters.get("expected").copied().unwrap_or(42);
                if i64::from(value) != expected {
                    admission.record_expected(format!(
                        "assertion-mismatch: scalar expected {expected}, got {value}"
                    ));
                    if admission.stopped {
                        break;
                    }
                    continue;
                }
            }
            ScenarioId::Rows => {
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
                    admission.record_expected("assertion-mismatch: row count mismatch".into());
                    if admission.stopped {
                        break;
                    }
                    continue;
                }
            }
            ScenarioId::SyntaxError => {
                let error = client
                    .simple_query("SELEC invalid")
                    .await
                    .expect_err("invalid SQL succeeded");
                if error.as_db_error().map(|error| error.code().code()) != Some("42601") {
                    admission.stop_for_invariant();
                    return Err("syntax error SQLSTATE mismatch".into());
                }
                let ready: i32 = client.query_one("SELECT 1::int4", &[]).await?.get(0);
                if ready != 1 {
                    admission.stop_for_invariant();
                    return Err("connection did not recover".into());
                }
            }
        }
        completed += 1;
        if let Some(pace) = pace {
            sleep(pace).await;
        }
    }
    drop(client);
    timeout(CHILD_TIMEOUT, connection_task).await???;
    Ok(DriverExecution {
        completed,
        admission,
    })
}

async fn write_result(path: &Path, result: &SoakResult) -> Result<(), Box<dyn Error>> {
    atomic_write(
        &path.join("result.json"),
        &serde_json::to_vec_pretty(result)?,
    )
    .await?;
    let status = if result.success { "PASS" } else { "FAIL" };
    let summary = format!(
        "# pg-proto {}\n\n{status}: {}/{} scheduled operations completed (seed {}).\n\nFailure: {}. Reproduced captured failure: {}. Failure bundle: {}.\n\nTrace policy: {} (payloads: {}, retained: {}/{}).\n\nResource gates: {} (authoritative: {}, task growth: {}, descriptor growth: {}, PostgreSQL connections: {}, locks: {}).\n\nResource checkpoints: {} (graceful restart: {}, abrupt termination: {}, teardown: {}).\n",
        result.command,
        result.completed,
        result.sequence.len(),
        result.seed,
        result
            .failure
            .as_ref()
            .map_or("none", |failure| failure.kind.as_str()),
        result
            .reproduced_failure
            .map_or("not applicable", |reproduced| if reproduced {
                "yes"
            } else {
                "no"
            }),
        if result.failure_bundle.is_some() {
            "recorded"
        } else {
            "not applicable"
        },
        result.trace_policy.mode,
        result.trace_policy.payloads,
        result.recent_trace.len(),
        result.trace_policy.capacity,
        if result.resource_gates.passed {
            "PASS"
        } else {
            "FAIL"
        },
        result.resource_gates.authoritative,
        result.resource_gates.intermediary_task_growth,
        result.resource_gates.intermediary_descriptor_growth,
        result.resource_gates.postgres_connections_after_drain,
        result.resource_gates.postgres_locks_after_drain,
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
                    .map(|entry| scenario_name(entry.scenario))
                    .collect::<Vec<_>>(),
                ["scalar", "rows", "syntax-error"]
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
    fn duration_schedule_allocates_one_paced_operation_per_second() {
        let sequence = schedule(9, Budget::DurationSeconds(12)).unwrap();
        assert_eq!(sequence.len(), 12);
        assert_eq!(
            sequence
                .iter()
                .filter(|entry| entry.phase == Phase::LongLived)
                .count(),
            4
        );
        assert_eq!(
            sequence
                .iter()
                .filter(|entry| entry.phase == Phase::ConnectionChurn)
                .count(),
            4
        );
        assert_eq!(
            sequence
                .iter()
                .filter(|entry| entry.phase == Phase::BoundedConcurrency)
                .count(),
            4
        );
    }

    #[test]
    fn scenario_registry_is_unique_complete_and_weighted() {
        let catalogue = scenario_catalogue();
        let generated: serde_json::Value =
            serde_json::from_str(include_str!("../catalogue/generated-v1.json")).unwrap();
        let generated = generated["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(catalogue.len(), SCENARIOS.len());
        assert_eq!(SCENARIOS.iter().map(|entry| entry.weight).sum::<u64>(), 6);
        for (index, scenario) in SCENARIOS.iter().enumerate() {
            assert!(scenario.weight > 0);
            assert!(!scenario.prerequisites.is_empty());
            assert!(!scenario.expected_coverage.is_empty());
            assert!(
                scenario
                    .expected_coverage
                    .iter()
                    .all(|id| generated.contains(id)),
                "scenario {} references unknown coverage",
                scenario_name(scenario.id)
            );
            assert!(!scenario.assertions.is_empty());
            assert!(
                SCENARIOS[..index]
                    .iter()
                    .all(|earlier| earlier.id != scenario.id)
            );
        }
    }

    #[test]
    fn expected_failures_are_bounded_but_invariants_stop_immediately() {
        let mut expected = FailureAdmission::default();
        expected.record_expected("first".into());
        expected.record_expected("second".into());
        assert!(!expected.stopped);
        expected.record_expected("third".into());
        assert!(expected.stopped);

        let mut invariant = FailureAdmission::default();
        invariant.stop_for_invariant();
        assert!(invariant.stopped);
        assert!(invariant.expected_failures.is_empty());
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
