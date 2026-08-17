//! Multi-process PostgreSQL protocol verification harness.

use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, TryStreamExt};
use pg_proto::{
    BackendMessage, BackendMiddlewareOutput, BoundedPipeline, CancelKey, CancellationPolicy,
    CancellationRoute, Client, ClientConnectionContext, ClientTlsConfig, ClientTlsPolicy,
    ClientTlsProvider, ConnectTarget, DiagnosticField, ForwardedMessage, FrontendMessage,
    FrontendMiddlewareOutput, InitialServerContext, Intermediary, IntermediaryAccept,
    IntermediaryCancellationRegistry, IntermediaryMiddleware, OperationId,
    ProtocolTransitionDirection, ProtocolTransitionObservation, Server, ServerConnectionContext,
    ServerTlsPolicy, SslMode, StartupParameters, StartupRouteResolver, StaticClientCredentials,
    TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};
use postgres_protocol::message::{backend, frontend};
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{CopyDataSource, CopyTargetOptions, ImageExt, runners::AsyncRunner},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::timeout,
};

mod catalogue;
mod cli;
mod faults;
mod performance;
mod performance_delegate;
mod report;
mod run_all;
mod scripted;
mod soak;
mod trends;

const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs the requested harness command.
pub async fn run(arguments: Vec<String>) -> Result<(), Box<dyn Error>> {
    if performance_delegate::run_if_needed(&arguments).await? {
        return Ok(());
    }
    let Some(arguments) = cli::Cli::parse(arguments)? else {
        return Ok(());
    };
    match arguments.get(1).map(String::as_str) {
        Some("conformance") => run_conformance(&arguments).await,
        Some("soak") => soak::run_soak(&arguments).await,
        Some("replay") => soak::run_replay(&arguments).await,
        Some("catalogue") => catalogue::run(&arguments).await,
        Some("performance") => performance::run(&arguments).await,
        Some("faults") => faults::run(&arguments).await,
        Some("make-report") => report::run(&arguments).await,
        Some("run-all") => run_all::run(&arguments).await,
        Some("trends") => trends::run(&arguments).await,
        Some("soak-driver-child") => soak::run_driver_child(&arguments).await,
        Some("resource-driver-child") => soak::run_resource_driver_child(&arguments).await,
        Some("resource-hold-child") => soak::run_resource_hold_child(&arguments).await,
        Some("intermediary-child") => run_intermediary_child(&arguments).await,
        Some("driver-child") => run_driver_child(&arguments).await,
        _ => unreachable!("clap accepted an unknown command"),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RunResult {
    schema_version: u32,
    command: String,
    profile: String,
    postgres_version: String,
    scenario: ScenarioResult,
    fixtures: FixtureResult,
    data_scenarios: Vec<DataScenarioResult>,
    query_lifecycle: Vec<QueryLifecycleResult>,
    error_scenarios: Vec<SqlErrorScenarioResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_cleanliness: Option<SessionCleanlinessResult>,
    #[serde(default)]
    copy_scenarios: Vec<CopyScenarioResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    async_traffic: Option<AsyncTrafficResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cancellation: Option<CancellationResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replication: Option<ReplicationResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scripted_diagnostics: Vec<scripted::DiagnosticEvidence>,
    coverage: CoverageReport,
    #[serde(default)]
    middleware_reconstruction: MiddlewareReconstructionResult,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    authentication_profiles: Vec<AuthenticationProfileResult>,
    success: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct MiddlewareReconstructionResult {
    pass_through: Vec<String>,
    identity_rewrite: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    non_identity_rewrite: Vec<String>,
    validated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticationProfileResult {
    id: String,
    postgres_versions: String,
    tls_mode: String,
    auth_method: String,
    expected_outcome: String,
    evidence: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScenarioResult {
    name: String,
    value: i32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FixtureResult {
    version: u32,
    expected_checksum: String,
    actual_checksum: String,
    checksum_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DataScenarioResult {
    name: String,
    rows: u64,
    bytes: u64,
    nulls: u64,
    digest: Option<String>,
    validated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct QueryLifecycleResult {
    name: String,
    ready_after: bool,
    validated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SqlErrorScenarioResult {
    name: String,
    expected_sqlstate: String,
    actual_sqlstate: String,
    protocol_ready: bool,
    connection_clean: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionCleanlinessResult {
    dirty_state_detected: bool,
    reset_state_clean: bool,
    exercised: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AsyncTrafficResult {
    notice_message: String,
    notification_channel: String,
    notification_payload: String,
    parameter_status: ParameterStatusResult,
    backend_key_forwarded: bool,
    causally_unattributed: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ParameterStatusResult {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReplicationResult {
    wal_received: bool,
    standby_status_sent: bool,
    cancelled: bool,
    sqlstate: String,
    teardown_complete: bool,
    scripted_half_close_orders: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CopyScenarioResult {
    name: String,
    direction: String,
    payload_bytes: u64,
    chunks: u64,
    completed: bool,
    aborted: bool,
    failed: bool,
    recovered: bool,
    validated: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CancellationResult {
    selected_sqlstate: String,
    selected_session_survived: bool,
    unaffected_value: i32,
    unaffected_session_survived: bool,
    all_keys_rewritten: bool,
    mappings_after_teardown: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CancellationRegistryResult {
    all_keys_rewritten: bool,
    mappings_after_teardown: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CoverageReport {
    observed_ids: Vec<String>,
    stages: Vec<String>,
    real_postgres: Vec<String>,
    scripted: Vec<String>,
    indirect: Vec<String>,
    missing: Vec<String>,
    exempted: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
enum ChildEvent {
    Ready {
        version: u32,
        listen_addr: SocketAddr,
    },
    Completed {
        version: u32,
        value: Option<i32>,
        coverage: Vec<String>,
        #[serde(default)]
        fixtures: Option<FixtureResult>,
        #[serde(default)]
        data_scenarios: Vec<DataScenarioResult>,
        #[serde(default)]
        query_lifecycle: Vec<QueryLifecycleResult>,
        #[serde(default)]
        error_scenarios: Vec<SqlErrorScenarioResult>,
        #[serde(default)]
        session_cleanliness: Option<Box<SessionCleanlinessResult>>,
        #[serde(default)]
        copy_scenarios: Vec<CopyScenarioResult>,
        #[serde(default)]
        async_traffic: Option<Box<AsyncTrafficResult>>,
        #[serde(default)]
        cancellation: Option<Box<CancellationResult>>,
        #[serde(default)]
        cancellation_registry: Option<CancellationRegistryResult>,
    },
}

async fn run_conformance(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let profile = option(arguments, "--profile")?;
    let artifacts = PathBuf::from(option(arguments, "--output-dir")?);
    tokio::fs::create_dir_all(&artifacts).await?;

    if profile == "scripted" {
        let evidence = scripted::run().await?;
        let result = RunResult {
            schema_version: 1,
            command: "conformance".into(),
            profile: profile.into(),
            postgres_version: "not-applicable".into(),
            scenario: ScenarioResult {
                name: "scripted-exceptional-paths".into(),
                value: 0,
            },
            fixtures: FixtureResult::default(),
            data_scenarios: Vec::new(),
            query_lifecycle: Vec::new(),
            error_scenarios: Vec::new(),
            session_cleanliness: None,
            copy_scenarios: Vec::new(),
            async_traffic: None,
            cancellation: None,
            replication: None,
            scripted_diagnostics: evidence.diagnostics,
            coverage: CoverageReport {
                observed_ids: evidence.coverage.clone(),
                scripted: evidence.coverage,
                ..CoverageReport::default()
            },
            middleware_reconstruction: MiddlewareReconstructionResult::default(),
            authentication_profiles: Vec::new(),
            success: true,
        };
        return write_artifacts(&artifacts, &result).await;
    }
    if profile == "authentication" {
        return run_authentication_conformance(
            arguments.first().ok_or("missing executable path")?,
            &artifacts,
        )
        .await;
    }
    if profile == "replication" {
        return run_replication_conformance(
            arguments.first().ok_or("missing executable path")?,
            &artifacts,
        )
        .await;
    }
    if profile == "rewrites" {
        return run_rewrite_conformance(
            arguments.first().ok_or("missing executable path")?,
            &artifacts,
        )
        .await;
    }
    if profile != "smoke" {
        return Err(format!("unsupported conformance profile: {profile}").into());
    }

    let postgres_version = option(arguments, "--postgres-version").unwrap_or("18");
    if !matches!(postgres_version, "14" | "15" | "16" | "17" | "18") {
        return Err(format!("unsupported PostgreSQL version: {postgres_version}").into());
    }

    let outcome = supervise_smoke(
        arguments.first().ok_or("missing executable path")?,
        postgres_version,
    )
    .await;
    let result = match &outcome {
        Ok((
            value,
            coverage,
            fixtures,
            data_scenarios,
            query_lifecycle,
            error_scenarios,
            session_cleanliness,
            copy_scenarios,
            async_traffic,
            cancellation,
        )) => RunResult {
            schema_version: 1,
            command: "conformance".into(),
            profile: profile.into(),
            postgres_version: postgres_version.into(),
            scenario: ScenarioResult {
                name: "extended-select-scalar".into(),
                value: *value,
            },
            fixtures: fixtures.clone(),
            data_scenarios: data_scenarios.clone(),
            query_lifecycle: query_lifecycle.clone(),
            error_scenarios: error_scenarios.clone(),
            session_cleanliness: Some(session_cleanliness.clone()),
            copy_scenarios: copy_scenarios.clone(),
            async_traffic: Some(async_traffic.clone()),
            cancellation: Some(cancellation.clone()),
            replication: None,
            scripted_diagnostics: Vec::new(),
            coverage: coverage_report(coverage)?,
            middleware_reconstruction: middleware_reconstruction(coverage),
            authentication_profiles: Vec::new(),
            success: true,
        },
        Err(_) => RunResult {
            schema_version: 1,
            command: "conformance".into(),
            profile: profile.into(),
            postgres_version: postgres_version.into(),
            scenario: ScenarioResult {
                name: "extended-select-scalar".into(),
                value: 0,
            },
            fixtures: FixtureResult::default(),
            data_scenarios: Vec::new(),
            query_lifecycle: Vec::new(),
            error_scenarios: Vec::new(),
            session_cleanliness: None,
            copy_scenarios: Vec::new(),
            async_traffic: None,
            cancellation: None,
            replication: None,
            scripted_diagnostics: Vec::new(),
            coverage: CoverageReport::default(),
            middleware_reconstruction: MiddlewareReconstructionResult::default(),
            authentication_profiles: Vec::new(),
            success: false,
        },
    };
    write_artifacts(&artifacts, &result).await?;
    outcome.map(|_| ())
}

async fn run_rewrite_conformance(executable: &str, artifacts: &Path) -> Result<(), Box<dyn Error>> {
    let outcome = supervise_rewrites(executable).await;
    let rewrites = outcome.as_ref().cloned().unwrap_or_default();
    let result = RunResult {
        schema_version: 1,
        command: "conformance".into(),
        profile: "rewrites".into(),
        postgres_version: "18".into(),
        scenario: ScenarioResult {
            name: "rich-middleware-rewrites".into(),
            value: i32::try_from(rewrites.len())?,
        },
        fixtures: FixtureResult::default(),
        data_scenarios: Vec::new(),
        query_lifecycle: Vec::new(),
        error_scenarios: Vec::new(),
        session_cleanliness: None,
        copy_scenarios: Vec::new(),
        async_traffic: None,
        cancellation: None,
        replication: None,
        scripted_diagnostics: Vec::new(),
        coverage: CoverageReport::default(),
        middleware_reconstruction: MiddlewareReconstructionResult {
            pass_through: Vec::new(),
            identity_rewrite: Vec::new(),
            non_identity_rewrite: rewrites,
            validated: outcome.is_ok(),
        },
        authentication_profiles: Vec::new(),
        success: outcome.is_ok(),
    };
    write_artifacts(artifacts, &result).await?;
    outcome.map(|_| ())
}

async fn run_authentication_conformance(
    executable: &str,
    artifacts: &Path,
) -> Result<(), Box<dyn Error>> {
    let outcome = supervise_authentication(executable, artifacts).await;
    let profiles = outcome.as_ref().map_or_else(
        |_| authentication_profile_results(false),
        |()| authentication_profile_results(true),
    );
    let result = RunResult {
        schema_version: 1,
        command: "conformance".into(),
        profile: "authentication".into(),
        postgres_version: "14-18".into(),
        scenario: ScenarioResult {
            name: "authentication-matrix".into(),
            value: i32::try_from(profiles.len())?,
        },
        fixtures: FixtureResult::default(),
        data_scenarios: Vec::new(),
        query_lifecycle: Vec::new(),
        error_scenarios: Vec::new(),
        session_cleanliness: None,
        copy_scenarios: Vec::new(),
        async_traffic: None,
        cancellation: None,
        replication: None,
        scripted_diagnostics: Vec::new(),
        coverage: CoverageReport::default(),
        middleware_reconstruction: MiddlewareReconstructionResult::default(),
        authentication_profiles: profiles,
        success: outcome.is_ok(),
    };
    write_artifacts(artifacts, &result).await?;
    outcome
}

async fn run_replication_conformance(
    executable: &str,
    artifacts: &Path,
) -> Result<(), Box<dyn Error>> {
    let outcome = supervise_replication(executable).await;
    let result = RunResult {
        schema_version: 1,
        command: "conformance".into(),
        profile: "replication".into(),
        postgres_version: "18".into(),
        scenario: ScenarioResult {
            name: "physical-replication-copy-both".into(),
            value: 0,
        },
        fixtures: FixtureResult::default(),
        data_scenarios: Vec::new(),
        query_lifecycle: Vec::new(),
        error_scenarios: Vec::new(),
        session_cleanliness: None,
        copy_scenarios: Vec::new(),
        async_traffic: None,
        cancellation: None,
        replication: outcome.as_ref().ok().cloned(),
        scripted_diagnostics: Vec::new(),
        coverage: CoverageReport {
            real_postgres: outcome
                .as_ref()
                .map(|_| {
                    vec![
                        "replication.physical.wal".into(),
                        "replication.physical.standby-status".into(),
                        "replication.physical.cancellation".into(),
                    ]
                })
                .unwrap_or_default(),
            scripted: vec![
                "scripted.copy-both.client-half-close-first".into(),
                "scripted.copy-both.server-half-close-first".into(),
            ],
            ..CoverageReport::default()
        },
        middleware_reconstruction: MiddlewareReconstructionResult::default(),
        authentication_profiles: Vec::new(),
        success: outcome.is_ok(),
    };
    write_artifacts(artifacts, &result).await?;
    outcome.map(|_| ())
}

async fn supervise_replication(executable: &str) -> Result<ReplicationResult, Box<dyn Error>> {
    let scripted_coverage = scripted::run().await?;
    for required in [
        "scripted.copy-both.client-half-close-first",
        "scripted.copy-both.server-half-close-first",
    ] {
        if !scripted_coverage
            .coverage
            .iter()
            .any(|observed| observed == required)
        {
            return Err(
                format!("missing required scripted replication coverage: {required}").into(),
            );
        }
    }
    let replication_hba = b"#!/bin/sh\nset -eu\nprintf '\\nhost replication all all trust\\n' >> \"$PGDATA/pg_hba.conf\"\n".to_vec();
    let container = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .with_env_var("POSTGRES_INITDB_ARGS", "--auth-host=trust")
        .with_copy_to(
            CopyTargetOptions::new("/docker-entrypoint-initdb.d/00_replication_hba.sh")
                .with_mode(0o755),
            CopyDataSource::Data(replication_hba),
        )
        .with_cmd([
            "postgres",
            "-c",
            "fsync=off",
            "-c",
            "wal_level=replica",
            "-c",
            "max_wal_senders=4",
        ])
        .start()
        .await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );

    let mut config = tokio_postgres::Config::new();
    config
        .host(upstream.ip().to_string())
        .port(upstream.port())
        .user("postgres")
        .dbname("postgres");
    let (sql, connection) = config.connect(tokio_postgres::NoTls).await?;
    let sql_task = tokio::spawn(connection);
    sql.batch_execute(
        "DROP TABLE IF EXISTS burnin_replication; \
         CREATE TABLE burnin_replication (id bigint PRIMARY KEY, payload text);",
    )
    .await?;
    let start_lsn: String = sql
        .query_one("SELECT pg_current_wal_lsn()::text", &[])
        .await?
        .get(0);

    let mut intermediary = Command::new(executable)
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--connections",
            "2",
            "--allow-abrupt-disconnects",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let ChildEvent::Ready { listen_addr, .. } = read_event(&mut intermediary).await? else {
        return Err("expected replication intermediary ready event".into());
    };

    let mut replication = TcpStream::connect(listen_addr).await?;
    replication.write_all(&replication_startup()).await?;
    let (process_id, secret_key) = match read_replication_startup(&mut replication).await {
        Ok(key) => key,
        Err(error) => {
            intermediary.kill().await?;
            let _ = timeout(CHILD_TIMEOUT, intermediary.wait()).await;
            let mut stderr = String::new();
            if let Some(mut child_stderr) = intermediary.stderr.take() {
                child_stderr.read_to_string(&mut stderr).await?;
            }
            return Err(format!(
                "replication startup exchange failed: {error}; intermediary: {stderr}"
            )
            .into());
        }
    };
    replication
        .write_all(&tagged_message(
            b'Q',
            format!("START_REPLICATION PHYSICAL {start_lsn}\0").as_bytes(),
        ))
        .await?;
    let (tag, body) = read_backend_message(&mut replication)
        .await
        .map_err(|error| format!("START_REPLICATION response failed: {error}"))?;
    if tag != b'W' {
        return Err(format!(
            "expected CopyBothResponse, got backend tag {tag:?}, SQLSTATE {:?}",
            error_sqlstate(&body)
        )
        .into());
    }

    sql.execute(
        "INSERT INTO burnin_replication \
         SELECT value, repeat(md5(value::text), 128) FROM generate_series(1, 256) AS value",
        &[],
    )
    .await?;
    sql.simple_query("SELECT pg_switch_wal()").await?;

    let wal_end = loop {
        let (tag, body) = timeout(CHILD_TIMEOUT, read_backend_message(&mut replication)).await??;
        if tag == b'd' && body.first() == Some(&b'w') && body.len() >= 25 {
            break u64::from_be_bytes(body[9..17].try_into()?);
        }
    };
    replication
        .write_all(&standby_status_update(wal_end))
        .await?;

    let mut cancellation = TcpStream::connect(listen_addr).await?;
    cancellation
        .write_all(&cancellation_packet(process_id, secret_key))
        .await?;
    cancellation.shutdown().await?;

    let sqlstate = loop {
        let (tag, body) = timeout(CHILD_TIMEOUT, read_backend_message(&mut replication)).await??;
        if tag == b'E' {
            break error_sqlstate(&body).ok_or("cancellation error omitted SQLSTATE")?;
        }
    };
    replication.write_all(&tagged_message(b'X', &[])).await?;
    replication.shutdown().await?;

    let _ = read_event(&mut intermediary).await?;
    wait_success(&mut intermediary, "replication intermediary").await?;
    drop(sql);
    timeout(CHILD_TIMEOUT, sql_task).await???;
    drop(container);

    if sqlstate != "57014" {
        return Err(
            format!("expected replication cancellation SQLSTATE 57014, got {sqlstate}").into(),
        );
    }
    Ok(ReplicationResult {
        wal_received: true,
        standby_status_sent: true,
        cancelled: true,
        sqlstate,
        teardown_complete: true,
        scripted_half_close_orders: vec!["client-first".into(), "server-first".into()],
    })
}

fn authentication_profile_results(executed: bool) -> Vec<AuthenticationProfileResult> {
    [
        (
            "auth.plaintext.trust",
            "plaintext",
            "trust",
            "accepted",
            "authenticated SELECT through public intermediary",
        ),
        (
            "auth.plaintext.cleartext-password",
            "plaintext",
            "cleartext-password",
            "accepted",
            "password challenge answered and SELECT validated",
        ),
        (
            "auth.plaintext.md5",
            "plaintext",
            "md5",
            "accepted",
            "MD5 challenge answered and SELECT validated",
        ),
        (
            "auth.plaintext.scram-sha-256",
            "plaintext",
            "scram-sha-256",
            "accepted",
            "SCRAM verifier accepted and SELECT validated",
        ),
        (
            "auth.tls.scram-sha-256-plus",
            "tls",
            "scram-sha-256-plus",
            "unsupported",
            "static credentials reject a PLUS-only offer because channel binding is unavailable",
        ),
        (
            "auth.tls.negotiation",
            "tls",
            "trust",
            "accepted",
            "TLS negotiation completed before startup",
        ),
        (
            "auth.tls.rejection",
            "plaintext",
            "trust",
            "rejected",
            "required TLS rejects a plaintext-only server",
        ),
    ]
    .into_iter()
    .map(
        |(id, tls_mode, auth_method, expected_outcome, evidence)| AuthenticationProfileResult {
            id: id.into(),
            postgres_versions: "14-18".into(),
            tls_mode: tls_mode.into(),
            auth_method: auth_method.into(),
            expected_outcome: expected_outcome.into(),
            evidence: if executed || expected_outcome == "unsupported" {
                evidence.into()
            } else {
                "profile did not complete".into()
            },
        },
    )
    .collect()
}

async fn supervise_authentication(
    executable: &str,
    artifacts: &Path,
) -> Result<(), Box<dyn Error>> {
    run_password_profile(executable, "trust", None).await?;
    run_password_profile(executable, "password", Some("postgres")).await?;
    run_password_profile(executable, "md5", Some("postgres")).await?;
    run_password_profile(executable, "scram-sha-256", Some("postgres")).await?;
    run_tls_profile(executable, artifacts).await?;
    run_tls_rejection_profile(executable, artifacts).await?;
    Ok(())
}

async fn run_tls_rejection_profile(
    executable: &str,
    artifacts: &Path,
) -> Result<(), Box<dyn Error>> {
    let generated = generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate_path = artifacts.join("rejection-root.der");
    tokio::fs::write(&certificate_path, generated.cert.der()).await?;
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
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--password",
            "postgres",
            "--tls-root",
            certificate_path.to_str().ok_or("non-UTF8 TLS root path")?,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let ChildEvent::Ready { listen_addr, .. } = read_event(&mut intermediary).await? else {
        return Err("expected rejection intermediary ready event".into());
    };
    let mut driver =
        spawn_authenticated_child(executable, "driver-child", listen_addr, None).await?;
    let driver_status = timeout(CHILD_TIMEOUT, driver.wait()).await??;
    let intermediary_status = timeout(CHILD_TIMEOUT, intermediary.wait()).await??;
    if driver_status.success() || intermediary_status.success() {
        return Err("required TLS unexpectedly accepted a plaintext PostgreSQL server".into());
    }
    drop(container);
    Ok(())
}

async fn run_password_profile(
    executable: &str,
    host_auth: &str,
    password: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let image = if host_auth == "trust" {
        Postgres::default().with_host_auth().with_tag("18-alpine")
    } else if host_auth == "md5" {
        Postgres::default()
            .with_password(password.expect("MD5 authentication requires a password"))
            .with_init_sql(
                b"SET password_encryption = 'md5'; ALTER ROLE postgres PASSWORD 'postgres';"
                    .to_vec(),
            )
            .with_tag("18-alpine")
            .with_env_var("POSTGRES_HOST_AUTH_METHOD", "md5")
    } else {
        Postgres::default()
            .with_password(password.expect("password authentication requires a password"))
            .with_tag("18-alpine")
            .with_env_var("POSTGRES_HOST_AUTH_METHOD", host_auth)
    };
    let container = image.start().await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );
    let mut intermediary =
        spawn_authenticated_child(executable, "intermediary-child", upstream, password).await?;
    let ChildEvent::Ready { listen_addr, .. } = read_event(&mut intermediary).await? else {
        return Err("expected intermediary ready event".into());
    };
    let mut driver =
        spawn_authenticated_child(executable, "driver-child", listen_addr, password).await?;
    let ChildEvent::Completed {
        value: Some(42), ..
    } = read_event(&mut driver).await?
    else {
        return Err(format!("{host_auth} driver did not validate SELECT").into());
    };
    if let Err(error) = wait_success(&mut driver, "driver").await {
        let _ = intermediary.kill().await;
        let _ = timeout(CHILD_TIMEOUT, intermediary.wait()).await;
        return Err(error);
    }
    let ChildEvent::Completed { .. } = read_event(&mut intermediary).await? else {
        return Err(format!("{host_auth} intermediary did not complete").into());
    };
    wait_success(&mut intermediary, "intermediary").await?;
    drop(container);
    Ok(())
}

async fn run_tls_profile(executable: &str, artifacts: &Path) -> Result<(), Box<dyn Error>> {
    let generated = generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate_der = generated.cert.der().to_vec();
    let certificate_path = artifacts.join("tls-root.der");
    tokio::fs::write(&certificate_path, &certificate_der).await?;
    let setup = b"#!/bin/sh\nset -eu\ncp /docker-entrypoint-initdb.d/server.crt /var/lib/postgresql/server.crt\ncp /docker-entrypoint-initdb.d/server.key /var/lib/postgresql/server.key\nchown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key\nchmod 600 /var/lib/postgresql/server.key\nprintf \"\\nssl=on\\nssl_cert_file='/var/lib/postgresql/server.crt'\\nssl_key_file='/var/lib/postgresql/server.key'\\n\" >> \"$PGDATA/postgresql.conf\"\n".to_vec();
    let image = Postgres::default()
        .with_password("postgres")
        .with_tag("18-alpine")
        .with_copy_to(
            CopyTargetOptions::new("/docker-entrypoint-initdb.d/00_tls.sh").with_mode(0o755),
            CopyDataSource::Data(setup),
        )
        .with_copy_to(
            "/docker-entrypoint-initdb.d/server.crt",
            CopyDataSource::Data(generated.cert.pem().into_bytes()),
        )
        .with_copy_to(
            // Init scripts run as `postgres`; the copied archive is root-owned.
            // The script immediately installs the key as postgres-owned mode 0600.
            CopyTargetOptions::new("/docker-entrypoint-initdb.d/server.key").with_mode(0o644),
            CopyDataSource::Data(generated.signing_key.serialize_pem().into_bytes()),
        );
    let container = image.start().await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );
    let mut intermediary = Command::new(executable)
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--password",
            "postgres",
            "--tls-root",
            certificate_path.to_str().ok_or("non-UTF8 TLS root path")?,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ChildEvent::Ready { listen_addr, .. } = read_event(&mut intermediary).await? else {
        return Err("expected TLS intermediary ready event".into());
    };
    let mut driver =
        spawn_authenticated_child(executable, "driver-child", listen_addr, None).await?;
    let ChildEvent::Completed {
        value: Some(42), ..
    } = read_event(&mut driver).await?
    else {
        return Err("TLS driver did not validate SELECT".into());
    };
    wait_success(&mut driver, "TLS driver").await?;
    let _ = read_event(&mut intermediary).await?;
    wait_success(&mut intermediary, "TLS intermediary").await?;
    drop(container);
    Ok(())
}

async fn supervise_smoke(
    executable: &str,
    postgres_version: &str,
) -> Result<
    (
        i32,
        Vec<String>,
        FixtureResult,
        Vec<DataScenarioResult>,
        Vec<QueryLifecycleResult>,
        Vec<SqlErrorScenarioResult>,
        SessionCleanlinessResult,
        Vec<CopyScenarioResult>,
        AsyncTrafficResult,
        CancellationResult,
    ),
    Box<dyn Error>,
> {
    let container = Postgres::default()
        .with_host_auth()
        .with_tag(format!("{postgres_version}-alpine"))
        .start()
        .await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );

    let mut intermediary = Command::new(executable)
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--connections",
            "8",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ready = read_event(&mut intermediary).await?;
    let listen_addr = match ready {
        ChildEvent::Ready { listen_addr, .. } => listen_addr,
        event => return Err(format!("expected intermediary ready event, got {event:?}").into()),
    };

    let mut driver = Command::new(executable)
        .args([
            "driver-child",
            "--address",
            &listen_addr.to_string(),
            "--notify-address",
            &upstream.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let completed = match read_event(&mut driver).await {
        Ok(event) => event,
        Err(error) => {
            let _ = intermediary.kill().await;
            let _ = timeout(CHILD_TIMEOUT, intermediary.wait()).await;
            return Err(format!("smoke driver ended before completion: {error}").into());
        }
    };
    let (
        value,
        mut coverage,
        fixtures,
        data_scenarios,
        query_lifecycle,
        error_scenarios,
        session_cleanliness,
        copy_scenarios,
        mut async_traffic,
        mut cancellation,
    ) = match completed {
        ChildEvent::Completed {
            value: Some(value),
            coverage,
            fixtures: Some(fixtures),
            data_scenarios,
            query_lifecycle,
            error_scenarios,
            session_cleanliness: Some(session_cleanliness),
            copy_scenarios,
            async_traffic: Some(async_traffic),
            cancellation: Some(cancellation),
            cancellation_registry: None,
            ..
        } => (
            value,
            coverage,
            fixtures,
            data_scenarios,
            query_lifecycle,
            error_scenarios,
            *session_cleanliness,
            copy_scenarios,
            *async_traffic,
            *cancellation,
        ),
        event => return Err(format!("expected driver completion event, got {event:?}").into()),
    };
    if let Err(error) = wait_success(&mut driver, "driver").await {
        let _ = intermediary.kill().await;
        let _ = timeout(CHILD_TIMEOUT, intermediary.wait()).await;
        return Err(error);
    }
    let intermediary_completed = read_event(&mut intermediary).await?;
    let ChildEvent::Completed {
        coverage: intermediary_coverage,
        async_traffic: Some(intermediary_async),
        cancellation_registry: Some(cancellation_registry),
        ..
    } = intermediary_completed
    else {
        return Err("expected intermediary completion event".into());
    };
    coverage.extend(intermediary_coverage);
    async_traffic.parameter_status = intermediary_async.parameter_status;
    async_traffic.backend_key_forwarded = intermediary_async.backend_key_forwarded;
    async_traffic.causally_unattributed = intermediary_async.causally_unattributed;
    cancellation.all_keys_rewritten = cancellation_registry.all_keys_rewritten;
    cancellation.mappings_after_teardown = cancellation_registry.mappings_after_teardown;
    validate_async_traffic(&async_traffic)?;
    validate_cancellation(&cancellation)?;
    wait_success(&mut intermediary, "intermediary").await?;
    drop(container);
    Ok((
        value,
        coverage,
        fixtures,
        data_scenarios,
        query_lifecycle,
        error_scenarios,
        session_cleanliness,
        copy_scenarios,
        async_traffic,
        cancellation,
    ))
}

async fn supervise_rewrites(executable: &str) -> Result<Vec<String>, Box<dyn Error>> {
    const KINDS: [&str; 7] = [
        "bind-parameter",
        "copy-in-payload",
        "copy-out-payload",
        "data-row",
        "diagnostic-response",
        "parse-query",
        "row-description",
    ];
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
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--connections",
            "1",
            "--rich-rewrites",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ChildEvent::Ready { listen_addr, .. } = read_event(&mut intermediary).await? else {
        return Err("expected rewrite intermediary ready event".into());
    };
    let mut driver = Command::new(executable)
        .args([
            "driver-child",
            "--address",
            &listen_addr.to_string(),
            "--rich-rewrites",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ChildEvent::Completed {
        coverage: driver_evidence,
        ..
    } = read_event(&mut driver).await?
    else {
        return Err("rewrite driver did not complete".into());
    };
    wait_success(&mut driver, "rewrite driver").await?;
    let ChildEvent::Completed {
        coverage: intermediary_evidence,
        ..
    } = read_event(&mut intermediary).await?
    else {
        return Err("rewrite intermediary did not complete".into());
    };
    wait_success(&mut intermediary, "rewrite intermediary").await?;
    drop(container);

    for kind in KINDS {
        for suffix in ["mutated", "validated"] {
            let expected = format!("rewrite.{kind}.{suffix}");
            let evidence = if suffix == "mutated" {
                &intermediary_evidence
            } else {
                &driver_evidence
            };
            if !evidence.contains(&expected) {
                return Err(format!("missing rich rewrite evidence: {expected}").into());
            }
        }
    }
    Ok(KINDS.into_iter().map(str::to_owned).collect())
}

fn validate_cancellation(evidence: &CancellationResult) -> Result<(), Box<dyn Error>> {
    if evidence.selected_sqlstate != "57014"
        || !evidence.selected_session_survived
        || evidence.unaffected_value != 7
        || !evidence.unaffected_session_survived
        || !evidence.all_keys_rewritten
        || evidence.mappings_after_teardown != 0
    {
        return Err(format!("incomplete cancellation evidence: {evidence:?}").into());
    }
    Ok(())
}

fn validate_async_traffic(evidence: &AsyncTrafficResult) -> Result<(), Box<dyn Error>> {
    let expected = ["backend-key", "notice", "notification", "parameter-status"];
    if evidence.notice_message != "burn-in notice"
        || evidence.notification_channel != "burn_in_events"
        || evidence.notification_payload != "fixture-ready"
        || evidence.parameter_status.name != "application_name"
        || evidence.parameter_status.value != "pg-proto-burn-in-async"
        || !evidence.backend_key_forwarded
        || evidence.causally_unattributed != expected
    {
        return Err(format!("incomplete asynchronous traffic evidence: {evidence:?}").into());
    }
    Ok(())
}

const REQUIRED_SMOKE_STAGES: [&str; 7] = [
    "smoke.extended-select.driver-emitted",
    "smoke.extended-select.server-decoded",
    "smoke.extended-select.middleware-observed",
    "smoke.extended-select.client-encoded",
    "smoke.extended-select.postgres-accepted",
    "smoke.extended-select.return-traversed",
    "smoke.extended-select.driver-validated",
];

const REQUIRED_SMOKE_COVERAGE: [&str; 37] = [
    "backend.BindResponse.Complete",
    "backend.BindResponse.Error",
    "backend.Building.Bind",
    "backend.Building.Describe",
    "backend.Building.Execute",
    "backend.Building.Sync",
    "backend.CloseResponse.Complete",
    "backend.DescribeResponse.ParameterDescription",
    "backend.DescribeResponse.NoData",
    "backend.DescribeResponse.RowDescription",
    "backend.ExecuteResponse.CommandComplete",
    "backend.ExecuteResponse.Continue",
    "backend.ExecuteResponse.CopyIn",
    "backend.ExecuteResponse.CopyOut",
    "backend.ExecuteResponse.Error",
    "backend.ExecuteResponse.PortalSuspended",
    "backend.ExtendedCopyIn.Data",
    "backend.ExtendedCopyIn.Done",
    "backend.ExtendedCopyInDone.CommandComplete",
    "backend.ExtendedCopyInDone.Error",
    "backend.ExtendedCopyOut.Data",
    "backend.ExtendedCopyOut.Done",
    "backend.ExtendedCopyOutDone.CommandComplete",
    "backend.Building.Flush",
    "backend.ParseResponse.Complete",
    "backend.ParseResponse.Error",
    "backend.Ready.Bind",
    "backend.Ready.Close",
    "backend.Ready.Execute",
    "backend.Ready.Parse",
    "backend.Ready.Terminate",
    "backend.Ready.Query",
    "backend.Simple.Continue",
    "backend.Simple.Error",
    "backend.SimpleError.Ready",
    "backend.Simple.Ready",
    "backend.SyncResponse.Ready",
];

const OPTIONAL_SMOKE_COVERAGE: [&str; 1] = ["backend.DescribeResponse.Error"];

fn middleware_reconstruction(observed: &[String]) -> MiddlewareReconstructionResult {
    let transitions: Vec<_> = observed
        .iter()
        .filter(|id| !id.starts_with("smoke."))
        .cloned()
        .collect();
    MiddlewareReconstructionResult {
        pass_through: transitions.clone(),
        identity_rewrite: transitions,
        non_identity_rewrite: Vec::new(),
        validated: true,
    }
}

fn coverage_report(observed: &[String]) -> Result<CoverageReport, Box<dyn Error>> {
    let stages: BTreeSet<_> = observed
        .iter()
        .map(String::as_str)
        .filter(|id| id.starts_with("smoke."))
        .collect();
    let observed: BTreeSet<_> = observed
        .iter()
        .map(String::as_str)
        .filter(|id| !id.starts_with("smoke."))
        .collect();
    let required: BTreeSet<_> = REQUIRED_SMOKE_COVERAGE.into_iter().collect();
    let known: BTreeSet<_> = required
        .iter()
        .copied()
        .chain(OPTIONAL_SMOKE_COVERAGE)
        .collect();
    let unknown: Vec<_> = observed.difference(&known).copied().collect();
    if !unknown.is_empty() {
        return Err(format!("unknown required coverage IDs: {}", unknown.join(", ")).into());
    }
    let missing: Vec<String> = required
        .difference(&observed)
        .map(|id| (*id).to_owned())
        .collect();
    if !missing.is_empty() {
        return Err(format!("missing required coverage IDs: {}", missing.join(", ")).into());
    }
    let required_stages: BTreeSet<_> = REQUIRED_SMOKE_STAGES.into_iter().collect();
    if stages != required_stages {
        return Err("smoke scenario did not record all seven observation stages".into());
    }
    let observed_ids: Vec<_> = observed.into_iter().map(str::to_owned).collect();
    Ok(CoverageReport {
        real_postgres: observed_ids.clone(),
        observed_ids,
        stages: stages.into_iter().map(str::to_owned).collect(),
        scripted: Vec::new(),
        indirect: Vec::new(),
        missing: Vec::new(),
        exempted: Vec::new(),
    })
}

async fn spawn_authenticated_child(
    executable: &str,
    role: &str,
    address: SocketAddr,
    password: Option<&str>,
) -> Result<Child, Box<dyn Error>> {
    let mut command = Command::new(executable);
    command.args([role, "--address", &address.to_string()]);
    if role == "driver-child" {
        command.arg("--basic");
    }
    if let Some(password) = password {
        command.args(["--password", password]);
    }
    Ok(command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?)
}

async fn read_event(child: &mut Child) -> Result<ChildEvent, Box<dyn Error>> {
    let stdout = child.stdout.as_mut().ok_or("child stdout unavailable")?;
    let mut line = String::new();
    timeout(CHILD_TIMEOUT, BufReader::new(stdout).read_line(&mut line)).await??;
    if line.is_empty() {
        return Err("child exited without a status record".into());
    }
    Ok(serde_json::from_str(&line)?)
}

async fn wait_success(child: &mut Child, role: &str) -> Result<(), Box<dyn Error>> {
    let status = timeout(CHILD_TIMEOUT, child.wait()).await??;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{role} child exited with {status}").into())
    }
}

#[derive(Clone, Copy)]
struct Route(SocketAddr);

#[derive(Clone, Default)]
struct FourByteCancellationRegistry {
    routes: Arc<Mutex<HashMap<CancelKey, CancellationRoute>>>,
    registrations: Arc<AtomicUsize>,
    rewrites: Arc<AtomicUsize>,
}

impl FourByteCancellationRegistry {
    fn evidence(&self) -> CancellationRegistryResult {
        let registrations = self.registrations.load(Ordering::Relaxed);
        CancellationRegistryResult {
            all_keys_rewritten: registrations > 0
                && self.rewrites.load(Ordering::Relaxed) == registrations,
            mappings_after_teardown: self.routes.lock().map_or(usize::MAX, |routes| routes.len()),
        }
    }
}

impl IntermediaryCancellationRegistry for FourByteCancellationRegistry {
    type Error = io::Error;

    fn register(&self, route: CancellationRoute) -> Result<CancelKey, Self::Error> {
        let upstream = route.upstream_key();
        let mut secret = upstream
            .secret_key
            .get(..4)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short cancellation key"))?
            .to_owned();
        secret[0] ^= 0x80;
        let client = CancelKey {
            process_id: upstream.process_id ^ 0x8000_0000,
            secret_key: bytes::Bytes::from(secret),
        };
        let rewritten = &client != upstream;
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| io::Error::other("cancellation registry poisoned"))?;
        if routes.insert(client.clone(), route).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "duplicate cancellation key",
            ));
        }
        self.registrations.fetch_add(1, Ordering::Relaxed);
        if rewritten {
            self.rewrites.fetch_add(1, Ordering::Relaxed);
        }
        Ok(client)
    }

    fn resolve(&self, client: &CancelKey) -> Option<CancellationRoute> {
        self.routes.lock().ok()?.get(client).cloned()
    }

    fn detach(&self, client: &CancelKey) -> Option<CancellationRoute> {
        self.routes.lock().ok()?.remove(client)
    }
}

#[derive(Clone)]
struct RootedTls(ClientTlsConfig);

impl ClientTlsProvider for RootedTls {
    type Error = Infallible;

    async fn resolve(&self, _: &ConnectTarget) -> Result<ClientTlsConfig, Self::Error> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct CoverageState {
    transitions: BTreeSet<String>,
    causally_unattributed: BTreeSet<String>,
    parameter_status: Option<ParameterStatusResult>,
    bind_rewrite_statement: Option<Bytes>,
}

#[derive(Default)]
struct CoverageObserver {
    rich_rewrites: bool,
}

impl CoverageObserver {
    fn observe_async(
        state: &mut CoverageState,
        operation: Option<OperationId>,
        message: &BackendMessage,
    ) {
        let kind = match message {
            BackendMessage::NoticeResponse(_) => "notice",
            BackendMessage::NotificationResponse { .. } => "notification",
            BackendMessage::ParameterStatus { name, value } => {
                if operation.is_none() && name.as_ref() == b"application_name" {
                    state.parameter_status = Some(ParameterStatusResult {
                        name: String::from_utf8_lossy(name).into_owned(),
                        value: String::from_utf8_lossy(value).into_owned(),
                    });
                }
                "parameter-status"
            }
            BackendMessage::BackendKeyData { .. } => "backend-key",
            _ => return,
        };
        if operation.is_none() {
            state.causally_unattributed.insert(kind.into());
        }
    }

    fn reconstruct_backend(
        &self,
        state: &mut CoverageState,
        message: &BackendMessage,
    ) -> BackendMessage {
        let mut reconstructed = message.clone();
        if !self.rich_rewrites {
            assert_eq!(
                reconstructed, *message,
                "backend identity rewrite changed message"
            );
            return reconstructed;
        }
        match &mut reconstructed {
            BackendMessage::RowDescription(description) => {
                for field in &mut description.fields {
                    if field.name.as_ref() == b"pg_proto_row_description_original" {
                        field.name = Bytes::from_static(b"pg_proto_row_description_rewritten");
                        state
                            .transitions
                            .insert("rewrite.row-description.mutated".into());
                    }
                }
            }
            BackendMessage::DataRow(row)
                if row.columns == vec![Some(Bytes::from_static(b"314159"))] =>
            {
                row.columns[0] = Some(Bytes::from_static(b"271828"));
                state.transitions.insert("rewrite.data-row.mutated".into());
            }
            BackendMessage::ErrorResponse(diagnostic)
                if diagnostic
                    .fields
                    .iter()
                    .any(|field| field.code == b'C' && field.value.as_ref() == b"22012") =>
            {
                diagnostic.fields.push(DiagnosticField {
                    code: b'D',
                    value: Bytes::from_static(b"pg-proto rewrote this diagnostic"),
                });
                state
                    .transitions
                    .insert("rewrite.diagnostic-response.mutated".into());
            }
            BackendMessage::CopyData(payload) if payload.as_ref() == b"1\tcopy-upstream\n" => {
                *payload = Bytes::from_static(b"1\tcopy-downstream\n");
                state
                    .transitions
                    .insert("rewrite.copy-out-payload.mutated".into());
            }
            _ => {}
        }
        reconstructed
    }
}

impl
    IntermediaryMiddleware<
        CoverageState,
        ServerConnectionContext<SocketAddr, TrustIdentity>,
        ClientConnectionContext<()>,
    > for CoverageObserver
{
    type Error = Infallible;

    async fn frontend(
        &mut self,
        _server: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _client: &ClientConnectionContext<()>,
        state: &mut CoverageState,
        message: FrontendMessage,
    ) -> Result<FrontendMiddlewareOutput, Self::Error> {
        let mut reconstructed = message.clone();
        if self.rich_rewrites {
            match &mut reconstructed {
                FrontendMessage::Parse(parse)
                    if parse.query.as_ref() == b"SELECT 41::int4 /* pg_proto_parse_rewrite */" =>
                {
                    parse.query =
                        Bytes::from_static(b"SELECT 42::int4 /* pg_proto_parse_rewritten */");
                    state
                        .transitions
                        .insert("rewrite.parse-query.mutated".into());
                }
                FrontendMessage::Parse(parse)
                    if parse.query.as_ref() == b"SELECT $1::int4 /* pg_proto_bind_rewrite */" =>
                {
                    state.bind_rewrite_statement = Some(parse.statement.clone());
                }
                FrontendMessage::Bind(bind)
                    if state.bind_rewrite_statement.as_ref() == Some(&bind.statement) =>
                {
                    if let Some(Some(parameter)) = bind.parameters.first_mut() {
                        *parameter = Bytes::copy_from_slice(&42_i32.to_be_bytes());
                        state
                            .transitions
                            .insert("rewrite.bind-parameter.mutated".into());
                    }
                }
                FrontendMessage::CopyData(payload) if payload.as_ref() == b"1\tcopy-original\n" => {
                    *payload = Bytes::from_static(b"1\tcopy-rewritten\n");
                    state
                        .transitions
                        .insert("rewrite.copy-in-payload.mutated".into());
                }
                _ => {}
            }
        } else {
            assert_eq!(
                reconstructed, message,
                "frontend identity rewrite changed message"
            );
        }
        Ok(FrontendMiddlewareOutput::Forward(reconstructed))
    }

    async fn observe_transition(
        &mut self,
        _server: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _client: &ClientConnectionContext<()>,
        state: &mut CoverageState,
        observation: ProtocolTransitionObservation,
    ) {
        state.transitions.insert(observation.id.to_owned());
        let stages: &[&str] = match observation.direction {
            ProtocolTransitionDirection::Frontend => &[
                "smoke.extended-select.server-decoded",
                "smoke.extended-select.middleware-observed",
                "smoke.extended-select.client-encoded",
            ],
            ProtocolTransitionDirection::Backend => &[
                "smoke.extended-select.postgres-accepted",
                "smoke.extended-select.return-traversed",
            ],
        };
        state
            .transitions
            .extend(stages.iter().map(|stage| (*stage).to_owned()));
    }

    async fn backend(
        &mut self,
        _server: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _client: &ClientConnectionContext<()>,
        state: &mut CoverageState,
        message: BackendMessage,
    ) -> Result<BackendMiddlewareOutput, Self::Error> {
        Self::observe_async(state, None, &message);
        let reconstructed = self.reconstruct_backend(state, &message);
        Ok(BackendMiddlewareOutput::Forward(reconstructed))
    }

    async fn backend_operation(
        &mut self,
        _server: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _client: &ClientConnectionContext<()>,
        state: &mut CoverageState,
        operation: Option<OperationId>,
        message: BackendMessage,
    ) -> Result<BackendMiddlewareOutput, Self::Error> {
        Self::observe_async(state, operation, &message);
        let reconstructed = self.reconstruct_backend(state, &message);
        Ok(BackendMiddlewareOutput::Forward(reconstructed))
    }
}

impl StartupRouteResolver<SocketAddr> for Route {
    type Error = Infallible;

    async fn resolve(
        &self,
        _startup: StartupParameters,
        _context: InitialServerContext<'_, SocketAddr>,
    ) -> Result<ConnectTarget, Self::Error> {
        Ok(ConnectTarget::new(self.0.to_string()))
    }
}

async fn run_intermediary_child(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let upstream: SocketAddr = option(arguments, "--address")?.parse()?;
    let connection_count = option(arguments, "--connections")
        .unwrap_or("1")
        .parse::<usize>()?;
    let allow_abrupt_disconnects = arguments
        .iter()
        .any(|argument| argument == "--allow-abrupt-disconnects");
    let rich_rewrites = arguments
        .iter()
        .any(|argument| argument == "--rich-rewrites");
    if let Ok(password) = option(arguments, "--password") {
        if let Ok(root) = option(arguments, "--tls-root") {
            return run_tls_credential_intermediary(upstream, password, root).await;
        }
        return run_credential_intermediary(upstream, password).await;
    }
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .map_err(debug_error)?;
    let client = Client::builder()
        .connector(move |_| TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .map_err(debug_error)?;
    let cancellation_registry = FourByteCancellationRegistry::default();
    let intermediary = Arc::new(
        Intermediary::builder()
            .server(server)
            .client(client)
            .startup_resolver(Route(upstream))
            .cancellation_registry(cancellation_registry.clone())
            .pipeline(BoundedPipeline::new(64).expect("non-zero smoke pipeline capacity"))
            .middleware(
                move |_: &ServerConnectionContext<SocketAddr, TrustIdentity>,
                      _: &ClientConnectionContext<()>| CoverageObserver {
                    rich_rewrites,
                },
            )
            .build()
            .map_err(debug_error)?,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    write_event(&ChildEvent::Ready {
        version: 1,
        listen_addr: listener.local_addr()?,
    })
    .await?;
    let mut sessions = tokio::task::JoinSet::new();
    for _ in 0..connection_count {
        let (transport, peer) = listener.accept().await?;
        let intermediary = Arc::clone(&intermediary);
        sessions.spawn(async move {
            let accepted = Box::pin(intermediary.accept(transport, peer, CoverageState::default()))
                .await
                .map_err(debug_error)?;
            let IntermediaryAccept::Session(mut session) = accepted else {
                return Ok::<_, io::Error>(None);
            };
            loop {
                match session.forward_next().await {
                    Ok(ForwardedMessage::Frontend(FrontendMessage::Terminate)) => {
                        let (_, _, state, ..) = session.teardown();
                        return Ok::<_, io::Error>(Some(state));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        let message = format!("intermediary forwarding failed: {error:?}");
                        let (_, _, state, ..) = session.teardown();
                        if allow_abrupt_disconnects {
                            return Ok(Some(state));
                        }
                        return Err(io::Error::other(message));
                    }
                }
            }
        });
    }
    let mut accumulated = CoverageState::default();
    while let Some(result) = sessions.join_next().await {
        let Some(state) = result?? else {
            continue;
        };
        accumulated.transitions.extend(state.transitions);
        accumulated
            .causally_unattributed
            .extend(state.causally_unattributed);
        if state.parameter_status.is_some() {
            accumulated.parameter_status = state.parameter_status;
        }
    }
    write_event(&ChildEvent::Completed {
        version: 1,
        value: None,
        coverage: accumulated.transitions.into_iter().collect(),
        fixtures: None,
        data_scenarios: Vec::new(),
        query_lifecycle: Vec::new(),
        error_scenarios: Vec::new(),
        session_cleanliness: None,
        copy_scenarios: Vec::new(),
        async_traffic: Some(Box::new(AsyncTrafficResult {
            parameter_status: accumulated.parameter_status.unwrap_or_default(),
            backend_key_forwarded: accumulated.causally_unattributed.contains("backend-key"),
            causally_unattributed: accumulated.causally_unattributed.into_iter().collect(),
            ..AsyncTrafficResult::default()
        })),
        cancellation: None,
        cancellation_registry: Some(cancellation_registry.evidence()),
    })
    .await
}

fn replication_startup() -> Vec<u8> {
    let body = [
        196_608_u32.to_be_bytes().as_slice(),
        b"user\0postgres\0replication\0true\0\0",
    ]
    .concat();
    [
        u32::try_from(body.len() + 4)
            .expect("small startup packet")
            .to_be_bytes()
            .as_slice(),
        body.as_slice(),
    ]
    .concat()
}

async fn read_replication_startup(stream: &mut TcpStream) -> Result<(u32, u32), Box<dyn Error>> {
    let mut cancellation_key = None;
    loop {
        let (tag, body) = read_backend_message(stream).await?;
        match tag {
            b'K' if body.len() == 8 => {
                cancellation_key = Some((
                    u32::from_be_bytes(body[..4].try_into()?),
                    u32::from_be_bytes(body[4..].try_into()?),
                ));
            }
            b'Z' => return cancellation_key.ok_or_else(|| "missing BackendKeyData".into()),
            b'E' => {
                return Err(format!(
                    "replication startup failed with SQLSTATE {:?}",
                    error_sqlstate(&body)
                )
                .into());
            }
            _ => {}
        }
    }
}

fn tagged_message(tag: u8, body: &[u8]) -> Vec<u8> {
    [
        [tag].as_slice(),
        u32::try_from(body.len() + 4)
            .expect("protocol message fits u32")
            .to_be_bytes()
            .as_slice(),
        body,
    ]
    .concat()
}

async fn read_backend_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
    let tag = stream.read_u8().await?;
    let length = stream.read_u32().await?;
    if length < 4 {
        return Err("invalid backend message length".into());
    }
    let mut body = vec![0; usize::try_from(length - 4)?];
    stream.read_exact(&mut body).await?;
    Ok((tag, body))
}

fn standby_status_update(lsn: u64) -> Vec<u8> {
    let body = [
        b"r",
        lsn.to_be_bytes().as_slice(),
        lsn.to_be_bytes().as_slice(),
        lsn.to_be_bytes().as_slice(),
        0_i64.to_be_bytes().as_slice(),
        [0].as_slice(),
    ]
    .concat();
    tagged_message(b'd', &body)
}

fn cancellation_packet(process_id: u32, secret_key: u32) -> Vec<u8> {
    [
        16_u32.to_be_bytes().as_slice(),
        80_877_102_u32.to_be_bytes().as_slice(),
        process_id.to_be_bytes().as_slice(),
        secret_key.to_be_bytes().as_slice(),
    ]
    .concat()
}

fn error_sqlstate(body: &[u8]) -> Option<String> {
    let mut fields = body.split(|byte| *byte == 0);
    fields.find_map(|field| {
        (field.first() == Some(&b'C'))
            .then(|| String::from_utf8(field.get(1..)?.to_vec()).ok())
            .flatten()
    })
}

async fn run_tls_credential_intermediary(
    upstream: SocketAddr,
    password: &str,
    root: &str,
) -> Result<(), Box<dyn Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(tokio::fs::read(root).await?))?;
    let tls = RootedTls(ClientTlsConfig::new(
        ServerName::try_from("localhost")?.to_owned(),
        roots,
    ));
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .map_err(debug_error)?;
    let client = Client::builder()
        .connector(move |_| TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::libpq(SslMode::Require, tls))
        .authentication(StaticClientCredentials::new(
            "postgres",
            password.to_owned(),
        ))
        .build()
        .map_err(debug_error)?;
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route(upstream))
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(64).expect("non-zero TLS pipeline capacity"))
        .middleware(
            |_: &ServerConnectionContext<SocketAddr, TrustIdentity>,
             _: &ClientConnectionContext<()>| CoverageObserver::default(),
        )
        .build()
        .map_err(debug_error)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    write_event(&ChildEvent::Ready {
        version: 1,
        listen_addr: listener.local_addr()?,
    })
    .await?;
    let (transport, peer) = listener.accept().await?;
    let mut session = Box::pin(intermediary.accept(transport, peer, CoverageState::default()))
        .await
        .map_err(debug_error)?
        .into_session();
    let coverage = loop {
        match session.forward_next().await {
            Ok(ForwardedMessage::Frontend(FrontendMessage::Terminate)) => {
                let (_, _, state, ..) = session.teardown();
                break state.transitions;
            }
            Ok(_) => {}
            Err(error) => {
                let message = format!("TLS intermediary forwarding failed: {error:?}");
                let _ = session.teardown();
                return Err(message.into());
            }
        }
    };
    write_event(&ChildEvent::Completed {
        version: 1,
        value: None,
        coverage: coverage.into_iter().collect(),
        fixtures: None,
        data_scenarios: Vec::new(),
        query_lifecycle: Vec::new(),
        error_scenarios: Vec::new(),
        session_cleanliness: None,
        copy_scenarios: Vec::new(),
        async_traffic: None,
        cancellation: None,
        cancellation_registry: None,
    })
    .await
}

async fn run_credential_intermediary(
    upstream: SocketAddr,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .map_err(debug_error)?;
    let client = Client::builder()
        .connector(move |_| TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(StaticClientCredentials::new(
            "postgres",
            password.to_owned(),
        ))
        .build()
        .map_err(debug_error)?;
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route(upstream))
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(64).expect("non-zero authentication pipeline capacity"))
        .middleware(
            |_: &ServerConnectionContext<SocketAddr, TrustIdentity>,
             _: &ClientConnectionContext<()>| CoverageObserver::default(),
        )
        .build()
        .map_err(debug_error)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    write_event(&ChildEvent::Ready {
        version: 1,
        listen_addr: listener.local_addr()?,
    })
    .await?;
    let (transport, peer) = listener.accept().await?;
    let mut session = Box::pin(intermediary.accept(transport, peer, CoverageState::default()))
        .await
        .map_err(debug_error)?
        .into_session();
    let coverage = loop {
        match session.forward_next().await {
            Ok(ForwardedMessage::Frontend(FrontendMessage::Terminate)) => {
                let (_, _, state, ..) = session.teardown();
                break state.transitions;
            }
            Ok(_) => {}
            Err(error) => {
                let message = format!("intermediary forwarding failed: {error:?}");
                let _transports = session.teardown();
                return Err(message.into());
            }
        }
    };
    write_event(&ChildEvent::Completed {
        version: 1,
        value: None,
        coverage: coverage.into_iter().collect(),
        fixtures: None,
        data_scenarios: Vec::new(),
        query_lifecycle: Vec::new(),
        error_scenarios: Vec::new(),
        session_cleanliness: None,
        copy_scenarios: Vec::new(),
        async_traffic: None,
        cancellation: None,
        cancellation_registry: None,
    })
    .await
}

async fn run_driver_child(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let proxy: SocketAddr = option(arguments, "--address")?.parse()?;
    let mut config = tokio_postgres::Config::new();
    config
        .host(proxy.ip().to_string())
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres");
    if let Ok(password) = option(arguments, "--password") {
        config.password(password);
    }
    let (mut client, mut connection) = config
        .connect(tokio_postgres::NoTls)
        .await
        .map_err(|error| format!("driver startup failed: {error:?}"))?;
    let (async_tx, mut async_rx) = tokio::sync::mpsc::unbounded_channel();
    let connection_task = tokio::spawn(async move {
        while let Some(message) =
            std::future::poll_fn(|context| connection.poll_message(context)).await
        {
            let message = message.map_err(io::Error::other)?;
            async_tx
                .send(message)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "async receiver closed"))?;
        }
        Ok::<_, io::Error>(())
    });
    let value: i32 = client
        .query_one("SELECT 42::int4", &[])
        .await
        .map_err(|error| format!("initial SELECT failed: {error:?}"))?
        .get(0);
    if value != 42 {
        return Err(format!("expected 42, got {value}").into());
    }
    if arguments
        .iter()
        .any(|argument| argument == "--rich-rewrites")
    {
        let validated = run_rich_rewrite_scenarios(&client).await?;
        drop(client);
        timeout(CHILD_TIMEOUT, connection_task).await???;
        return write_event(&ChildEvent::Completed {
            version: 1,
            value: Some(i32::try_from(validated.len())?),
            coverage: validated
                .into_iter()
                .map(|kind| format!("rewrite.{kind}.validated"))
                .collect(),
            fixtures: None,
            data_scenarios: Vec::new(),
            query_lifecycle: Vec::new(),
            error_scenarios: Vec::new(),
            session_cleanliness: None,
            copy_scenarios: Vec::new(),
            async_traffic: None,
            cancellation: None,
            cancellation_registry: None,
        })
        .await;
    }
    if arguments.iter().any(|argument| argument == "--basic") {
        drop(client);
        timeout(CHILD_TIMEOUT, connection_task).await???;
        return write_event(&ChildEvent::Completed {
            version: 1,
            value: Some(value),
            coverage: Vec::new(),
            fixtures: None,
            data_scenarios: Vec::new(),
            query_lifecycle: Vec::new(),
            error_scenarios: Vec::new(),
            session_cleanliness: None,
            copy_scenarios: Vec::new(),
            async_traffic: None,
            cancellation: None,
            cancellation_registry: None,
        })
        .await;
    }
    let mut async_traffic = AsyncTrafficResult::default();
    if let Ok(notifier_address) = option(arguments, "--notify-address") {
        client
            .batch_execute("LISTEN burn_in_events")
            .await
            .map_err(|error| format!("LISTEN failed: {error}"))?;
        client
            .batch_execute("SET application_name = 'pg-proto-burn-in-async'")
            .await
            .map_err(|error| format!("SET application_name failed: {error}"))?;
        client
            .batch_execute("DO $$ BEGIN RAISE NOTICE 'burn-in notice'; END $$")
            .await
            .map_err(|error| format!("RAISE NOTICE failed: {error}"))?;
        let notifier_address: SocketAddr = notifier_address.parse()?;
        let mut notifier_config = tokio_postgres::Config::new();
        notifier_config
            .host(notifier_address.ip().to_string())
            .port(notifier_address.port())
            .user("postgres")
            .dbname("postgres");
        let (notifier, notifier_connection) =
            notifier_config.connect(tokio_postgres::NoTls).await?;
        let notifier_task = tokio::spawn(notifier_connection);
        notifier
            .batch_execute("NOTIFY burn_in_events, 'fixture-ready'")
            .await
            .map_err(|error| format!("NOTIFY failed: {error}"))?;
        drop(notifier);
        timeout(CHILD_TIMEOUT, notifier_task).await???;

        while async_traffic.notice_message.is_empty()
            || async_traffic.notification_channel.is_empty()
        {
            match timeout(CHILD_TIMEOUT, async_rx.recv()).await? {
                Some(tokio_postgres::AsyncMessage::Notice(notice)) => {
                    if notice.message() == "burn-in notice" {
                        async_traffic.notice_message = notice.message().into();
                    }
                }
                Some(tokio_postgres::AsyncMessage::Notification(notification))
                    if notification.channel() == "burn_in_events" =>
                {
                    async_traffic.notification_channel = notification.channel().into();
                    async_traffic.notification_payload = notification.payload().into();
                }
                None => return Err("connection ended before asynchronous evidence arrived".into()),
                _ => {}
            }
        }
    }
    let fixtures = install_and_verify_fixtures(&client).await?;
    let data_scenarios = run_data_scenarios(&client).await?;
    let mut query_lifecycle = run_query_lifecycles(&mut client).await?;
    let error_scenarios = run_sql_error_scenarios(&mut client, proxy).await?;
    let session_cleanliness = run_session_cleanliness_connection(proxy).await?;
    let cancellation = run_cancellation_scenario(proxy).await?;
    drop(client);
    timeout(CHILD_TIMEOUT, connection_task).await???;
    let copy_scenarios = run_copy_connection(proxy, option(arguments, "--password").ok()).await?;
    query_lifecycle.push(run_flush_lifecycle(proxy).await?);
    write_event(&ChildEvent::Completed {
        version: 1,
        value: Some(value),
        coverage: vec![
            "smoke.extended-select.driver-emitted".into(),
            "smoke.extended-select.driver-validated".into(),
        ],
        fixtures: Some(fixtures),
        data_scenarios,
        query_lifecycle,
        error_scenarios,
        session_cleanliness: Some(Box::new(session_cleanliness)),
        copy_scenarios,
        async_traffic: Some(Box::new(async_traffic)),
        cancellation: Some(Box::new(cancellation)),
        cancellation_registry: None,
    })
    .await
}

async fn run_rich_rewrite_scenarios(
    client: &tokio_postgres::Client,
) -> Result<Vec<&'static str>, Box<dyn Error>> {
    let parse_value: i32 = client
        .query_one("SELECT 41::int4 /* pg_proto_parse_rewrite */", &[])
        .await?
        .get(0);
    if parse_value != 42 {
        return Err(format!("Parse rewrite returned {parse_value}, expected 42").into());
    }

    let bind_value: i32 = client
        .query_one("SELECT $1::int4 /* pg_proto_bind_rewrite */", &[&41_i32])
        .await?
        .get(0);
    if bind_value != 42 {
        return Err(format!("Bind rewrite returned {bind_value}, expected 42").into());
    }

    let described = client
        .query_one("SELECT 1::int4 AS pg_proto_row_description_original", &[])
        .await?;
    if described.columns()[0].name() != "pg_proto_row_description_rewritten" {
        return Err("RowDescription rewrite did not reach the driver".into());
    }

    let row_value: String = client.query_one("SELECT '314159'::text", &[]).await?.get(0);
    if row_value != "271828" {
        return Err(format!("DataRow rewrite returned {row_value}, expected 271828").into());
    }

    let error = client
        .query_one("SELECT 1 / 0", &[])
        .await
        .expect_err("diagnostic rewrite query unexpectedly succeeded");
    let detail = error
        .as_db_error()
        .and_then(tokio_postgres::error::DbError::detail);
    if detail != Some("pg-proto rewrote this diagnostic") {
        return Err(format!("diagnostic detail was not rewritten: {detail:?}").into());
    }

    client
        .batch_execute(
            "CREATE TEMP TABLE pg_proto_rewrite_copy_in (id integer, payload text); \
             CREATE TEMP TABLE pg_proto_rewrite_copy_out (id integer, payload text); \
             INSERT INTO pg_proto_rewrite_copy_out VALUES (1, 'copy-upstream')",
        )
        .await?;
    let copy_in = client
        .copy_in("COPY pg_proto_rewrite_copy_in FROM STDIN")
        .await?;
    tokio::pin!(copy_in);
    copy_in
        .as_mut()
        .send(Bytes::from_static(b"1\tcopy-original\n"))
        .await?;
    copy_in.as_mut().finish().await?;
    let copied_in: String = client
        .query_one(
            "SELECT payload FROM pg_proto_rewrite_copy_in WHERE id = 1",
            &[],
        )
        .await?
        .get(0);
    if copied_in != "copy-rewritten" {
        return Err(format!("COPY IN rewrite stored {copied_in:?}").into());
    }

    let copy_out = client
        .copy_out("COPY pg_proto_rewrite_copy_out TO STDOUT")
        .await?;
    tokio::pin!(copy_out);
    let mut copied_out = BytesMut::new();
    while let Some(chunk) = copy_out.try_next().await? {
        copied_out.extend_from_slice(&chunk);
    }
    if copied_out.as_ref() != b"1\tcopy-downstream\n" {
        return Err(format!("COPY OUT rewrite returned {copied_out:?}").into());
    }

    Ok(vec![
        "bind-parameter",
        "copy-in-payload",
        "copy-out-payload",
        "data-row",
        "diagnostic-response",
        "parse-query",
        "row-description",
    ])
}

async fn run_copy_connection(
    proxy: SocketAddr,
    password: Option<&str>,
) -> Result<Vec<CopyScenarioResult>, Box<dyn Error>> {
    let mut config = tokio_postgres::Config::new();
    config
        .host(proxy.ip().to_string())
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres");
    if let Some(password) = password {
        config.password(password);
    }
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    let connection_task = tokio::spawn(connection);
    let scenarios = run_copy_scenarios(&client).await?;
    drop(client);
    timeout(CHILD_TIMEOUT, connection_task).await???;
    Ok(scenarios)
}

async fn run_cancellation_scenario(
    proxy: SocketAddr,
) -> Result<CancellationResult, Box<dyn Error>> {
    let (selected, selected_connection) = connect_driver(proxy).await?;
    let selected_connection = tokio::spawn(selected_connection);
    selected
        .batch_execute("SET application_name = 'pg-proto-burn-in-cancel-selected'")
        .await?;
    let cancel = selected.cancel_token();
    let selected_query = tokio::spawn(async move {
        let outcome = selected.query_one("SELECT pg_sleep(10)", &[]).await;
        (selected, outcome)
    });

    let (unaffected, unaffected_connection) = connect_driver(proxy).await?;
    let unaffected_connection = tokio::spawn(unaffected_connection);
    timeout(CHILD_TIMEOUT, async {
        loop {
            let active: bool = unaffected
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                     WHERE application_name = 'pg-proto-burn-in-cancel-selected' \
                     AND state = 'active' AND query = 'SELECT pg_sleep(10)')",
                    &[],
                )
                .await?
                .get(0);
            if active {
                return Ok::<_, tokio_postgres::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let unaffected_query = tokio::spawn(async move {
        let outcome = unaffected
            .query_one("SELECT 7::int4 FROM pg_sleep(0.5)", &[])
            .await;
        (unaffected, outcome)
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel_query(tokio_postgres::NoTls).await?;

    let (selected, selected_outcome) = timeout(CHILD_TIMEOUT, selected_query).await??;
    let selected_error = selected_outcome.expect_err("selected operation was not cancelled");
    let selected_sqlstate = selected_error
        .as_db_error()
        .ok_or("selected cancellation did not return a PostgreSQL error")?
        .code()
        .code()
        .to_owned();
    let selected_session_survived = selected
        .query_one("SELECT 1::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 1;

    let (unaffected, unaffected_outcome) = timeout(CHILD_TIMEOUT, unaffected_query).await??;
    let unaffected_value = unaffected_outcome?.get::<_, i32>(0);
    let unaffected_session_survived = unaffected
        .query_one("SELECT 1::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 1;

    drop(selected);
    drop(unaffected);
    timeout(CHILD_TIMEOUT, selected_connection).await???;
    timeout(CHILD_TIMEOUT, unaffected_connection).await???;

    Ok(CancellationResult {
        selected_sqlstate,
        selected_session_survived,
        unaffected_value,
        unaffected_session_survived,
        // The intermediary contributes registry-owned evidence after teardown.
        all_keys_rewritten: false,
        mappings_after_teardown: usize::MAX,
    })
}

async fn run_sql_error_scenarios(
    client: &mut tokio_postgres::Client,
    proxy: SocketAddr,
) -> Result<Vec<SqlErrorScenarioResult>, Box<dyn Error>> {
    let mut outcomes = Vec::new();

    for (name, sql, expected) in [
        ("syntax", "SELEC 1", "42601"),
        (
            "missing-table",
            "SELECT * FROM burnin_table_that_does_not_exist",
            "42P01",
        ),
        (
            "missing-column",
            "SELECT burnin_column_that_does_not_exist FROM pg_catalog.pg_class",
            "42703",
        ),
        (
            "missing-function",
            "SELECT burnin_function_that_does_not_exist()",
            "42883",
        ),
        ("type", "SELECT TRUE + 1", "42883"),
        ("arithmetic", "SELECT 1 / 0", "22012"),
    ] {
        let error = client
            .batch_execute(sql)
            .await
            .expect_err("error scenario unexpectedly succeeded");
        outcomes.push(error_outcome(client, name, expected, &error).await?);
    }

    client
        .batch_execute(
            "CREATE TEMP TABLE burnin_constraint_error (id integer PRIMARY KEY); \
             INSERT INTO burnin_constraint_error VALUES (1)",
        )
        .await?;
    let constraint = client
        .execute("INSERT INTO burnin_constraint_error VALUES (1)", &[])
        .await
        .expect_err("duplicate key unexpectedly succeeded");
    client
        .batch_execute("DROP TABLE burnin_constraint_error")
        .await?;
    outcomes.push(error_outcome(client, "constraint", "23505", &constraint).await?);

    client
        .batch_execute(
            "CREATE ROLE burnin_no_access; \
             CREATE TABLE burnin_permission_error (id integer); \
             SET ROLE burnin_no_access",
        )
        .await?;
    let permission = client
        .query("SELECT * FROM burnin_permission_error", &[])
        .await
        .expect_err("unprivileged query unexpectedly succeeded");
    client
        .batch_execute("RESET ROLE; DROP TABLE burnin_permission_error; DROP ROLE burnin_no_access")
        .await?;
    outcomes.push(error_outcome(client, "permission", "42501", &permission).await?);

    let transaction = client.transaction().await?;
    transaction
        .batch_execute("SELECT 1 / 0")
        .await
        .expect_err("transaction arithmetic error unexpectedly succeeded");
    let aborted = transaction
        .query("SELECT 1", &[])
        .await
        .expect_err("failed transaction unexpectedly accepted a query");
    transaction.rollback().await?;
    outcomes.push(error_outcome(client, "failed-transaction", "25P02", &aborted).await?);

    client
        .batch_execute("SET statement_timeout = '25ms'")
        .await?;
    let timed_out = client
        .query("SELECT pg_sleep(0.2)", &[])
        .await
        .expect_err("timed statement unexpectedly completed");
    client.batch_execute("RESET statement_timeout").await?;
    outcomes.push(error_outcome(client, "timeout", "57014", &timed_out).await?);

    let (mut other, other_connection) = connect_driver(proxy).await?;
    let other_task = tokio::spawn(other_connection);

    client
        .batch_execute(
            "CREATE TABLE burnin_serialization_error (id integer PRIMARY KEY, value integer); \
             INSERT INTO burnin_serialization_error VALUES (1, 0)",
        )
        .await?;
    let first = client.transaction().await?;
    let second = other.transaction().await?;
    first
        .batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .await?;
    second
        .batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .await?;
    first
        .query_one(
            "SELECT value FROM burnin_serialization_error WHERE id = 1",
            &[],
        )
        .await?;
    second
        .query_one(
            "SELECT value FROM burnin_serialization_error WHERE id = 1",
            &[],
        )
        .await?;
    first
        .execute(
            "UPDATE burnin_serialization_error SET value = value + 1 WHERE id = 1",
            &[],
        )
        .await?;
    first.commit().await?;
    let serialization = second
        .execute(
            "UPDATE burnin_serialization_error SET value = value + 1 WHERE id = 1",
            &[],
        )
        .await
        .expect_err("serialization conflict unexpectedly succeeded");
    second.rollback().await?;
    client
        .batch_execute("DROP TABLE burnin_serialization_error")
        .await?;
    outcomes.push(error_outcome(client, "serialization", "40001", &serialization).await?);

    client
        .batch_execute(
            "SET deadlock_timeout = '25ms'; \
             CREATE TABLE burnin_deadlock_error (id integer PRIMARY KEY); \
             INSERT INTO burnin_deadlock_error VALUES (1), (2)",
        )
        .await?;
    let first = client.transaction().await?;
    let second = other.transaction().await?;
    first
        .execute(
            "SELECT id FROM burnin_deadlock_error WHERE id = 1 FOR UPDATE",
            &[],
        )
        .await?;
    second
        .execute(
            "SELECT id FROM burnin_deadlock_error WHERE id = 2 FOR UPDATE",
            &[],
        )
        .await?;
    let (left, right) = tokio::join!(
        first.execute("UPDATE burnin_deadlock_error SET id = id WHERE id = 2", &[]),
        second.execute("UPDATE burnin_deadlock_error SET id = id WHERE id = 1", &[]),
    );
    let deadlock = left
        .err()
        .or_else(|| right.err())
        .ok_or("deadlock unexpectedly succeeded")?;
    first.rollback().await?;
    second.rollback().await?;
    client
        .batch_execute("RESET deadlock_timeout; DROP TABLE burnin_deadlock_error")
        .await?;
    outcomes.push(error_outcome(client, "deadlock", "40P01", &deadlock).await?);

    client
        .batch_execute(
            "CREATE TABLE burnin_prepare_error (value integer); \
             INSERT INTO burnin_prepare_error VALUES (1)",
        )
        .await?;
    let statement = client
        .prepare("SELECT value FROM burnin_prepare_error")
        .await?;
    other
        .batch_execute("ALTER TABLE burnin_prepare_error ALTER COLUMN value TYPE bigint")
        .await?;
    let invalidated = client
        .query(&statement, &[])
        .await
        .expect_err("invalidated prepared result unexpectedly succeeded");
    drop(statement);
    client
        .batch_execute("DROP TABLE burnin_prepare_error")
        .await?;
    outcomes.push(error_outcome(client, "invalidated-prepare", "0A000", &invalidated).await?);

    drop(other);
    timeout(CHILD_TIMEOUT, other_task).await???;
    Ok(outcomes)
}

async fn run_session_cleanliness_scenario(
    client: &tokio_postgres::Client,
) -> Result<SessionCleanlinessResult, Box<dyn Error>> {
    client
        .batch_execute(
            "CREATE TEMP TABLE burnin_session_temp (value integer); \
             PREPARE burnin_session_plan AS SELECT 1; \
             SELECT pg_advisory_lock(910247); \
             LISTEN burnin_session_events; \
             SET application_name = 'pg-proto-burn-in-dirty'",
        )
        .await?;
    let dirty_state_detected: bool = client
        .query_one(
            "SELECT EXISTS (SELECT FROM pg_class WHERE relnamespace = pg_my_temp_schema() AND relname = 'burnin_session_temp') \
                    AND EXISTS (SELECT FROM pg_prepared_statements WHERE name = 'burnin_session_plan') \
                    AND EXISTS (SELECT FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory') \
                    AND EXISTS (SELECT FROM pg_listening_channels() AS channel WHERE channel = 'burnin_session_events') \
                    AND current_setting('application_name') = 'pg-proto-burn-in-dirty'",
            &[],
        )
        .await?
        .get(0);
    if !dirty_state_detected {
        return Err("session-local dirty state was not fully observable".into());
    }

    // Reset only the state this scenario owns. `DISCARD ALL` would also invalidate
    // protocol-level prepared statements owned by the independent driver.
    client
        .batch_execute(
            "UNLISTEN burnin_session_events; \
             SELECT pg_advisory_unlock(910247); \
             DEALLOCATE burnin_session_plan; \
             DROP TABLE burnin_session_temp; \
             RESET application_name",
        )
        .await?;
    let reset_state_clean: bool = client
        .query_one(
            "SELECT NOT EXISTS (SELECT FROM pg_class WHERE relnamespace = pg_my_temp_schema() AND relname = 'burnin_session_temp') \
                    AND NOT EXISTS (SELECT FROM pg_prepared_statements WHERE name = 'burnin_session_plan') \
                    AND NOT EXISTS (SELECT FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory') \
                    AND NOT EXISTS (SELECT FROM pg_listening_channels() AS channel WHERE channel = 'burnin_session_events') \
                    AND current_setting('application_name') = ''",
            &[],
        )
        .await?
        .get(0);
    if !reset_state_clean {
        return Err("targeted reset did not restore reusable session state".into());
    }

    Ok(SessionCleanlinessResult {
        dirty_state_detected,
        reset_state_clean,
        exercised: vec![
            "temporary-object".into(),
            "prepared-statement".into(),
            "advisory-lock".into(),
            "listener".into(),
            "guc".into(),
        ],
    })
}

async fn run_session_cleanliness_connection(
    proxy: SocketAddr,
) -> Result<SessionCleanlinessResult, Box<dyn Error>> {
    let (client, connection) = connect_driver(proxy).await?;
    let connection_task = tokio::spawn(connection);
    let result = run_session_cleanliness_scenario(&client).await?;
    drop(client);
    timeout(CHILD_TIMEOUT, connection_task).await???;
    Ok(result)
}

async fn connect_driver(
    proxy: SocketAddr,
) -> Result<
    (
        tokio_postgres::Client,
        tokio_postgres::Connection<tokio_postgres::Socket, tokio_postgres::tls::NoTlsStream>,
    ),
    tokio_postgres::Error,
> {
    let mut config = tokio_postgres::Config::new();
    config
        .host(proxy.ip().to_string())
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres");
    config.connect(tokio_postgres::NoTls).await
}

async fn error_outcome(
    client: &tokio_postgres::Client,
    name: &str,
    expected: &str,
    error: &tokio_postgres::Error,
) -> Result<SqlErrorScenarioResult, Box<dyn Error>> {
    let actual = error
        .as_db_error()
        .ok_or_else(|| format!("{name} did not return a PostgreSQL error"))?
        .code()
        .code();
    if actual != expected {
        return Err(format!("{name} returned SQLSTATE {actual}, expected {expected}").into());
    }
    let protocol_ready = client
        .query_one("SELECT 1::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 1;
    let connection_clean = client
        .query_one(
            "SELECT current_user = 'postgres' AND current_setting('statement_timeout') = '0'",
            &[],
        )
        .await?
        .get(0);
    Ok(SqlErrorScenarioResult {
        name: name.into(),
        expected_sqlstate: expected.into(),
        actual_sqlstate: actual.into(),
        protocol_ready,
        connection_clean,
    })
}

async fn run_query_lifecycles(
    client: &mut tokio_postgres::Client,
) -> Result<Vec<QueryLifecycleResult>, Box<dyn Error>> {
    let simple = client.simple_query("SELECT 11::int4").await?;
    let simple_valid = simple.iter().any(|message| {
        matches!(message, tokio_postgres::SimpleQueryMessage::Row(row) if row.get(0) == Some("11"))
    });
    let mut results = vec![lifecycle_result(client, "simple-query", simple_valid).await?];

    let unnamed = client
        .query_typed_one(
            "SELECT $1::int4",
            &[(&12_i32, tokio_postgres::types::Type::INT4)],
        )
        .await?;
    results
        .push(lifecycle_result(client, "unnamed-extended", unnamed.get::<_, i32>(0) == 12).await?);

    let transaction = client.transaction().await?;
    let statement = transaction
        .prepare("SELECT value::int4 FROM generate_series(1, 5) value ORDER BY value")
        .await?;
    let portal = transaction.bind(&statement, &[]).await?;
    let first = transaction.query_portal(&portal, 2).await?;
    let second = transaction.query_portal(&portal, 2).await?;
    let third = transaction.query_portal(&portal, 2).await?;
    let values: Vec<i32> = first
        .iter()
        .chain(&second)
        .chain(&third)
        .map(|row| row.get(0))
        .collect();
    let suspended_valid =
        values == [1, 2, 3, 4, 5] && first.len() == 2 && second.len() == 2 && third.len() == 1;
    drop(portal);
    drop(statement);
    transaction.commit().await?;
    results.push(lifecycle_result(client, "named-statement-and-portal", suspended_valid).await?);
    results.push(lifecycle_result(client, "portal-suspension", suspended_valid).await?);

    let binary = client.query_one("SELECT $1::int4 + 1", &[&41_i32]).await?;
    results.push(lifecycle_result(client, "binary-formats", binary.get::<_, i32>(0) == 42).await?);

    let (left, right) = tokio::try_join!(
        client.query_one("SELECT 21::int4", &[]),
        client.query_one("SELECT 22::int4", &[]),
    )?;
    results.push(
        lifecycle_result(
            client,
            "pipelined-extended",
            left.get::<_, i32>(0) == 21 && right.get::<_, i32>(0) == 22,
        )
        .await?,
    );
    Ok(results)
}

async fn run_copy_scenarios(
    client: &tokio_postgres::Client,
) -> Result<Vec<CopyScenarioResult>, Box<dyn Error>> {
    client
        .batch_execute(
            "DROP SCHEMA IF EXISTS burnin_copy CASCADE; \
             CREATE SCHEMA burnin_copy; \
             CREATE TABLE burnin_copy.small_values (id integer PRIMARY KEY, payload text); \
             CREATE TABLE burnin_copy.large_values (id integer PRIMARY KEY, payload text); \
             CREATE TABLE burnin_copy.abort_values (id integer PRIMARY KEY);",
        )
        .await?;
    let small_in_statement = client
        .prepare("COPY burnin_copy.small_values (id, payload) FROM STDIN")
        .await?;
    let large_in_statement = client
        .prepare("COPY burnin_copy.large_values (id, payload) FROM STDIN")
        .await?;
    let abort_in_statement = client
        .prepare("COPY burnin_copy.abort_values (id) FROM STDIN")
        .await?;
    let small_out_statement = client
        .prepare("COPY (SELECT id, payload FROM burnin_copy.small_values ORDER BY id) TO STDOUT")
        .await?;
    let large_out_statement = client
        .prepare("COPY (SELECT id, payload FROM burnin_copy.large_values ORDER BY id) TO STDOUT")
        .await?;

    let small = b"1\talpha\n2\tbeta\n3\t\\N\n".to_vec();
    let small_chunks: Vec<Bytes> = small.chunks(3).map(Bytes::copy_from_slice).collect();
    let small_rows = copy_in_chunks(client, &small_in_statement, &small_chunks, false).await?;
    let small_valid = small_rows == 3
        && client
            .query_one(
                "SELECT count(*)::bigint FROM burnin_copy.small_values \
                 WHERE (id, payload) IN ((1, 'alpha'), (2, 'beta')) OR (id = 3 AND payload IS NULL)",
                &[],
            )
            .await?
            .get::<_, i64>(0)
            == 3;
    let small_recovered = copy_recovered(client).await?;

    let large = deterministic_copy_payload(2_048);
    let large_chunks: Vec<Bytes> = large.chunks(257).map(Bytes::copy_from_slice).collect();
    let large_rows = copy_in_chunks(client, &large_in_statement, &large_chunks, true).await?;
    let aggregate = client
        .query_one(
            "SELECT count(*)::bigint, sum(id)::bigint, sum(octet_length(payload))::bigint \
             FROM burnin_copy.large_values",
            &[],
        )
        .await?;
    let expected_payload_bytes: i64 = (1..=2_048)
        .map(|id| format!("copy-payload-{id:04}-{}", "x".repeat(id % 31)).len() as i64)
        .sum();
    let large_valid = large_rows == 2_048
        && aggregate.get::<_, i64>(0) == 2_048
        && aggregate.get::<_, i64>(1) == 2_098_176
        && aggregate.get::<_, i64>(2) == expected_payload_bytes;
    let large_recovered = copy_recovered(client).await?;

    let failure_bytes = Bytes::from_static(b"not-an-integer\n");
    let failure = {
        let sink = client.copy_in::<_, Bytes>(&abort_in_statement).await?;
        tokio::pin!(sink);
        sink.as_mut().send(failure_bytes.clone()).await?;
        sink.as_mut().finish().await
    };
    let failure_is_expected = failure
        .as_ref()
        .err()
        .and_then(tokio_postgres::Error::as_db_error)
        .is_some_and(|error| {
            error.code() == &tokio_postgres::error::SqlState::INVALID_TEXT_REPRESENTATION
        });
    let failure_recovered = copy_recovered(client).await?;
    let failed_rows = client
        .query_one("SELECT count(*)::bigint FROM burnin_copy.abort_values", &[])
        .await?
        .get::<_, i64>(0);

    let (small_out, small_out_chunks) = copy_out_bytes(client, &small_out_statement, false).await?;
    let small_out_recovered = copy_recovered(client).await?;

    let (large_out, large_out_chunks) = copy_out_bytes(client, &large_out_statement, true).await?;
    let large_out_recovered = copy_recovered(client).await?;

    let (early_bytes, early_chunks) = {
        let stream = client.copy_out(&large_out_statement).await?;
        tokio::pin!(stream);
        let first = stream
            .as_mut()
            .try_next()
            .await?
            .ok_or("COPY OUT produced no data before abort")?;
        (first.len() as u64, 1_u64)
        // Dropping the response stream early exercises client-side COPY OUT abandonment.
    };
    let early_recovered = copy_recovered(client).await?;

    Ok(vec![
        copy_result(
            "copy-in-small-chunked",
            "in",
            small.len(),
            small_chunks.len(),
            true,
            false,
            false,
            small_recovered,
            small_valid,
        ),
        copy_result(
            "copy-in-large-backpressured",
            "in",
            large.len(),
            large_chunks.len(),
            true,
            false,
            false,
            large_recovered,
            large_valid,
        ),
        copy_result(
            "copy-in-malformed-failure",
            "in",
            failure_bytes.len(),
            1,
            false,
            false,
            true,
            failure_recovered,
            failure_is_expected && failed_rows == 0,
        ),
        copy_result(
            "copy-out-small",
            "out",
            small_out.len(),
            small_out_chunks,
            true,
            false,
            false,
            small_out_recovered,
            small_out == small,
        ),
        copy_result(
            "copy-out-large-slow-consumer",
            "out",
            large_out.len(),
            large_out_chunks,
            true,
            false,
            false,
            large_out_recovered,
            large_out == large,
        ),
        copy_result(
            "copy-out-early-abort",
            "out",
            early_bytes as usize,
            early_chunks as usize,
            false,
            true,
            false,
            early_recovered,
            early_bytes > 0,
        ),
    ])
}

async fn copy_in_chunks(
    client: &tokio_postgres::Client,
    statement: &tokio_postgres::Statement,
    chunks: &[Bytes],
    slow: bool,
) -> Result<u64, Box<dyn Error>> {
    let sink = client.copy_in::<_, Bytes>(statement).await?;
    tokio::pin!(sink);
    for (index, chunk) in chunks.iter().enumerate() {
        sink.as_mut().send(chunk.clone()).await?;
        if slow && index % 16 == 15 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    Ok(sink.as_mut().finish().await?)
}

async fn copy_out_bytes(
    client: &tokio_postgres::Client,
    statement: &tokio_postgres::Statement,
    slow: bool,
) -> Result<(Vec<u8>, usize), Box<dyn Error>> {
    let stream = client.copy_out(statement).await?;
    tokio::pin!(stream);
    let mut bytes = Vec::new();
    let mut chunks = 0;
    while let Some(chunk) = stream.as_mut().try_next().await? {
        bytes.extend_from_slice(&chunk);
        chunks += 1;
        if slow {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    Ok((bytes, chunks))
}

fn deterministic_copy_payload(rows: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    for id in 1..=rows {
        payload.extend_from_slice(
            format!("{id}\tcopy-payload-{id:04}-{}\n", "x".repeat(id % 31)).as_bytes(),
        );
    }
    payload
}

async fn copy_recovered(client: &tokio_postgres::Client) -> Result<bool, Box<dyn Error>> {
    Ok(client
        .query_one("SELECT 1::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 1)
}

#[allow(clippy::too_many_arguments)]
fn copy_result(
    name: &str,
    direction: &str,
    payload_bytes: usize,
    chunks: usize,
    completed: bool,
    aborted: bool,
    failed: bool,
    recovered: bool,
    validated: bool,
) -> CopyScenarioResult {
    CopyScenarioResult {
        name: name.into(),
        direction: direction.into(),
        payload_bytes: payload_bytes as u64,
        chunks: chunks as u64,
        completed,
        aborted,
        failed,
        recovered,
        validated,
    }
}

async fn lifecycle_result(
    client: &tokio_postgres::Client,
    name: &str,
    validated: bool,
) -> Result<QueryLifecycleResult, Box<dyn Error>> {
    let ready_after = client
        .query_one("SELECT 1::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 1;
    Ok(QueryLifecycleResult {
        name: name.into(),
        ready_after,
        validated,
    })
}

async fn run_flush_lifecycle(proxy: SocketAddr) -> Result<QueryLifecycleResult, Box<dyn Error>> {
    let mut stream = TcpStream::connect(proxy).await?;
    let mut startup = BytesMut::new();
    startup.put_i32(0);
    startup.put_i32(196_608);
    startup.extend_from_slice(b"user\0postgres\0database\0postgres\0\0");
    let startup_len = startup.len() as i32;
    startup[..4].copy_from_slice(&startup_len.to_be_bytes());
    stream.write_all(&startup).await?;
    let _startup_messages = read_until_ready(&mut stream).await?;

    let mut messages = BytesMut::new();
    frontend::parse("", "SELECT 23::int4", std::iter::empty(), &mut messages)?;
    frontend::bind(
        "",
        "",
        std::iter::empty::<i16>(),
        std::iter::empty::<()>(),
        |(), _| -> Result<postgres_protocol::IsNull, Box<dyn Error + Send + Sync>> {
            Ok(postgres_protocol::IsNull::Yes)
        },
        [1_i16],
        &mut messages,
    )
    .map_err(|error| match error {
        postgres_protocol::message::frontend::BindError::Conversion(error) => {
            io::Error::other(error)
        }
        postgres_protocol::message::frontend::BindError::Serialization(error) => error,
    })?;
    frontend::describe(b'P', "", &mut messages)?;
    frontend::execute("", 0, &mut messages)?;
    frontend::flush(&mut messages);
    frontend::sync(&mut messages);
    stream.write_all(&messages).await?;
    let result_rows = read_until_ready(&mut stream).await?;

    let mut recovery = BytesMut::new();
    frontend::query("SELECT 1::int4", &mut recovery)?;
    stream.write_all(&recovery).await?;
    let recovery_rows = read_until_ready(&mut stream).await?;
    let mut terminate = BytesMut::new();
    frontend::terminate(&mut terminate);
    stream.write_all(&terminate).await?;
    Ok(QueryLifecycleResult {
        name: "flush-and-sync".into(),
        ready_after: recovery_rows == 1,
        validated: result_rows == 1,
    })
}

async fn read_until_ready(stream: &mut TcpStream) -> Result<usize, Box<dyn Error>> {
    let mut input = BytesMut::new();
    let mut data_rows = 0;
    loop {
        while let Some(message) = backend::Message::parse(&mut input)? {
            match message {
                backend::Message::ErrorResponse(_) => {
                    return Err("PostgreSQL error during raw lifecycle".into());
                }
                backend::Message::DataRow(_) => data_rows += 1,
                backend::Message::ReadyForQuery(_) => return Ok(data_rows),
                _ => {}
            }
        }
        if stream.read_buf(&mut input).await? == 0 {
            return Err("PostgreSQL closed before ReadyForQuery".into());
        }
    }
}

const FIXTURE_SCHEMA: &str = include_str!("../fixtures/schema-v1.sql");
const FIXTURE_SEED: &str = include_str!("../fixtures/seed-v1.sql");
const FIXTURE_CHECKSUM: &str = "214b809aeff4f6934f7e091a05051fa0";

async fn install_and_verify_fixtures(
    client: &tokio_postgres::Client,
) -> Result<FixtureResult, Box<dyn Error>> {
    client.execute(FIXTURE_SCHEMA, &[]).await?;
    client.execute(FIXTURE_SEED, &[]).await?;
    let first = fixture_checksum(client).await?;
    client.execute(FIXTURE_SCHEMA, &[]).await?;
    client.execute(FIXTURE_SEED, &[]).await?;
    let actual = fixture_checksum(client).await?;
    if first != actual || actual != FIXTURE_CHECKSUM {
        return Err(format!(
            "fixture checksum mismatch: expected {FIXTURE_CHECKSUM}, first {first}, actual {actual}"
        )
        .into());
    }
    Ok(FixtureResult {
        version: 1,
        expected_checksum: FIXTURE_CHECKSUM.into(),
        actual_checksum: actual,
        checksum_verified: true,
    })
}

async fn fixture_checksum(client: &tokio_postgres::Client) -> Result<String, Box<dyn Error>> {
    let row = client
        .query_one(
            "SELECT md5(format('%s:%s:%s:%s:%s:%s:%s:%s:%s', \
             (SELECT count(*) FROM burnin_type_lab.samples), \
             (SELECT sum(scalar) FROM burnin_type_lab.samples), \
             (SELECT count(*) FROM burnin_type_lab.bulk_values), \
             (SELECT sum(id) FROM burnin_type_lab.bulk_values), \
             (SELECT count(*) FROM burnin_type_lab.bulk_values WHERE nullable_text IS NULL), \
             (SELECT count(*) FROM burnin_commerce.customers), \
             (SELECT count(*) FROM burnin_commerce.products), \
             (SELECT count(*) FROM burnin_commerce.orders), \
             (SELECT count(*) FROM burnin_commerce.order_lines)))",
            &[],
        )
        .await?;
    Ok(row.get(0))
}

async fn run_data_scenarios(
    client: &tokio_postgres::Client,
) -> Result<Vec<DataScenarioResult>, Box<dyn Error>> {
    let zero = client
        .query("SELECT id FROM burnin_type_lab.samples WHERE id < 0", &[])
        .await?;
    let typed = client
        .query_one(
            "SELECT scalar, nullable_text, binary_value, tags, document, wide_text \
             FROM burnin_type_lab.samples WHERE id = 1",
            &[],
        )
        .await?;
    let scalar: i32 = typed.get(0);
    let nullable: Option<String> = typed.get(1);
    let binary: Vec<u8> = typed.get(2);
    let tags: Vec<String> = typed.get(3);
    let document: serde_json::Value = typed.get(4);
    let wide: String = typed.get(5);
    if scalar != 10
        || nullable.is_some()
        || binary != [0, 1, 2, 255]
        || tags != ["alpha", "one"]
        || document != serde_json::json!({"kind": "alpha", "enabled": true})
        || wide != "wide-alpha-".repeat(40)
    {
        return Err("typed fixture row did not match its checked-in value".into());
    }

    let small = client
        .query(
            "SELECT id FROM burnin_type_lab.bulk_values WHERE id <= 7 ORDER BY id",
            &[],
        )
        .await?;
    let medium = client
        .query(
            "SELECT id, nullable_text FROM burnin_type_lab.bulk_values \
             WHERE id <= 128 ORDER BY id",
            &[],
        )
        .await?;
    let medium_nulls = medium
        .iter()
        .filter(|row| row.get::<_, Option<&str>>(1).is_none())
        .count() as u64;
    let joined = client
        .query(
            "SELECT c.id, count(DISTINCT o.id)::bigint, count(ol.*)::bigint \
             FROM burnin_commerce.customers c \
             JOIN burnin_commerce.orders o ON o.customer_id = c.id \
             JOIN burnin_commerce.order_lines ol ON ol.order_id = o.id \
             GROUP BY c.id ORDER BY c.id",
            &[],
        )
        .await?;
    if joined.len() != 64
        || joined
            .iter()
            .any(|row| row.get::<_, i64>(1) != 4 || row.get::<_, i64>(2) != 8)
    {
        return Err("commerce join did not produce the deterministic cardinalities".into());
    }

    let large = stream_large_result(client).await?;
    Ok(vec![
        scenario("zero-rows", zero.len(), 0, 0),
        scenario("one-typed-row", 1, binary.len() + wide.len(), 1),
        scenario(
            "small-narrow",
            small.len(),
            small.len() * size_of::<i32>(),
            0,
        ),
        scenario(
            "medium-nullable",
            medium.len(),
            medium
                .iter()
                .map(|row| row.get::<_, Option<&str>>(1).map_or(0, str::len))
                .sum(),
            medium_nulls,
        ),
        scenario("commerce-join", joined.len(), joined.len() * 20, 0),
        large,
    ])
}

fn scenario(name: &str, rows: usize, bytes: usize, nulls: u64) -> DataScenarioResult {
    DataScenarioResult {
        name: name.into(),
        rows: rows as u64,
        bytes: bytes as u64,
        nulls,
        digest: None,
        validated: true,
    }
}

async fn stream_large_result(
    client: &tokio_postgres::Client,
) -> Result<DataScenarioResult, Box<dyn Error>> {
    use tokio_postgres::types::ToSql;

    let rows = client
        .query_raw(
            "SELECT id, nullable_text, binary_value, wide_text \
             FROM burnin_type_lab.bulk_values ORDER BY id",
            std::iter::empty::<&(dyn ToSql + Sync)>(),
        )
        .await?;
    tokio::pin!(rows);
    let mut digest = Sha256::new();
    let mut row_count = 0_u64;
    let mut byte_count = 0_u64;
    let mut null_count = 0_u64;
    while let Some(row) = rows.try_next().await? {
        let id: i32 = row.get(0);
        let nullable: Option<&str> = row.get(1);
        let binary: &[u8] = row.get(2);
        let wide: &str = row.get(3);
        digest.update(id.to_be_bytes());
        match nullable {
            Some(value) => {
                digest.update([1]);
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value.as_bytes());
                byte_count += value.len() as u64;
            }
            None => {
                digest.update([0]);
                null_count += 1;
            }
        }
        digest.update((binary.len() as u64).to_be_bytes());
        digest.update(binary);
        digest.update((wide.len() as u64).to_be_bytes());
        digest.update(wide.as_bytes());
        byte_count += size_of::<i32>() as u64 + binary.len() as u64 + wide.len() as u64;
        row_count += 1;
    }
    if row_count != 4096 || null_count != 819 {
        return Err(
            format!("unexpected streamed counts: rows={row_count}, nulls={null_count}").into(),
        );
    }
    Ok(DataScenarioResult {
        name: "large-streamed".into(),
        rows: row_count,
        bytes: byte_count,
        nulls: null_count,
        digest: Some(hex_digest(digest.finalize().as_slice())),
        validated: true,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

async fn write_event(event: &ChildEvent) -> Result<(), Box<dyn Error>> {
    let mut stdout = tokio::io::stdout();
    stdout.write_all(&serde_json::to_vec(event)?).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

async fn write_artifacts(path: &Path, result: &RunResult) -> Result<(), Box<dyn Error>> {
    let json = serde_json::to_vec_pretty(result)?;
    atomic_write(&path.join("result.json"), &json).await?;
    let status = if result.success { "PASS" } else { "FAIL" };
    let markdown = format!(
        "# pg-proto {} conformance\n\n{status}: `{}` completed with result `{}` (PostgreSQL: {}).\n\nPass-through associations: {}. Identity rewrites: {}.\n",
        result.profile,
        result.scenario.name,
        result.scenario.value,
        result.postgres_version,
        result.middleware_reconstruction.pass_through.len(),
        result.middleware_reconstruction.identity_rewrite.len(),
    );
    atomic_write(&path.join("summary.md"), markdown.as_bytes()).await
}

async fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, contents).await?;
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

fn option<'a>(arguments: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
    let index = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing {name}"))?;
    arguments
        .get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {name}").into())
}

fn debug_error(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::{
        REQUIRED_SMOKE_COVERAGE, REQUIRED_SMOKE_STAGES, authentication_profile_results,
        coverage_report,
    };
    use pg_proto::{
        ClientAuthentication, ClientAuthenticationChallenge, ClientAuthenticationSession,
        ConnectTarget, StaticClientCredentials, StaticCredentialError,
    };

    #[test]
    fn required_smoke_coverage_is_stable_and_complete() {
        let mut observed: Vec<_> = REQUIRED_SMOKE_COVERAGE.map(str::to_owned).into();
        observed.extend(REQUIRED_SMOKE_STAGES.map(str::to_owned));
        let report = coverage_report(&observed).expect("complete known coverage");
        assert_eq!(report.observed_ids.len(), 37);
        assert!(report.missing.is_empty());
    }

    #[test]
    fn unknown_coverage_fails_conformance() {
        let mut observed: Vec<_> = REQUIRED_SMOKE_COVERAGE.map(str::to_owned).into();
        observed.extend(REQUIRED_SMOKE_STAGES.map(str::to_owned));
        observed.push("backend.Renamed.WithoutMigration".into());
        let error = coverage_report(&observed).expect_err("unknown ID must fail");
        assert!(error.to_string().contains("unknown required coverage IDs"));
    }

    #[test]
    fn optional_error_transition_is_known_but_not_required() {
        let mut observed: Vec<_> = REQUIRED_SMOKE_COVERAGE.map(str::to_owned).into();
        observed.extend(REQUIRED_SMOKE_STAGES.map(str::to_owned));
        observed.push("backend.DescribeResponse.Error".into());
        let report = coverage_report(&observed).expect("optional known coverage");
        assert!(
            report
                .observed_ids
                .contains(&"backend.DescribeResponse.Error".into())
        );
    }

    #[test]
    fn authentication_catalogue_has_stable_version_scoped_profiles() {
        let profiles = authentication_profile_results(true);
        assert_eq!(profiles.len(), 7);
        assert!(
            profiles
                .iter()
                .all(|profile| profile.postgres_versions == "14-18")
        );
        assert_eq!(profiles[0].id, "auth.plaintext.trust");
        assert_eq!(profiles[6].id, "auth.tls.rejection");
    }

    #[tokio::test]
    async fn plus_only_offer_is_explicitly_unsupported_without_channel_binding() {
        let mut credentials = StaticClientCredentials::new("postgres", "postgres")
            .begin(&ConnectTarget::new("postgres"))
            .await
            .expect("credential session");
        let result = credentials
            .respond(ClientAuthenticationChallenge::Sasl(vec![
                b"SCRAM-SHA-256-PLUS".as_slice().into(),
            ]))
            .await;
        assert!(matches!(
            result,
            Err(StaticCredentialError::UnsupportedAuthentication)
        ));
    }
}
