//! Multi-process PostgreSQL protocol verification harness.

use std::{
    collections::BTreeSet,
    convert::Infallible,
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use pg_proto::{
    BoundedPipeline, CancellationPolicy, Client, ClientConnectionContext, ClientTlsPolicy,
    ConnectTarget, ForwardedMessage, FrontendMessage, InitialServerContext, Intermediary,
    IntermediaryMiddleware, ProtocolTransitionDirection, ProtocolTransitionObservation, Server,
    ServerConnectionContext, ServerTlsPolicy, StartupParameters, StartupRouteResolver,
    TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};
use serde::{Deserialize, Serialize};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt, runners::AsyncRunner},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::timeout,
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs the requested harness command.
pub async fn run(arguments: Vec<String>) -> Result<(), Box<dyn Error>> {
    match arguments.get(1).map(String::as_str) {
        Some("conformance") => run_conformance(&arguments).await,
        Some("intermediary-child") => run_intermediary_child(&arguments).await,
        Some("driver-child") => run_driver_child(&arguments).await,
        _ => Err("usage: pg-proto-burn-in conformance --profile smoke --artifacts DIR".into()),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RunResult {
    schema_version: u32,
    command: String,
    profile: String,
    postgres_version: String,
    scenario: ScenarioResult,
    coverage: CoverageReport,
    success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScenarioResult {
    name: String,
    value: i32,
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
    },
}

async fn run_conformance(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let profile = option(arguments, "--profile")?;
    if profile != "smoke" {
        return Err(format!("unsupported conformance profile: {profile}").into());
    }
    let artifacts = PathBuf::from(option(arguments, "--artifacts")?);
    tokio::fs::create_dir_all(&artifacts).await?;

    let outcome = supervise_smoke(arguments.first().ok_or("missing executable path")?).await;
    let result = match &outcome {
        Ok((value, coverage)) => RunResult {
            schema_version: 1,
            command: "conformance".into(),
            profile: profile.into(),
            postgres_version: "18".into(),
            scenario: ScenarioResult {
                name: "extended-select-scalar".into(),
                value: *value,
            },
            coverage: coverage_report(coverage)?,
            success: true,
        },
        Err(_) => RunResult {
            schema_version: 1,
            command: "conformance".into(),
            profile: profile.into(),
            postgres_version: "18".into(),
            scenario: ScenarioResult {
                name: "extended-select-scalar".into(),
                value: 0,
            },
            coverage: CoverageReport::default(),
            success: false,
        },
    };
    write_artifacts(&artifacts, &result).await?;
    outcome.map(|_| ())
}

async fn supervise_smoke(executable: &str) -> Result<(i32, Vec<String>), Box<dyn Error>> {
    let container = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );

    let mut intermediary = spawn_child(executable, "intermediary-child", upstream).await?;
    let ready = read_event(&mut intermediary).await?;
    let listen_addr = match ready {
        ChildEvent::Ready { listen_addr, .. } => listen_addr,
        event => return Err(format!("expected intermediary ready event, got {event:?}").into()),
    };

    let mut driver = spawn_child(executable, "driver-child", listen_addr).await?;
    let completed = read_event(&mut driver).await?;
    let (value, mut coverage) = match completed {
        ChildEvent::Completed {
            value: Some(value),
            coverage,
            ..
        } => (value, coverage),
        event => return Err(format!("expected driver completion event, got {event:?}").into()),
    };
    wait_success(&mut driver, "driver").await?;
    let intermediary_completed = read_event(&mut intermediary).await?;
    let ChildEvent::Completed {
        coverage: intermediary_coverage,
        ..
    } = intermediary_completed
    else {
        return Err("expected intermediary completion event".into());
    };
    coverage.extend(intermediary_coverage);
    wait_success(&mut intermediary, "intermediary").await?;
    drop(container);
    Ok((value, coverage))
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

const REQUIRED_SMOKE_COVERAGE: [&str; 15] = [
    "backend.BindResponse.Complete",
    "backend.Building.Describe",
    "backend.Building.Execute",
    "backend.Building.Sync",
    "backend.CloseResponse.Complete",
    "backend.DescribeResponse.ParameterDescription",
    "backend.DescribeResponse.RowDescription",
    "backend.ExecuteResponse.CommandComplete",
    "backend.ExecuteResponse.Continue",
    "backend.ParseResponse.Complete",
    "backend.Ready.Bind",
    "backend.Ready.Close",
    "backend.Ready.Parse",
    "backend.Ready.Terminate",
    "backend.SyncResponse.Ready",
];

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
    let unknown: Vec<_> = observed.difference(&required).copied().collect();
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

async fn spawn_child(
    executable: &str,
    role: &str,
    address: SocketAddr,
) -> Result<Child, Box<dyn Error>> {
    Ok(Command::new(executable)
        .args([role, "--address", &address.to_string()])
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

#[derive(Default)]
struct CoverageState(BTreeSet<String>);

struct CoverageObserver;

impl
    IntermediaryMiddleware<
        CoverageState,
        ServerConnectionContext<SocketAddr, TrustIdentity>,
        ClientConnectionContext<()>,
    > for CoverageObserver
{
    type Error = Infallible;

    async fn observe_transition(
        &mut self,
        _server: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _client: &ClientConnectionContext<()>,
        state: &mut CoverageState,
        observation: ProtocolTransitionObservation,
    ) {
        state.0.insert(observation.id.to_owned());
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
            .0
            .extend(stages.iter().map(|stage| (*stage).to_owned()));
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
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route(upstream))
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(64).expect("non-zero smoke pipeline capacity"))
        .middleware(
            |_: &ServerConnectionContext<SocketAddr, TrustIdentity>,
             _: &ClientConnectionContext<()>| CoverageObserver,
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
                break state.0;
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
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    let connection_task = tokio::spawn(connection);
    let value: i32 = client.query_one("SELECT 42::int4", &[]).await?.get(0);
    if value != 42 {
        return Err(format!("expected 42, got {value}").into());
    }
    drop(client);
    timeout(CHILD_TIMEOUT, connection_task).await???;
    write_event(&ChildEvent::Completed {
        version: 1,
        value: Some(value),
        coverage: vec![
            "smoke.extended-select.driver-emitted".into(),
            "smoke.extended-select.driver-validated".into(),
        ],
    })
    .await
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
        "# pg-proto smoke conformance\n\n{status}: `{}` returned `{}` through PostgreSQL {}.\n",
        result.scenario.name, result.scenario.value, result.postgres_version
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
    use super::{REQUIRED_SMOKE_COVERAGE, REQUIRED_SMOKE_STAGES, coverage_report};

    #[test]
    fn required_smoke_coverage_is_stable_and_complete() {
        let mut observed: Vec<_> = REQUIRED_SMOKE_COVERAGE.map(str::to_owned).into();
        observed.extend(REQUIRED_SMOKE_STAGES.map(str::to_owned));
        let report = coverage_report(&observed).expect("complete known coverage");
        assert_eq!(report.observed_ids.len(), 15);
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
}
