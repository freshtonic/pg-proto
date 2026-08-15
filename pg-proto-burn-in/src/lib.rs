//! Multi-process PostgreSQL protocol verification harness.

use std::{
    convert::Infallible,
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use pg_proto::{
    BoundedPipeline, CancellationPolicy, Client, ClientTlsPolicy, ConnectTarget, ForwardedMessage,
    FrontendMessage, InitialServerContext, Intermediary, Server, ServerTlsPolicy,
    StartupParameters, StartupRouteResolver, TrustClientAuthentication, TrustServerAuthentication,
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
    success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScenarioResult {
    name: String,
    value: i32,
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
        Ok(value) => RunResult {
            schema_version: 1,
            command: "conformance".into(),
            profile: profile.into(),
            postgres_version: "18".into(),
            scenario: ScenarioResult {
                name: "extended-select-scalar".into(),
                value: *value,
            },
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
            success: false,
        },
    };
    write_artifacts(&artifacts, &result).await?;
    outcome.map(|_| ())
}

async fn supervise_smoke(executable: &str) -> Result<i32, Box<dyn Error>> {
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
    let value = match completed {
        ChildEvent::Completed {
            value: Some(value), ..
        } => value,
        event => return Err(format!("expected driver completion event, got {event:?}").into()),
    };
    wait_success(&mut driver, "driver").await?;
    let intermediary_completed = read_event(&mut intermediary).await?;
    if !matches!(intermediary_completed, ChildEvent::Completed { .. }) {
        return Err(format!(
            "expected intermediary completion event, got {intermediary_completed:?}"
        )
        .into());
    }
    wait_success(&mut intermediary, "intermediary").await?;
    drop(container);
    Ok(value)
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
        .build()
        .map_err(debug_error)?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    write_event(&ChildEvent::Ready {
        version: 1,
        listen_addr: listener.local_addr()?,
    })
    .await?;
    let (transport, peer) = listener.accept().await?;
    let mut session = Box::pin(intermediary.accept(transport, peer, ()))
        .await
        .map_err(debug_error)?
        .into_session();
    loop {
        match session.forward_next().await {
            Ok(ForwardedMessage::Frontend(FrontendMessage::Terminate)) => {
                let _transports = session.teardown();
                break;
            }
            Ok(_) => {}
            Err(error) => {
                let message = format!("intermediary forwarding failed: {error:?}");
                let _transports = session.teardown();
                return Err(message.into());
            }
        }
    }
    write_event(&ChildEvent::Completed {
        version: 1,
        value: None,
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
