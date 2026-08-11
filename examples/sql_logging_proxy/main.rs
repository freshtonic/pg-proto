//! Runs a builder-based proxy which logs inbound SQL and result row counts.
//!
//! The integration test includes this example as a module, so its small test
//! seam deliberately uses crate visibility even when that module is private.

#![allow(clippy::redundant_pub_crate)]

use std::{convert::Infallible, env, error::Error, io, net::SocketAddr, sync::Arc};

use pg_proto::{
    BackendMessage, BoundedPipeline, CancellationPolicy, Client, ClientConnectionContext,
    ClientTlsPolicy, ConnectTarget, ForwardedMessage, FrontendMessage, InitialServerContext,
    Intermediary, IntermediaryMiddleware, Server, ServerConnectionContext, ServerIdentity,
    ServerIdentityProvider, ServerTlsPolicy, StartupParameters, StartupRouteResolver,
    TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};
use rcgen::generate_simple_self_signed;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Observation {
    Sql {
        connection: u64,
        statement: String,
    },
    RowCount {
        connection: u64,
        rows: usize,
        command: String,
    },
}

type Reporter = Arc<dyn Fn(Observation) + Send + Sync>;

struct SqlState {
    connection: u64,
    rows: usize,
    reporter: Reporter,
}

#[derive(Clone, Copy)]
struct SqlLogger;

impl
    IntermediaryMiddleware<
        SqlState,
        ServerConnectionContext<SocketAddr, TrustIdentity>,
        ClientConnectionContext<()>,
    > for SqlLogger
{
    type Error = std::convert::Infallible;

    async fn frontend(
        &mut self,
        _: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut SqlState,
        message: FrontendMessage,
    ) -> Result<pg_proto::FrontendMiddlewareOutput, Self::Error> {
        if let FrontendMessage::Query(sql)
        | FrontendMessage::Parse(pg_proto::Parse { query: sql, .. }) = &message
        {
            (state.reporter)(Observation::Sql {
                connection: state.connection,
                statement: String::from_utf8_lossy(sql).into_owned(),
            });
        }
        Ok(pg_proto::FrontendMiddlewareOutput::Forward(message))
    }

    async fn backend(
        &mut self,
        _: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut SqlState,
        message: BackendMessage,
    ) -> Result<pg_proto::BackendMiddlewareOutput, Self::Error> {
        match &message {
            BackendMessage::DataRow(_) => state.rows = state.rows.saturating_add(1),
            BackendMessage::CommandComplete(tag) => {
                (state.reporter)(Observation::RowCount {
                    connection: state.connection,
                    rows: state.rows,
                    command: String::from_utf8_lossy(tag).into_owned(),
                });
                state.rows = 0;
            }
            BackendMessage::ErrorResponse(_) => state.rows = 0,
            _ => {}
        }
        Ok(pg_proto::BackendMiddlewareOutput::Forward(message))
    }
}

#[derive(Clone)]
pub(crate) struct ExampleTlsIdentity {
    identity: ServerIdentity,
    #[cfg(test)]
    certificate: CertificateDer<'static>,
}

impl ExampleTlsIdentity {
    pub(crate) fn generate() -> Result<Self, Box<dyn Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated =
            generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
        let certificate = CertificateDer::from(generated.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der())?;
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)?,
        );
        Ok(Self {
            identity: ServerIdentity::new(config, certificate.clone()),
            #[cfg(test)]
            certificate,
        })
    }

    #[cfg(test)]
    pub(crate) fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }
}

impl ServerIdentityProvider for ExampleTlsIdentity {
    type Error = Infallible;

    fn resolve(&self) -> Result<ServerIdentity, Self::Error> {
        Ok(self.identity.clone())
    }
}

pub(crate) struct ExampleUpstream {
    address: SocketAddr,
    _container: Option<ContainerAsync<Postgres>>,
}

impl ExampleUpstream {
    pub(crate) async fn resolve(configured: Option<&str>) -> Result<Self, Box<dyn Error>> {
        if let Some(configured) = configured {
            let address: SocketAddr = configured.parse()?;
            TcpStream::connect(address).await.map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot connect to PostgreSQL at {address}: {error}; start that server or \
                         omit the upstream argument to use the example container"
                    ),
                )
            })?;
            return Ok(Self {
                address,
                _container: None,
            });
        }
        let version = env::var("PG_PROTO_POSTGRES_VERSION").unwrap_or_else(|_| "18".to_owned());
        if !matches!(version.as_str(), "14" | "15" | "16" | "17" | "18") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PG_PROTO_POSTGRES_VERSION must be 14, 15, 16, 17, or 18",
            )
            .into());
        }
        let container = Postgres::default()
            .with_init_sql(include_bytes!("customer_orders.sql").to_vec())
            .with_host_auth()
            .with_tag(format!("{version}-alpine"))
            .start()
            .await?;
        let port = container.get_host_port_ipv4(5432).await?;
        Ok(Self {
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            _container: Some(container),
        })
    }

    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }
}

#[derive(Clone, Copy)]
struct Route(SocketAddr);

impl StartupRouteResolver<SocketAddr> for Route {
    type Error = Infallible;

    async fn resolve(
        &self,
        _: StartupParameters,
        _: InitialServerContext<'_, SocketAddr>,
    ) -> Result<ConnectTarget, Self::Error> {
        Ok(ConnectTarget::new(self.0.to_string()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen = address(1, "127.0.0.1:6432")?;
    let upstream = ExampleUpstream::resolve(env::args().nth(2).as_deref()).await?;
    let upstream_address = upstream.address();
    let tls = ExampleTlsIdentity::generate()?;
    let listener = TcpListener::bind(listen).await?;
    println!("SQL logging proxy listening on {listen}; upstream is {upstream_address}");
    serve(
        listener,
        upstream_address,
        tls,
        Arc::new(|event| match event {
            Observation::Sql {
                connection,
                statement,
            } => println!("[{connection}] SQL: {statement}"),
            Observation::RowCount {
                connection,
                rows,
                command,
            } => println!("[{connection}] ROWS: {rows} ({command})"),
        }),
    )
    .await?;
    Ok(())
}

pub(crate) async fn serve(
    listener: TcpListener,
    upstream: SocketAddr,
    tls: ExampleTlsIdentity,
    reporter: Reporter,
) -> io::Result<()> {
    let mut next = 1_u64;
    let workers = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        let (transport, peer) = listener.accept().await?;
        let worker = Arc::clone(&workers)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("connection worker pool closed"))?;
        let connection = next;
        next = next.wrapping_add(1);
        let reporter = Arc::clone(&reporter);
        let tls = tls.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("connection runtime");
            runtime.block_on(async move {
                let _worker = worker;
                if let Err(error) = Box::pin(proxy_connection(
                    transport, peer, upstream, tls, connection, reporter,
                ))
                .await
                {
                    eprintln!("connection {connection}: {error}");
                }
            });
        });
    }
}

async fn proxy_connection(
    transport: TcpStream,
    peer: SocketAddr,
    upstream: SocketAddr,
    tls: ExampleTlsIdentity,
    connection: u64,
    reporter: Reporter,
) -> io::Result<()> {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Required(tls))
        .authentication(TrustServerAuthentication)
        .build()
        .map_err(other)?;
    let client = Client::builder()
        .connector(move |_| TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .map_err(other)?;
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route(upstream))
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(64).expect("non-zero proxy pipeline capacity"))
        .middleware(
            |_: &ServerConnectionContext<SocketAddr, TrustIdentity>,
             _: &ClientConnectionContext<()>| SqlLogger,
        )
        .build()
        .map_err(other)?;
    let accepted = Box::pin(intermediary.accept(
        transport,
        peer,
        SqlState {
            connection,
            rows: 0,
            reporter,
        },
    ))
    .await
    .map_err(other)?;
    let mut session = accepted.into_session();
    loop {
        match session.forward_next().await {
            Ok(ForwardedMessage::Frontend(FrontendMessage::Terminate)) => {
                let _ = session.teardown();
                return Ok(());
            }
            Ok(_) => {}
            Err(error) => {
                let error = other(error);
                let _ = session.teardown();
                return Err(error);
            }
        }
    }
}

fn address(argument: usize, default: &str) -> Result<SocketAddr, Box<dyn Error>> {
    Ok(env::args()
        .nth(argument)
        .as_deref()
        .unwrap_or(default)
        .parse()?)
}

fn other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}
