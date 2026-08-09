use std::{convert::Infallible, error::Error, io, net::SocketAddr, sync::Arc};

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
pub enum Observation {
    Sql {
        connection: u64,
        statement: String,
    },
    RowCount {
        connection: u64,
        rows: usize,
        command: String,
    },
    Protocol {
        connection: u64,
        direction: &'static str,
        message: String,
    },
}
pub type Reporter = Arc<dyn Fn(Observation) + Send + Sync>;

pub struct ExampleState {
    connection: u64,
    rows: usize,
    reporter: Reporter,
}

#[derive(Clone, Copy)]
struct Logger;
impl
    IntermediaryMiddleware<
        ExampleState,
        ServerConnectionContext<SocketAddr, TrustIdentity>,
        ClientConnectionContext<()>,
    > for Logger
{
    fn frontend(
        &mut self,
        _: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut ExampleState,
        message: FrontendMessage,
    ) -> FrontendMessage {
        (state.reporter)(Observation::Protocol {
            connection: state.connection,
            direction: "client -> server",
            message: format!("{message:?}"),
        });
        if let FrontendMessage::Query(sql)
        | FrontendMessage::Parse(pg_proto::Parse { query: sql, .. }) = &message
        {
            (state.reporter)(Observation::Sql {
                connection: state.connection,
                statement: String::from_utf8_lossy(sql).into_owned(),
            });
        }
        message
    }
    fn backend(
        &mut self,
        _: &ServerConnectionContext<SocketAddr, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut ExampleState,
        message: BackendMessage,
    ) -> BackendMessage {
        (state.reporter)(Observation::Protocol {
            connection: state.connection,
            direction: "server -> client",
            message: format!("{message:?}"),
        });
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
        message
    }
}

#[derive(Clone)]
pub struct ExampleTlsIdentity {
    identity: ServerIdentity,
    #[allow(dead_code)]
    certificate: CertificateDer<'static>,
}
impl ExampleTlsIdentity {
    pub fn generate() -> Result<Self, Box<dyn Error>> {
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
            certificate,
        })
    }
    #[cfg(test)]
    pub fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }
}
impl ServerIdentityProvider for ExampleTlsIdentity {
    type Error = Infallible;
    fn resolve(&self) -> Result<ServerIdentity, Self::Error> {
        Ok(self.identity.clone())
    }
}

pub struct ExampleUpstream {
    address: SocketAddr,
    _container: Option<ContainerAsync<Postgres>>,
}
impl ExampleUpstream {
    pub async fn resolve(configured: Option<&str>) -> Result<Self, Box<dyn Error>> {
        if let Some(configured) = configured {
            let address: SocketAddr = configured.parse()?;
            TcpStream::connect(address).await.map_err(|error| io::Error::new(error.kind(), format!("cannot connect to PostgreSQL at {address}: {error}; start that server or omit the upstream argument to use the example container")))?;
            return Ok(Self {
                address,
                _container: None,
            });
        }
        let version =
            std::env::var("PG_PROTO_POSTGRES_VERSION").unwrap_or_else(|_| "18".to_owned());
        if !matches!(version.as_str(), "14" | "15" | "16" | "17" | "18") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PG_PROTO_POSTGRES_VERSION must be 14, 15, 16, 17, or 18",
            )
            .into());
        }
        let container = Postgres::default()
            .with_init_sql(include_bytes!("../sql_logging_proxy/customer_orders.sql").to_vec())
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
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

#[derive(Clone, Copy)]
struct Route(SocketAddr);
impl StartupRouteResolver<SocketAddr> for Route {
    type Error = Infallible;
    fn resolve<'a>(
        &'a self,
        _: StartupParameters,
        _: InitialServerContext<'a, SocketAddr>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ConnectTarget, Self::Error>> + 'a>>
    {
        Box::pin(async move { Ok(ConnectTarget::new(self.0.to_string())) })
    }
}

pub async fn serve(
    listener: TcpListener,
    upstream: SocketAddr,
    tls: ExampleTlsIdentity,
    reporter: Reporter,
) -> io::Result<()> {
    let mut next = 1_u64;
    // The facade intentionally permits non-Send authentication and routing
    // policies. Bound the application-owned connection workers explicitly.
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
             _: &ClientConnectionContext<()>| Logger,
        )
        .build()
        .map_err(other)?;
    let accepted = Box::pin(intermediary.accept(
        transport,
        peer,
        ExampleState {
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

fn other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}
