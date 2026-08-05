use std::{convert::Infallible, error::Error, io, net::SocketAddr, sync::Arc};

use pg_proto::{
    Conn,
    codec::{Backend, BackendMessage, Frontend, FrontendMessage},
    middleware::{MessageMiddleware, MessageMiddlewareExt as _, Middleware, Then},
    pre_startup::{PreStartup, PreStartupMessage, PreStartupOffer, Startup},
    tls::ServerTls,
    transport::Buffered,
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
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

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

#[derive(Debug)]
struct ExampleState {
    connection: u64,
    rows: usize,
}

#[derive(Clone)]
struct ProtocolLogger(Reporter);

#[derive(Clone)]
struct SqlLogger(Reporter);

#[derive(Clone)]
struct RowStatistics(Reporter);

type ExampleHandler = Then<Then<ProtocolLogger, SqlLogger>, RowStatistics>;
type ExampleMiddleware = Middleware<ExampleState, ExampleHandler>;

fn middleware(connection: u64, reporter: Reporter) -> ExampleMiddleware {
    Middleware::new(
        ExampleState {
            connection,
            rows: 0,
        },
        ProtocolLogger(Arc::clone(&reporter))
            .then(SqlLogger(Arc::clone(&reporter)))
            .then(RowStatistics(reporter)),
    )
}

macro_rules! pass_through {
    ($handler:ty, $message:ty) => {
        impl MessageMiddleware<$message, ExampleState> for $handler {
            type Error = Infallible;

            fn intercept(
                &mut self,
                _state: &mut ExampleState,
                message: $message,
            ) -> Result<$message, Self::Error> {
                Ok(message)
            }
        }
    };
}

impl MessageMiddleware<PreStartupMessage, ExampleState> for ProtocolLogger {
    type Error = Infallible;

    fn intercept(
        &mut self,
        state: &mut ExampleState,
        message: PreStartupMessage,
    ) -> Result<PreStartupMessage, Self::Error> {
        (self.0)(Observation::Protocol {
            connection: state.connection,
            direction: "client -> server",
            message: format!("{message:?}"),
        });
        Ok(message)
    }
}

impl MessageMiddleware<FrontendMessage, ExampleState> for ProtocolLogger {
    type Error = Infallible;

    fn intercept(
        &mut self,
        state: &mut ExampleState,
        message: FrontendMessage,
    ) -> Result<FrontendMessage, Self::Error> {
        (self.0)(Observation::Protocol {
            connection: state.connection,
            direction: "client -> server",
            message: format!("{message:?}"),
        });
        Ok(message)
    }
}

impl MessageMiddleware<BackendMessage, ExampleState> for ProtocolLogger {
    type Error = Infallible;

    fn intercept(
        &mut self,
        state: &mut ExampleState,
        message: BackendMessage,
    ) -> Result<BackendMessage, Self::Error> {
        (self.0)(Observation::Protocol {
            connection: state.connection,
            direction: "server -> client",
            message: format!("{message:?}"),
        });
        Ok(message)
    }
}

pass_through!(SqlLogger, PreStartupMessage);
pass_through!(SqlLogger, BackendMessage);

impl MessageMiddleware<FrontendMessage, ExampleState> for SqlLogger {
    type Error = Infallible;

    fn intercept(
        &mut self,
        state: &mut ExampleState,
        message: FrontendMessage,
    ) -> Result<FrontendMessage, Self::Error> {
        let statement = match &message {
            FrontendMessage::Query(sql) => Some(sql),
            FrontendMessage::Parse(parse) => Some(&parse.query),
            _ => None,
        };
        if let Some(statement) = statement {
            (self.0)(Observation::Sql {
                connection: state.connection,
                statement: String::from_utf8_lossy(statement).into_owned(),
            });
        }
        Ok(message)
    }
}

pass_through!(RowStatistics, PreStartupMessage);
pass_through!(RowStatistics, FrontendMessage);

impl MessageMiddleware<BackendMessage, ExampleState> for RowStatistics {
    type Error = Infallible;

    fn intercept(
        &mut self,
        state: &mut ExampleState,
        message: BackendMessage,
    ) -> Result<BackendMessage, Self::Error> {
        match &message {
            BackendMessage::DataRow(_) => state.rows = state.rows.saturating_add(1),
            BackendMessage::CommandComplete(tag) => {
                (self.0)(Observation::RowCount {
                    connection: state.connection,
                    rows: state.rows,
                    command: String::from_utf8_lossy(tag).into_owned(),
                });
                state.rows = 0;
            }
            BackendMessage::ErrorResponse(_) => state.rows = 0,
            _ => {}
        }
        Ok(message)
    }
}

#[derive(Clone)]
pub struct ExampleTlsIdentity {
    config: Arc<ServerConfig>,
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
            config,
            certificate,
        })
    }

    #[cfg(test)]
    pub fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
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
            TcpStream::connect(address).await.map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot connect to PostgreSQL at {address}: {error}; start that server or omit the upstream argument to use the example container"
                    ),
                )
            })?;
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

pub async fn serve(
    listener: TcpListener,
    upstream: SocketAddr,
    tls: ExampleTlsIdentity,
    reporter: Reporter,
) -> io::Result<()> {
    let mut next_connection = 1_u64;
    loop {
        let (client, _) = listener.accept().await?;
        let connection = next_connection;
        next_connection = next_connection.wrapping_add(1);
        let middleware = middleware(connection, Arc::clone(&reporter));
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(error) = proxy_connection(client, upstream, tls, middleware).await {
                eprintln!("connection {connection}: {error}");
            }
        });
    }
}

async fn proxy_connection(
    client: TcpStream,
    upstream: SocketAddr,
    tls: ExampleTlsIdentity,
    mut middleware: ExampleMiddleware,
) -> io::Result<()> {
    let mut pre_startup = Conn::new(Buffered::new_frontend(client));
    loop {
        let message = middleware
            .intercept(pre_startup.receive_pre_startup_wire().await?)
            .expect("example middleware is infallible");
        match pre_startup.offer_pre_startup(message) {
            PreStartupOffer::Ssl(decision) => {
                let mut handshake = decision.approve_ssl();
                handshake.flush().await?;
                let encrypted = handshake.accept_tls(tls.config, tls.certificate).await?;
                return encrypted_startup(encrypted, upstream, middleware).await;
            }
            PreStartupOffer::Gss(decision) => {
                pre_startup = decision.decline_gss();
                pre_startup.flush().await?;
            }
            PreStartupOffer::Cancel {
                conn,
                process_id,
                secret_key,
            } => {
                drop(conn.into_transport().into_inner());
                return forward_cancel(
                    PreStartupMessage::CancelRequest {
                        process_id,
                        secret_key,
                    },
                    upstream,
                )
                .await;
            }
            PreStartupOffer::Startup { conn, message } => {
                return begin_forwarding(conn, message, upstream, middleware).await;
            }
        }
    }
}

async fn encrypted_startup(
    mut pre_startup: Conn<Buffered<ServerTls<TcpStream>, Frontend>, PreStartup>,
    upstream: SocketAddr,
    mut middleware: ExampleMiddleware,
) -> io::Result<()> {
    let message = middleware
        .intercept(pre_startup.receive_pre_startup_wire().await?)
        .expect("example middleware is infallible");
    match pre_startup.offer_pre_startup(message) {
        PreStartupOffer::Startup { conn, message } => {
            begin_forwarding(conn, message, upstream, middleware).await
        }
        PreStartupOffer::Cancel {
            conn,
            process_id,
            secret_key,
        } => {
            drop(conn.into_transport().into_inner());
            forward_cancel(
                PreStartupMessage::CancelRequest {
                    process_id,
                    secret_key,
                },
                upstream,
            )
            .await
        }
        PreStartupOffer::Ssl(conn) => invalid_encrypted_request(conn, "SSLRequest"),
        PreStartupOffer::Gss(conn) => invalid_encrypted_request(conn, "GSSENCRequest"),
    }
}

fn invalid_encrypted_request<S, Phase>(
    conn: Conn<Buffered<S, Frontend>, Phase>,
    request: &str,
) -> io::Result<()> {
    drop(conn.into_transport().into_inner());
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{request} is not valid inside TLS"),
    ))
}

async fn forward_cancel(message: PreStartupMessage, upstream: SocketAddr) -> io::Result<()> {
    let mut server = TcpStream::connect(upstream).await?;
    server.write_all(&message.to_packet()?).await
}

async fn begin_forwarding<S>(
    conn: Conn<Buffered<S, Frontend>, Startup>,
    message: pg_proto::startup::StartupMessage,
    upstream: SocketAddr,
    middleware: ExampleMiddleware,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client = conn.into_transport().into_inner();
    let mut server = TcpStream::connect(upstream).await?;
    server
        .write_all(&PreStartupMessage::Startup(message).to_packet()?)
        .await?;
    forward_tagged(client, server, middleware).await
}

async fn forward_tagged<S>(
    client: S,
    server: TcpStream,
    mut middleware: ExampleMiddleware,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut downstream: Buffered<_, Frontend> = Buffered::new_frontend(client);
    let mut upstream: Buffered<_, Backend> = Buffered::new(server);
    loop {
        tokio::select! {
            frontend = downstream.receive_wire() => {
                let frontend = middleware
                    .intercept(frontend?)
                    .expect("example middleware is infallible");
                let terminate = matches!(frontend, FrontendMessage::Terminate);
                upstream.push(frontend.to_frame()?)?;
                upstream.flush().await?;
                if terminate {
                    return Ok(());
                }
            }
            backend = upstream.receive_wire() => {
                let backend = middleware
                    .intercept(backend?)
                    .expect("example middleware is infallible");
                downstream.push(backend.to_frame()?)?;
                downstream.flush().await?;
            }
        }
    }
}
