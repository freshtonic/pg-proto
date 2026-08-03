use std::{error::Error, io, net::SocketAddr, sync::Arc};

use pg_proto::{
    Conn,
    codec::{Backend, BackendMessage, Frontend, FrontendMessage},
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

pub type Observer = Arc<dyn Fn(Observation) + Send + Sync>;

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
    observer: Observer,
) -> io::Result<()> {
    let mut next_connection = 1_u64;
    loop {
        let (client, _) = listener.accept().await?;
        let connection = next_connection;
        next_connection = next_connection.wrapping_add(1);
        let observer = Arc::clone(&observer);
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(error) = proxy_connection(client, upstream, tls, connection, observer).await
            {
                eprintln!("connection {connection}: {error}");
            }
        });
    }
}

async fn proxy_connection(
    client: TcpStream,
    upstream: SocketAddr,
    tls: ExampleTlsIdentity,
    connection: u64,
    observer: Observer,
) -> io::Result<()> {
    let mut pre_startup = Conn::new(Buffered::new_frontend(client));
    loop {
        let message = pre_startup.receive_pre_startup_wire().await?;
        observer(Observation::Protocol {
            connection,
            direction: "client -> server",
            message: format!("{message:?}"),
        });
        match pre_startup.offer_pre_startup(message) {
            PreStartupOffer::Ssl(decision) => {
                let mut handshake = decision.approve_ssl();
                handshake.flush().await?;
                observer(Observation::Protocol {
                    connection,
                    direction: "server -> client",
                    message: "SslAccepted".to_owned(),
                });
                let encrypted = handshake.accept_tls(tls.config, tls.certificate).await?;
                return encrypted_startup(encrypted, upstream, connection, observer).await;
            }
            PreStartupOffer::Gss(decision) => {
                pre_startup = decision.decline_gss();
                pre_startup.flush().await?;
                observer(Observation::Protocol {
                    connection,
                    direction: "server -> client",
                    message: "GssEncryptionRejected".to_owned(),
                });
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
                return begin_forwarding(conn, message, upstream, connection, observer).await;
            }
        }
    }
}

async fn encrypted_startup(
    mut pre_startup: Conn<Buffered<ServerTls<TcpStream>, Frontend>, PreStartup>,
    upstream: SocketAddr,
    connection: u64,
    observer: Observer,
) -> io::Result<()> {
    let message = pre_startup.receive_pre_startup_wire().await?;
    observer(Observation::Protocol {
        connection,
        direction: "client -> server (TLS plaintext)",
        message: format!("{message:?}"),
    });
    match pre_startup.offer_pre_startup(message) {
        PreStartupOffer::Startup { conn, message } => {
            begin_forwarding(conn, message, upstream, connection, observer).await
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
    connection: u64,
    observer: Observer,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client = conn.into_transport().into_inner();
    let mut server = TcpStream::connect(upstream).await?;
    server
        .write_all(&PreStartupMessage::Startup(message).to_packet()?)
        .await?;
    forward_tagged(client, server, connection, observer).await
}

async fn forward_tagged<S>(
    client: S,
    server: TcpStream,
    connection: u64,
    observer: Observer,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut downstream: Buffered<_, Frontend> = Buffered::new_frontend(client);
    let mut upstream: Buffered<_, Backend> = Buffered::new(server);
    let mut rows = 0_usize;

    loop {
        tokio::select! {
            frontend = downstream.receive_wire() => {
                let frontend = frontend?;
                observer(Observation::Protocol {
                    connection,
                    direction: "client -> server",
                    message: format!("{frontend:?}"),
                });
                match &frontend {
                    FrontendMessage::Query(sql) => observer(Observation::Sql {
                        connection,
                        statement: String::from_utf8_lossy(sql).into_owned(),
                    }),
                    FrontendMessage::Parse(parse) => observer(Observation::Sql {
                        connection,
                        statement: String::from_utf8_lossy(&parse.query).into_owned(),
                    }),
                    _ => {}
                }
                let terminate = matches!(frontend, FrontendMessage::Terminate);
                upstream.push(frontend.to_frame()?)?;
                upstream.flush().await?;
                if terminate {
                    return Ok(());
                }
            }
            backend = upstream.receive_wire() => {
                let backend = backend?;
                observer(Observation::Protocol {
                    connection,
                    direction: "server -> client",
                    message: format!("{backend:?}"),
                });
                match &backend {
                    BackendMessage::DataRow(_) => rows = rows.saturating_add(1),
                    BackendMessage::CommandComplete(tag) => {
                        observer(Observation::RowCount {
                            connection,
                            rows,
                            command: String::from_utf8_lossy(tag).into_owned(),
                        });
                        rows = 0;
                    }
                    BackendMessage::ErrorResponse(_) => rows = 0,
                    _ => {}
                }
                downstream.push(backend.to_frame()?)?;
                downstream.flush().await?;
            }
        }
    }
}
