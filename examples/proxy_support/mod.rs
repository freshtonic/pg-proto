use std::{error::Error, io, net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use pg_proto::{
    codec::{Backend, BackendMessage, Frontend, FrontendMessage},
    pre_startup::{PreStartupMessage, decode_pre_startup},
    transport::Buffered,
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
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
    observer: Observer,
) -> io::Result<()> {
    let mut next_connection = 1_u64;
    loop {
        let (client, _) = listener.accept().await?;
        let connection = next_connection;
        next_connection = next_connection.wrapping_add(1);
        let observer = Arc::clone(&observer);
        tokio::spawn(async move {
            if let Err(error) = proxy_connection(client, upstream, connection, observer).await {
                eprintln!("connection {connection}: {error}");
            }
        });
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    upstream: SocketAddr,
    connection: u64,
    observer: Observer,
) -> io::Result<()> {
    loop {
        let message = read_pre_startup(&mut client).await?;
        observer(Observation::Protocol {
            connection,
            direction: "client -> server",
            message: format!("{message:?}"),
        });
        match message {
            PreStartupMessage::SslRequest | PreStartupMessage::GssEncRequest => {
                // These examples deliberately keep the session inspectable. A
                // production proxy would terminate TLS here with pg-proto's
                // changing-transport pre-startup API.
                client.write_all(b"N").await?;
                observer(Observation::Protocol {
                    connection,
                    direction: "server -> client",
                    message: "EncryptionRejected".to_owned(),
                });
            }
            PreStartupMessage::CancelRequest { .. } => {
                let mut server = TcpStream::connect(upstream).await?;
                server.write_all(&message.to_packet()?).await?;
                return Ok(());
            }
            PreStartupMessage::Startup(_) => {
                let mut server = TcpStream::connect(upstream).await?;
                server.write_all(&message.to_packet()?).await?;
                return forward_tagged(client, server, connection, observer).await;
            }
        }
    }
}

async fn read_pre_startup(client: &mut TcpStream) -> io::Result<PreStartupMessage> {
    let wire_length = client.read_u32().await?;
    let length = usize::try_from(wire_length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "packet length overflow"))?;
    if !(8..=pg_proto::pre_startup::DEFAULT_MAX_PRE_STARTUP_PACKET_LEN).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pre-startup packet length is outside the configured limit",
        ));
    }
    let mut packet = BytesMut::with_capacity(length);
    packet.extend_from_slice(&wire_length.to_be_bytes());
    packet.resize(length, 0);
    client.read_exact(&mut packet[4..]).await?;
    decode_pre_startup(&mut packet)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete pre-startup packet",
        )
    })
}

async fn forward_tagged(
    client: TcpStream,
    server: TcpStream,
    connection: u64,
    observer: Observer,
) -> io::Result<()> {
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
