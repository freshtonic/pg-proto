use std::{collections::BTreeMap, error::Error, time::Duration};

use bytes::{Bytes, BytesMut};
use pg_proto::{
    Conn,
    codec::{Backend, BackendMessage, PgCodec},
    startup::{ProtocolVersion, StartupMessage},
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt, runners::AsyncRunner},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::Decoder;

/// Exercises our bytes directly against the official `PostgreSQL` image. Kept
/// ignored so ordinary unit tests do not require a local container runtime.
#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn startup_and_protocol_negotiation_match_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;

    let startup = StartupMessage {
        version: ProtocolVersion::V3_2,
        parameters: BTreeMap::from([
            (Bytes::from_static(b"user"), Bytes::from_static(b"postgres")),
            (
                Bytes::from_static(b"database"),
                Bytes::from_static(b"postgres"),
            ),
            (
                Bytes::from_static(b"_pq_.pg_proto_probe"),
                Bytes::from_static(b"1"),
            ),
        ]),
    };
    let (startup_conn, packet) = Conn::new(stream).startup(&startup)?;
    let mut stream = startup_conn.into_transport();
    stream.write_all(&packet).await?;

    let mut codec = PgCodec::<Backend>::default();
    let mut input = BytesMut::new();
    let mut saw_auth_ok = false;
    let mut negotiation = None;
    let mut saw_backend_key = false;

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let read = stream.read_buf(&mut input).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "PostgreSQL closed before ReadyForQuery",
                ));
            }
            while let Some(message) = codec.decode(&mut input)? {
                match message {
                    BackendMessage::Authentication(pg_proto::codec::Authentication::Ok) => {
                        saw_auth_ok = true;
                    }
                    BackendMessage::NegotiateProtocolVersion(message) => {
                        negotiation = Some(message);
                    }
                    BackendMessage::BackendKeyData { .. } => saw_backend_key = true,
                    BackendMessage::ReadyForQuery(status) => return Ok(status),
                    _ => {}
                }
            }
        }
    })
    .await??;

    assert!(
        saw_auth_ok,
        "server did not authenticate the startup session"
    );
    let negotiation = negotiation.expect("server did not negotiate protocol 3.2 options");
    assert_eq!(negotiation.newest, ProtocolVersion::V3_2);
    assert_eq!(
        negotiation.unsupported_options,
        [Bytes::from_static(b"_pq_.pg_proto_probe")]
    );
    assert!(saw_backend_key, "server did not expose cancellation keys");
    Ok(())
}
