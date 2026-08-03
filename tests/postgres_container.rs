use std::{collections::BTreeMap, error::Error, time::Duration};

use bytes::Bytes;
use pg_proto::{
    Conn,
    auth::{AuthOffer, AwaitingStartupReady},
    codec::{Authentication, BackendMessage, NegotiateProtocolVersion},
    demux::SessionItem,
    pre_startup::Startup,
    startup::{ProtocolVersion, StartupMessage},
    transport::Buffered,
};
use postgres_protocol::authentication::sasl::{ChannelBinding, SCRAM_SHA_256, ScramSha256};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt, runners::AsyncRunner},
};

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
    let mut startup_conn = startup_conn.map_transport(Buffered::new);
    startup_conn.push_startup_packet(&packet);
    startup_conn.flush().await?;

    let mut auth = startup_conn.authentication();
    let mut negotiation = None;
    let mut awaiting_ready = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SessionItem::Message(message) = auth.receive().await? {
                match message {
                    BackendMessage::Authentication(authentication) => {
                        return match auth.offer(authentication)? {
                            AuthOffer::Ok(conn) => Ok(conn),
                            _ => Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "trust-authenticated server requested credentials",
                            )),
                        };
                    }
                    BackendMessage::NegotiateProtocolVersion(message) => {
                        negotiation = Some(message);
                    }
                    _ => {}
                }
            }
        }
    })
    .await??;

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                awaiting_ready.receive().await?,
                SessionItem::Message(BackendMessage::ReadyForQuery(_))
            ) {
                return Ok::<_, std::io::Error>(());
            }
        }
    })
    .await??;

    assert_negotiation(negotiation);
    assert!(
        awaiting_ready.cancel_key().is_some(),
        "server did not expose cancellation keys"
    );

    let ready = awaiting_ready.ready();
    let (mut query, frame) = ready.push_query(b"SELECT 42::int4")?;
    query.push_frame(frame)?;
    query.flush().await?;
    let mut saw_row_description = false;
    let mut saw_data_row = false;
    let mut saw_command_complete = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match query.receive().await? {
                SessionItem::Message(BackendMessage::RowDescription(_)) => {
                    saw_row_description = true;
                }
                SessionItem::Message(BackendMessage::Recognised(frame)) if frame.tag == b'D' => {
                    saw_data_row = true;
                }
                SessionItem::CommandComplete { .. } => saw_command_complete = true,
                SessionItem::Message(BackendMessage::ReadyForQuery(_)) => {
                    return Ok::<_, std::io::Error>(());
                }
                SessionItem::Message(_) => {}
            }
        }
    })
    .await??;
    assert!(saw_row_description);
    assert!(saw_data_row);
    assert!(saw_command_complete);

    let ready = query.response_complete().ready();
    let _transport = ready.release();
    Ok(())
}

fn assert_negotiation(negotiation: Option<NegotiateProtocolVersion>) {
    let negotiation = negotiation.expect("server did not negotiate protocol 3.2 options");
    assert_eq!(negotiation.newest, ProtocolVersion::V3_2);
    assert_eq!(
        negotiation.unsupported_options,
        [Bytes::from_static(b"_pq_.pg_proto_probe")]
    );
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn scram_sha_256_matches_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default().with_tag("18-alpine").start().await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let startup = connected_startup(port).await?;
    let mut auth = startup.authentication();

    let (sasl_initial, mechanisms) = loop {
        if let SessionItem::Message(BackendMessage::Authentication(authentication)) =
            auth.receive().await?
        {
            match auth.offer(authentication)? {
                AuthOffer::Sasl { conn, mechanisms } => break (conn, mechanisms),
                _ => panic!("PostgreSQL did not offer SASL"),
            }
        }
    };
    assert!(mechanisms.contains(&Bytes::from_static(SCRAM_SHA_256.as_bytes())));

    let mut scram = ScramSha256::new(b"postgres", ChannelBinding::unsupported());
    let (mut sasl, initial) = sasl_initial.scram_sha_256(scram.message())?;
    sasl.push_frame(initial)?;
    sasl.flush().await?;

    let SessionItem::Message(BackendMessage::Authentication(Authentication::SaslContinue(
        server_first,
    ))) = sasl.receive().await?
    else {
        panic!("PostgreSQL did not continue SASL")
    };
    scram.update(&server_first)?;
    let (mut sasl, response) = sasl.continue_with(Bytes::copy_from_slice(scram.message()));
    sasl.push_frame(response)?;
    sasl.flush().await?;

    let SessionItem::Message(BackendMessage::Authentication(Authentication::SaslFinal(
        server_final,
    ))) = sasl.receive().await?
    else {
        panic!("PostgreSQL did not finish SASL")
    };
    scram.finish(&server_final)?;
    let mut awaiting_ok = sasl.server_final(server_final);
    let SessionItem::Message(BackendMessage::Authentication(Authentication::Ok)) =
        awaiting_ok.receive().await?
    else {
        panic!("PostgreSQL did not confirm authentication")
    };
    let awaiting_ready = awaiting_ok.authentication_ok();
    finish_startup(awaiting_ready).await?;
    Ok(())
}

async fn connected_startup(
    port: u16,
) -> Result<Conn<Buffered<tokio::net::TcpStream>, Startup>, Box<dyn Error>> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let message = StartupMessage {
        version: ProtocolVersion::V3_2,
        parameters: BTreeMap::from([
            (Bytes::from_static(b"user"), Bytes::from_static(b"postgres")),
            (
                Bytes::from_static(b"database"),
                Bytes::from_static(b"postgres"),
            ),
        ]),
    };
    let (conn, packet) = Conn::new(stream).startup(&message)?;
    let mut conn = conn.map_transport(Buffered::new);
    conn.push_startup_packet(&packet);
    conn.flush().await?;
    Ok(conn)
}

async fn finish_startup(
    mut conn: Conn<Buffered<tokio::net::TcpStream>, AwaitingStartupReady>,
) -> Result<(), Box<dyn Error>> {
    loop {
        if matches!(
            conn.receive().await?,
            SessionItem::Message(BackendMessage::ReadyForQuery(_))
        ) {
            let _ready = conn.ready();
            return Ok(());
        }
    }
}
