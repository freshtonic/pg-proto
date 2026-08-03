use std::{collections::BTreeMap, error::Error, time::Duration};

use bytes::Bytes;
use pg_proto::{
    Conn,
    auth::{AuthOffer, AwaitingStartupReady, PasswordResponse},
    codec::{
        Authentication, BackendMessage, Bind, Describe, DescribeTarget, Execute,
        NegotiateProtocolVersion, Parse,
    },
    demux::SessionItem,
    pre_startup::Startup,
    session::{AwaitingReadyTransition, ReadyState, SimpleTransition},
    startup::{ProtocolVersion, StartupMessage},
    transport::Buffered,
};
use postgres_protocol::authentication::{
    md5_hash,
    sasl::{ChannelBinding, SCRAM_SHA_256, ScramSha256},
};
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
    let awaiting_ready = tokio::time::timeout(Duration::from_secs(10), async {
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

    let ready = finish_startup(awaiting_ready).await?;

    assert_negotiation(negotiation);
    assert!(
        ready.cancel_key().is_some(),
        "server did not expose cancellation keys"
    );

    run_select_42(ready).await?;
    Ok(())
}

async fn run_select_42(
    ready: Conn<Buffered<tokio::net::TcpStream>, pg_proto::auth::Ready>,
) -> Result<(), Box<dyn Error>> {
    let (mut query, frame) = ready.push_query(b"SELECT 42::int4")?;
    query.push_frame(frame)?;
    query.flush().await?;
    let mut saw_row_description = false;
    let mut saw_data_row = false;
    let mut saw_command_complete = false;
    let ready = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let item = query.receive().await?;
            match query.offer(item) {
                Ok(SimpleTransition::Continue(next, item)) => {
                    query = next;
                    match item {
                        SessionItem::Message(BackendMessage::RowDescription(_)) => {
                            saw_row_description = true;
                        }
                        SessionItem::Message(BackendMessage::DataRow(_)) => {
                            saw_data_row = true;
                        }
                        SessionItem::CommandComplete { .. } => saw_command_complete = true,
                        SessionItem::Message(_) => {}
                        SessionItem::ReadyForQuery { .. } => {
                            unreachable!("ReadyForQuery cannot be a Continue transition")
                        }
                    }
                }
                Ok(SimpleTransition::Ready(ReadyState::Clean(ready))) => {
                    return Ok::<_, std::io::Error>(ready);
                }
                Ok(SimpleTransition::Ready(ReadyState::Dirty { .. })) => {
                    return Err(std::io::Error::other("query left a dirty connection"));
                }
                Ok(SimpleTransition::Error(_, _)) => {
                    return Err(std::io::Error::other("query returned ErrorResponse"));
                }
                Ok(
                    SimpleTransition::CopyIn(_, _)
                    | SimpleTransition::CopyOut(_, _)
                    | SimpleTransition::CopyBoth(_, _),
                ) => {
                    return Err(std::io::Error::other("query unexpectedly entered COPY"));
                }
                Err((_next, _item)) => {
                    return Err(std::io::Error::other("illegal simple-query response"));
                }
            }
        }
    })
    .await??;
    assert!(saw_row_description);
    assert!(saw_data_row);
    assert!(saw_command_complete);

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
    let _ready = finish_startup(awaiting_ready).await?;
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
) -> Result<Conn<Buffered<tokio::net::TcpStream>, pg_proto::auth::Ready>, Box<dyn Error>> {
    loop {
        let item = conn.receive().await?;
        match conn.offer_ready(item) {
            Ok(ready) => return Ok(ready),
            Err((next, _item)) => conn = next,
        }
    }
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn cleartext_password_matches_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_tag("18-alpine")
        .with_env_var("POSTGRES_HOST_AUTH_METHOD", "password")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let offer = receive_auth_offer(connected_startup(port).await?).await?;
    let AuthOffer::Cleartext(conn) = offer else {
        panic!("PostgreSQL did not offer cleartext password authentication")
    };
    submit_password(conn, b"postgres").await
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn md5_password_matches_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_init_sql(
            b"SET password_encryption = 'md5'; ALTER ROLE postgres PASSWORD 'postgres';".to_vec(),
        )
        .with_tag("18-alpine")
        .with_env_var("POSTGRES_HOST_AUTH_METHOD", "md5")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let offer = receive_auth_offer(connected_startup(port).await?).await?;
    let AuthOffer::Md5 { conn, salt } = offer else {
        panic!("PostgreSQL did not offer MD5 password authentication")
    };
    let response = md5_hash(b"postgres", b"postgres", salt);
    submit_password(conn, response.as_bytes()).await
}

async fn receive_auth_offer(
    startup: Conn<Buffered<tokio::net::TcpStream>, Startup>,
) -> Result<AuthOffer<Buffered<tokio::net::TcpStream>>, Box<dyn Error>> {
    let mut auth = startup.authentication();
    loop {
        if let SessionItem::Message(BackendMessage::Authentication(authentication)) =
            auth.receive().await?
        {
            return Ok(auth.offer(authentication)?);
        }
    }
}

async fn submit_password(
    conn: Conn<Buffered<tokio::net::TcpStream>, PasswordResponse>,
    password: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (mut awaiting_ok, frame) = conn.password(password)?;
    awaiting_ok.push_frame(frame)?;
    awaiting_ok.flush().await?;
    let SessionItem::Message(BackendMessage::Authentication(Authentication::Ok)) =
        awaiting_ok.receive().await?
    else {
        panic!("PostgreSQL rejected the password response")
    };
    finish_startup(awaiting_ok.authentication_ok())
        .await
        .map(|_ready| ())
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn extended_query_pipeline_matches_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let ready = trust_ready(port).await?;

    let building = ready.begin_extended();
    let (mut building, frame) = building.push_parse(&Parse {
        statement: Bytes::from_static(b"answer"),
        query: Bytes::from_static(b"SELECT $1::int4"),
        parameter_types: vec![23],
    })?;
    building.push_frame(frame)?;
    let (mut bound, frame) = building.push_bind(&Bind {
        portal: Bytes::from_static(b"answer_portal"),
        statement: Bytes::from_static(b"answer"),
        parameter_formats: vec![0],
        parameters: vec![Some(Bytes::from_static(b"42"))],
        result_formats: vec![0],
    })?;
    bound.push_frame(frame)?;
    let (mut bound, frame) = bound.push_describe(&Describe {
        target: DescribeTarget::Portal,
        name: Bytes::from_static(b"answer_portal"),
    })?;
    bound.push_frame(frame)?;
    let (mut bound, frame) = bound.push_execute(&Execute {
        portal: Bytes::from_static(b"answer_portal"),
        max_rows: 0,
    })?;
    bound.push_frame(frame)?;
    let (mut awaiting, frame) = bound.push_sync();
    awaiting.push_frame(frame)?;
    awaiting.flush().await?;

    let mut parse_complete = false;
    let mut bind_complete = false;
    let mut row_description = false;
    let mut data_row = false;
    let ready = loop {
        let item = awaiting.receive().await?;
        match awaiting.offer(item) {
            AwaitingReadyTransition::Continue(next, item) => {
                awaiting = next;
                match item {
                    SessionItem::Message(BackendMessage::ParseComplete) => parse_complete = true,
                    SessionItem::Message(BackendMessage::BindComplete) => bind_complete = true,
                    SessionItem::Message(BackendMessage::RowDescription(_)) => {
                        row_description = true;
                    }
                    SessionItem::Message(BackendMessage::DataRow(_)) => data_row = true,
                    _ => {}
                }
            }
            AwaitingReadyTransition::Ready(ReadyState::Clean(ready)) => break ready,
            AwaitingReadyTransition::Ready(ReadyState::Dirty { .. }) => {
                return Err("extended query left a dirty connection".into());
            }
            AwaitingReadyTransition::Error(_, error) => {
                return Err(format!("extended query failed: {error:?}").into());
            }
        }
    };
    assert!(parse_complete && bind_complete && row_description && data_row);
    let _transport = ready.release();
    Ok(())
}

async fn trust_ready(
    port: u16,
) -> Result<Conn<Buffered<tokio::net::TcpStream>, pg_proto::auth::Ready>, Box<dyn Error>> {
    let offer = receive_auth_offer(connected_startup(port).await?).await?;
    let AuthOffer::Ok(awaiting_ready) = offer else {
        return Err("PostgreSQL did not use trust authentication".into());
    };
    finish_startup(awaiting_ready).await
}
