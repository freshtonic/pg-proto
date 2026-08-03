use std::{collections::BTreeMap, error::Error, time::Duration};

use bytes::Bytes;
use pg_proto::{
    Conn,
    auth::{AuthCompletion, AuthOffer, AwaitingStartupReady, PasswordResponse, SaslEvent},
    codec::{
        BackendMessage, Bind, Describe, DescribeTarget, Execute, NegotiateProtocolVersion, Parse,
    },
    demux::SessionItem,
    pre_startup::{Negotiation, Startup},
    session::{
        AwaitingReadyTransition, CopyOutTransition, DrainingTransition, ReadyState,
        SimpleTransition,
    },
    startup::{ProtocolVersion, StartupMessage},
    transport::Buffered,
};
use postgres_protocol::authentication::{
    md5_hash,
    sasl::{ChannelBinding, SCRAM_SHA_256, SCRAM_SHA_256_PLUS, ScramSha256},
};
use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use std::sync::Arc;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{CopyTargetOptions, ImageExt, runners::AsyncRunner},
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

    let SessionItem::Message(BackendMessage::Authentication(authentication)) =
        sasl.receive().await?
    else {
        panic!("PostgreSQL did not continue SASL")
    };
    let SaslEvent::Continue {
        conn: challenge,
        challenge: server_first,
    } = sasl.offer(authentication).unwrap()
    else {
        panic!("PostgreSQL finished SASL before a challenge")
    };
    scram.update(&server_first)?;
    let (mut sasl, response) = challenge.respond(Bytes::copy_from_slice(scram.message()));
    sasl.push_frame(response)?;
    sasl.flush().await?;

    let SessionItem::Message(BackendMessage::Authentication(authentication)) =
        sasl.receive().await?
    else {
        panic!("PostgreSQL did not finish SASL")
    };
    let SaslEvent::Final {
        conn: final_state,
        server_final,
    } = sasl.offer(authentication).unwrap()
    else {
        panic!("PostgreSQL sent another SASL challenge")
    };
    scram.finish(&server_final)?;
    let mut awaiting_ok = final_state.verified();
    let SessionItem::Message(message) = awaiting_ok.receive().await? else {
        panic!("PostgreSQL did not confirm authentication")
    };
    let AuthCompletion::Ok(awaiting_ready) = awaiting_ok.offer(message).unwrap() else {
        panic!("PostgreSQL rejected authentication")
    };
    let ready = finish_startup(awaiting_ready).await?;
    let _transport = ready.into_transport();
    Ok(())
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
#[allow(clippy::too_many_lines)]
async fn scram_sha_256_plus_over_typed_tls_matches_postgres_18() -> Result<(), Box<dyn Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let generated = generate_simple_self_signed(["localhost".into()])?;
    let certificate_pem = generated.cert.pem();
    let private_key_pem = generated.signing_key.serialize_pem();
    let certificate = CertificateDer::from(generated.cert.der().to_vec());
    let postgres = Postgres::default()
        .with_tag("18-alpine")
        .with_user("postgres:root")
        .with_copy_to(
            CopyTargetOptions::new("/tmp/server.crt").with_mode(0o644),
            certificate_pem.into_bytes(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/tmp/server.key").with_mode(0o640),
            private_key_pem.into_bytes(),
        )
        .with_cmd([
            "postgres",
            "-c",
            "ssl=on",
            "-c",
            "ssl_cert_file=/tmp/server.crt",
            "-c",
            "ssl_key_file=/tmp/server.key",
        ])
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let mut awaiting_reply = Conn::new(Buffered::new(stream)).request_ssl();
    awaiting_reply.flush().await?;
    let Negotiation::Accepted(handshake) = awaiting_reply.receive_ssl_reply().await? else {
        panic!("PostgreSQL rejected SSLRequest")
    };
    let pre_startup = handshake
        .connect_tls(ServerName::try_from("localhost")?, client_config)
        .await?;
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
    let (mut startup, packet) = pre_startup.startup(&message)?;
    startup.push_startup_packet(&packet);
    startup.flush().await?;
    let mut auth = startup.authentication();

    let (sasl_initial, mechanisms) = loop {
        if let SessionItem::Message(BackendMessage::Authentication(authentication)) =
            auth.receive().await?
        {
            match auth.offer(authentication)? {
                AuthOffer::Sasl { conn, mechanisms } => break (conn, mechanisms),
                _ => panic!("PostgreSQL did not offer SASL over TLS"),
            }
        }
    };
    assert!(mechanisms.contains(&Bytes::from_static(SCRAM_SHA_256_PLUS.as_bytes())));
    let binding = sasl_initial.tls_server_end_point().to_vec();
    let mut scram = ScramSha256::new(b"postgres", ChannelBinding::tls_server_end_point(binding));
    let (mut sasl, initial) = sasl_initial.scram_sha_256_plus(scram.message())?;
    sasl.push_frame(initial)?;
    sasl.flush().await?;

    let SessionItem::Message(BackendMessage::Authentication(authentication)) =
        sasl.receive().await?
    else {
        panic!("PostgreSQL did not continue SCRAM-PLUS")
    };
    let SaslEvent::Continue {
        conn: challenge,
        challenge: server_first,
    } = sasl.offer(authentication).unwrap()
    else {
        panic!("PostgreSQL finished SCRAM-PLUS before a challenge")
    };
    scram.update(&server_first)?;
    let (mut sasl, response) = challenge.respond(Bytes::copy_from_slice(scram.message()));
    sasl.push_frame(response)?;
    sasl.flush().await?;
    let SessionItem::Message(BackendMessage::Authentication(authentication)) =
        sasl.receive().await?
    else {
        panic!("PostgreSQL did not finish SCRAM-PLUS")
    };
    let SaslEvent::Final {
        conn: final_state,
        server_final,
    } = sasl.offer(authentication).unwrap()
    else {
        panic!("PostgreSQL sent another SCRAM-PLUS challenge")
    };
    scram.finish(&server_final)?;
    let mut awaiting_ok = final_state.verified();
    let SessionItem::Message(message) = awaiting_ok.receive().await? else {
        panic!("PostgreSQL did not confirm SCRAM-PLUS authentication")
    };
    let AuthCompletion::Ok(mut awaiting_ready) = awaiting_ok.offer(message).unwrap() else {
        panic!("PostgreSQL rejected SCRAM-PLUS authentication")
    };
    let ready = loop {
        let item = awaiting_ready.receive().await?;
        match awaiting_ready.offer_ready(item) {
            Ok(ready) => break ready,
            Err((next, _)) => awaiting_ready = next,
        }
    };
    ready.into_transport();
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
    let SessionItem::Message(message) = awaiting_ok.receive().await? else {
        panic!("PostgreSQL rejected the password response")
    };
    let AuthCompletion::Ok(awaiting_ready) = awaiting_ok.offer(message).unwrap() else {
        panic!("PostgreSQL rejected the password response")
    };
    finish_startup(awaiting_ready).await.map(|ready| {
        let _transport = ready.into_transport();
    })
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
    let _transport = ready.into_transport();
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

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn error_response_drains_to_ready_on_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let ready = trust_ready(port).await?;
    let (mut query, frame) = ready.push_query(b"SELECT FROM")?;
    query.push_frame(frame)?;
    query.flush().await?;

    let mut draining = loop {
        let item = query.receive().await?;
        match query.offer(item) {
            Ok(SimpleTransition::Continue(next, _)) | Err((next, _)) => query = next,
            Ok(SimpleTransition::Error(draining, error)) => {
                assert!(
                    error
                        .fields
                        .iter()
                        .any(|field| field.code == b'C' && field.value == "42601")
                );
                break draining;
            }
            Ok(_) => return Err("invalid query did not enter Draining".into()),
        }
    };

    let ready = loop {
        let item = draining.receive().await?;
        match draining.offer(item) {
            DrainingTransition::Continue(next, _) => draining = next,
            DrainingTransition::Ready(ReadyState::Clean(ready)) => break ready,
            DrainingTransition::Ready(ReadyState::Dirty { .. }) => {
                return Err("error drain left a dirty connection".into());
            }
        }
    };
    let _transport = ready.release();
    Ok(())
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn copy_out_nested_session_matches_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let ready = trust_ready(port).await?;
    let (mut query, frame) = ready.push_query(b"COPY (SELECT generate_series(1, 2)) TO STDOUT")?;
    query.push_frame(frame)?;
    query.flush().await?;

    let mut copy = loop {
        let item = query.receive().await?;
        match query.offer(item) {
            Ok(SimpleTransition::Continue(next, _)) | Err((next, _)) => query = next,
            Ok(SimpleTransition::CopyOut(copy, response)) => {
                assert_eq!(response.column_formats, [0]);
                break copy;
            }
            Ok(_) => return Err("COPY OUT did not enter its nested session".into()),
        }
    };

    let mut output = Vec::new();
    let mut awaiting = loop {
        let item = copy.receive().await?;
        match copy.offer(item) {
            Ok(CopyOutTransition::Data(next, data)) => {
                copy = next;
                output.extend_from_slice(&data);
            }
            Ok(CopyOutTransition::Done(awaiting)) => break awaiting,
            Ok(CopyOutTransition::Error(_, error)) => {
                return Err(format!("COPY OUT failed: {error:?}").into());
            }
            Err((next, _)) => copy = next,
        }
    };
    assert_eq!(output, b"1\n2\n");

    let ready = loop {
        let item = awaiting.receive().await?;
        match awaiting.offer(item) {
            AwaitingReadyTransition::Continue(next, _) => awaiting = next,
            AwaitingReadyTransition::Ready(ReadyState::Clean(ready)) => break ready,
            AwaitingReadyTransition::Ready(ReadyState::Dirty { .. }) => {
                return Err("COPY OUT left a dirty connection".into());
            }
            AwaitingReadyTransition::Error(_, error) => {
                return Err(format!("COPY OUT completion failed: {error:?}").into());
            }
        }
    };
    let _transport = ready.release();
    Ok(())
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn copy_in_nested_session_matches_postgres_18() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_init_sql(b"CREATE TABLE copy_test(value integer);".to_vec())
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let ready = trust_ready(port).await?;
    let (mut query, frame) = ready.push_query(b"COPY copy_test FROM STDIN")?;
    query.push_frame(frame)?;
    query.flush().await?;

    let copy = loop {
        let item = query.receive().await?;
        match query.offer(item) {
            Ok(SimpleTransition::Continue(next, _)) | Err((next, _)) => query = next,
            Ok(SimpleTransition::CopyIn(copy, response)) => {
                assert_eq!(response.column_formats, [0]);
                break copy;
            }
            Ok(_) => return Err("COPY IN did not enter its nested session".into()),
        }
    };
    let (mut copy, data) = copy.push_copy_data(Bytes::from_static(b"1\n2\n"));
    copy.push_frame(data)?;
    let (mut awaiting, done) = copy.push_copy_done();
    awaiting.push_frame(done)?;
    awaiting.flush().await?;

    let ready = loop {
        let item = awaiting.receive().await?;
        match awaiting.offer(item) {
            AwaitingReadyTransition::Continue(next, _) => awaiting = next,
            AwaitingReadyTransition::Ready(ReadyState::Clean(ready)) => break ready,
            AwaitingReadyTransition::Ready(ReadyState::Dirty { .. }) => {
                return Err("COPY IN left a dirty connection".into());
            }
            AwaitingReadyTransition::Error(_, error) => {
                return Err(format!("COPY IN failed: {error:?}").into());
            }
        }
    };
    let _transport = ready.release();
    Ok(())
}
