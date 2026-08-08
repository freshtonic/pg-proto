//! Behavioural coverage for the reusable server-role builder.

use std::collections::BTreeMap;

use bytes::Bytes;
use pg_proto::{
    BuildServerError, Server, ServerAccept, ServerProtocolLimits, ServerTlsPolicy,
    TrustServerAuthentication,
    codec::FrontendMessage,
    pre_startup::PreStartupMessage,
    startup::{ProtocolVersion, StartupMessage},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[test]
fn server_build_requires_explicit_security_policies() {
    assert!(matches!(
        Server::builder()
            .authentication(TrustServerAuthentication)
            .build(),
        Err(BuildServerError::MissingTlsPolicy)
    ));
    assert!(matches!(
        Server::builder().tls(ServerTlsPolicy::Disabled).build(),
        Err(BuildServerError::MissingAuthenticationPolicy)
    ));
}

#[tokio::test]
async fn plaintext_trust_accept_reaches_an_operational_session() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(4096);
    let client_task = tokio::spawn(async move {
        let ssl_request = PreStartupMessage::SslRequest.to_packet().unwrap();
        client.write_all(&ssl_request).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), b'N');
        let startup = StartupMessage {
            version: ProtocolVersion::V3_2,
            parameters: BTreeMap::from([(
                Bytes::from_static(b"user"),
                Bytes::from_static(b"alice"),
            )]),
        };
        client.write_all(&startup.encode().unwrap()).await.unwrap();
        let mut response = [0; 15];
        client.read_exact(&mut response).await.unwrap();
        response
    });

    let accepted = server
        .accept(server_io, "peer-1", vec!["initial"])
        .await
        .unwrap();
    let ServerAccept::Session(connection) = accepted else {
        panic!("expected session")
    };
    assert_eq!(connection.context().peer(), &"peer-1");
    assert_eq!(connection.state(), &["initial"]);
    assert_eq!(
        connection.startup().parameters[b"user".as_slice()],
        Bytes::from_static(b"alice")
    );
    let (_transport, state, _handler, context) = connection.teardown();
    assert_eq!(state, vec!["initial"]);
    assert_eq!(context.peer(), &"peer-1");

    let response = client_task.await.unwrap();
    assert_eq!(&response[..9], &[b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
    assert_eq!(response[9], b'Z');
}

#[tokio::test]
async fn cancellation_is_a_distinct_accept_branch_with_owned_parts() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(256);
    let packet = PreStartupMessage::CancelRequest {
        process_id: 42,
        secret_key: Bytes::from_static(b"key!"),
    }
    .to_packet()
    .unwrap();
    client.write_all(&packet).await.unwrap();

    let accepted = server.accept(server_io, "peer-2", 7_u8).await.unwrap();
    let ServerAccept::Cancellation(cancel) = accepted else {
        panic!("expected cancellation")
    };
    assert_eq!(cancel.request().process_id(), 42);
    assert_eq!(cancel.request().secret_key(), b"key!");
    assert!(!format!("{:?}", cancel.request()).contains("key!"));
    let (_transport, request, state, _handler, context) = cancel.teardown();
    assert_eq!(request.process_id(), 42);
    assert_eq!(state, 7);
    assert_eq!(context.peer(), &"peer-2");
}

#[tokio::test]
async fn startup_packet_limit_defaults_conservatively_and_can_be_overridden() {
    let build = |limits| {
        Server::builder()
            .tls(ServerTlsPolicy::Disabled)
            .authentication(TrustServerAuthentication)
            .limits(limits)
            .build()
            .unwrap()
    };
    let oversized = startup_with_value(10_100);
    let default_error =
        accept_packet(build(ServerProtocolLimits::default()), oversized.clone()).await;
    assert!(
        default_error
            .unwrap_err()
            .to_string()
            .contains("configured limit")
    );

    let accepted = accept_packet(
        build(ServerProtocolLimits::default().with_max_pre_startup_packet_len(20_000)),
        oversized,
    )
    .await;
    assert!(accepted.is_ok(), "{accepted:?}");
}

#[tokio::test]
async fn operational_connection_receives_traffic_and_applies_tagged_frame_limit() {
    let accept_query = |limits: ServerProtocolLimits| async move {
        let server = Server::builder()
            .tls(ServerTlsPolicy::Disabled)
            .authentication(TrustServerAuthentication)
            .limits(limits)
            .build()
            .unwrap();
        let (mut client, server_io) = tokio::io::duplex(1024);
        client.write_all(&startup_with_value(1)).await.unwrap();
        let accepted = server.accept(server_io, (), ()).await.unwrap();
        let ServerAccept::Session(mut connection) = accepted else {
            panic!("expected session")
        };
        let client_task = tokio::spawn(async move {
            let mut startup_response = [0; 15];
            client.read_exact(&mut startup_response).await.unwrap();
            client
                .write_all(&[b'Q', 0, 0, 0, 9, b'1', b'2', b'3', b'4', 0])
                .await
                .unwrap();
        });
        let received = connection.receive_wire().await;
        let _ = connection.teardown();
        client_task.await.unwrap();
        received
    };

    assert_eq!(
        accept_query(ServerProtocolLimits::default()).await.unwrap(),
        FrontendMessage::Query(Bytes::from_static(b"1234"))
    );
    let error = accept_query(ServerProtocolLimits::default().with_max_frame_len(9))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("configured"), "{error}");
}

async fn accept_packet(
    server: Server<TrustServerAuthentication>,
    packet: Bytes,
) -> Result<(), pg_proto::AcceptError> {
    let (mut client, server_io) = tokio::io::duplex(32 * 1024);
    client.write_all(&packet).await.unwrap();
    let result = server
        .accept(server_io, (), ())
        .await
        .map(|accepted| match accepted {
            ServerAccept::Session(connection) => {
                let _ = connection.teardown();
            }
            ServerAccept::Cancellation(cancel) => {
                let _ = cancel.teardown();
            }
        });
    drop(client);
    result
}

fn startup_with_value(value_len: usize) -> Bytes {
    StartupMessage {
        version: ProtocolVersion::V3_2,
        parameters: BTreeMap::from([(
            Bytes::from_static(b"application_name"),
            Bytes::from(vec![b'x'; value_len]),
        )]),
    }
    .encode()
    .unwrap()
}
