//! Public behavioural tests for the reusable client-role builder.

use pg_proto::{
    BuildError, Client, ClientTlsPolicy, ConnectTarget, ProtocolLimits, StartupParameters,
    TrustClientAuthentication,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Debug)]
struct BorrowedConnectorError<'a>(&'a str);

impl std::fmt::Display for BorrowedConnectorError<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for BorrowedConnectorError<'_> {}

#[test]
fn client_requires_connector_and_explicit_security_policies() {
    assert_eq!(
        Client::builder().build().unwrap_err(),
        BuildError::MissingConnector
    );
    assert_eq!(
        Client::builder()
            .connector(|_| async { Ok::<_, std::io::Error>(()) })
            .build()
            .unwrap_err(),
        BuildError::MissingTls
    );
    assert_eq!(
        Client::builder()
            .connector(|_| async { Ok::<_, std::io::Error>(()) })
            .tls(ClientTlsPolicy::Disabled)
            .build()
            .unwrap_err(),
        BuildError::MissingAuthentication
    );

    let client = Client::builder()
        .connector(|_| async { Ok::<_, std::io::Error>(()) })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    assert_eq!(
        format!("{client:?}"),
        "Client { tls: Disabled, authentication: Trust, .. }"
    );

    let _ = ConnectTarget::new("in-memory");
    let _ = StartupParameters::new("alice");
}

#[tokio::test]
async fn client_establishes_an_operational_session_and_tears_down_all_parts() {
    let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(async move {
        let length = peer_io.read_u32().await.unwrap();
        let mut body = vec![0; usize::try_from(length).unwrap() - 4];
        peer_io.read_exact(&mut body).await.unwrap();
        let startup = pg_proto::StartupMessage::decode(
            [length.to_be_bytes().as_slice(), body.as_slice()]
                .concat()
                .into(),
        )
        .unwrap();
        assert_eq!(
            startup.parameters.get(b"user".as_slice()).unwrap(),
            "default-user"
        );
        assert_eq!(
            startup.parameters.get(b"database".as_slice()).unwrap(),
            "call-db"
        );
        assert_eq!(
            startup
                .parameters
                .get(b"application_name".as_slice())
                .unwrap(),
            "builder-test"
        );

        peer_io
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
            .await
            .unwrap();
        let body = b"server_version\0test\0";
        peer_io.write_u8(b'S').await.unwrap();
        peer_io
            .write_u32(u32::try_from(body.len() + 4).unwrap())
            .await
            .unwrap();
        peer_io.write_all(body).await.unwrap();
        peer_io.flush().await.unwrap();

        assert_eq!(peer_io.read_u8().await.unwrap(), b'Q');
        let query_length = peer_io.read_u32().await.unwrap();
        let mut query = vec![0; usize::try_from(query_length).unwrap() - 4];
        peer_io.read_exact(&mut query).await.unwrap();
        assert_eq!(query, b"SELECT 1\0");
        peer_io
            .write_all(&[
                b'C', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', 0, b'Z', 0, 0,
                0, 5, b'I',
            ])
            .await
            .unwrap();
        peer_io.flush().await.unwrap();
    });
    let transport = std::sync::Mutex::new(Some(client_io));
    let client = Client::builder()
        .connector(move |_| {
            let transport = transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .startup_parameters(
            StartupParameters::new("default-user")
                .database("default-db")
                .extension("application_name", "builder-test")
                .unwrap(),
        )
        .build()
        .unwrap();

    let mut connection = client
        .connect(
            ConnectTarget::new("in-memory"),
            StartupParameters::default().database("call-db"),
            vec!["caller-state"],
        )
        .await
        .unwrap();
    assert!(matches!(
        connection.receive_wire().await.unwrap(),
        pg_proto::BackendMessage::ParameterStatus { name, value }
            if name == "server_version" && value == "test"
    ));
    let (connection, responses) = connection.simple_query(b"SELECT 1").await.unwrap();
    assert!(matches!(
        responses.as_slice(),
        [
            pg_proto::BackendMessage::CommandComplete(tag),
            pg_proto::BackendMessage::ReadyForQuery(_)
        ] if tag == "SELECT 1"
    ));
    let (_transport, state, handler, context) = connection.into_parts();
    assert_eq!(state, ["caller-state"]);
    assert_eq!(handler, pg_proto::IdentityHandler);
    assert_eq!(context.target().name(), "in-memory");
    peer.await.unwrap();
}

#[test]
fn startup_extensions_reject_reserved_standard_fields() {
    let error = StartupParameters::default()
        .extension("user", "shadow-user")
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "startup extension name `user` is reserved"
    );
    let parameters = StartupParameters::new("secret-user")
        .extension("secret", "secret-value")
        .unwrap();
    assert!(!format!("{parameters:?}").contains("secret"));
    assert!(!format!("{:?}", ConnectTarget::new("secret-host")).contains("secret-host"));
}

#[tokio::test]
async fn missing_startup_user_is_a_structured_pre_network_error() {
    let connector_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = std::sync::Arc::clone(&connector_called);
    let client = Client::builder()
        .connector(move |_| {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            async { Ok::<_, std::io::Error>(tokio::io::duplex(64).0) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let Err(pg_proto::ConnectError::Startup(error)) = client
        .connect(
            ConnectTarget::new("never-connected"),
            StartupParameters::default(),
            (),
        )
        .await
    else {
        panic!("missing startup user was not reported structurally")
    };
    assert_eq!(error, pg_proto::StartupParameterError::MissingUser);
    assert!(!connector_called.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn connector_errors_may_borrow_without_global_concurrency_or_static_bounds() {
    let detail = String::from("borrowed connector failure");
    let client = Client::builder()
        .connector(|_| async { Err::<tokio::io::DuplexStream, _>(BorrowedConnectorError(&detail)) })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let Err(pg_proto::ConnectError::Connector(error)) = client
        .connect(
            ConnectTarget::new("borrowed"),
            StartupParameters::new("alice"),
            (),
        )
        .await
    else {
        panic!("borrowed connector error was not preserved")
    };
    assert_eq!(error.0, "borrowed connector failure");
}

#[tokio::test]
async fn explicit_frame_limit_rejects_an_oversized_authentication_message() {
    let (client_io, mut peer_io) = tokio::io::duplex(1024);
    let peer = tokio::spawn(async move {
        let length = peer_io.read_u32().await.unwrap();
        let mut body = vec![0; usize::try_from(length).unwrap() - 4];
        peer_io.read_exact(&mut body).await.unwrap();
        peer_io
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let transport = std::sync::Mutex::new(Some(client_io));
    let client = Client::builder()
        .connector(move |_| {
            let transport = transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .protocol_limits(ProtocolLimits::default().max_frame_len(8).unwrap())
        .build()
        .unwrap();

    let Err(error) = client
        .connect(
            ConnectTarget::new("limited"),
            StartupParameters::new("alice"),
            (),
        )
        .await
    else {
        panic!("oversized authentication frame was accepted")
    };
    assert!(error.to_string().contains("frame"));
    peer.await.unwrap();
}

#[tokio::test]
async fn trust_authentication_rejects_a_credential_challenge_without_panicking() {
    let (client_io, mut peer_io) = tokio::io::duplex(1024);
    let peer = tokio::spawn(async move {
        let length = peer_io.read_u32().await.unwrap();
        let mut body = vec![0; usize::try_from(length).unwrap() - 4];
        peer_io.read_exact(&mut body).await.unwrap();
        peer_io
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3])
            .await
            .unwrap();
    });
    let transport = std::sync::Mutex::new(Some(client_io));
    let client = Client::builder()
        .connector(move |_| {
            let transport = transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let Err(error) = client
        .connect(
            ConnectTarget::new("challenge"),
            StartupParameters::new("alice"),
            (),
        )
        .await
    else {
        panic!("credential challenge was accepted")
    };
    assert!(error.to_string().contains("credential challenge"));
    peer.await.unwrap();
}

#[tokio::test]
async fn conservative_default_and_explicit_risk_override_change_live_frame_acceptance() {
    async fn attempt(limits: ProtocolLimits) -> String {
        let (client_io, mut peer_io) = tokio::io::duplex(2 * 1024 * 1024);
        let peer = tokio::spawn(async move {
            let length = peer_io.read_u32().await.unwrap();
            let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
            peer_io.read_exact(&mut startup).await.unwrap();
            let mut body = vec![b'M'];
            body.extend(std::iter::repeat_n(b'x', 1024 * 1024));
            body.extend_from_slice(&[0, 0]);
            peer_io.write_u8(b'E').await.unwrap();
            peer_io
                .write_u32(u32::try_from(body.len() + 4).unwrap())
                .await
                .unwrap();
            peer_io.write_all(&body).await.unwrap();
        });
        let transport = std::sync::Mutex::new(Some(client_io));
        let client = Client::builder()
            .connector(move |_| {
                let transport = transport.lock().unwrap().take().unwrap();
                async move { Ok::<_, std::io::Error>(transport) }
            })
            .tls(ClientTlsPolicy::Disabled)
            .authentication(TrustClientAuthentication)
            .protocol_limits(limits)
            .build()
            .unwrap();
        let Err(error) = client
            .connect(
                ConnectTarget::new("large-frame"),
                StartupParameters::new("alice"),
                (),
            )
            .await
        else {
            panic!("authentication error unexpectedly established a session")
        };
        peer.await.unwrap();
        error.to_string()
    }

    let default_error = attempt(ProtocolLimits::default()).await;
    assert!(default_error.contains("frame"));
    let explicit_override_error = attempt(ProtocolLimits::default().without_frame_limit()).await;
    assert_eq!(explicit_override_error, "server rejected authentication");
}
