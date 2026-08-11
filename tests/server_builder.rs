//! Behavioural coverage for the reusable server-role builder.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use pg_proto::{
    BuildServerError, DisabledServerTls, FrontendMessage, NegotiatedServerTls, PreStartupMessage,
    ProtocolVersion, Server, ServerAccept, ServerAuthentication, ServerAuthenticationAction,
    ServerAuthenticationProvider, ServerAuthenticationRequest, ServerAuthenticationResponse,
    ServerIdentity, ServerIdentityProvider, ServerProtocolLimits, ServerTlsPolicy, StartupMessage,
    TrustServerAuthentication,
};
use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use sha2::{Digest as _, Sha256};
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

#[derive(Clone)]
struct ReloadingIdentity {
    resolutions: Arc<AtomicUsize>,
    identity: ServerIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentityUnavailable;

struct FailingIdentity;

impl ServerIdentityProvider for FailingIdentity {
    type Error = IdentityUnavailable;

    fn resolve(&self) -> Result<ServerIdentity, Self::Error> {
        Err(IdentityUnavailable)
    }
}

impl ServerIdentityProvider for ReloadingIdentity {
    type Error = Infallible;

    fn resolve(&self) -> Result<ServerIdentity, Self::Error> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(self.identity.clone())
    }
}

#[derive(Clone)]
struct AuthenticationFactory {
    instances: Arc<AtomicUsize>,
    expected_binding: Option<Bytes>,
}

struct AuthenticationSession {
    expected_binding: Option<Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserIdentity(String);

#[derive(Clone, Copy)]
struct Md5AuthenticationFactory;

struct Md5Authentication;

#[derive(Clone, Copy)]
enum TokenMethod {
    Kerberos,
    Gss,
    Sspi,
}
struct TokenAuthenticationFactory(TokenMethod);
struct InvalidSaslAuthentication;

impl ServerAuthenticationProvider for InvalidSaslAuthentication {
    type Authentication = Self;
    fn create(&self) -> Self::Authentication {
        Self
    }
}

impl ServerAuthentication<()> for InvalidSaslAuthentication {
    type Identity = ();
    type Error = Infallible;
    async fn start(
        &mut self,
        _request: ServerAuthenticationRequest<'_, ()>,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        Ok(ServerAuthenticationAction::Sasl {
            mechanisms: vec![Bytes::from_static(b"bad\0mechanism")],
        })
    }
    async fn respond(
        &mut self,
        _request: ServerAuthenticationRequest<'_, ()>,
        _response: ServerAuthenticationResponse,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        unreachable!()
    }
}

struct TokenAuthentication {
    method: TokenMethod,
    responses: usize,
}

impl ServerAuthenticationProvider for TokenAuthenticationFactory {
    type Authentication = TokenAuthentication;
    fn create(&self) -> Self::Authentication {
        TokenAuthentication {
            method: self.0,
            responses: 0,
        }
    }
}

impl ServerAuthentication<()> for TokenAuthentication {
    type Identity = &'static str;
    type Error = Infallible;

    async fn start(
        &mut self,
        _request: ServerAuthenticationRequest<'_, ()>,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        let action = match self.method {
            TokenMethod::Kerberos => ServerAuthenticationAction::KerberosV5,
            TokenMethod::Gss => ServerAuthenticationAction::Gss,
            TokenMethod::Sspi => ServerAuthenticationAction::Sspi,
        };
        Ok(action)
    }

    async fn respond(
        &mut self,
        _request: ServerAuthenticationRequest<'_, ()>,
        response: ServerAuthenticationResponse,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        let ServerAuthenticationResponse::Token(token) = response else {
            unreachable!()
        };
        self.responses += 1;
        Ok(
            if matches!(self.method, TokenMethod::Gss) && self.responses == 1 {
                assert_eq!(token, b"client-one".as_slice());
                ServerAuthenticationAction::GssContinue(Bytes::from_static(b"server-two"))
            } else {
                if matches!(self.method, TokenMethod::Gss) {
                    assert_eq!(token, b"client-three".as_slice());
                }
                ServerAuthenticationAction::Accept("gss-user")
            },
        )
    }
}

impl ServerAuthenticationProvider for Md5AuthenticationFactory {
    type Authentication = Md5Authentication;

    fn create(&self) -> Self::Authentication {
        Md5Authentication
    }
}

impl ServerAuthentication<()> for Md5Authentication {
    type Identity = Vec<u8>;
    type Error = Infallible;

    async fn start(
        &mut self,
        _request: ServerAuthenticationRequest<'_, ()>,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        Ok(ServerAuthenticationAction::Md5Password { salt: [1, 2, 3, 4] })
    }

    async fn respond(
        &mut self,
        _request: ServerAuthenticationRequest<'_, ()>,
        response: ServerAuthenticationResponse,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        let ServerAuthenticationResponse::Password(body) = response else {
            unreachable!()
        };
        Ok(ServerAuthenticationAction::Accept(body.to_vec()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticationFailure(&'static str);

impl ServerAuthenticationProvider for AuthenticationFactory {
    type Authentication = AuthenticationSession;

    fn create(&self) -> Self::Authentication {
        self.instances.fetch_add(1, Ordering::SeqCst);
        AuthenticationSession {
            expected_binding: self.expected_binding.clone(),
        }
    }
}

impl ServerAuthentication<&str> for AuthenticationSession {
    type Identity = UserIdentity;
    type Error = AuthenticationFailure;

    async fn start(
        &mut self,
        _request: ServerAuthenticationRequest<'_, &str>,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        Ok(ServerAuthenticationAction::CleartextPassword)
    }

    async fn respond(
        &mut self,
        request: ServerAuthenticationRequest<'_, &str>,
        response: ServerAuthenticationResponse,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        let ServerAuthenticationResponse::Password(credential) = response else {
            unreachable!()
        };
        if credential != b"secret".as_slice() {
            return Err(AuthenticationFailure("invalid password"));
        }
        if *request.peer() != "peer" {
            return Err(AuthenticationFailure("unexpected peer"));
        }
        let user = request
            .startup()
            .parameters
            .get(b"user".as_slice())
            .ok_or(AuthenticationFailure("user is required"))?;
        if let Some(expected) = &self.expected_binding {
            let NegotiatedServerTls::Tls { server_end_point } = request.tls() else {
                panic!("expected TLS authentication facts")
            };
            assert_eq!(server_end_point, expected);
        }
        Ok(ServerAuthenticationAction::Accept(UserIdentity(
            String::from_utf8_lossy(user).into_owned(),
        )))
    }
}

#[tokio::test]
async fn required_tls_and_async_authentication_enrich_connection_context() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let generated = generate_simple_self_signed(["localhost".into()]).unwrap();
    let certificate = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der()).unwrap();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap(),
    );
    let resolutions = Arc::new(AtomicUsize::new(0));
    let instances = Arc::new(AtomicUsize::new(0));
    let provider = ReloadingIdentity {
        resolutions: resolutions.clone(),
        identity: ServerIdentity::new(server_config, certificate.clone()),
    };
    let expected_binding = Bytes::copy_from_slice(&Sha256::digest(certificate.as_ref()));
    let server = Server::builder()
        .tls(ServerTlsPolicy::Required(provider))
        .authentication(AuthenticationFactory {
            instances: instances.clone(),
            expected_binding: Some(expected_binding),
        })
        .build()
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let (mut client, server_io) = tokio::io::duplex(16 * 1024);
    let first_client_config = client_config.clone();
    let client_task = tokio::spawn(async move {
        client
            .write_all(&PreStartupMessage::SslRequest.to_packet().unwrap())
            .await
            .unwrap();
        assert_eq!(client.read_u8().await.unwrap(), b'S');
        let mut client = tokio_rustls::TlsConnector::from(first_client_config)
            .connect(ServerName::try_from("localhost").unwrap(), client)
            .await
            .unwrap();
        client.write_all(&startup_with_user("alice")).await.unwrap();
        let mut challenge = [0; 9];
        client.read_exact(&mut challenge).await.unwrap();
        assert_eq!(challenge, [b'R', 0, 0, 0, 8, 0, 0, 0, 3]);
        client.write_all(&password_packet(b"secret")).await.unwrap();
        let mut response = [0; 15];
        client.read_exact(&mut response).await.unwrap();
    });

    let accepted = server.accept(server_io, "peer", ()).await.unwrap();
    let ServerAccept::Session(connection) = accepted else {
        panic!("expected session")
    };
    assert!(matches!(
        connection.context().tls(),
        NegotiatedServerTls::Tls { server_end_point } if !server_end_point.is_empty()
    ));
    assert_eq!(
        connection.context().identity(),
        &UserIdentity("alice".into())
    );
    let _ = connection.teardown();
    client_task.await.unwrap();
    let (mut client, server_io) = tokio::io::duplex(16 * 1024);
    let client_task = tokio::spawn(async move {
        client
            .write_all(&PreStartupMessage::SslRequest.to_packet().unwrap())
            .await
            .unwrap();
        assert_eq!(client.read_u8().await.unwrap(), b'S');
        let mut client = tokio_rustls::TlsConnector::from(client_config)
            .connect(ServerName::try_from("localhost").unwrap(), client)
            .await
            .unwrap();
        client.write_all(&startup_with_user("bob")).await.unwrap();
        let mut challenge = [0; 9];
        client.read_exact(&mut challenge).await.unwrap();
        client.write_all(&password_packet(b"secret")).await.unwrap();
        let mut response = [0; 15];
        client.read_exact(&mut response).await.unwrap();
    });
    let accepted = server.accept(server_io, "peer", ()).await.unwrap();
    let ServerAccept::Session(connection) = accepted else {
        panic!("expected second session")
    };
    assert_eq!(connection.context().identity(), &UserIdentity("bob".into()));
    let _ = connection.teardown();
    client_task.await.unwrap();
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(instances.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn required_tls_rejects_plaintext_and_authentication_rejection_is_typed() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let generated = generate_simple_self_signed(["localhost".into()]).unwrap();
    let certificate = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der()).unwrap();
    let provider = ReloadingIdentity {
        resolutions: Arc::new(AtomicUsize::new(0)),
        identity: ServerIdentity::new(
            Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![certificate.clone()], key)
                    .unwrap(),
            ),
            certificate,
        ),
    };
    let server = Server::builder()
        .tls(ServerTlsPolicy::Required(provider))
        .authentication(AuthenticationFactory {
            instances: Arc::new(AtomicUsize::new(0)),
            expected_binding: None,
        })
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(1024);
    client.write_all(&startup_with_user("alice")).await.unwrap();
    assert!(matches!(
        server.accept(server_io, "peer", ()).await,
        Err(pg_proto::AcceptError::TlsRequired)
    ));

    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(AuthenticationFactory {
            instances: Arc::new(AtomicUsize::new(0)),
            expected_binding: None,
        })
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(1024);
    client.write_all(&startup_with_value(1)).await.unwrap();
    let accept = server.accept(server_io, "peer", ());
    let client_exchange = async {
        let mut challenge = [0; 9];
        client.read_exact(&mut challenge).await.unwrap();
        client.write_all(&password_packet(b"secret")).await.unwrap();
    };
    let (result, ()) = tokio::join!(accept, client_exchange);
    assert!(matches!(
        result,
        Err(pg_proto::AcceptError::Authentication(
            AuthenticationFailure("user is required")
        ))
    ));
}

#[tokio::test]
async fn tls_identity_provider_errors_remain_typed() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Required(FailingIdentity))
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(64);
    client
        .write_all(&PreStartupMessage::SslRequest.to_packet().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        server.accept(server_io, (), ()).await,
        Err(pg_proto::AcceptError::TlsIdentity(IdentityUnavailable))
    ));
}

#[tokio::test]
async fn optional_tls_accepts_plaintext_without_resolving_an_identity() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let generated = generate_simple_self_signed(["localhost".into()]).unwrap();
    let certificate = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der()).unwrap();
    let resolutions = Arc::new(AtomicUsize::new(0));
    let server = Server::builder()
        .tls(ServerTlsPolicy::Optional(ReloadingIdentity {
            resolutions: resolutions.clone(),
            identity: ServerIdentity::new(
                Arc::new(
                    ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(vec![certificate.clone()], key)
                        .unwrap(),
                ),
                certificate,
            ),
        }))
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(1024);
    client.write_all(&startup_with_user("alice")).await.unwrap();
    let accepted = server.accept(server_io, (), ()).await.unwrap();
    let ServerAccept::Session(connection) = accepted else {
        panic!("expected session")
    };
    assert_eq!(connection.context().tls(), &NegotiatedServerTls::Plaintext);
    let _ = connection.teardown();
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn application_authentication_selects_md5_protocol_orchestration() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(Md5AuthenticationFactory)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(1024);
    client.write_all(&startup_with_user("alice")).await.unwrap();
    let client_exchange = async {
        let mut challenge = [0; 13];
        client.read_exact(&mut challenge).await.unwrap();
        assert_eq!(&challenge[..9], &[b'R', 0, 0, 0, 12, 0, 0, 0, 5]);
        assert_eq!(&challenge[9..], &[1, 2, 3, 4]);
        client
            .write_all(&password_packet(b"md5response"))
            .await
            .unwrap();
        let mut ready = [0; 15];
        client.read_exact(&mut ready).await.unwrap();
    };
    let (accepted, ()) = tokio::join!(server.accept(server_io, (), ()), client_exchange);
    let ServerAccept::Session(connection) = accepted.unwrap() else {
        panic!("expected session")
    };
    assert_eq!(connection.context().identity(), b"md5response");
    let _ = connection.teardown();
}

#[tokio::test]
async fn application_authentication_drives_recursive_token_continuations() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TokenAuthenticationFactory(TokenMethod::Gss))
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(1024);
    client.write_all(&startup_with_user("alice")).await.unwrap();
    let client_exchange = async {
        let mut request = [0; 9];
        client.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [b'R', 0, 0, 0, 8, 0, 0, 0, 7]);
        client
            .write_all(&token_packet(b"client-one"))
            .await
            .unwrap();
        let mut continuation = [0; 19];
        client.read_exact(&mut continuation).await.unwrap();
        assert_eq!(&continuation[..9], &[b'R', 0, 0, 0, 18, 0, 0, 0, 8]);
        assert_eq!(&continuation[9..], b"server-two");
        client
            .write_all(&token_packet(b"client-three"))
            .await
            .unwrap();
        let mut ready = [0; 15];
        client.read_exact(&mut ready).await.unwrap();
    };
    let (accepted, ()) = tokio::join!(server.accept(server_io, (), ()), client_exchange);
    let ServerAccept::Session(connection) = accepted.unwrap() else {
        panic!("expected session")
    };
    assert_eq!(connection.context().identity(), &"gss-user");
    let _ = connection.teardown();
}

#[tokio::test]
async fn application_authentication_reaches_kerberos_and_sspi_branches() {
    for (method, code) in [(TokenMethod::Kerberos, 2_u32), (TokenMethod::Sspi, 9_u32)] {
        let server = Server::builder()
            .tls(ServerTlsPolicy::Disabled)
            .authentication(TokenAuthenticationFactory(method))
            .build()
            .unwrap();
        let (mut client, server_io) = tokio::io::duplex(512);
        client.write_all(&startup_with_user("alice")).await.unwrap();
        let client_exchange = async {
            let mut request = [0; 9];
            client.read_exact(&mut request).await.unwrap();
            assert_eq!(u32::from_be_bytes(request[5..9].try_into().unwrap()), code);
            client
                .write_all(&token_packet(b"accepted-token"))
                .await
                .unwrap();
            let mut ready = [0; 15];
            client.read_exact(&mut ready).await.unwrap();
        };
        let (accepted, ()) = tokio::join!(server.accept(server_io, (), ()), client_exchange);
        let ServerAccept::Session(connection) = accepted.unwrap() else {
            panic!("expected session")
        };
        let _ = connection.teardown();
    }
}

#[tokio::test]
async fn oversized_policy_continuation_returns_error_without_dropping_live_connection() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TokenAuthenticationFactory(TokenMethod::Gss))
        .limits(ServerProtocolLimits::default().with_max_frame_len(16))
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(512);
    client.write_all(&startup_with_user("alice")).await.unwrap();
    let client_exchange = async {
        let mut request = [0; 9];
        client.read_exact(&mut request).await.unwrap();
        client
            .write_all(&token_packet(b"client-one"))
            .await
            .unwrap();
    };
    let (accepted, ()) = tokio::join!(server.accept(server_io, (), ()), client_exchange);
    assert!(matches!(accepted, Err(pg_proto::AcceptError::Io(_))));
}

#[tokio::test]
async fn invalid_application_sasl_offer_returns_error_without_dropping_live_connection() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(InvalidSaslAuthentication)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(256);
    client.write_all(&startup_with_user("alice")).await.unwrap();
    let error = server.accept(server_io, (), ()).await.unwrap_err();
    assert!(matches!(error, pg_proto::AcceptError::Io(_)));
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
    server: Server<DisabledServerTls, TrustServerAuthentication>,
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

fn startup_with_user(user: &str) -> Bytes {
    StartupMessage {
        version: ProtocolVersion::V3_2,
        parameters: BTreeMap::from([(
            Bytes::from_static(b"user"),
            Bytes::copy_from_slice(user.as_bytes()),
        )]),
    }
    .encode()
    .unwrap()
}

fn password_packet(password: &[u8]) -> Vec<u8> {
    let length = u32::try_from(password.len() + 5).unwrap();
    let mut packet = vec![b'p'];
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(password);
    packet.push(0);
    packet
}

fn token_packet(token: &[u8]) -> Vec<u8> {
    let length = u32::try_from(token.len() + 4).unwrap();
    let mut packet = vec![b'p'];
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(token);
    packet
}
