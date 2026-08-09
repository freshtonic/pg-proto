//! Public client TLS and authentication builder behavior.

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use pg_proto::{
    Client, ClientAuthentication, ClientAuthenticationChallenge, ClientAuthenticationResponse,
    ClientAuthenticationSession, ClientTlsConfig, ClientTlsPolicy, ClientTlsProvider, ConnectError,
    ConnectTarget, SslMode, StartupParameters, TrustClientAuthentication,
};
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt as _, runners::AsyncRunner as _},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone)]
struct PasswordPolicy;

struct PasswordSession {
    identity: String,
}

impl ClientAuthentication for PasswordPolicy {
    type Error = Infallible;
    type Evidence = String;
    type Session = PasswordSession;

    fn begin<'a>(
        &'a self,
        target: &'a ConnectTarget,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, Self::Error>> + 'a>> {
        let identity = target.metadata().get("tenant").unwrap().to_owned();
        Box::pin(async move { Ok(PasswordSession { identity }) })
    }
}

impl ClientAuthenticationSession for PasswordSession {
    type Error = Infallible;
    type Evidence = String;

    fn respond<'a>(
        &'a mut self,
        challenge: ClientAuthenticationChallenge,
    ) -> Pin<Box<dyn Future<Output = Result<ClientAuthenticationResponse, Self::Error>> + 'a>> {
        Box::pin(async move {
            assert_eq!(challenge, ClientAuthenticationChallenge::CleartextPassword);
            Ok(ClientAuthenticationResponse::Password(Bytes::from_static(
                b"secret",
            )))
        })
    }

    fn authenticated(self) -> Pin<Box<dyn Future<Output = Result<Self::Evidence, Self::Error>>>> {
        Box::pin(async move { Ok(self.identity) })
    }
}

#[tokio::test]
async fn authentication_is_created_per_connection_uses_routing_metadata_and_returns_evidence() {
    let starts = Arc::new(AtomicUsize::new(0));
    let starts_in_connector = Arc::clone(&starts);
    let client = Client::builder()
        .connector(move |_| {
            starts_in_connector.fetch_add(1, Ordering::SeqCst);
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let length = server.read_u32().await.unwrap();
                let mut startup = vec![0; length as usize - 4];
                server.read_exact(&mut startup).await.unwrap();
                server
                    .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3])
                    .await
                    .unwrap();
                server.flush().await.unwrap();
                assert_eq!(server.read_u8().await.unwrap(), b'p');
                let length = server.read_u32().await.unwrap();
                let mut password = vec![0; length as usize - 4];
                server.read_exact(&mut password).await.unwrap();
                assert_eq!(&password, b"secret\0");
                server
                    .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            });
            async move { Ok::<_, Infallible>(client) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(PasswordPolicy)
        .build()
        .unwrap();

    let target = ConnectTarget::new("memory").with_metadata("tenant", "tenant-a");
    let connection = client
        .connect(target, StartupParameters::new("alice"), ())
        .await
        .unwrap();
    assert_eq!(connection.context().identity(), "tenant-a");
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    let _ = connection.into_parts();
}

#[derive(Clone)]
struct ReloadingTls {
    resolutions: Arc<AtomicUsize>,
    roots: RootCertStore,
}

impl ClientTlsProvider for ReloadingTls {
    type Error = Infallible;

    fn resolve<'a>(
        &'a self,
        _target: &'a ConnectTarget,
    ) -> Pin<Box<dyn Future<Output = Result<ClientTlsConfig, Self::Error>> + 'a>> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        let roots = self.roots.clone();
        Box::pin(async move {
            Ok(ClientTlsConfig::new(
                ServerName::try_from("localhost").unwrap(),
                roots,
            ))
        })
    }
}

#[tokio::test]
async fn tls_material_is_resolved_per_connection_and_establishes_encrypted_sessions() {
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
    let server_config_for_connector = Arc::clone(&server_config);
    let client = Client::builder()
        .connector(move |_| {
            let (client, mut server) = tokio::io::duplex(16 * 1024);
            let config = Arc::clone(&server_config_for_connector);
            tokio::spawn(async move {
                let mut request = [0; 8];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
                server.write_all(b"S").await.unwrap();
                server.flush().await.unwrap();
                let mut server = tokio_rustls::TlsAcceptor::from(config)
                    .accept(server)
                    .await
                    .unwrap();
                let length = server.read_u32().await.unwrap();
                let mut startup = vec![0; length as usize - 4];
                server.read_exact(&mut startup).await.unwrap();
                server
                    .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            });
            async move { Ok::<_, Infallible>(client) }
        })
        .tls(ClientTlsPolicy::libpq(
            SslMode::Require,
            ReloadingTls {
                resolutions: Arc::clone(&resolutions),
                roots: RootCertStore::empty(),
            },
        ))
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();

    for _ in 0..2 {
        let connection = client
            .connect(
                ConnectTarget::new("memory"),
                StartupParameters::new("alice"),
                (),
            )
            .await
            .unwrap();
        let _ = connection.into_parts();
    }
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn required_tls_rejection_is_reported_in_the_tls_error_layer() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = Client::builder()
        .connector(|_| async {
            let (client, mut server) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let mut request = [0; 8];
                server.read_exact(&mut request).await.unwrap();
                server.write_all(b"N").await.unwrap();
                server.flush().await.unwrap();
            });
            Ok::<_, Infallible>(client)
        })
        .tls(ClientTlsPolicy::libpq(
            SslMode::VerifyFull,
            ReloadingTls {
                resolutions: Arc::new(AtomicUsize::new(0)),
                roots: RootCertStore::empty(),
            },
        ))
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();

    let result = client
        .connect(
            ConnectTarget::new("memory"),
            StartupParameters::new("alice"),
            (),
        )
        .await;
    let Err(error) = result else {
        panic!("required TLS unexpectedly accepted plaintext")
    };
    assert!(matches!(error, ConnectError::Tls(_)));
}

#[tokio::test]
async fn sslmode_allow_reconnects_with_tls_after_plaintext_establishment_fails() {
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
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_connector = Arc::clone(&attempts);
    let server_config_for_connector = Arc::clone(&server_config);
    let resolutions = Arc::new(AtomicUsize::new(0));
    let client = Client::builder()
        .connector(move |_| {
            let attempt = attempts_for_connector.fetch_add(1, Ordering::SeqCst);
            let (client, mut server) = tokio::io::duplex(16 * 1024);
            let config = Arc::clone(&server_config_for_connector);
            tokio::spawn(async move {
                if attempt == 0 {
                    let length = server.read_u32().await.unwrap();
                    let mut startup = vec![0; length as usize - 4];
                    server.read_exact(&mut startup).await.unwrap();
                    return;
                }
                let mut request = [0; 8];
                server.read_exact(&mut request).await.unwrap();
                server.write_all(b"S").await.unwrap();
                server.flush().await.unwrap();
                let mut server = tokio_rustls::TlsAcceptor::from(config)
                    .accept(server)
                    .await
                    .unwrap();
                let length = server.read_u32().await.unwrap();
                let mut startup = vec![0; length as usize - 4];
                server.read_exact(&mut startup).await.unwrap();
                server
                    .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            });
            async move { Ok::<_, Infallible>(client) }
        })
        .tls(ClientTlsPolicy::libpq(
            SslMode::Allow,
            ReloadingTls {
                resolutions: Arc::clone(&resolutions),
                roots: RootCertStore::empty(),
            },
        ))
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();

    let connection = client
        .connect(
            ConnectTarget::new("memory"),
            StartupParameters::new("alice"),
            (),
        )
        .await
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(resolutions.load(Ordering::SeqCst), 1);
    let _ = connection.into_parts();
}

#[derive(Clone, Copy, Debug)]
struct Denied;

impl std::fmt::Display for Denied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("denied")
    }
}

impl std::error::Error for Denied {}

struct DenyingPolicy;

impl ClientAuthentication for DenyingPolicy {
    type Error = Denied;
    type Evidence = ();
    type Session = Self;

    fn begin<'a>(
        &'a self,
        _target: &'a ConnectTarget,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, Self::Error>> + 'a>> {
        Box::pin(async { Err(Denied) })
    }
}

impl ClientAuthenticationSession for DenyingPolicy {
    type Error = Denied;
    type Evidence = ();

    fn respond(
        &mut self,
        _challenge: ClientAuthenticationChallenge,
    ) -> Pin<Box<dyn Future<Output = Result<ClientAuthenticationResponse, Self::Error>> + '_>> {
        Box::pin(async { Err(Denied) })
    }

    fn authenticated(self) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>>>> {
        Box::pin(async { Err(Denied) })
    }
}

#[tokio::test]
async fn application_authentication_failure_has_its_own_error_layer() {
    let client = Client::builder()
        .connector(|_| async {
            let (client, _server) = tokio::io::duplex(64);
            Ok::<_, Infallible>(client)
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(DenyingPolicy)
        .build()
        .unwrap();
    let result = client
        .connect(
            ConnectTarget::new("memory"),
            StartupParameters::new("alice"),
            (),
        )
        .await;
    assert!(matches!(result, Err(ConnectError::Authentication(_))));
}

#[tokio::test]
async fn server_authentication_rejection_has_its_own_error_layer() {
    let client = Client::builder()
        .connector(|_| async {
            let (client, mut server) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let length = server.read_u32().await.unwrap();
                let mut startup = vec![0; length as usize - 4];
                server.read_exact(&mut startup).await.unwrap();
                server.write_all(&[b'E', 0, 0, 0, 5, 0]).await.unwrap();
                server.flush().await.unwrap();
            });
            Ok::<_, Infallible>(client)
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let result = client
        .connect(
            ConnectTarget::new("memory"),
            StartupParameters::new("alice"),
            (),
        )
        .await;
    assert!(matches!(result, Err(ConnectError::Authentication(_))));
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn builder_establishes_a_session_with_postgres() -> Result<(), Box<dyn std::error::Error>> {
    let postgres = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let port = postgres.get_host_port_ipv4(5432).await?;
    let client = Client::builder()
        .connector(
            move |_| async move { tokio::net::TcpStream::connect(("127.0.0.1", port)).await },
        )
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()?;
    let connection = client
        .connect(
            ConnectTarget::new("postgres-container"),
            StartupParameters::new("postgres").database("postgres"),
            (),
        )
        .await?;
    let _ = connection.into_parts();
    Ok(())
}
