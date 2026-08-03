//! TLS transport upgrades and RFC 5929 channel binding.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, ServerConfig,
    SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::{
    prelude::{FromDer, X509Certificate},
    signature_algorithm::SignatureAlgorithm,
};

use crate::{
    auth::TlsServerEndPoint,
    pre_startup::{CertificateVerification, SslMode},
};

#[derive(Debug)]
struct CertificateVerifier {
    verification: CertificateVerification,
    roots: RootCertStore,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.verification {
            CertificateVerification::None => Ok(ServerCertVerified::assertion()),
            CertificateVerification::CertificateAuthority => {
                let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
                rustls::client::verify_server_cert_signed_by_trust_anchor(
                    &parsed,
                    &self.roots,
                    intermediates,
                    now,
                    self.supported.all,
                )?;
                Ok(ServerCertVerified::assertion())
            }
            CertificateVerification::CertificateAuthorityAndHost => {
                let verifier = WebPkiServerVerifier::builder(Arc::new(self.roots.clone()))
                    .build()
                    .map_err(|error| TlsError::General(error.to_string()))?;
                verifier.verify_server_cert(end_entity, intermediates, server_name, &[], now)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Builds a client TLS configuration with libpq-compatible `sslmode` verification.
///
/// `require`, `prefer`, and `allow` encrypt without checking the certificate chain;
/// `verify-ca` checks the chain without checking the host; `verify-full` checks both.
#[must_use]
pub fn client_config(mode: SslMode, roots: RootCertStore) -> ClientConfig {
    let verification = mode.strategy().verification;
    if verification == CertificateVerification::CertificateAuthorityAndHost {
        return ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
    }

    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let verifier = CertificateVerifier {
        verification,
        roots,
        supported: provider.signature_verification_algorithms,
    };
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}

/// A client-side TLS stream carrying its `PostgreSQL` channel-binding value.
#[derive(Debug)]
pub struct ClientTls<S> {
    inner: tokio_rustls::client::TlsStream<S>,
    tls_server_end_point: Vec<u8>,
}

/// A server-side TLS stream carrying its `PostgreSQL` channel-binding value.
#[derive(Debug)]
pub struct ServerTls<S> {
    inner: tokio_rustls::server::TlsStream<S>,
    tls_server_end_point: Vec<u8>,
}

impl<S> TlsServerEndPoint for ClientTls<S> {
    fn tls_server_end_point(&self) -> &[u8] {
        &self.tls_server_end_point
    }
}

impl<S> TlsServerEndPoint for ServerTls<S> {
    fn tls_server_end_point(&self) -> &[u8] {
        &self.tls_server_end_point
    }
}

macro_rules! delegate_io {
    ($wrapper:ident) => {
        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for $wrapper<S> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buffer)
            }
        }

        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for $wrapper<S> {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &[u8],
            ) -> Poll<Result<usize, io::Error>> {
                Pin::new(&mut self.inner).poll_write(cx, buffer)
            }

            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), io::Error>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), io::Error>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
    };
}

delegate_io!(ClientTls);
delegate_io!(ServerTls);

/// Negotiates TLS as a `PostgreSQL` client and records the peer certificate binding.
///
/// # Errors
///
/// Returns a TLS handshake, certificate, or channel-binding error.
pub async fn connect<S>(
    stream: S,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
) -> io::Result<ClientTls<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let inner = TlsConnector::from(config)
        .connect(server_name, stream)
        .await?;
    let certificate = inner
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "TLS peer sent no certificate")
        })?;

    Ok(ClientTls {
        tls_server_end_point: channel_binding(certificate)?,
        inner,
    })
}

/// Negotiates TLS as a `PostgreSQL` server using the configured leaf certificate.
///
/// # Errors
///
/// Returns a TLS handshake or invalid-certificate error.
pub async fn accept<S>(
    stream: S,
    config: Arc<ServerConfig>,
    leaf_certificate: &CertificateDer<'_>,
) -> io::Result<ServerTls<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tls_server_end_point = channel_binding(leaf_certificate)?;
    let inner = TlsAcceptor::from(config).accept(stream).await?;
    Ok(ServerTls {
        inner,
        tls_server_end_point,
    })
}

/// Computes the RFC 5929 `tls-server-end-point` value from a DER certificate.
///
/// # Errors
///
/// Returns an error if the certificate is not valid DER.
pub fn channel_binding(certificate: &CertificateDer<'_>) -> io::Result<Vec<u8>> {
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid TLS certificate: {error}"),
        )
    })?;
    let signature_oid = match SignatureAlgorithm::try_from(&parsed.signature_algorithm) {
        Ok(SignatureAlgorithm::RSASSA_PSS(parameters)) => {
            parameters.hash_algorithm_oid().to_id_string()
        }
        _ => parsed.signature_algorithm.algorithm.to_id_string(),
    };

    Ok(match signature_oid.as_str() {
        // SHA-384, sha384WithRSAEncryption, and ecdsa-with-SHA384.
        "2.16.840.1.101.3.4.2.2" | "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => {
            Sha384::digest(certificate.as_ref()).to_vec()
        }
        // SHA-512, sha512WithRSAEncryption, and ecdsa-with-SHA512.
        "2.16.840.1.101.3.4.2.3" | "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => {
            Sha512::digest(certificate.as_ref()).to_vec()
        }
        // RFC 5929 promotes MD5 and SHA-1 to SHA-256. SHA-256 is also the
        // interoperable fallback for signature schemes whose digest is not
        // expressed directly by their algorithm identifier.
        _ => Sha256::digest(certificate.as_ref()).to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Conn,
        pre_startup::{Negotiation, PreStartupOffer},
        transport::Buffered,
    };
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384, generate_simple_self_signed};
    use rustls::{RootCertStore, pki_types::PrivateKeyDer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn handshake_with_mode(
        mode: SslMode,
        roots: RootCertStore,
        certificate: CertificateDer<'static>,
        key_der: &[u8],
    ) -> io::Result<ClientTls<tokio::io::DuplexStream>> {
        let key = PrivateKeyDer::try_from(key_der.to_vec()).unwrap();
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)
                .unwrap(),
        );
        let client_config = Arc::new(client_config(mode, roots));
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (client, _) = tokio::join!(
            connect(
                client_io,
                ServerName::try_from("localhost").unwrap(),
                client_config,
            ),
            accept(server_io, server_config, &certificate),
        );
        client
    }

    #[tokio::test]
    async fn sslmode_controls_chain_and_hostname_verification() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated = generate_simple_self_signed(["database.example".into()]).unwrap();
        let certificate = CertificateDer::from(generated.cert.der().to_vec());
        let key = generated.signing_key.serialize_der();

        handshake_with_mode(
            SslMode::Require,
            RootCertStore::empty(),
            certificate.clone(),
            &key,
        )
        .await
        .expect("require encrypts without validating the self-signed certificate");

        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        handshake_with_mode(SslMode::VerifyCa, roots.clone(), certificate.clone(), &key)
            .await
            .expect("verify-ca validates the chain but deliberately ignores the host");

        let error = handshake_with_mode(SslMode::VerifyFull, roots, certificate, &key)
            .await
            .expect_err("verify-full must reject a certificate for another host");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn negotiates_tls_and_exposes_equal_channel_bindings() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated = generate_simple_self_signed(["localhost".into()]).unwrap();
        let certificate = CertificateDer::from(generated.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der()).unwrap();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let expected = channel_binding(&certificate).unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let (client, server) = tokio::join!(
            connect(
                client_io,
                ServerName::try_from("localhost").unwrap(),
                Arc::new(client_config),
            ),
            accept(server_io, Arc::new(server_config), &certificate),
        );
        let client = client.unwrap();
        let server = server.unwrap();

        assert_eq!(client.tls_server_end_point(), expected);
        assert_eq!(server.tls_server_end_point(), expected);
    }

    #[tokio::test]
    async fn typed_pre_startup_upgrade_changes_the_buffered_transport() {
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
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let expected = channel_binding(&certificate).unwrap();
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);

        let server = tokio::spawn(async move {
            let mut request = [0; 8];
            server_io.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
            server_io.write_all(b"S").await.unwrap();
            accept(server_io, server_config, &certificate)
                .await
                .unwrap()
        });

        let mut awaiting_reply = Conn::new(Buffered::new(client_io)).request_ssl();
        awaiting_reply.flush().await.unwrap();
        let Negotiation::Accepted(handshake) = awaiting_reply.receive_ssl_reply().await.unwrap()
        else {
            panic!("test server rejected TLS")
        };
        let pre_startup = handshake
            .connect_tls(ServerName::try_from("localhost").unwrap(), client_config)
            .await
            .unwrap();
        let client = pre_startup.into_transport().into_inner();
        let server = server.await.unwrap();

        assert_eq!(client.tls_server_end_point(), expected);
        assert_eq!(server.tls_server_end_point(), expected);
    }

    #[tokio::test]
    async fn server_role_terminates_tls_before_accepting_startup() {
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
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let expected = channel_binding(&certificate).unwrap();
        let (mut client_io, server_io) = tokio::io::duplex(16 * 1024);

        let client = tokio::spawn(async move {
            client_io
                .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
                .await
                .unwrap();
            assert_eq!(client_io.read_u8().await.unwrap(), b'S');
            connect(
                client_io,
                ServerName::try_from("localhost").unwrap(),
                client_config,
            )
            .await
            .unwrap()
        });

        let mut pre_startup = Conn::new(Buffered::new_frontend(server_io));
        let message = pre_startup.receive_pre_startup_wire().await.unwrap();
        let PreStartupOffer::Ssl(decision) = pre_startup.offer_pre_startup(message) else {
            panic!("test client did not request TLS")
        };
        let mut handshake = decision.approve_ssl();
        handshake.flush().await.unwrap();
        let pre_startup = handshake
            .accept_tls(server_config, certificate)
            .await
            .unwrap();
        let server = pre_startup.into_transport().into_inner();
        let client = client.await.unwrap();

        assert_eq!(client.tls_server_end_point(), expected);
        assert_eq!(server.tls_server_end_point(), expected);
    }

    #[test]
    fn channel_binding_uses_the_certificate_signature_digest() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let params = CertificateParams::new(["localhost".to_owned()]).unwrap();
        let generated = params.self_signed(&key).unwrap();
        let certificate = CertificateDer::from(generated.der().to_vec());

        assert_eq!(
            channel_binding(&certificate).unwrap(),
            Sha384::digest(certificate.as_ref()).to_vec()
        );
    }
}
