//! TLS transport upgrades and RFC 5929 channel binding.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, ServerName},
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::auth::TlsServerEndPoint;

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
    let signature_oid = parsed.signature_algorithm.algorithm.to_id_string();

    Ok(match signature_oid.as_str() {
        // sha384WithRSAEncryption and ecdsa-with-SHA384
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => {
            Sha384::digest(certificate.as_ref()).to_vec()
        }
        // sha512WithRSAEncryption and ecdsa-with-SHA512
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => {
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
    use crate::{Conn, pre_startup::Negotiation, transport::Buffered};
    use rcgen::generate_simple_self_signed;
    use rustls::{RootCertStore, pki_types::PrivateKeyDer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
}
