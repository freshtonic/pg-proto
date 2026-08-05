//! TCP establishment, socket configuration, and negotiated network streams.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::sleep,
};

use crate::{
    auth::TlsServerEndPoint,
    tls::{ClientTls, ServerTls},
};

/// A PostgreSQL network transport after optional TLS negotiation.
#[derive(Debug)]
pub enum NetworkStream<S> {
    /// An unencrypted transport.
    Plain(S),
    /// TLS initiated by this endpoint as a client.
    ClientTls(ClientTls<S>),
    /// TLS accepted by this endpoint as a server.
    ServerTls(ServerTls<S>),
}

impl<S> NetworkStream<S> {
    /// Wraps an unencrypted transport.
    pub const fn plain(stream: S) -> Self {
        Self::Plain(stream)
    }

    /// Wraps a completed client-side TLS upgrade.
    pub const fn client_tls(stream: ClientTls<S>) -> Self {
        Self::ClientTls(stream)
    }

    /// Wraps a completed server-side TLS upgrade.
    pub const fn server_tls(stream: ServerTls<S>) -> Self {
        Self::ServerTls(stream)
    }

    /// Reports whether the transport is encrypted.
    pub const fn is_tls(&self) -> bool {
        !matches!(self, Self::Plain(_))
    }

    /// Reports whether the transport is unencrypted.
    pub const fn is_plain(&self) -> bool {
        matches!(self, Self::Plain(_))
    }

    /// Returns the plain transport when TLS has not already been negotiated.
    ///
    /// # Errors
    ///
    /// Returns [`AlreadyTls`] for either negotiated TLS variant.
    pub fn into_plain(self) -> Result<S, AlreadyTls> {
        match self {
            Self::Plain(stream) => Ok(stream),
            Self::ClientTls(_) | Self::ServerTls(_) => Err(AlreadyTls),
        }
    }

    /// Returns RFC 5929 `tls-server-end-point` bytes for an encrypted stream.
    pub fn tls_server_end_point(&self) -> Option<&[u8]> {
        match self {
            Self::Plain(_) => None,
            Self::ClientTls(stream) => Some(stream.tls_server_end_point()),
            Self::ServerTls(stream) => Some(stream.tls_server_end_point()),
        }
    }
}

impl<S> TlsServerEndPoint for NetworkStream<S> {
    fn tls_server_end_point(&self) -> &[u8] {
        match self {
            Self::Plain(_) => &[],
            Self::ClientTls(stream) => stream.tls_server_end_point(),
            Self::ServerTls(stream) => stream.tls_server_end_point(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> NetworkStream<S> {
    /// Splits the negotiated transport into independently owned read and write halves.
    pub fn split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        tokio::io::split(self)
    }
}

/// A plain transport was requested after TLS had already been negotiated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlreadyTls;

impl fmt::Display for AlreadyTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transport is already using TLS")
    }
}

impl std::error::Error for AlreadyTls {}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for NetworkStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::ClientTls(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::ServerTls(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for NetworkStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::ClientTls(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::ServerTls(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::ClientTls(stream) => Pin::new(stream).poll_flush(context),
            Self::ServerTls(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::ClientTls(stream) => Pin::new(stream).poll_shutdown(context),
            Self::ServerTls(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

/// Retry policy for establishing an outbound TCP connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectRetry {
    /// Number of retries after the initial attempt.
    pub max_retries: u32,
    /// Initial exponential-backoff delay.
    pub initial_delay: Duration,
    /// Upper bound for an individual delay.
    pub max_delay: Duration,
}

impl Default for ConnectRetry {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
        }
    }
}

/// Connects to `address`, retrying failures with capped exponential backoff.
///
/// # Errors
///
/// Returns the final connection error after the configured attempts are exhausted.
pub async fn connect_with_retry(address: &str, retry: ConnectRetry) -> io::Result<TcpStream> {
    let mut retries = 0_u32;
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) if retries == retry.max_retries => return Err(error),
            Err(_) => {
                let exponent = retries.min(63);
                let multiplier = 1_u64 << exponent;
                let delay = retry
                    .initial_delay
                    .saturating_mul(u32::try_from(multiplier).unwrap_or(u32::MAX))
                    .min(retry.max_delay);
                sleep(delay).await;
                retries = retries.saturating_add(1);
            }
        }
    }
}

/// Best-effort TCP socket configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSettings {
    /// Whether to disable Nagle's algorithm.
    pub no_delay: bool,
    /// Optional TCP user timeout on supported operating systems.
    pub user_timeout: Option<Duration>,
    /// Optional keepalive idle time.
    pub keepalive_time: Option<Duration>,
    /// Optional keepalive probe interval.
    pub keepalive_interval: Option<Duration>,
    /// Optional number of failed probes before the connection is closed.
    pub keepalive_retries: Option<u32>,
}

impl Default for TcpSettings {
    fn default() -> Self {
        Self {
            no_delay: true,
            user_timeout: None,
            keepalive_time: None,
            keepalive_interval: None,
            keepalive_retries: None,
        }
    }
}

/// One socket option which could not be applied.
#[derive(Debug)]
pub struct TcpConfigurationError {
    /// Stable socket-option name.
    pub option: &'static str,
    /// Operating-system error returned while applying the option.
    pub source: io::Error,
}

impl fmt::Display for TcpConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to configure {}: {}",
            self.option, self.source
        )
    }
}

impl std::error::Error for TcpConfigurationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Applies every configured TCP option and reports individual failures.
#[must_use]
pub fn configure_tcp(stream: &TcpStream, settings: TcpSettings) -> Vec<TcpConfigurationError> {
    let mut errors = Vec::new();
    if let Err(source) = stream.set_nodelay(settings.no_delay) {
        errors.push(TcpConfigurationError {
            option: "TCP_NODELAY",
            source,
        });
    }

    let socket = SockRef::from(stream);
    #[cfg(target_os = "linux")]
    if let Some(timeout) = settings.user_timeout {
        if let Err(source) = socket.set_tcp_user_timeout(Some(timeout)) {
            errors.push(TcpConfigurationError {
                option: "TCP_USER_TIMEOUT",
                source,
            });
        }
    }

    if settings.keepalive_time.is_some()
        || settings.keepalive_interval.is_some()
        || settings.keepalive_retries.is_some()
    {
        if let Err(source) = socket.set_keepalive(true) {
            errors.push(TcpConfigurationError {
                option: "SO_KEEPALIVE",
                source,
            });
            return errors;
        }
        let mut keepalive = TcpKeepalive::new();
        if let Some(time) = settings.keepalive_time {
            keepalive = keepalive.with_time(time);
        }
        if let Some(interval) = settings.keepalive_interval {
            keepalive = keepalive.with_interval(interval);
        }
        if let Some(retries) = settings.keepalive_retries {
            keepalive = keepalive.with_retries(retries);
        }
        if let Err(source) = socket.set_tcp_keepalive(&keepalive) {
            errors.push(TcpConfigurationError {
                option: "TCP_KEEPALIVE",
                source,
            });
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn network_stream_delegates_plain_io() {
        let (client, server) = tokio::io::duplex(16);
        let mut client = NetworkStream::plain(client);
        let mut server = NetworkStream::plain(server);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"ping")
            .await
            .unwrap();
        let mut bytes = [0; 4];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut bytes)
            .await
            .unwrap();
        assert_eq!(&bytes, b"ping");
        assert!(client.is_plain());
        assert_eq!(client.tls_server_end_point(), None);
    }

    #[tokio::test]
    async fn connects_with_configurable_retry() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let client = connect_with_retry(&address, ConnectRetry::default())
            .await
            .unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        assert!(configure_tcp(&client, TcpSettings::default()).is_empty());
    }
}
