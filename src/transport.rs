//! Buffered, cancellation-safe outbound transport.

use std::{collections::BTreeMap, io, sync::Arc};

use bytes::{Buf, Bytes, BytesMut};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, ServerName},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    Conn,
    auth::TlsServerEndPoint,
    codec::{Backend, BackendMessage, Direction, Frame, Frontend, FrontendMessage, PgCodec},
    demux::{CancelKey, Demux, Notification, ParameterStatus, SessionItem, TaggedNotice},
    pre_startup::{
        AwaitingSslReply, DEFAULT_MAX_PRE_STARTUP_PACKET_LEN, EncryptionReply, Negotiation,
        PreStartup, PreStartupMessage, ServerSslDecision, SslMode, SslModeNegotiation,
        TlsHandshake, decode_pre_startup_with_limit, gssenc_request_packet, ssl_request_packet,
    },
    tls::{ClientTls, ServerTls},
};

/// Transport wrapper which retains bytes until each write has completed.
#[derive(Debug)]
pub struct Buffered<S, D = Backend> {
    io: S,
    outbound: BytesMut,
    inbound: BytesMut,
    inbound_codec: PgCodec<D>,
    max_pre_startup_packet_len: usize,
    demux: Demux,
}

impl<S> Buffered<S, Backend> {
    pub fn new(io: S) -> Self {
        Self {
            io,
            outbound: BytesMut::new(),
            inbound: BytesMut::new(),
            inbound_codec: PgCodec::default(),
            max_pre_startup_packet_len: DEFAULT_MAX_PRE_STARTUP_PACKET_LEN,
            demux: Demux::default(),
        }
    }

    /// Creates a backend-facing transport with a bounded tagged-frame size.
    ///
    /// # Errors
    ///
    /// Returns an error when the limit is outside `PostgreSQL`'s frame range.
    pub fn with_max_frame_len(io: S, max_frame_len: usize) -> io::Result<Self> {
        Ok(Self {
            io,
            outbound: BytesMut::new(),
            inbound: BytesMut::new(),
            inbound_codec: PgCodec::with_max_frame_len(max_frame_len)?,
            max_pre_startup_packet_len: DEFAULT_MAX_PRE_STARTUP_PACKET_LEN,
            demux: Demux::default(),
        })
    }
}

impl<S> Buffered<S, Frontend> {
    pub fn new_frontend(io: S) -> Self {
        Self {
            io,
            outbound: BytesMut::new(),
            inbound: BytesMut::new(),
            inbound_codec: PgCodec::default(),
            max_pre_startup_packet_len: DEFAULT_MAX_PRE_STARTUP_PACKET_LEN,
            demux: Demux::default(),
        }
    }

    /// Creates a frontend-facing transport with a bounded tagged-frame size.
    ///
    /// # Errors
    ///
    /// Returns an error when the limit is outside `PostgreSQL`'s frame range.
    pub fn with_max_frame_len_frontend(io: S, max_frame_len: usize) -> io::Result<Self> {
        Self::with_limits_frontend(io, max_frame_len, DEFAULT_MAX_PRE_STARTUP_PACKET_LEN)
    }

    /// Creates a frontend-facing transport with bounded tagged and pre-startup packets.
    ///
    /// # Errors
    ///
    /// Returns an error when either limit is outside `PostgreSQL`'s framing range.
    pub fn with_limits_frontend(
        io: S,
        max_frame_len: usize,
        max_pre_startup_packet_len: usize,
    ) -> io::Result<Self> {
        if !(8..=i32::MAX as usize).contains(&max_pre_startup_packet_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pre-startup packet limit must be between 8 and i32::MAX bytes",
            ));
        }
        Ok(Self {
            io,
            outbound: BytesMut::new(),
            inbound: BytesMut::new(),
            inbound_codec: PgCodec::with_max_frame_len(max_frame_len)?,
            max_pre_startup_packet_len,
            demux: Demux::default(),
        })
    }
}

impl<S, D> Buffered<S, D> {
    /// Encodes a frame synchronously into the outbound buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too large to encode.
    pub fn push(&mut self, frame: Frame) -> io::Result<()> {
        self.inbound_codec.encode(frame, &mut self.outbound)
    }

    #[must_use]
    pub fn pending(&self) -> &[u8] {
        &self.outbound
    }

    pub fn into_inner(self) -> S {
        self.io
    }

    fn push_raw(&mut self, bytes: &[u8]) {
        self.outbound.extend_from_slice(bytes);
    }

    #[must_use]
    pub const fn demux(&self) -> &Demux {
        &self.demux
    }

    pub const fn demux_mut(&mut self) -> &mut Demux {
        &mut self.demux
    }
}

impl<S, D> Buffered<S, D>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn connect_tls(
        self,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    ) -> io::Result<Buffered<ClientTls<S>, D>> {
        if !self.outbound.is_empty() || !self.inbound.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS upgrade requires empty plaintext buffers",
            ));
        }
        Ok(Buffered {
            io: crate::tls::connect(self.io, server_name, config).await?,
            outbound: self.outbound,
            inbound: self.inbound,
            inbound_codec: self.inbound_codec,
            max_pre_startup_packet_len: self.max_pre_startup_packet_len,
            demux: self.demux,
        })
    }

    async fn accept_tls(
        self,
        config: Arc<ServerConfig>,
        leaf_certificate: CertificateDer<'static>,
    ) -> io::Result<Buffered<ServerTls<S>, D>> {
        if !self.outbound.is_empty() || !self.inbound.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS upgrade requires empty plaintext buffers",
            ));
        }
        Ok(Buffered {
            io: crate::tls::accept(self.io, config, &leaf_certificate).await?,
            outbound: self.outbound,
            inbound: self.inbound,
            inbound_codec: self.inbound_codec,
            max_pre_startup_packet_len: self.max_pre_startup_packet_len,
            demux: self.demux,
        })
    }
}

impl<S: TlsServerEndPoint, D> TlsServerEndPoint for Buffered<S, D> {
    fn tls_server_end_point(&self) -> &[u8] {
        self.io.tls_server_end_point()
    }
}

impl<S: AsyncWrite + Unpin, D> Buffered<S, D> {
    /// Writes all buffered bytes without consuming the connection.
    ///
    /// Completed partial writes are removed immediately. If this future is
    /// cancelled, the connection remains owned by the caller and all unwritten
    /// bytes remain buffered for the next call.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport's write error or `WriteZero`.
    pub async fn flush(&mut self) -> io::Result<()> {
        while !self.outbound.is_empty() {
            let written = self.io.write(&self.outbound).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "transport wrote zero buffered bytes",
                ));
            }
            self.outbound.advance(written);
        }
        self.io.flush().await
    }
}

impl<S: AsyncRead + Unpin, D: Direction> Buffered<S, D> {
    /// Receives one typed message in this transport's inbound direction.
    ///
    /// # Errors
    ///
    /// Returns decoding and underlying transport read errors, or `UnexpectedEof`.
    pub async fn receive_wire(&mut self) -> io::Result<D::Message> {
        loop {
            if let Some(message) = self.inbound_codec.decode(&mut self.inbound)? {
                return Ok(message);
            }
            if self.io.read_buf(&mut self.inbound).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed with no complete message",
                ));
            }
        }
    }
}

impl<S: AsyncRead + Unpin> Buffered<S, Backend> {
    async fn receive_encryption_reply(&mut self) -> io::Result<EncryptionReply> {
        let byte = self.io.read_u8().await?;
        EncryptionReply::try_from(byte)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid encryption reply"))
    }
}

impl<S: AsyncRead + Unpin> Buffered<S, Frontend> {
    /// Receives one raw first packet before tagged frontend framing begins.
    ///
    /// # Errors
    ///
    /// Returns malformed pre-startup data and underlying transport read errors.
    pub async fn receive_pre_startup(&mut self) -> io::Result<PreStartupMessage> {
        loop {
            if let Some(message) =
                decode_pre_startup_with_limit(&mut self.inbound, self.max_pre_startup_packet_len)?
            {
                return Ok(message);
            }
            if self.io.read_buf(&mut self.inbound).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed with no complete pre-startup packet",
                ));
            }
        }
    }
}

impl<S: AsyncRead + Unpin> Buffered<S, Backend> {
    /// Receives one decoded backend message while retaining partial input.
    ///
    /// # Errors
    ///
    /// Returns decoding and underlying transport read errors, or `UnexpectedEof`.
    pub async fn receive_backend(&mut self) -> io::Result<BackendMessage> {
        self.receive_wire().await
    }

    /// Receives the next protocol-advancing message through the async demux.
    ///
    /// # Errors
    ///
    /// Returns decoding and underlying transport read errors, or `UnexpectedEof`.
    pub async fn receive_session(&mut self) -> io::Result<SessionItem> {
        loop {
            let message = self.receive_backend().await?;
            if let Some(item) = self.project_backend(message) {
                return Ok(item);
            }
        }
    }

    /// Projects an inspected or modified backend message into the session stream.
    pub fn project_backend(&mut self, message: BackendMessage) -> Option<SessionItem> {
        self.demux.route(message)
    }
}

impl<S, D, Phase, Cleanliness> Conn<Buffered<S, D>, Phase, Cleanliness> {
    /// Adds an already-typed message to this connection's outbound buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too large to encode.
    pub fn push_frame(&mut self, frame: Frame) -> io::Result<()> {
        self.transport_mut().push(frame)
    }

    #[must_use]
    pub fn pending_output(&self) -> &[u8] {
        self.transport().pending()
    }
}

impl<S, Cleanliness> Conn<Buffered<S, Backend>, PreStartup, Cleanliness> {
    /// Buffers an `SSLRequest` and enters the raw single-byte reply phase.
    pub fn request_ssl(mut self) -> Conn<Buffered<S, Backend>, AwaitingSslReply, Cleanliness> {
        self.transport_mut().push_raw(&ssl_request_packet());
        self.transition()
    }

    /// Buffers a `GSSENCRequest` and enters the raw single-byte reply phase.
    pub fn request_gss(
        mut self,
    ) -> Conn<Buffered<S, Backend>, crate::pre_startup::AwaitingGssReply, Cleanliness> {
        self.transport_mut().push_raw(&gssenc_request_packet());
        self.transition()
    }
}

impl<S, Cleanliness> Conn<Buffered<S, Frontend>, ServerSslDecision, Cleanliness> {
    /// Buffers the server's raw `S` response and enters the TLS handshake phase.
    pub fn approve_ssl(mut self) -> Conn<Buffered<S, Frontend>, TlsHandshake, Cleanliness> {
        self.transport_mut().push_raw(b"S");
        self.transition()
    }

    /// Buffers the server's raw `N` response and returns to pre-startup choice.
    pub fn decline_ssl(mut self) -> Conn<Buffered<S, Frontend>, PreStartup, Cleanliness> {
        self.transport_mut().push_raw(b"N");
        self.transition()
    }

    /// Buffers the historical raw `E` response and terminates negotiation.
    pub fn reject_ssl_with_legacy_error(
        mut self,
    ) -> Conn<Buffered<S, Frontend>, crate::pre_startup::Terminated, Cleanliness> {
        self.transport_mut().push_raw(b"E");
        self.transition()
    }
}

impl<S, Cleanliness>
    Conn<Buffered<S, Frontend>, crate::pre_startup::ServerGssDecision, Cleanliness>
{
    /// Buffers the server's raw `S` response and enters the GSS handshake phase.
    pub fn approve_gss(
        mut self,
    ) -> Conn<Buffered<S, Frontend>, crate::pre_startup::GssHandshake, Cleanliness> {
        self.transport_mut().push_raw(b"S");
        self.transition()
    }

    /// Buffers the server's raw `N` response and returns to pre-startup choice.
    pub fn decline_gss(mut self) -> Conn<Buffered<S, Frontend>, PreStartup, Cleanliness> {
        self.transport_mut().push_raw(b"N");
        self.transition()
    }

    /// Buffers the historical raw `E` response and terminates negotiation.
    pub fn reject_gss_with_legacy_error(
        mut self,
    ) -> Conn<Buffered<S, Frontend>, crate::pre_startup::Terminated, Cleanliness> {
        self.transport_mut().push_raw(b"E");
        self.transition()
    }
}

impl<S: AsyncRead + Unpin, Cleanliness> Conn<Buffered<S, Backend>, AwaitingSslReply, Cleanliness> {
    /// Receives and projects the server's raw SSL decision byte.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or rejects a byte other than `S`, `N`, or `E`.
    pub async fn receive_ssl_reply(
        mut self,
    ) -> io::Result<Negotiation<Buffered<S, Backend>, TlsHandshake, Cleanliness>> {
        let reply = self.transport_mut().receive_encryption_reply().await?;
        Ok(match reply {
            EncryptionReply::Accepted => Negotiation::Accepted(self.transition()),
            EncryptionReply::Rejected => Negotiation::Rejected(self.transition()),
            EncryptionReply::LegacyError => Negotiation::LegacyError(self.transition()),
        })
    }

    /// Receives the server decision and enforces the selected plaintext fallback policy.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or rejects a byte other than `S`, `N`, or `E`.
    pub async fn receive_ssl_reply_for_mode(
        mut self,
        mode: SslMode,
    ) -> io::Result<SslModeNegotiation<Buffered<S, Backend>, Cleanliness>> {
        let reply = self.transport_mut().receive_encryption_reply().await?;
        Ok(self.apply_ssl_reply(reply, mode))
    }
}

impl<S: AsyncRead + Unpin, Cleanliness>
    Conn<Buffered<S, Backend>, crate::pre_startup::AwaitingGssReply, Cleanliness>
{
    /// Receives and projects the server's raw GSSENC decision byte.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or rejects a byte other than `S`, `N`, or `E`.
    pub async fn receive_gss_reply(
        mut self,
    ) -> io::Result<Negotiation<Buffered<S, Backend>, crate::pre_startup::GssHandshake, Cleanliness>>
    {
        let reply = self.transport_mut().receive_encryption_reply().await?;
        Ok(match reply {
            EncryptionReply::Accepted => Negotiation::Accepted(self.transition()),
            EncryptionReply::Rejected => Negotiation::Rejected(self.transition()),
            EncryptionReply::LegacyError => Negotiation::LegacyError(self.transition()),
        })
    }
}

impl<S, Cleanliness> Conn<Buffered<S, Backend>, TlsHandshake, Cleanliness>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Completes a client-side TLS handshake and changes the transport type.
    ///
    /// # Errors
    ///
    /// Returns a TLS handshake, certificate, channel-binding, or buffer-state error.
    pub async fn connect_tls(
        self,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    ) -> io::Result<Conn<Buffered<ClientTls<S>, Backend>, PreStartup, Cleanliness>> {
        let transport = self.into_transport();
        Ok(Conn::new(transport.connect_tls(server_name, config).await?)
            .transition::<PreStartup, Cleanliness>())
    }
}

impl<S, Cleanliness> Conn<Buffered<S, Frontend>, TlsHandshake, Cleanliness>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Completes a server-side TLS handshake and changes the transport type.
    ///
    /// # Errors
    ///
    /// Returns a TLS handshake, certificate, channel-binding, or buffer-state error.
    pub async fn accept_tls(
        self,
        config: Arc<ServerConfig>,
        leaf_certificate: CertificateDer<'static>,
    ) -> io::Result<Conn<Buffered<ServerTls<S>, Frontend>, PreStartup, Cleanliness>> {
        let transport = self.into_transport();
        Ok(
            Conn::new(transport.accept_tls(config, leaf_certificate).await?)
                .transition::<PreStartup, Cleanliness>(),
        )
    }
}

impl<S, D, Cleanliness> Conn<Buffered<S, D>, crate::pre_startup::Startup, Cleanliness> {
    /// Buffers the raw, untagged startup packet before normal framing begins.
    pub fn push_startup_packet(&mut self, packet: &[u8]) {
        self.transport_mut().outbound.extend_from_slice(packet);
    }
}

impl<S: AsyncWrite + Unpin, D, Phase, Cleanliness> Conn<Buffered<S, D>, Phase, Cleanliness> {
    /// Flushes buffered output while retaining ownership of the typed connection.
    ///
    /// # Errors
    ///
    /// Returns an error from the underlying transport.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.transport_mut().flush().await
    }
}

impl<S: AsyncRead + Unpin, Phase, Cleanliness> Conn<Buffered<S, Backend>, Phase, Cleanliness> {
    /// Receives one backend message before demultiplexing or state advancement.
    /// This is the interception point for proxy policy and message rewriting.
    ///
    /// # Errors
    ///
    /// Returns decoding and underlying transport read errors, or `UnexpectedEof`.
    pub async fn receive_backend_wire(&mut self) -> io::Result<BackendMessage> {
        self.transport_mut().receive_backend().await
    }

    /// Projects an inspected or modified message into the filtered session stream.
    pub fn project_backend(&mut self, message: BackendMessage) -> Option<SessionItem> {
        self.transport_mut().project_backend(message)
    }

    /// Receives the next message in the filtered session projection.
    ///
    /// # Errors
    ///
    /// Returns decoding and underlying transport read errors, or `UnexpectedEof`.
    pub async fn receive(&mut self) -> io::Result<SessionItem> {
        self.transport_mut().receive_session().await
    }

    #[must_use]
    pub fn cancel_key(&self) -> Option<&CancelKey> {
        self.transport().demux().cancel_key()
    }

    /// Returns the latest backend parameter values observed by the demux.
    #[must_use]
    pub fn parameters(&self) -> &BTreeMap<Bytes, Bytes> {
        self.transport().demux().parameters()
    }

    /// Returns whether current parameters differ from the startup baseline.
    #[must_use]
    pub fn parameters_changed(&self) -> bool {
        self.transport().demux().parameters_changed()
    }

    /// Returns the latest transaction status observed in `ReadyForQuery`.
    #[must_use]
    pub fn transaction_status(&self) -> Option<crate::codec::TransactionStatus> {
        self.transport().demux().transaction_status()
    }

    pub fn pop_notification(&mut self) -> Option<Notification> {
        self.transport_mut().demux_mut().pop_notification()
    }

    /// Removes the next tagged notice for prompt forwarding to the client.
    pub fn pop_notice(&mut self) -> Option<TaggedNotice> {
        self.transport_mut().demux_mut().pop_notice()
    }

    /// Removes the next ordered parameter update for forwarding to the client.
    pub fn pop_parameter_status(&mut self) -> Option<ParameterStatus> {
        self.transport_mut().demux_mut().pop_parameter_status()
    }
}

impl<S: AsyncRead + Unpin, Phase, Cleanliness> Conn<Buffered<S, Frontend>, Phase, Cleanliness> {
    /// Receives one frontend message before any server-role state advancement.
    ///
    /// # Errors
    ///
    /// Returns decoding and underlying transport read errors, or `UnexpectedEof`.
    pub async fn receive_frontend_wire(&mut self) -> io::Result<FrontendMessage> {
        self.transport_mut().receive_wire().await
    }
}

impl<S: AsyncRead + Unpin, Cleanliness> Conn<Buffered<S, Frontend>, PreStartup, Cleanliness> {
    /// Receives a raw pre-startup packet before server-role state projection.
    ///
    /// # Errors
    ///
    /// Returns malformed pre-startup data and underlying transport read errors.
    pub async fn receive_pre_startup_wire(&mut self) -> io::Result<PreStartupMessage> {
        self.transport_mut().receive_pre_startup().await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use tokio::io::AsyncWrite;

    use super::*;

    #[derive(Debug, Default)]
    struct ShortWriter {
        output: Vec<u8>,
    }

    impl AsyncWrite for ShortWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let written = buffer.len().min(2);
            self.output.extend_from_slice(&buffer[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn flush_handles_partial_writes_without_losing_bytes() {
        let frame = Frame {
            tag: b'S',
            body: Bytes::new(),
        };
        let mut transport = Buffered::new(ShortWriter::default());
        transport.push(frame).expect("encodable frame");
        assert_eq!(transport.pending(), &[b'S', 0, 0, 0, 4]);
        transport.flush().await.expect("writable transport");
        assert!(transport.pending().is_empty());
        assert_eq!(transport.into_inner().output, [b'S', 0, 0, 0, 4]);
    }

    #[test]
    fn buffered_transport_enforces_its_frame_limit_on_output() {
        let mut transport = Buffered::<_, Backend>::with_max_frame_len((), 9).unwrap();
        let error = transport
            .push(Frame {
                tag: b'Q',
                body: Bytes::from_static(b"12345"),
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(transport.pending().is_empty());
    }

    #[test]
    fn cancelling_flush_retains_unwritten_bytes() {
        #[derive(Debug, Default)]
        struct PausingWriter {
            output: Vec<u8>,
            blocked: bool,
        }

        impl AsyncWrite for PausingWriter {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buffer: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.blocked {
                    return Poll::Pending;
                }
                let written = buffer.len().min(2);
                self.output.extend_from_slice(&buffer[..written]);
                self.blocked = true;
                Poll::Ready(Ok(written))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut transport = Buffered::new(PausingWriter::default());
        transport
            .push(Frame {
                tag: b'S',
                body: Bytes::new(),
            })
            .expect("encodable frame");

        let mut flush = Box::pin(transport.flush());
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(flush.as_mut().poll(&mut context).is_pending());
        drop(flush);

        assert_eq!(transport.pending(), &[0, 0, 4]);
        assert_eq!(transport.io.output, [b'S', 0]);
    }

    #[tokio::test]
    async fn receive_filters_parameter_status_before_session_message() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut wire = BytesMut::new();
        let mut encoder = PgCodec::<Backend>::default();
        encoder
            .encode(
                Frame {
                    tag: b'S',
                    body: Bytes::from_static(b"client_encoding\0UTF8\0"),
                },
                &mut wire,
            )
            .expect("encodable ParameterStatus");
        encoder
            .encode(
                Frame {
                    tag: b'Z',
                    body: Bytes::from_static(b"I"),
                },
                &mut wire,
            )
            .expect("encodable ReadyForQuery");
        server.write_all(&wire).await.expect("writable test peer");

        let mut transport = Buffered::new(client);
        assert_eq!(
            transport.receive_session().await.expect("valid messages"),
            SessionItem::ReadyForQuery {
                status: crate::codec::TransactionStatus::Idle,
                parameters_changed: false,
            }
        );
        assert_eq!(
            transport
                .demux()
                .parameters()
                .get(&Bytes::from_static(b"client_encoding")),
            Some(&Bytes::from_static(b"UTF8"))
        );
        let conn: Conn<_, crate::auth::Ready> = Conn::new(transport).transition();
        assert_eq!(
            conn.parameters().get(b"client_encoding".as_slice()),
            Some(&Bytes::from_static(b"UTF8"))
        );
        assert!(!conn.parameters_changed());
        assert_eq!(
            conn.transaction_status(),
            Some(crate::codec::TransactionStatus::Idle)
        );
        conn.into_transport();
    }

    #[tokio::test]
    async fn wire_message_can_be_modified_before_projection() {
        let (client, mut server) = tokio::io::duplex(128);
        let original = BackendMessage::ParameterStatus {
            name: Bytes::from_static(b"application_name"),
            value: Bytes::from_static(b"upstream"),
        };
        let mut bytes = BytesMut::new();
        PgCodec::<Backend>::default()
            .encode(
                original.to_frame().expect("reconstructable message"),
                &mut bytes,
            )
            .expect("encodable message");
        server.write_all(&bytes).await.expect("writable test peer");

        let mut transport = Buffered::new(client);
        let mut message = transport
            .receive_backend()
            .await
            .expect("decodable message");
        let BackendMessage::ParameterStatus { value, .. } = &mut message else {
            panic!("unexpected message")
        };
        *value = Bytes::from_static(b"proxy");
        assert!(transport.project_backend(message).is_none());
        assert_eq!(
            transport
                .demux()
                .parameters()
                .get(&Bytes::from_static(b"application_name")),
            Some(&Bytes::from_static(b"proxy"))
        );
    }

    #[tokio::test]
    async fn client_facing_transport_intercepts_typed_frontend_messages() {
        let (proxy, mut client) = tokio::io::duplex(128);
        let message = FrontendMessage::Query(Bytes::from_static(b"select plaintext"));
        let mut bytes = BytesMut::new();
        PgCodec::<Frontend>::default()
            .encode(
                message.to_frame().expect("reconstructable Query"),
                &mut bytes,
            )
            .expect("encodable Query");
        client.write_all(&bytes).await.expect("writable client");

        let mut transport = Buffered::<_, Frontend>::new_frontend(proxy);
        let mut intercepted = transport.receive_wire().await.expect("decodable Query");
        let FrontendMessage::Query(query) = &mut intercepted else {
            panic!("unexpected frontend message")
        };
        *query = Bytes::from_static(b"select encrypted");
        assert_eq!(
            intercepted,
            FrontendMessage::Query(Bytes::from_static(b"select encrypted"))
        );
    }

    #[tokio::test]
    async fn client_facing_transport_projects_repeated_pre_startup_choice() {
        let (proxy, mut client) = tokio::io::duplex(256);
        let ssl = PreStartupMessage::SslRequest
            .to_packet()
            .expect("encodable SSLRequest");
        let startup = PreStartupMessage::Startup(crate::startup::StartupMessage {
            version: crate::startup::ProtocolVersion::V3_2,
            parameters: std::collections::BTreeMap::from([(
                Bytes::from_static(b"user"),
                Bytes::from_static(b"postgres"),
            )]),
        });
        let startup_packet = startup.to_packet().expect("encodable StartupMessage");
        client.write_all(&ssl).await.expect("writable client");
        client
            .write_all(&startup_packet)
            .await
            .expect("writable client");

        let mut conn = Conn::new(Buffered::<_, Frontend>::new_frontend(proxy));
        let ssl = conn
            .receive_pre_startup_wire()
            .await
            .expect("decodable SSLRequest");
        let crate::pre_startup::PreStartupOffer::Ssl(decision) = conn.offer_pre_startup(ssl) else {
            panic!("unexpected pre-startup branch")
        };
        let (mut conn, reply) = decision.reject_ssl();
        assert_eq!(reply, b'N');
        let message = conn
            .receive_pre_startup_wire()
            .await
            .expect("decodable StartupMessage");
        assert_eq!(message, startup);
        let crate::pre_startup::PreStartupOffer::Startup { conn, .. } =
            conn.offer_pre_startup(message)
        else {
            panic!("unexpected pre-startup branch")
        };
        let _transport = conn.into_transport();
    }

    #[tokio::test]
    async fn client_facing_transport_applies_its_pre_startup_limit() {
        let (proxy, mut client) = tokio::io::duplex(32);
        client
            .write_all(&17_u32.to_be_bytes())
            .await
            .expect("writable client");

        let mut transport =
            Buffered::<_, Frontend>::with_limits_frontend(proxy, 64, 16).expect("valid limits");
        let error = transport
            .receive_pre_startup()
            .await
            .expect_err("declared packet exceeds the configured limit");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn upstream_transport_negotiates_raw_gssenc_reply() {
        let (proxy, mut server) = tokio::io::duplex(32);
        let mut pending = Conn::new(Buffered::new(proxy)).request_gss();
        pending.flush().await.expect("GSSENCRequest is writable");

        let mut request = [0_u8; 8];
        server
            .read_exact(&mut request)
            .await
            .expect("server receives GSSENCRequest");
        assert_eq!(request, gssenc_request_packet());
        server
            .write_all(b"N")
            .await
            .expect("server writes decision");

        let Negotiation::Rejected(plaintext) = pending
            .receive_gss_reply()
            .await
            .expect("valid GSSENC decision")
        else {
            panic!("expected plaintext fallback")
        };
        plaintext.into_transport();
    }

    #[test]
    fn client_facing_transport_buffers_raw_gssenc_decision() {
        let conn = Conn::new(Buffered::<_, Frontend>::new_frontend(()));
        let crate::pre_startup::PreStartupOffer::Gss(decision) =
            conn.offer_pre_startup(PreStartupMessage::GssEncRequest)
        else {
            panic!("expected GSSENC decision")
        };

        let handshake = decision.approve_gss();
        assert_eq!(handshake.pending_output(), b"S");
        handshake.into_transport();

        let conn = Conn::new(Buffered::<_, Frontend>::new_frontend(()));
        let crate::pre_startup::PreStartupOffer::Gss(decision) =
            conn.offer_pre_startup(PreStartupMessage::GssEncRequest)
        else {
            panic!("expected GSSENC decision")
        };
        let terminated = decision.reject_gss_with_legacy_error();
        assert_eq!(terminated.pending_output(), b"E");
        terminated.into_transport();
    }

    #[test]
    fn client_facing_transport_buffers_legacy_ssl_error() {
        let conn = Conn::new(Buffered::<_, Frontend>::new_frontend(()));
        let crate::pre_startup::PreStartupOffer::Ssl(decision) =
            conn.offer_pre_startup(PreStartupMessage::SslRequest)
        else {
            panic!("expected SSL decision")
        };

        let terminated = decision.reject_ssl_with_legacy_error();
        assert_eq!(terminated.pending_output(), b"E");
        terminated.into_transport();
    }
}
