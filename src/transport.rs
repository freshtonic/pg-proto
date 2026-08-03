//! Buffered, cancellation-safe outbound transport.

use std::io;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    Conn,
    auth::TlsServerEndPoint,
    codec::{Backend, BackendMessage, Frame, PgCodec},
    demux::{CancelKey, Demux, Notification, SessionItem},
};

/// Transport wrapper which retains bytes until each write has completed.
#[derive(Debug)]
pub struct Buffered<S> {
    io: S,
    outbound: BytesMut,
    inbound: BytesMut,
    backend_codec: PgCodec<Backend>,
    demux: Demux,
}

impl<S> Buffered<S> {
    pub fn new(io: S) -> Self {
        Self {
            io,
            outbound: BytesMut::new(),
            inbound: BytesMut::new(),
            backend_codec: PgCodec::default(),
            demux: Demux::default(),
        }
    }

    /// Encodes a frame synchronously into the outbound buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too large to encode.
    pub fn push(&mut self, frame: Frame) -> io::Result<()> {
        crate::codec::PgCodec::<crate::codec::Frontend>::default().encode(frame, &mut self.outbound)
    }

    #[must_use]
    pub fn pending(&self) -> &[u8] {
        &self.outbound
    }

    pub fn into_inner(self) -> S {
        self.io
    }

    #[must_use]
    pub const fn demux(&self) -> &Demux {
        &self.demux
    }

    pub const fn demux_mut(&mut self) -> &mut Demux {
        &mut self.demux
    }
}

impl<S: TlsServerEndPoint> TlsServerEndPoint for Buffered<S> {
    fn tls_server_end_point(&self) -> &[u8] {
        self.io.tls_server_end_point()
    }
}

impl<S: AsyncWrite + Unpin> Buffered<S> {
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

impl<S: AsyncRead + Unpin> Buffered<S> {
    /// Receives one decoded backend message while retaining partial input.
    ///
    /// # Errors
    ///
    /// Returns decoding and underlying transport read errors, or `UnexpectedEof`.
    pub async fn receive_backend(&mut self) -> io::Result<BackendMessage> {
        loop {
            if let Some(message) = self.backend_codec.decode(&mut self.inbound)? {
                return Ok(message);
            }
            if self.io.read_buf(&mut self.inbound).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "backend closed with no complete message",
                ));
            }
        }
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

impl<S, Phase, Cleanliness> Conn<Buffered<S>, Phase, Cleanliness> {
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

impl<S, Cleanliness> Conn<Buffered<S>, crate::pre_startup::Startup, Cleanliness> {
    /// Buffers the raw, untagged startup packet before normal framing begins.
    pub fn push_startup_packet(&mut self, packet: &[u8]) {
        self.transport_mut().outbound.extend_from_slice(packet);
    }
}

impl<S: AsyncWrite + Unpin, Phase, Cleanliness> Conn<Buffered<S>, Phase, Cleanliness> {
    /// Flushes buffered output while retaining ownership of the typed connection.
    ///
    /// # Errors
    ///
    /// Returns an error from the underlying transport.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.transport_mut().flush().await
    }
}

impl<S: AsyncRead + Unpin, Phase, Cleanliness> Conn<Buffered<S>, Phase, Cleanliness> {
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

    pub fn pop_notification(&mut self) -> Option<Notification> {
        self.transport_mut().demux_mut().pop_notification()
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
            SessionItem::Message(BackendMessage::ReadyForQuery(
                crate::codec::TransactionStatus::Idle
            ))
        );
        assert_eq!(
            transport
                .demux()
                .parameters()
                .get(&Bytes::from_static(b"client_encoding")),
            Some(&Bytes::from_static(b"UTF8"))
        );
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
}
