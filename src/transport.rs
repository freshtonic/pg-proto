//! Buffered, cancellation-safe outbound transport.

use std::io;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::codec::Encoder;

use crate::{Conn, codec::Frame};

/// Transport wrapper which retains bytes until each write has completed.
#[derive(Debug)]
pub struct Buffered<S> {
    io: S,
    outbound: BytesMut,
}

impl<S> Buffered<S> {
    pub fn new(io: S) -> Self {
        Self {
            io,
            outbound: BytesMut::new(),
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
}
