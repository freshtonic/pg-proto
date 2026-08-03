//! Server-role query sessions used when a proxy terminates the client protocol.

use std::io;

use bytes::Bytes;

use crate::{
    Conn, Dirty,
    auth::Ready,
    codec::{BackendMessage, DiagnosticResponse, Frame, FrontendMessage, TransactionStatus},
    pre_startup::Terminated,
};

#[derive(Debug)]
pub enum ServerSimpleQuery {}

#[derive(Debug)]
pub enum ServerSimpleError {}

/// External choice offered by a client while the server role is ready.
#[derive(Debug)]
pub enum ServerReadyOffer<S, C> {
    Query {
        conn: Conn<S, ServerSimpleQuery, C>,
        query: Bytes,
    },
    Terminate(Conn<S, Terminated, C>),
}

/// Ready state produced from the status byte sent to the client.
#[derive(Debug)]
pub enum ServerReadyState<S, C> {
    Ready(Conn<S, Ready, C>),
    Dirty {
        conn: Conn<S, Ready, Dirty>,
        status: TransactionStatus,
    },
}

pub type ReadyProjection<S, C> =
    Result<ServerReadyOffer<S, C>, Box<(Conn<S, Ready, C>, FrontendMessage)>>;

impl<S, C> Conn<S, Ready, C> {
    /// Projects an inspected client message into the server-role ready state.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and message for choices not yet legal in
    /// this simple-query projection.
    pub fn offer_frontend(self, message: FrontendMessage) -> ReadyProjection<S, C> {
        match message {
            FrontendMessage::Query(query) => Ok(ServerReadyOffer::Query {
                conn: self.transition(),
                query,
            }),
            FrontendMessage::Terminate => Ok(ServerReadyOffer::Terminate(self.transition())),
            other => Err(Box::new((self, other))),
        }
    }
}

impl<S, C> Conn<S, ServerSimpleQuery, C> {
    /// Sends a non-terminal typed result message after proxy inspection or rewriting.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be reconstructed, or if it would
    /// prematurely change the simple-query state.
    pub fn send(self, message: &BackendMessage) -> io::Result<(Self, Frame)> {
        if matches!(
            message,
            BackendMessage::ErrorResponse(_)
                | BackendMessage::ReadyForQuery(_)
                | BackendMessage::CopyInResponse(_)
                | BackendMessage::CopyOutResponse(_)
                | BackendMessage::CopyBothResponse(_)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "state-changing response requires its typed transition",
            ));
        }
        Ok((self, message.to_frame()?))
    }

    /// Sends an error response before the mandatory `ReadyForQuery`.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, ServerSimpleError, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::ErrorResponse(response).to_frame()?,
        ))
    }

    /// Ends a successful simple-query exchange and surfaces transaction status.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed ready message cannot be encoded.
    pub fn ready(self, status: TransactionStatus) -> io::Result<(ServerReadyState<S, C>, Frame)> {
        ready(self, status)
    }
}

impl<S, C> Conn<S, ServerSimpleError, C> {
    /// Ends an errored simple-query exchange and surfaces transaction status.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed ready message cannot be encoded.
    pub fn ready(self, status: TransactionStatus) -> io::Result<(ServerReadyState<S, C>, Frame)> {
        ready(self, status)
    }
}

fn ready<S, Phase, C>(
    conn: Conn<S, Phase, C>,
    status: TransactionStatus,
) -> io::Result<(ServerReadyState<S, C>, Frame)> {
    let frame = BackendMessage::ReadyForQuery(status).to_frame()?;
    let state = if status == TransactionStatus::Idle {
        ServerReadyState::Ready(conn.transition())
    } else {
        ServerReadyState::Dirty {
            conn: conn.transition(),
            status,
        }
    };
    Ok((state, frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Pristine, codec::DataRow};

    #[test]
    fn simple_query_allows_rewriting_before_ready() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let ServerReadyOffer::Query { conn, query } = ready
            .offer_frontend(FrontendMessage::Query(Bytes::from_static(b"select 1")))
            .unwrap()
        else {
            panic!("query projected to the wrong branch")
        };
        assert_eq!(query, Bytes::from_static(b"select 1"));

        let rewritten = BackendMessage::DataRow(DataRow {
            columns: vec![Some(Bytes::from_static(b"2"))],
        });
        let (conn, frame) = conn.send(&rewritten).unwrap();
        assert_eq!(frame.tag, b'D');
        let (state, frame) = conn.ready(TransactionStatus::Idle).unwrap();
        assert_eq!(frame.body, Bytes::from_static(b"I"));
        let ServerReadyState::Ready(ready) = state else {
            panic!("idle response was marked dirty")
        };
        ready.into_transport();
    }

    #[test]
    fn transaction_status_taints_the_server_connection() {
        let query: Conn<(), ServerSimpleQuery, Pristine> = Conn::new(()).transition();
        let (state, _) = query.ready(TransactionStatus::InTransaction).unwrap();
        let ServerReadyState::Dirty { conn, status } = state else {
            panic!("transactional response was marked clean")
        };
        assert_eq!(status, TransactionStatus::InTransaction);
        conn.into_transport();
    }
}
