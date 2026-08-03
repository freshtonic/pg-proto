//! Server-role query sessions used when a proxy terminates the client protocol.

use std::io;

use bytes::Bytes;

use crate::{
    Conn, Dirty,
    auth::Ready,
    codec::{
        BackendMessage, Bind, Close, Describe, DiagnosticResponse, Execute, Frame, FrontendMessage,
        Parse, RowDescription, TransactionStatus,
    },
    pre_startup::Terminated,
};

#[derive(Debug)]
pub enum ServerSimpleQuery {}

#[derive(Debug)]
pub enum ServerSimpleError {}

#[derive(Debug)]
pub enum ServerBuilding {}

#[derive(Debug)]
pub enum ServerParse {}

#[derive(Debug)]
pub enum ServerBind {}

#[derive(Debug)]
pub enum ServerDescribe {}

#[derive(Debug)]
pub enum ServerExecute {}

#[derive(Debug)]
pub enum ServerClose {}

#[derive(Debug)]
pub enum ServerSync {}

#[derive(Debug)]
pub enum ServerExtendedError {}

/// External choice offered by a client while the server role is ready.
#[derive(Debug)]
pub enum ServerReadyOffer<S, C> {
    Query {
        conn: Conn<S, ServerSimpleQuery, C>,
        query: Bytes,
    },
    Extended(ServerExtendedOffer<S, C>),
    Terminate(Conn<S, Terminated, C>),
}

/// A response-specific branch of the extended-query building loop.
#[derive(Debug)]
pub enum ServerExtendedOffer<S, C> {
    Parse {
        conn: Conn<S, ServerParse, C>,
        message: Parse,
    },
    Bind {
        conn: Conn<S, ServerBind, C>,
        message: Bind,
    },
    Describe {
        conn: Conn<S, ServerDescribe, C>,
        message: Describe,
    },
    Execute {
        conn: Conn<S, ServerExecute, C>,
        message: Execute,
    },
    Close {
        conn: Conn<S, ServerClose, C>,
        message: Close,
    },
    Flush(Conn<S, ServerBuilding, C>),
    Sync(Conn<S, ServerSync, C>),
}

/// Projection while discarding a failed pipeline up to its synchronisation point.
#[derive(Debug)]
pub enum ServerDiscard<S, C> {
    Continue(Conn<S, ServerExtendedError, C>),
    Sync(Conn<S, ServerSync, C>),
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
pub type ExtendedProjection<S, Phase, C> =
    Result<ServerExtendedOffer<S, C>, Box<(Conn<S, Phase, C>, FrontendMessage)>>;

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
            other => project_extended(self, other).map(ServerReadyOffer::Extended),
        }
    }
}

impl<S, C> Conn<S, ServerBuilding, C> {
    /// Projects the next inspected message in an extended-query pipeline.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not legal before `Sync`.
    pub fn offer_frontend(
        self,
        message: FrontendMessage,
    ) -> ExtendedProjection<S, ServerBuilding, C> {
        project_extended(self, message)
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

impl<S, C> Conn<S, ServerParse, C> {
    /// Confirms a successful `Parse` and returns to the building loop.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed response cannot be encoded.
    pub fn complete(self) -> io::Result<(Conn<S, ServerBuilding, C>, Frame)> {
        Ok((self.transition(), BackendMessage::ParseComplete.to_frame()?))
    }

    /// Rejects `Parse` and begins discarding the pipeline until `Sync`.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, ServerExtendedError, C>, Frame)> {
        extended_error(self, response)
    }
}

impl<S, C> Conn<S, ServerBind, C> {
    /// Confirms a successful `Bind` and returns to the building loop.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed response cannot be encoded.
    pub fn complete(self) -> io::Result<(Conn<S, ServerBuilding, C>, Frame)> {
        Ok((self.transition(), BackendMessage::BindComplete.to_frame()?))
    }

    /// Rejects `Bind` and begins discarding the pipeline until `Sync`.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, ServerExtendedError, C>, Frame)> {
        extended_error(self, response)
    }
}

impl<S, C> Conn<S, ServerClose, C> {
    /// Confirms `Close` and returns to the building loop.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed response cannot be encoded.
    pub fn complete(self) -> io::Result<(Conn<S, ServerBuilding, C>, Frame)> {
        Ok((self.transition(), BackendMessage::CloseComplete.to_frame()?))
    }

    /// Rejects `Close` and begins discarding the pipeline until `Sync`.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, ServerExtendedError, C>, Frame)> {
        extended_error(self, response)
    }
}

impl<S, C> Conn<S, ServerDescribe, C> {
    /// Sends statement parameter OIDs before its row metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the OID count overflows the protocol field.
    pub fn parameter_description(self, oids: Vec<u32>) -> io::Result<(Self, Frame)> {
        Ok((self, BackendMessage::ParameterDescription(oids).to_frame()?))
    }

    /// Sends reconstructable row metadata and returns to the building loop.
    ///
    /// # Errors
    ///
    /// Returns an error if field metadata is invalid.
    pub fn row_description(
        self,
        description: RowDescription,
    ) -> io::Result<(Conn<S, ServerBuilding, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::RowDescription(description).to_frame()?,
        ))
    }

    /// Sends `NoData` and returns to the building loop.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed response cannot be encoded.
    pub fn no_data(self) -> io::Result<(Conn<S, ServerBuilding, C>, Frame)> {
        Ok((self.transition(), BackendMessage::NoData.to_frame()?))
    }

    /// Rejects `Describe` and begins discarding the pipeline until `Sync`.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, ServerExtendedError, C>, Frame)> {
        extended_error(self, response)
    }
}

impl<S, C> Conn<S, ServerExecute, C> {
    /// Sends a non-terminal result message for `Execute`.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be reconstructed or requires a
    /// dedicated state transition.
    pub fn send(self, message: &BackendMessage) -> io::Result<(Self, Frame)> {
        if matches!(
            message,
            BackendMessage::CommandComplete(_)
                | BackendMessage::PortalSuspended
                | BackendMessage::ErrorResponse(_)
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

    /// Completes execution and returns to the building loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the command tag contains a NUL byte.
    pub fn command_complete(self, tag: Bytes) -> io::Result<(Conn<S, ServerBuilding, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::CommandComplete(tag).to_frame()?,
        ))
    }

    /// Suspends a portal and returns to the building loop.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed response cannot be encoded.
    pub fn portal_suspended(self) -> io::Result<(Conn<S, ServerBuilding, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::PortalSuspended.to_frame()?,
        ))
    }

    /// Rejects `Execute` and begins discarding the pipeline until `Sync`.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, ServerExtendedError, C>, Frame)> {
        extended_error(self, response)
    }
}

impl<S, C> Conn<S, ServerExtendedError, C> {
    /// Discards one pipelined message; only `Sync` exits error recovery.
    #[must_use]
    pub fn discard(self, message: &FrontendMessage) -> ServerDiscard<S, C> {
        if *message == FrontendMessage::Sync {
            ServerDiscard::Sync(self.transition())
        } else {
            ServerDiscard::Continue(self)
        }
    }
}

impl<S, C> Conn<S, ServerSync, C> {
    /// Answers `Sync` with `ReadyForQuery` and surfaces transaction status.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed ready message cannot be encoded.
    pub fn ready(self, status: TransactionStatus) -> io::Result<(ServerReadyState<S, C>, Frame)> {
        ready(self, status)
    }
}

fn project_extended<S, Phase, C>(
    conn: Conn<S, Phase, C>,
    message: FrontendMessage,
) -> ExtendedProjection<S, Phase, C> {
    Ok(match message {
        FrontendMessage::Parse(message) => ServerExtendedOffer::Parse {
            conn: conn.transition(),
            message,
        },
        FrontendMessage::Bind(message) => ServerExtendedOffer::Bind {
            conn: conn.transition(),
            message,
        },
        FrontendMessage::Describe(message) => ServerExtendedOffer::Describe {
            conn: conn.transition(),
            message,
        },
        FrontendMessage::Execute(message) => ServerExtendedOffer::Execute {
            conn: conn.transition(),
            message,
        },
        FrontendMessage::Close(message) => ServerExtendedOffer::Close {
            conn: conn.transition(),
            message,
        },
        FrontendMessage::Flush => ServerExtendedOffer::Flush(conn.transition()),
        FrontendMessage::Sync => ServerExtendedOffer::Sync(conn.transition()),
        other => return Err(Box::new((conn, other))),
    })
}

fn extended_error<S, Phase, C>(
    conn: Conn<S, Phase, C>,
    response: DiagnosticResponse,
) -> io::Result<(Conn<S, ServerExtendedError, C>, Frame)> {
    Ok((
        conn.transition(),
        BackendMessage::ErrorResponse(response).to_frame()?,
    ))
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
    use crate::{
        Pristine,
        codec::{DataRow, DiagnosticField},
    };

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

    #[test]
    fn extended_pipeline_rewrites_parse_and_exits_only_through_sync() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let parse = Parse {
            statement: Bytes::from_static(b"statement"),
            query: Bytes::from_static(b"select $1"),
            parameter_types: vec![23],
        };
        let ServerReadyOffer::Extended(ServerExtendedOffer::Parse { conn, message }) = ready
            .offer_frontend(FrontendMessage::Parse(parse.clone()))
            .unwrap()
        else {
            panic!("parse projected to the wrong branch")
        };
        assert_eq!(message, parse);
        let (building, complete) = conn.complete().unwrap();
        assert_eq!(complete.tag, b'1');

        let ServerExtendedOffer::Bind { conn, message } = building
            .offer_frontend(FrontendMessage::Bind(Bind {
                portal: Bytes::new(),
                statement: Bytes::from_static(b"statement"),
                parameter_formats: vec![],
                parameters: vec![Some(Bytes::from_static(b"42"))],
                result_formats: vec![],
            }))
            .unwrap()
        else {
            panic!("bind projected to the wrong branch")
        };
        assert_eq!(message.parameters[0], Some(Bytes::from_static(b"42")));
        let (building, _) = conn.complete().unwrap();
        let ServerExtendedOffer::Sync(sync) =
            building.offer_frontend(FrontendMessage::Sync).unwrap()
        else {
            panic!("sync projected to the wrong branch")
        };
        let (state, _) = sync.ready(TransactionStatus::Idle).unwrap();
        let ServerReadyState::Ready(ready) = state else {
            panic!("idle sync was marked dirty")
        };
        ready.into_transport();
    }

    #[test]
    fn extended_error_discards_everything_before_sync() {
        let parse: Conn<(), ServerParse> = Conn::new(()).transition();
        let (error, frame) = parse
            .error(DiagnosticResponse {
                fields: vec![DiagnosticField {
                    code: b'C',
                    value: Bytes::from_static(b"42601"),
                }],
            })
            .unwrap();
        assert_eq!(frame.tag, b'E');
        let ServerDiscard::Continue(error) = error.discard(&FrontendMessage::Flush) else {
            panic!("flush escaped error recovery")
        };
        let ServerDiscard::Sync(sync) = error.discard(&FrontendMessage::Sync) else {
            panic!("sync did not exit error recovery")
        };
        let (state, _) = sync.ready(TransactionStatus::Idle).unwrap();
        let ServerReadyState::Ready(ready) = state else {
            panic!("idle sync was marked dirty")
        };
        ready.into_transport();
    }
}
