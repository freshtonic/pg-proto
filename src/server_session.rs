//! Server-role query sessions used when a proxy terminates the client protocol.

use std::io;
use std::marker::PhantomData;

use bytes::Bytes;

use crate::{
    Conn, Dirty,
    auth::Ready,
    codec::{
        BackendMessage, Bind, Close, CopyResponse, Describe, DiagnosticResponse, Execute, Frame,
        FrontendMessage, FunctionCall, Parse, RowDescription, TransactionStatus,
    },
    grammar::backend,
    pre_startup::Terminated,
    replication::{BackendReplication, FrontendReplication},
};

#[derive(Debug)]
/// A client simple query is being served.
pub enum ServerSimpleQuery {}

#[derive(Debug)]
/// A simple-query error was sent and readiness must follow.
pub enum ServerSimpleError {}

#[derive(Debug)]
/// A legacy function call is being served.
pub enum ServerFunctionCall {}

#[derive(Debug)]
/// A function result was sent and readiness must follow.
pub enum ServerFunctionCallDone {}

#[derive(Debug)]
/// A function-call error was sent and readiness must follow.
pub enum ServerFunctionCallError {}

#[derive(Debug)]
/// The server is accepting an extended-query pipeline.
pub enum ServerBuilding {}

#[derive(Debug)]
/// An inspected `Parse` awaits its response.
pub enum ServerParse {}

#[derive(Debug)]
/// An inspected `Bind` awaits its response.
pub enum ServerBind {}

#[derive(Debug)]
/// An inspected `Describe` awaits its response.
pub enum ServerDescribe {}

#[derive(Debug)]
/// An inspected `Execute` is being served.
pub enum ServerExecute {}

#[derive(Debug)]
/// An inspected `Close` awaits its response.
pub enum ServerClose {}

#[derive(Debug)]
/// A client `Sync` awaits `ReadyForQuery`.
pub enum ServerSync {}

#[derive(Debug)]
/// A failed extended pipeline is discarded until `Sync`.
pub enum ServerExtendedError {}

#[derive(Debug)]
/// COPY resumes in a simple-query session.
pub enum CopySimple {}

#[derive(Debug)]
/// COPY resumes in an extended-query session.
pub enum CopyExtended {}

/// Maps a COPY resumption marker to its generated nested-session states.
pub trait CopyResume {
    /// Generated state while both COPY directions remain open.
    const BOTH_OPEN_STATE: backend::RuntimeState;
    /// Generated state after the server closes its COPY direction.
    const BOTH_SERVER_DONE_STATE: backend::RuntimeState;
}

impl CopyResume for CopySimple {
    const BOTH_OPEN_STATE: backend::RuntimeState = backend::RuntimeState::SimpleCopyBoth;
    const BOTH_SERVER_DONE_STATE: backend::RuntimeState =
        backend::RuntimeState::SimpleCopyBothServerDone;
}

impl CopyResume for CopyExtended {
    const BOTH_OPEN_STATE: backend::RuntimeState = backend::RuntimeState::ExtendedCopyBoth;
    const BOTH_SERVER_DONE_STATE: backend::RuntimeState =
        backend::RuntimeState::ExtendedCopyBothServerDone;
}

#[derive(Debug)]
/// Server-role COPY IN stream, resumed according to `Resume`.
pub struct ServerCopyIn<Resume>(PhantomData<Resume>);

#[derive(Debug)]
/// Client completed a server-role COPY IN stream.
pub struct ServerCopyInDone<Resume>(PhantomData<Resume>);

#[derive(Debug)]
/// Client failed a server-role COPY IN stream.
pub struct ServerCopyInFailed<Resume>(PhantomData<Resume>);

#[derive(Debug)]
/// Server-role COPY OUT stream, resumed according to `Resume`.
pub struct ServerCopyOut<Resume>(PhantomData<Resume>);

#[derive(Debug)]
/// Server completed a server-role COPY OUT stream.
pub struct ServerCopyOutDone<Resume>(PhantomData<Resume>);

#[derive(Debug)]
/// Both halves of a COPY BOTH stream remain open.
pub enum BothOpen {}

#[derive(Debug)]
/// The client half of a COPY BOTH stream is closed.
pub enum BothClientDone {}

#[derive(Debug)]
/// The server half of a COPY BOTH stream is closed.
pub enum BothServerDone {}

#[derive(Debug)]
/// Both halves of a COPY BOTH stream are closed.
pub enum BothDone {}

#[derive(Debug)]
/// Server-role COPY BOTH stream parameterised by resumption and half-close state.
pub struct ServerCopyBoth<Resume, Ends>(PhantomData<(Resume, Ends)>);

#[derive(Debug)]
/// Client failed a server-role COPY BOTH stream.
pub struct ServerCopyBothFailed<Resume>(PhantomData<Resume>);

/// Client choice while both COPY BOTH directions remain open.
#[derive(Debug)]
pub enum ServerCopyBothOpenOffer<S, C, Resume> {
    /// The client sent one opaque data chunk.
    Data {
        /// Connection remaining in COPY BOTH.
        conn: Conn<S, ServerCopyBoth<Resume, BothOpen>, C>,
        /// Copy payload.
        data: Bytes,
    },
    /// The client closed its sending half.
    Done(Conn<S, ServerCopyBoth<Resume, BothClientDone>, C>),
    /// The client aborted COPY.
    Fail {
        /// Failed COPY connection.
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        /// Client error message without its terminating NUL.
        message: Bytes,
    },
}

/// Client choice after the server closes its COPY BOTH direction.
#[derive(Debug)]
pub enum ServerCopyBothServerDoneOffer<S, C, Resume> {
    /// The client sent one final opaque data chunk.
    Data {
        /// Connection with only the client direction open.
        conn: Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>,
        /// Copy payload.
        data: Bytes,
    },
    /// The client closed the remaining direction.
    Done(Conn<S, ServerCopyBoth<Resume, BothDone>, C>),
    /// The client aborted COPY.
    Fail {
        /// Failed COPY connection.
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        /// Client error message without its terminating NUL.
        message: Bytes,
    },
}

/// Typed standby choice while both replication directions remain open.
#[derive(Debug)]
pub enum ServerReplicationOpenOffer<S, C, Resume> {
    /// The standby sent one decoded replication message.
    Message {
        /// Connection remaining in COPY BOTH.
        conn: Conn<S, ServerCopyBoth<Resume, BothOpen>, C>,
        /// Decoded standby message.
        message: FrontendReplication,
    },
    /// The standby closed its sending half.
    Done(Conn<S, ServerCopyBoth<Resume, BothClientDone>, C>),
    /// The standby aborted replication.
    Fail {
        /// Failed replication connection.
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        /// Standby error message without its terminating NUL.
        message: Bytes,
    },
}

/// Typed standby choice after the walsender closes its direction.
#[derive(Debug)]
pub enum ServerReplicationServerDoneOffer<S, C, Resume> {
    /// The standby sent one final decoded replication message.
    Message {
        /// Connection with only the standby direction open.
        conn: Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>,
        /// Decoded standby message.
        message: FrontendReplication,
    },
    /// The standby closed the remaining direction.
    Done(Conn<S, ServerCopyBoth<Resume, BothDone>, C>),
    /// The standby aborted replication.
    Fail {
        /// Failed replication connection.
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        /// Standby error message without its terminating NUL.
        message: Bytes,
    },
}

/// Replication projection preserving the open connection when decoding fails.
pub type ServerReplicationOpenProjection<S, C, Resume> = Result<
    ServerReplicationOpenOffer<S, C, Resume>,
    (Conn<S, ServerCopyBoth<Resume, BothOpen>, C>, io::Error),
>;
/// Replication projection after server half-close, preserving decode failures.
pub type ServerReplicationServerDoneProjection<S, C, Resume> = Result<
    ServerReplicationServerDoneOffer<S, C, Resume>,
    (
        Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>,
        io::Error,
    ),
>;

/// Client choice inside a server-role COPY IN sub-session.
#[derive(Debug)]
pub enum ServerCopyInOffer<S, C, Resume> {
    /// The client sent one data chunk.
    Data {
        /// Connection remaining in COPY IN.
        conn: Conn<S, ServerCopyIn<Resume>, C>,
        /// Copy payload.
        data: Bytes,
    },
    /// The client completed COPY IN.
    Done(Conn<S, ServerCopyInDone<Resume>, C>),
    /// The client aborted COPY IN.
    Fail {
        /// Failed COPY connection.
        conn: Conn<S, ServerCopyInFailed<Resume>, C>,
        /// Client error message without its terminating NUL.
        message: Bytes,
    },
}

/// COPY IN projection preserving the connection and message on mismatch.
pub type CopyInProjection<S, C, Resume> = Result<
    ServerCopyInOffer<S, C, Resume>,
    Box<(Conn<S, ServerCopyIn<Resume>, C>, FrontendMessage)>,
>;
/// Result of starting a server-role COPY IN stream.
pub type CopyInStart<S, C, Resume> = io::Result<(Conn<S, ServerCopyIn<Resume>, C>, Frame)>;
/// Result of starting a server-role COPY OUT stream.
pub type CopyOutStart<S, C, Resume> = io::Result<(Conn<S, ServerCopyOut<Resume>, C>, Frame)>;
/// Result of closing a server-role COPY OUT stream.
pub type CopyOutCompletion<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyOutDone<Resume>, C>, Frame)>;
/// Result of starting a server-role COPY BOTH stream.
pub type CopyBothStart<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyBoth<Resume, BothOpen>, C>, Frame)>;
/// COPY BOTH projection while both directions remain open.
pub type CopyBothOpenProjection<S, C, Resume> = Result<
    ServerCopyBothOpenOffer<S, C, Resume>,
    Box<(
        Conn<S, ServerCopyBoth<Resume, BothOpen>, C>,
        FrontendMessage,
    )>,
>;
/// COPY BOTH projection after the server direction closes.
pub type CopyBothServerDoneProjection<S, C, Resume> = Result<
    ServerCopyBothServerDoneOffer<S, C, Resume>,
    Box<(
        Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>,
        FrontendMessage,
    )>,
>;
/// Result of closing the server half of COPY BOTH.
pub type CopyBothServerHalfClose<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>, Frame)>;
/// Result of completing COPY BOTH after both halves close.
pub type CopyBothCompletion<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyBoth<Resume, BothDone>, C>, Frame)>;

/// External choice offered by a client while the server role is ready.
#[derive(Debug)]
pub enum ServerReadyOffer<S, C> {
    /// A simple query, conservatively marking the session dirty.
    Query {
        /// Connection serving the query.
        conn: Conn<S, ServerSimpleQuery, Dirty>,
        /// Inspectable and replaceable SQL bytes.
        query: Bytes,
    },
    /// A legacy function-call request.
    FunctionCall {
        /// Connection serving the function call.
        conn: Conn<S, ServerFunctionCall, Dirty>,
        /// Fully decoded function-call message.
        message: FunctionCall,
    },
    /// One message in an extended-query pipeline.
    Extended(ServerExtendedOffer<S, C>),
    /// The client terminated the session.
    Terminate(Conn<S, Terminated, C>),
}

/// A response-specific branch of the extended-query building loop.
#[derive(Debug)]
pub enum ServerExtendedOffer<S, C> {
    /// An inspected and reconstructable `Parse` request.
    Parse {
        /// Connection awaiting a parse response.
        conn: Conn<S, ServerParse, Dirty>,
        /// Decoded request available to application policy.
        message: Parse,
    },
    /// An inspected and reconstructable `Bind` request.
    Bind {
        /// Connection awaiting a bind response.
        conn: Conn<S, ServerBind, Dirty>,
        /// Decoded request available to application policy.
        message: Bind,
    },
    /// An inspected and reconstructable `Describe` request.
    Describe {
        /// Connection awaiting a description response.
        conn: Conn<S, ServerDescribe, C>,
        /// Decoded request available to application policy.
        message: Describe,
    },
    /// An inspected and reconstructable `Execute` request.
    Execute {
        /// Connection serving the portal execution.
        conn: Conn<S, ServerExecute, C>,
        /// Decoded request available to application policy.
        message: Execute,
    },
    /// An inspected and reconstructable `Close` request.
    Close {
        /// Connection awaiting a close response.
        conn: Conn<S, ServerClose, C>,
        /// Decoded request available to application policy.
        message: Close,
    },
    /// The client requested immediate delivery of buffered responses.
    Flush(Conn<S, ServerBuilding, C>),
    /// The client ended the pipeline.
    Sync(Conn<S, ServerSync, C>),
}

/// Projection while discarding a failed pipeline up to its synchronisation point.
#[derive(Debug)]
pub enum ServerDiscard<S, C> {
    /// A pipeline message was discarded; continue until synchronisation.
    Continue(Conn<S, ServerExtendedError, C>),
    /// `Sync` ended the failed pipeline.
    Sync(Conn<S, ServerSync, C>),
}

/// Ready state produced from the status byte sent to the client.
#[derive(Debug)]
pub enum ServerReadyState<S, C> {
    /// Idle readiness retained the existing cleanliness index.
    Ready(Conn<S, Ready, C>),
    /// Non-idle readiness made the connection dirty.
    Dirty {
        /// Ready connection carrying the dirty marker.
        conn: Conn<S, Ready, Dirty>,
        /// Transaction status sent to the client.
        status: TransactionStatus,
    },
}

/// Projection of a client ready-state choice, preserving invalid input.
pub type ReadyProjection<S, C> =
    Result<ServerReadyOffer<S, C>, Box<(Conn<S, Ready, C>, FrontendMessage)>>;
/// Projection of an extended-query choice, preserving invalid input.
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
        match (
            backend::project_external(backend::RuntimeState::Ready, &message),
            message,
        ) {
            (Some(backend::Event::Query), FrontendMessage::Query(query)) => {
                Ok(ServerReadyOffer::Query {
                    conn: self.transition(),
                    query,
                })
            }
            (Some(backend::Event::FunctionCall), FrontendMessage::FunctionCall(message)) => {
                Ok(ServerReadyOffer::FunctionCall {
                    conn: self.transition(),
                    message,
                })
            }
            (Some(backend::Event::Terminate), FrontendMessage::Terminate) => {
                Ok(ServerReadyOffer::Terminate(self.transition()))
            }
            (Some(_), other) => project_extended(self, backend::RuntimeState::Ready, other)
                .map(ServerReadyOffer::Extended),
            (None, other) => Err(Box::new((self, other))),
        }
    }

    /// Accepts inspected query text which cannot retain client session state.
    pub fn accept_stateless_query(self, query: Bytes) -> (Conn<S, ServerSimpleQuery, C>, Bytes) {
        (self.transition(), query)
    }

    /// Accepts an allow-listed function call known not to retain session state.
    pub fn accept_stateless_function_call(
        self,
        message: FunctionCall,
    ) -> (Conn<S, ServerFunctionCall, C>, FunctionCall) {
        (self.transition(), message)
    }
}

impl<S, C> Conn<S, ServerFunctionCall, C> {
    /// Sends the typed function result before the mandatory ready message.
    ///
    /// # Errors
    ///
    /// Returns an error if the result is too large for a wire frame.
    pub fn respond(self, value: Bytes) -> io::Result<(Conn<S, ServerFunctionCallDone, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::FunctionCallResponse(value).to_frame()?,
        ))
    }

    /// Rejects the call before the mandatory ready message.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, ServerFunctionCallError, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::ErrorResponse(response).to_frame()?,
        ))
    }
}

impl<S, C> Conn<S, ServerFunctionCallDone, C> {
    /// Sends readiness after a successful function call.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed ready message cannot be encoded.
    pub fn ready(self, status: TransactionStatus) -> io::Result<(ServerReadyState<S, C>, Frame)> {
        ready(self, status)
    }
}

impl<S, C> Conn<S, ServerFunctionCallError, C> {
    /// Sends readiness after a failed function call.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed ready message cannot be encoded.
    pub fn ready(self, status: TransactionStatus) -> io::Result<(ServerReadyState<S, C>, Frame)> {
        ready(self, status)
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
        project_extended(self, backend::RuntimeState::Building, message)
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

    /// Starts a simple-query COPY IN sub-session.
    ///
    /// # Errors
    ///
    /// Returns an error if the format count overflows the protocol field.
    pub fn copy_in(self, response: CopyResponse) -> CopyInStart<S, C, CopySimple> {
        Ok((
            self.transition(),
            BackendMessage::CopyInResponse(response).to_frame()?,
        ))
    }

    /// Starts a simple-query COPY OUT sub-session.
    ///
    /// # Errors
    ///
    /// Returns an error if the format count overflows the protocol field.
    pub fn copy_out(self, response: CopyResponse) -> CopyOutStart<S, C, CopySimple> {
        Ok((
            self.transition(),
            BackendMessage::CopyOutResponse(response).to_frame()?,
        ))
    }

    /// Starts a simple-query COPY BOTH sub-session.
    ///
    /// # Errors
    ///
    /// Returns an error if the format count overflows the protocol field.
    pub fn copy_both(self, response: CopyResponse) -> CopyBothStart<S, C, CopySimple> {
        Ok((
            self.transition(),
            BackendMessage::CopyBothResponse(response).to_frame()?,
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

    /// Starts an extended-query COPY IN sub-session.
    ///
    /// # Errors
    ///
    /// Returns an error if the format count overflows the protocol field.
    pub fn copy_in(self, response: CopyResponse) -> CopyInStart<S, C, CopyExtended> {
        Ok((
            self.transition(),
            BackendMessage::CopyInResponse(response).to_frame()?,
        ))
    }

    /// Starts an extended-query COPY OUT sub-session.
    ///
    /// # Errors
    ///
    /// Returns an error if the format count overflows the protocol field.
    pub fn copy_out(self, response: CopyResponse) -> CopyOutStart<S, C, CopyExtended> {
        Ok((
            self.transition(),
            BackendMessage::CopyOutResponse(response).to_frame()?,
        ))
    }

    /// Starts an extended-query COPY BOTH sub-session.
    ///
    /// # Errors
    ///
    /// Returns an error if the format count overflows the protocol field.
    pub fn copy_both(self, response: CopyResponse) -> CopyBothStart<S, C, CopyExtended> {
        Ok((
            self.transition(),
            BackendMessage::CopyBothResponse(response).to_frame()?,
        ))
    }
}

impl<S, C> Conn<S, ServerCopyIn<CopySimple>, C> {
    /// Projects one inspected frontend message inside COPY IN.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message for anything other than COPY data,
    /// completion, or failure.
    pub fn offer_frontend(self, message: FrontendMessage) -> CopyInProjection<S, C, CopySimple> {
        project_copy_in(self, backend::RuntimeState::SimpleCopyIn, message)
    }
}

impl<S, C> Conn<S, ServerCopyIn<CopyExtended>, C> {
    /// Projects one inspected frontend message inside extended-query COPY IN.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message for anything other than COPY data,
    /// completion, or failure.
    pub fn offer_frontend(self, message: FrontendMessage) -> CopyInProjection<S, C, CopyExtended> {
        project_copy_in(self, backend::RuntimeState::ExtendedCopyIn, message)
    }
}

impl<S, C> Conn<S, ServerCopyInDone<CopySimple>, C> {
    /// Completes simple-query COPY IN before `ReadyForQuery`.
    ///
    /// # Errors
    ///
    /// Returns an error if the command tag contains a NUL byte.
    pub fn command_complete(
        self,
        tag: Bytes,
    ) -> io::Result<(Conn<S, ServerSimpleQuery, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::CommandComplete(tag).to_frame()?,
        ))
    }
}

impl<S, C> Conn<S, ServerCopyInDone<CopyExtended>, C> {
    /// Completes extended-query COPY IN and returns to the building loop.
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
}

impl<S, C> Conn<S, ServerCopyInFailed<CopySimple>, C> {
    /// Reports a client COPY failure before simple-query readiness.
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
}

impl<S, C> Conn<S, ServerCopyInFailed<CopyExtended>, C> {
    /// Reports a client COPY failure and discards the pipeline until `Sync`.
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

impl<S, C, Resume> Conn<S, ServerCopyOut<Resume>, C> {
    /// Sends one COPY OUT data chunk and remains in the nested session.
    ///
    /// # Errors
    ///
    /// Returns an error only if the data frame cannot be encoded.
    pub fn data(self, data: Bytes) -> io::Result<(Self, Frame)> {
        Ok((self, BackendMessage::CopyData(data).to_frame()?))
    }

    /// Sends a structured WAL or keepalive payload.
    ///
    /// # Errors
    ///
    /// Returns an error only if the data frame cannot be encoded.
    pub fn replication(self, message: &BackendReplication) -> io::Result<(Self, Frame)> {
        self.data(message.encode())
    }

    /// Ends the COPY data stream before its command completion.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed response cannot be encoded.
    pub fn done(self) -> CopyOutCompletion<S, C, Resume> {
        Ok((self.transition(), BackendMessage::CopyDone.to_frame()?))
    }
}

impl<S, C> Conn<S, ServerCopyOutDone<CopySimple>, C> {
    /// Completes simple-query COPY OUT before `ReadyForQuery`.
    ///
    /// # Errors
    ///
    /// Returns an error if the command tag contains a NUL byte.
    pub fn command_complete(
        self,
        tag: Bytes,
    ) -> io::Result<(Conn<S, ServerSimpleQuery, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::CommandComplete(tag).to_frame()?,
        ))
    }
}

impl<S, C> Conn<S, ServerCopyOutDone<CopyExtended>, C> {
    /// Completes extended-query COPY OUT and returns to the building loop.
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
}

impl<S, C, Resume: CopyResume> Conn<S, ServerCopyBoth<Resume, BothOpen>, C> {
    /// Projects client data, half-close, or failure while both directions are open.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not COPY traffic.
    pub fn offer_frontend(self, message: FrontendMessage) -> CopyBothOpenProjection<S, C, Resume> {
        match (
            backend::project_external(Resume::BOTH_OPEN_STATE, &message),
            message,
        ) {
            (Some(backend::Event::ReceiveData), FrontendMessage::CopyData(data)) => {
                Ok(ServerCopyBothOpenOffer::Data { conn: self, data })
            }
            (Some(backend::Event::ReceiveDone), FrontendMessage::CopyDone) => {
                Ok(ServerCopyBothOpenOffer::Done(self.transition()))
            }
            (Some(backend::Event::Fail), FrontendMessage::CopyFail(message)) => {
                Ok(ServerCopyBothOpenOffer::Fail {
                    conn: self.transition(),
                    message,
                })
            }
            (_, other) => Err(Box::new((self, other))),
        }
    }

    /// Sends backend COPY data while its direction remains open.
    ///
    /// # Errors
    ///
    /// Returns an error only if the data frame cannot be encoded.
    pub fn data(self, data: Bytes) -> io::Result<(Self, Frame)> {
        Ok((self, BackendMessage::CopyData(data).to_frame()?))
    }

    /// Sends a structured WAL or keepalive payload while both halves are open.
    ///
    /// # Errors
    ///
    /// Returns an error only if the data frame cannot be encoded.
    pub fn replication(self, message: &BackendReplication) -> io::Result<(Self, Frame)> {
        self.data(message.encode())
    }

    /// Half-closes the backend direction while the client direction remains open.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed completion frame cannot be encoded.
    pub fn done(self) -> CopyBothServerHalfClose<S, C, Resume> {
        Ok((self.transition(), BackendMessage::CopyDone.to_frame()?))
    }
}

impl<S, C, Resume> Conn<S, ServerCopyBoth<Resume, BothClientDone>, C> {
    /// Sends remaining backend data after the client has half-closed.
    ///
    /// # Errors
    ///
    /// Returns an error only if the data frame cannot be encoded.
    pub fn data(self, data: Bytes) -> io::Result<(Self, Frame)> {
        Ok((self, BackendMessage::CopyData(data).to_frame()?))
    }

    /// Sends a structured WAL or keepalive payload after the client half-close.
    ///
    /// # Errors
    ///
    /// Returns an error only if the data frame cannot be encoded.
    pub fn replication(self, message: &BackendReplication) -> io::Result<(Self, Frame)> {
        self.data(message.encode())
    }

    /// Half-closes the backend direction, completing both COPY streams.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed completion frame cannot be encoded.
    pub fn done(self) -> CopyBothCompletion<S, C, Resume> {
        Ok((self.transition(), BackendMessage::CopyDone.to_frame()?))
    }
}

impl<S, C, Resume: CopyResume> Conn<S, ServerCopyBoth<Resume, BothServerDone>, C> {
    /// Projects remaining client traffic after the backend has half-closed.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not COPY traffic.
    pub fn offer_frontend(
        self,
        message: FrontendMessage,
    ) -> CopyBothServerDoneProjection<S, C, Resume> {
        match (
            backend::project_external(Resume::BOTH_SERVER_DONE_STATE, &message),
            message,
        ) {
            (Some(backend::Event::ReceiveData), FrontendMessage::CopyData(data)) => {
                Ok(ServerCopyBothServerDoneOffer::Data { conn: self, data })
            }
            (Some(backend::Event::ReceiveDone), FrontendMessage::CopyDone) => {
                Ok(ServerCopyBothServerDoneOffer::Done(self.transition()))
            }
            (Some(backend::Event::Fail), FrontendMessage::CopyFail(message)) => {
                Ok(ServerCopyBothServerDoneOffer::Fail {
                    conn: self.transition(),
                    message,
                })
            }
            (_, other) => Err(Box::new((self, other))),
        }
    }
}

impl<S, C, Resume> ServerCopyBothOpenOffer<S, C, Resume> {
    /// Decodes client COPY data as a structured standby message.
    ///
    /// # Errors
    ///
    /// Returns the live connection with a decoding error for malformed known payloads.
    pub fn decode_replication(self) -> ServerReplicationOpenProjection<S, C, Resume> {
        match self {
            Self::Data { conn, data } => match FrontendReplication::decode(data) {
                Ok(message) => Ok(ServerReplicationOpenOffer::Message { conn, message }),
                Err(error) => Err((conn, error)),
            },
            Self::Done(conn) => Ok(ServerReplicationOpenOffer::Done(conn)),
            Self::Fail { conn, message } => Ok(ServerReplicationOpenOffer::Fail { conn, message }),
        }
    }
}

impl<S, C, Resume> ServerCopyBothServerDoneOffer<S, C, Resume> {
    /// Decodes remaining client COPY data as a structured standby message.
    ///
    /// # Errors
    ///
    /// Returns the live connection with a decoding error for malformed known payloads.
    pub fn decode_replication(self) -> ServerReplicationServerDoneProjection<S, C, Resume> {
        match self {
            Self::Data { conn, data } => match FrontendReplication::decode(data) {
                Ok(message) => Ok(ServerReplicationServerDoneOffer::Message { conn, message }),
                Err(error) => Err((conn, error)),
            },
            Self::Done(conn) => Ok(ServerReplicationServerDoneOffer::Done(conn)),
            Self::Fail { conn, message } => {
                Ok(ServerReplicationServerDoneOffer::Fail { conn, message })
            }
        }
    }
}

impl<S, C> Conn<S, ServerCopyBoth<CopySimple, BothDone>, C> {
    /// Completes simple-query COPY BOTH before `ReadyForQuery`.
    ///
    /// # Errors
    ///
    /// Returns an error if the command tag contains a NUL byte.
    pub fn command_complete(
        self,
        tag: Bytes,
    ) -> io::Result<(Conn<S, ServerSimpleQuery, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::CommandComplete(tag).to_frame()?,
        ))
    }
}

impl<S, C> Conn<S, ServerCopyBoth<CopyExtended, BothDone>, C> {
    /// Completes extended-query COPY BOTH and returns to the building loop.
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
}

impl<S, C> Conn<S, ServerCopyBothFailed<CopySimple>, C> {
    /// Reports a client COPY failure before simple-query readiness.
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
}

impl<S, C> Conn<S, ServerCopyBothFailed<CopyExtended>, C> {
    /// Reports a client COPY failure and discards the pipeline until `Sync`.
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
        match backend::project_external(backend::RuntimeState::ExtendedError, message) {
            Some(backend::Event::Sync) => ServerDiscard::Sync(self.transition()),
            Some(backend::Event::Discard) | None => ServerDiscard::Continue(self),
            Some(_) => unreachable!("extended-error grammar has only discard and sync events"),
        }
    }
}

fn project_copy_in<S, C, Resume>(
    conn: Conn<S, ServerCopyIn<Resume>, C>,
    state: backend::RuntimeState,
    message: FrontendMessage,
) -> CopyInProjection<S, C, Resume> {
    match (backend::project_external(state, &message), message) {
        (Some(backend::Event::Data), FrontendMessage::CopyData(data)) => {
            Ok(ServerCopyInOffer::Data { conn, data })
        }
        (Some(backend::Event::Done), FrontendMessage::CopyDone) => {
            Ok(ServerCopyInOffer::Done(conn.transition()))
        }
        (Some(backend::Event::Fail), FrontendMessage::CopyFail(message)) => {
            Ok(ServerCopyInOffer::Fail {
                conn: conn.transition(),
                message,
            })
        }
        (_, other) => Err(Box::new((conn, other))),
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
    state: backend::RuntimeState,
    message: FrontendMessage,
) -> ExtendedProjection<S, Phase, C> {
    Ok(
        match (backend::project_external(state, &message), message) {
            (Some(backend::Event::Parse), FrontendMessage::Parse(message)) => {
                ServerExtendedOffer::Parse {
                    conn: conn.transition(),
                    message,
                }
            }
            (Some(backend::Event::Bind), FrontendMessage::Bind(message)) => {
                ServerExtendedOffer::Bind {
                    conn: conn.transition(),
                    message,
                }
            }
            (Some(backend::Event::Describe), FrontendMessage::Describe(message)) => {
                ServerExtendedOffer::Describe {
                    conn: conn.transition(),
                    message,
                }
            }
            (Some(backend::Event::Execute), FrontendMessage::Execute(message)) => {
                ServerExtendedOffer::Execute {
                    conn: conn.transition(),
                    message,
                }
            }
            (Some(backend::Event::Close), FrontendMessage::Close(message)) => {
                ServerExtendedOffer::Close {
                    conn: conn.transition(),
                    message,
                }
            }
            (Some(backend::Event::Flush), FrontendMessage::Flush) => {
                ServerExtendedOffer::Flush(conn.transition())
            }
            (Some(backend::Event::Sync), FrontendMessage::Sync) => {
                ServerExtendedOffer::Sync(conn.transition())
            }
            (_, other) => return Err(Box::new((conn, other))),
        },
    )
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
        fn require_dirty<S>(conn: Conn<S, Ready, Dirty>) {
            conn.into_transport();
        }

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
            panic!("idle response unexpectedly changed the transaction state")
        };
        require_dirty(ready);

        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let (query, inspected) = ready.accept_stateless_query(Bytes::from_static(b"select 1"));
        assert_eq!(inspected, Bytes::from_static(b"select 1"));
        let (state, _) = query.ready(TransactionStatus::Idle).unwrap();
        let ServerReadyState::Ready(pristine) = state else {
            panic!("stateless query did not return to ready")
        };
        pristine.release();
    }

    #[test]
    fn function_call_is_inspectable_and_replaceable() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let call = FunctionCall {
            function_oid: 42,
            argument_formats: vec![1],
            arguments: vec![Some(Bytes::from_static(b"original"))],
            result_format: 1,
        };
        let ServerReadyOffer::FunctionCall { conn, message } = ready
            .offer_frontend(FrontendMessage::FunctionCall(call.clone()))
            .unwrap()
        else {
            panic!("function call projected to the wrong branch")
        };
        assert_eq!(message, call);

        let (done, frame) = conn.respond(Bytes::from_static(b"replacement")).unwrap();
        assert_eq!(frame.tag, b'V');
        let (state, _) = done.ready(TransactionStatus::Idle).unwrap();
        let ServerReadyState::Ready(ready) = state else {
            panic!("idle function call was marked dirty")
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
        fn require_dirty<S>(conn: Conn<S, Ready, Dirty>) {
            conn.into_transport();
        }

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
            panic!("idle sync unexpectedly changed transaction state")
        };
        require_dirty(ready);
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

    #[test]
    fn extended_copy_in_is_a_nested_client_choice() {
        let execute: Conn<(), ServerExecute> = Conn::new(()).transition();
        let (copy, response) = execute
            .copy_in(CopyResponse {
                overall_format: 0,
                column_formats: vec![],
            })
            .unwrap();
        assert_eq!(response.tag, b'G');
        let ServerCopyInOffer::Data { conn: copy, data } = copy
            .offer_frontend(FrontendMessage::CopyData(Bytes::from_static(b"one\n")))
            .unwrap()
        else {
            panic!("COPY data projected to the wrong branch")
        };
        assert_eq!(data, Bytes::from_static(b"one\n"));
        let ServerCopyInOffer::Done(done) = copy.offer_frontend(FrontendMessage::CopyDone).unwrap()
        else {
            panic!("COPY completion projected to the wrong branch")
        };
        let (building, complete) = done
            .command_complete(Bytes::from_static(b"COPY 1"))
            .unwrap();
        assert_eq!(complete.tag, b'C');
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
    fn simple_copy_out_requires_done_before_command_completion() {
        let query: Conn<(), ServerSimpleQuery> = Conn::new(()).transition();
        let (copy, response) = query
            .copy_out(CopyResponse {
                overall_format: 0,
                column_formats: vec![],
            })
            .unwrap();
        assert_eq!(response.tag, b'H');
        let (copy, data) = copy.data(Bytes::from_static(b"one\n")).unwrap();
        assert_eq!(data.tag, b'd');
        let (done, done_frame) = copy.done().unwrap();
        assert_eq!(done_frame.tag, b'c');
        let (query, complete) = done
            .command_complete(Bytes::from_static(b"COPY 1"))
            .unwrap();
        assert_eq!(complete.tag, b'C');
        let (state, _) = query.ready(TransactionStatus::Idle).unwrap();
        let ServerReadyState::Ready(ready) = state else {
            panic!("idle COPY was marked dirty")
        };
        ready.into_transport();
    }

    #[test]
    fn copy_both_tracks_half_closes_independently() {
        use crate::grammar::backend::{Event, RuntimeFsm, RuntimeState};

        let mut generated = RuntimeFsm::new();
        generated.step(Event::Execute).unwrap();
        let execute: Conn<(), ServerExecute> = Conn::new(()).transition();
        let (both, response) = execute
            .copy_both(CopyResponse {
                overall_format: 0,
                column_formats: vec![],
            })
            .unwrap();
        generated.step(Event::CopyBoth).unwrap();
        assert_eq!(response.tag, b'W');
        let ServerCopyBothOpenOffer::Done(client_done) =
            both.offer_frontend(FrontendMessage::CopyDone).unwrap()
        else {
            panic!("client half-close projected to the wrong branch")
        };
        generated.step(Event::ReceiveDone).unwrap();
        let (client_done, data) = client_done
            .data(Bytes::from_static(b"remaining backend data"))
            .unwrap();
        generated.step(Event::SendData).unwrap();
        assert_eq!(data.tag, b'd');
        let (done, backend_done) = client_done.done().unwrap();
        generated.step(Event::SendDone).unwrap();
        assert_eq!(backend_done.tag, b'c');
        let (building, _) = done
            .command_complete(Bytes::from_static(b"COPY 0"))
            .unwrap();
        generated.step(Event::CommandComplete).unwrap();
        let ServerExtendedOffer::Sync(sync) =
            building.offer_frontend(FrontendMessage::Sync).unwrap()
        else {
            panic!("sync projected to the wrong branch")
        };
        generated.step(Event::Sync).unwrap();
        let (state, _) = sync.ready(TransactionStatus::Idle).unwrap();
        let ServerReadyState::Ready(ready) = state else {
            panic!("idle sync was marked dirty")
        };
        generated.step(Event::Ready).unwrap();
        assert_eq!(generated.state(), RuntimeState::Ready);
        ready.into_transport();
    }

    #[test]
    fn copy_both_inspects_and_replaces_replication_messages() {
        let both: Conn<(), ServerCopyBoth<CopySimple, BothOpen>> = Conn::new(()).transition();
        let status = FrontendReplication::StandbyStatus {
            written: 10,
            flushed: 9,
            applied: 8,
            client_time: 7,
            reply_requested: true,
        };
        let offer = both
            .offer_frontend(FrontendMessage::CopyData(status.encode()))
            .unwrap();
        let ServerReplicationOpenOffer::Message {
            conn: both,
            message,
        } = offer.decode_replication().unwrap()
        else {
            panic!("standby status projected to the wrong branch")
        };
        assert_eq!(message, status);

        let replacement = BackendReplication::PrimaryKeepalive {
            wal_end: 11,
            server_time: 12,
            reply_requested: false,
        };
        let (both, frame) = both.replication(&replacement).unwrap();
        assert_eq!(frame.body, replacement.encode());
        both.into_transport();

        let both: Conn<(), ServerCopyBoth<CopySimple, BothOpen>> = Conn::new(()).transition();
        let offer = both
            .offer_frontend(FrontendMessage::CopyData(Bytes::from_static(b"rshort")))
            .unwrap();
        let (both, _) = offer.decode_replication().unwrap_err();
        both.into_transport();
    }
}
