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
    pre_startup::Terminated,
    replication::{BackendReplication, FrontendReplication},
};

#[derive(Debug)]
pub enum ServerSimpleQuery {}

#[derive(Debug)]
pub enum ServerSimpleError {}

#[derive(Debug)]
pub enum ServerFunctionCall {}

#[derive(Debug)]
pub enum ServerFunctionCallDone {}

#[derive(Debug)]
pub enum ServerFunctionCallError {}

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

#[derive(Debug)]
pub enum CopySimple {}

#[derive(Debug)]
pub enum CopyExtended {}

#[derive(Debug)]
pub struct ServerCopyIn<Resume>(PhantomData<Resume>);

#[derive(Debug)]
pub struct ServerCopyInDone<Resume>(PhantomData<Resume>);

#[derive(Debug)]
pub struct ServerCopyInFailed<Resume>(PhantomData<Resume>);

#[derive(Debug)]
pub struct ServerCopyOut<Resume>(PhantomData<Resume>);

#[derive(Debug)]
pub struct ServerCopyOutDone<Resume>(PhantomData<Resume>);

#[derive(Debug)]
pub enum BothOpen {}

#[derive(Debug)]
pub enum BothClientDone {}

#[derive(Debug)]
pub enum BothServerDone {}

#[derive(Debug)]
pub enum BothDone {}

#[derive(Debug)]
pub struct ServerCopyBoth<Resume, Ends>(PhantomData<(Resume, Ends)>);

#[derive(Debug)]
pub struct ServerCopyBothFailed<Resume>(PhantomData<Resume>);

#[derive(Debug)]
pub enum ServerCopyBothOpenOffer<S, C, Resume> {
    Data {
        conn: Conn<S, ServerCopyBoth<Resume, BothOpen>, C>,
        data: Bytes,
    },
    Done(Conn<S, ServerCopyBoth<Resume, BothClientDone>, C>),
    Fail {
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        message: Bytes,
    },
}

#[derive(Debug)]
pub enum ServerCopyBothServerDoneOffer<S, C, Resume> {
    Data {
        conn: Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>,
        data: Bytes,
    },
    Done(Conn<S, ServerCopyBoth<Resume, BothDone>, C>),
    Fail {
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        message: Bytes,
    },
}

#[derive(Debug)]
pub enum ServerReplicationOpenOffer<S, C, Resume> {
    Message {
        conn: Conn<S, ServerCopyBoth<Resume, BothOpen>, C>,
        message: FrontendReplication,
    },
    Done(Conn<S, ServerCopyBoth<Resume, BothClientDone>, C>),
    Fail {
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        message: Bytes,
    },
}

#[derive(Debug)]
pub enum ServerReplicationServerDoneOffer<S, C, Resume> {
    Message {
        conn: Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>,
        message: FrontendReplication,
    },
    Done(Conn<S, ServerCopyBoth<Resume, BothDone>, C>),
    Fail {
        conn: Conn<S, ServerCopyBothFailed<Resume>, C>,
        message: Bytes,
    },
}

pub type ServerReplicationOpenProjection<S, C, Resume> = Result<
    ServerReplicationOpenOffer<S, C, Resume>,
    (Conn<S, ServerCopyBoth<Resume, BothOpen>, C>, io::Error),
>;
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
    Data {
        conn: Conn<S, ServerCopyIn<Resume>, C>,
        data: Bytes,
    },
    Done(Conn<S, ServerCopyInDone<Resume>, C>),
    Fail {
        conn: Conn<S, ServerCopyInFailed<Resume>, C>,
        message: Bytes,
    },
}

pub type CopyInProjection<S, C, Resume> = Result<
    ServerCopyInOffer<S, C, Resume>,
    Box<(Conn<S, ServerCopyIn<Resume>, C>, FrontendMessage)>,
>;
pub type CopyInStart<S, C, Resume> = io::Result<(Conn<S, ServerCopyIn<Resume>, C>, Frame)>;
pub type CopyOutStart<S, C, Resume> = io::Result<(Conn<S, ServerCopyOut<Resume>, C>, Frame)>;
pub type CopyOutCompletion<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyOutDone<Resume>, C>, Frame)>;
pub type CopyBothStart<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyBoth<Resume, BothOpen>, C>, Frame)>;
pub type CopyBothOpenProjection<S, C, Resume> = Result<
    ServerCopyBothOpenOffer<S, C, Resume>,
    Box<(
        Conn<S, ServerCopyBoth<Resume, BothOpen>, C>,
        FrontendMessage,
    )>,
>;
pub type CopyBothServerDoneProjection<S, C, Resume> = Result<
    ServerCopyBothServerDoneOffer<S, C, Resume>,
    Box<(
        Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>,
        FrontendMessage,
    )>,
>;
pub type CopyBothServerHalfClose<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyBoth<Resume, BothServerDone>, C>, Frame)>;
pub type CopyBothCompletion<S, C, Resume> =
    io::Result<(Conn<S, ServerCopyBoth<Resume, BothDone>, C>, Frame)>;

/// External choice offered by a client while the server role is ready.
#[derive(Debug)]
pub enum ServerReadyOffer<S, C> {
    Query {
        conn: Conn<S, ServerSimpleQuery, Dirty>,
        query: Bytes,
    },
    FunctionCall {
        conn: Conn<S, ServerFunctionCall, C>,
        message: FunctionCall,
    },
    Extended(ServerExtendedOffer<S, C>),
    Terminate(Conn<S, Terminated, C>),
}

/// A response-specific branch of the extended-query building loop.
#[derive(Debug)]
pub enum ServerExtendedOffer<S, C> {
    Parse {
        conn: Conn<S, ServerParse, Dirty>,
        message: Parse,
    },
    Bind {
        conn: Conn<S, ServerBind, Dirty>,
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
            FrontendMessage::FunctionCall(message) => Ok(ServerReadyOffer::FunctionCall {
                conn: self.transition(),
                message,
            }),
            FrontendMessage::Terminate => Ok(ServerReadyOffer::Terminate(self.transition())),
            other => project_extended(self, other).map(ServerReadyOffer::Extended),
        }
    }

    /// Accepts inspected query text which cannot retain client session state.
    pub fn accept_stateless_query(self, query: Bytes) -> (Conn<S, ServerSimpleQuery, C>, Bytes) {
        (self.transition(), query)
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

impl<S, C, Resume> Conn<S, ServerCopyIn<Resume>, C> {
    /// Projects one inspected frontend message inside COPY IN.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message for anything other than COPY data,
    /// completion, or failure.
    pub fn offer_frontend(self, message: FrontendMessage) -> CopyInProjection<S, C, Resume> {
        match message {
            FrontendMessage::CopyData(data) => Ok(ServerCopyInOffer::Data { conn: self, data }),
            FrontendMessage::CopyDone => Ok(ServerCopyInOffer::Done(self.transition())),
            FrontendMessage::CopyFail(message) => Ok(ServerCopyInOffer::Fail {
                conn: self.transition(),
                message,
            }),
            other => Err(Box::new((self, other))),
        }
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

impl<S, C, Resume> Conn<S, ServerCopyBoth<Resume, BothOpen>, C> {
    /// Projects client data, half-close, or failure while both directions are open.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not COPY traffic.
    pub fn offer_frontend(self, message: FrontendMessage) -> CopyBothOpenProjection<S, C, Resume> {
        match message {
            FrontendMessage::CopyData(data) => {
                Ok(ServerCopyBothOpenOffer::Data { conn: self, data })
            }
            FrontendMessage::CopyDone => Ok(ServerCopyBothOpenOffer::Done(self.transition())),
            FrontendMessage::CopyFail(message) => Ok(ServerCopyBothOpenOffer::Fail {
                conn: self.transition(),
                message,
            }),
            other => Err(Box::new((self, other))),
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

impl<S, C, Resume> Conn<S, ServerCopyBoth<Resume, BothServerDone>, C> {
    /// Projects remaining client traffic after the backend has half-closed.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not COPY traffic.
    pub fn offer_frontend(
        self,
        message: FrontendMessage,
    ) -> CopyBothServerDoneProjection<S, C, Resume> {
        match message {
            FrontendMessage::CopyData(data) => {
                Ok(ServerCopyBothServerDoneOffer::Data { conn: self, data })
            }
            FrontendMessage::CopyDone => Ok(ServerCopyBothServerDoneOffer::Done(self.transition())),
            FrontendMessage::CopyFail(message) => Ok(ServerCopyBothServerDoneOffer::Fail {
                conn: self.transition(),
                message,
            }),
            other => Err(Box::new((self, other))),
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
        let execute: Conn<(), ServerExecute> = Conn::new(()).transition();
        let (both, response) = execute
            .copy_both(CopyResponse {
                overall_format: 0,
                column_formats: vec![],
            })
            .unwrap();
        assert_eq!(response.tag, b'W');
        let ServerCopyBothOpenOffer::Done(client_done) =
            both.offer_frontend(FrontendMessage::CopyDone).unwrap()
        else {
            panic!("client half-close projected to the wrong branch")
        };
        let (client_done, data) = client_done
            .data(Bytes::from_static(b"remaining backend data"))
            .unwrap();
        assert_eq!(data.tag, b'd');
        let (done, backend_done) = client_done.done().unwrap();
        assert_eq!(backend_done.tag, b'c');
        let (building, _) = done
            .command_complete(Bytes::from_static(b"COPY 0"))
            .unwrap();
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
