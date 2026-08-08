//! Core query, COPY, and error-draining typestates.

use std::io;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    Conn, Dirty, Pristine,
    auth::Ready,
    codec::{
        BackendMessage, Bind, Close, CopyResponse, Describe, DiagnosticResponse, Execute, Frame,
        FunctionCall, Parse, TransactionStatus,
    },
    demux::SessionItem,
    grammar::frontend,
    pre_startup::Terminated,
    replication::{BackendReplication, FrontendReplication},
};

#[derive(Debug)]
/// A simple-query command is awaiting backend results and readiness.
pub(crate) enum SimpleQuery {}

#[derive(Debug)]
/// A legacy function call is awaiting its result.
pub(crate) enum FunctionCalling {}

#[derive(Debug)]
/// An extended-query pipeline is being built but has no bound portal yet.
pub(crate) enum Building {}

#[derive(Debug)]
/// An extended-query pipeline contains a bound, executable portal.
pub(crate) enum BoundBuilding {}

#[derive(Debug)]
/// Command results are complete and `ReadyForQuery` is required.
pub(crate) enum AwaitingReady {}

#[derive(Debug)]
/// The client may stream COPY data to the backend.
pub(crate) enum CopyIn {}

#[derive(Debug)]
/// The backend may stream COPY data to the client.
pub(crate) enum CopyOut {}

#[derive(Debug)]
/// Both peers may stream COPY data.
pub(crate) enum CopyBoth {}

#[derive(Debug)]
/// The client half of a COPY BOTH session is closed.
pub(crate) enum CopyBothClientDone {}

#[derive(Debug)]
/// The backend half of a COPY BOTH session is closed.
pub(crate) enum CopyBothServerDone {}

#[derive(Debug)]
/// An errored command is being drained until `ReadyForQuery`.
pub(crate) enum Draining {}

#[derive(Debug)]
/// A pool-reset query is executing on a dirty connection.
pub(crate) enum Resetting {}

#[derive(Debug)]
/// Reset command completion was observed and readiness is required.
pub(crate) enum ResetComplete {}

/// Structured backend error used by session transitions.
pub(crate) type ErrorResponse = DiagnosticResponse;

/// A successful transition or a backend error that enters [`Draining`].
pub(crate) type Fallible<T, S, C = Pristine> = Result<T, (Conn<S, Draining, C>, ErrorResponse)>;

/// Backend branch available while a simple query is active.
#[derive(Debug)]
pub(crate) enum SimpleTransition<S, C> {
    /// A result item was consumed and more results may follow.
    Continue(Conn<S, SimpleQuery, C>, SessionItem),
    /// The command entered COPY IN.
    CopyIn(Conn<S, CopyIn, C>, CopyResponse),
    /// The command entered COPY OUT.
    CopyOut(Conn<S, CopyOut, C>, CopyResponse),
    /// The command entered COPY BOTH.
    CopyBoth(Conn<S, CopyBoth, C>, CopyResponse),
    /// Readiness completed the simple-query cycle.
    Ready(ReadyState<S, C>),
    /// An error entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Backend branch available after a result completes.
#[derive(Debug)]
pub(crate) enum AwaitingReadyTransition<S, C> {
    /// A non-terminal item was consumed; continue waiting.
    Continue(Conn<S, AwaitingReady, C>, SessionItem),
    /// Readiness completed the command cycle.
    Ready(ReadyState<S, C>),
    /// An error entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Backend branch available for the legacy function-call protocol.
#[derive(Debug)]
pub(crate) enum FunctionCallTransition<S, C> {
    /// The backend returned the function value.
    Response(Conn<S, AwaitingReady, C>, Bytes),
    /// The backend rejected the call.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Backend branch while discarding messages after an error.
#[derive(Debug)]
pub(crate) enum DrainingTransition<S, C> {
    /// A non-terminal item was discarded; continue draining.
    Continue(Conn<S, Draining, C>, SessionItem),
    /// Readiness completed recovery.
    Ready(ReadyState<S, C>),
}

/// Backend branch during COPY OUT.
#[derive(Debug)]
pub(crate) enum CopyOutTransition<S, C> {
    /// One chunk of copy data was received.
    Data(Conn<S, CopyOut, C>, Bytes),
    /// The backend closed the copy stream.
    Done(Conn<S, AwaitingReady, C>),
    /// COPY failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Asynchronous backend branch available while sending COPY IN data.
#[derive(Debug)]
pub(crate) enum CopyInTransition<S, C> {
    /// COPY failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Backend branch while both COPY directions remain open.
#[derive(Debug)]
pub(crate) enum CopyBothReceive<S, C> {
    /// One opaque backend data chunk was received.
    Data(Conn<S, CopyBoth, C>, Bytes),
    /// The backend closed its half of the stream.
    Done(Conn<S, CopyBothServerDone, C>),
    /// COPY failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Backend branch after the client closes its COPY BOTH half.
#[derive(Debug)]
pub(crate) enum CopyBothClientDoneReceive<S, C> {
    /// One final opaque backend data chunk was received.
    Data(Conn<S, CopyBothClientDone, C>, Bytes),
    /// The backend closed its half of the stream.
    Done(Conn<S, AwaitingReady, C>),
    /// COPY failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Typed walsender branch while both replication directions remain open.
#[derive(Debug)]
pub(crate) enum ReplicationReceive<S, C> {
    /// One decoded backend replication message was received.
    Message(Conn<S, CopyBoth, C>, BackendReplication),
    /// The backend closed its half of the stream.
    Done(Conn<S, CopyBothServerDone, C>),
    /// Replication failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Typed walsender branch after the standby closes its sending half.
#[derive(Debug)]
pub(crate) enum ReplicationClientDoneReceive<S, C> {
    /// One decoded backend replication message was received.
    Message(Conn<S, CopyBothClientDone, C>, BackendReplication),
    /// The backend closed its half of the stream.
    Done(Conn<S, AwaitingReady, C>),
    /// Replication failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, C>, ErrorResponse),
}

/// Replication projection preserving the connection when decoding fails.
pub(crate) type ReplicationProjection<S, C> =
    Result<ReplicationReceive<S, C>, (Conn<S, CopyBoth, C>, io::Error)>;
/// Replication projection after client half-close, preserving decode failures.
pub(crate) type ReplicationClientDoneProjection<S, C> =
    Result<ReplicationClientDoneReceive<S, C>, (Conn<S, CopyBothClientDone, C>, io::Error)>;

/// Readiness classified by pooling cleanliness evidence.
#[derive(Debug)]
pub(crate) enum ReadyState<S, C> {
    /// The connection retained its existing cleanliness index.
    Clean(Conn<S, Ready, C>),
    /// Transaction or parameter evidence made the connection dirty.
    Dirty {
        /// Ready connection carrying the dirty cleanliness marker.
        conn: Conn<S, Ready, Dirty>,
        /// Transaction status reported by the backend.
        status: TransactionStatus,
        /// Whether reported parameters differ from startup values.
        parameters_changed: bool,
    },
}

/// Backend branch while a reset command is executing.
#[derive(Debug)]
pub(crate) enum ResettingTransition<S> {
    /// A non-terminal item was consumed; continue waiting.
    Continue(Conn<S, Resetting, Dirty>, SessionItem),
    /// Reset command completion was observed.
    Complete(Conn<S, ResetComplete, Dirty>),
    /// Reset failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, Dirty>, ErrorResponse),
}

/// Backend branch after reset command completion.
#[derive(Debug)]
pub(crate) enum ResetCompleteTransition<S> {
    /// A non-terminal item was consumed; continue waiting.
    Continue(Conn<S, ResetComplete, Dirty>, SessionItem),
    /// Idle readiness with restored parameters proved the connection pristine.
    Ready(Conn<S, Ready, Pristine>),
    /// Readiness retained dirty transaction or parameter state.
    Dirty {
        /// Ready connection retaining its dirty marker.
        conn: Conn<S, Ready, Dirty>,
        /// Transaction status reported by the backend.
        status: TransactionStatus,
        /// Whether reported parameters differ from startup values.
        parameters_changed: bool,
    },
    /// Reset failed and entered drain-until-ready recovery.
    Error(Conn<S, Draining, Dirty>, ErrorResponse),
}

impl<S, C> Conn<S, Ready, C> {
    /// Gracefully terminates a ready session without waiting for a backend reply.
    pub(crate) fn push_terminate(self) -> (Conn<S, Terminated, C>, Frame) {
        (self.transition(), empty_frame(b'X'))
    }

    /// Buffers a simple query and conservatively taints the pooled session.
    ///
    /// Simple-query text can create resources which are not reflected in
    /// `ParameterStatus`, including listeners, prepared statements, and
    /// advisory locks. Use [`Self::push_stateless_query`] only after custom SQL
    /// inspection has established that the command cannot retain session state.
    ///
    /// # Errors
    ///
    /// Returns an error if the query contains a NUL byte.
    pub(crate) fn push_query(
        self,
        query: &[u8],
    ) -> io::Result<(Conn<S, SimpleQuery, Dirty>, Frame)> {
        Ok((self.transition(), cstr_frame(b'Q', query)?))
    }

    /// Buffers query text which the caller has proved leaves no session state.
    ///
    /// # Errors
    ///
    /// Returns an error if the query contains a NUL byte.
    pub(crate) fn push_stateless_query(
        self,
        query: &[u8],
    ) -> io::Result<(Conn<S, SimpleQuery, C>, Frame)> {
        Ok((self.transition(), cstr_frame(b'Q', query)?))
    }

    /// Buffers the deprecated function-call protocol message as a typed exchange.
    ///
    /// # Errors
    ///
    /// Returns an error if a count or argument length exceeds its wire field.
    pub(crate) fn push_function_call(
        self,
        message: &FunctionCall,
    ) -> io::Result<(Conn<S, FunctionCalling, Dirty>, Frame)> {
        Ok((self.transition(), message.to_frame()?))
    }

    /// Buffers an allow-listed function call known not to retain session state.
    ///
    /// # Errors
    ///
    /// Returns an error if a count or argument length exceeds its wire field.
    pub(crate) fn push_stateless_function_call(
        self,
        message: &FunctionCall,
    ) -> io::Result<(Conn<S, FunctionCalling, C>, Frame)> {
        Ok((self.transition(), message.to_frame()?))
    }

    /// Begins extended-query construction and consumes the ready connection.
    ///
    /// ```compile_fail
    /// use pg_proto::{Conn, auth::Ready};
    /// fn use_after_transition<S, C>(conn: Conn<S, Ready, C>) {
    ///     let _building = conn.begin_extended();
    ///     let _again = conn.begin_extended();
    /// }
    /// ```
    pub(crate) fn begin_extended(self) -> Conn<S, Building, C> {
        self.transition()
    }
}

impl<S, C> Conn<S, FunctionCalling, C> {
    /// Accepts exactly the function result or an error, after which readiness
    /// must still be consumed.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and message for an illegal response.
    pub(crate) fn offer(
        self,
        message: BackendMessage,
    ) -> Result<FunctionCallTransition<S, C>, (Self, BackendMessage)> {
        match (
            frontend::project_external(frontend::RuntimeState::FunctionCalling, &message),
            message,
        ) {
            (
                Some(frontend::Event::FunctionResponse),
                BackendMessage::FunctionCallResponse(value),
            ) => Ok(FunctionCallTransition::Response(self.transition(), value)),
            (Some(frontend::Event::Error), BackendMessage::ErrorResponse(error)) => {
                Ok(FunctionCallTransition::Error(self.transition(), error))
            }
            (_, other) => Err((self, other)),
        }
    }
}

impl<S> Conn<S, Ready, Pristine> {
    /// Releases only a statically pristine, ready connection to a pool.
    ///
    /// ```compile_fail
    /// use pg_proto::{Conn, Dirty, auth::Ready};
    /// fn cannot_release<S>(conn: Conn<S, Ready, Dirty>) {
    ///     let _transport = conn.release();
    /// }
    /// ```
    pub(crate) fn release(self) -> S {
        self.into_transport()
    }
}

impl<S> Conn<S, Ready, Dirty> {
    /// Begins the only typed path which can recover pool-safe cleanliness.
    ///
    /// `ROLLBACK` makes the sequence legal after either transaction status;
    /// `DISCARD ALL` then clears session-local resources and settings.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed reset query cannot be encoded.
    pub(crate) fn begin_reset(self) -> io::Result<(Conn<S, Resetting, Dirty>, Frame)> {
        Ok((
            self.transition(),
            cstr_frame(b'Q', b"ROLLBACK; DISCARD ALL")?,
        ))
    }
}

impl<S, C> Conn<S, Building, C> {
    /// Parse is a self-loop while constructing an extended-query pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_parse(
        self,
        message: &Parse,
    ) -> io::Result<(Conn<S, Building, Dirty>, Frame)> {
        Ok((self.transition(), message.to_frame()?))
    }

    /// Describe is a self-loop while constructing an extended-query pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_describe(self, message: &Describe) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// Bind introduces an executable portal.
    ///
    /// Execute is not available before this transition:
    ///
    /// ```compile_fail
    /// use bytes::Bytes;
    /// use pg_proto::{Conn, session::Building};
    /// fn execute_without_bind<S, C>(conn: Conn<S, Building, C>) {
    ///     let _ = conn.push_execute(Bytes::new());
    /// }
    /// ```
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_bind(
        self,
        message: &Bind,
    ) -> io::Result<(Conn<S, BoundBuilding, Dirty>, Frame)> {
        Ok((self.transition(), message.to_frame()?))
    }

    /// Close is legal while building, but does not make a portal executable.
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_close(self, message: &Close) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// Requests delivery of buffered extended-query responses without ending the cycle.
    pub(crate) fn push_flush(self) -> (Self, Frame) {
        (self, empty_frame(b'H'))
    }

    /// Ends the extended-query pipeline and waits for readiness.
    pub(crate) fn push_sync(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'S'))
    }
}

impl<S, C> Conn<S, BoundBuilding, C> {
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_parse(
        self,
        message: &Parse,
    ) -> io::Result<(Conn<S, BoundBuilding, Dirty>, Frame)> {
        Ok((self.transition(), message.to_frame()?))
    }

    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_bind(
        self,
        message: &Bind,
    ) -> io::Result<(Conn<S, BoundBuilding, Dirty>, Frame)> {
        Ok((self.transition(), message.to_frame()?))
    }

    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_describe(self, message: &Describe) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// Execute is unavailable until a Bind transition has occurred.
    ///
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_execute(self, message: &Execute) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub(crate) fn push_close(self, message: &Close) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// Requests delivery of buffered extended-query responses without ending the cycle.
    pub(crate) fn push_flush(self) -> (Self, Frame) {
        (self, empty_frame(b'H'))
    }

    /// Ends the extended-query pipeline and waits for readiness.
    pub(crate) fn push_sync(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'S'))
    }
}

impl<S, C> Conn<S, SimpleQuery, C> {
    /// Advances a simple-query session using an actual projected backend item.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item if it is illegal in this phase.
    pub(crate) fn offer(
        self,
        item: SessionItem,
    ) -> Result<SimpleTransition<S, C>, (Self, SessionItem)> {
        match (
            project_session_item(frontend::RuntimeState::Simple, &item),
            item,
        ) {
            (
                Some(frontend::Event::CopyIn),
                SessionItem::Message(BackendMessage::CopyInResponse(response)),
            ) => Ok(SimpleTransition::CopyIn(self.transition(), response)),
            (
                Some(frontend::Event::CopyOut),
                SessionItem::Message(BackendMessage::CopyOutResponse(response)),
            ) => Ok(SimpleTransition::CopyOut(self.transition(), response)),
            (
                Some(frontend::Event::CopyBoth),
                SessionItem::Message(BackendMessage::CopyBothResponse(response)),
            ) => Ok(SimpleTransition::CopyBoth(self.transition(), response)),
            (
                Some(frontend::Event::Ready),
                SessionItem::ReadyForQuery {
                    status,
                    parameters_changed,
                },
            ) => Ok(SimpleTransition::Ready(ready_state(
                self,
                status,
                parameters_changed,
            ))),
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => Ok(SimpleTransition::Error(self.transition(), error)),
            (
                Some(frontend::Event::Continue),
                item @ (SessionItem::CommandComplete { .. }
                | SessionItem::Message(
                    BackendMessage::RowDescription(_)
                    | BackendMessage::DataRow(_)
                    | BackendMessage::EmptyQueryResponse,
                )),
            ) => Ok(SimpleTransition::Continue(self, item)),
            (_, item) => Err((self, item)),
        }
    }
}

impl<S, C> Conn<S, CopyIn, C> {
    /// Query is unavailable in this nested COPY session.
    ///
    /// ```compile_fail
    /// use pg_proto::{Conn, session::CopyIn};
    /// fn query_during_copy<S, C>(conn: Conn<S, CopyIn, C>) {
    ///     let _ = conn.push_query(b"select 1");
    /// }
    /// ```
    pub(crate) fn push_copy_data(self, data: Bytes) -> (Self, Frame) {
        (
            self,
            Frame {
                tag: b'd',
                body: data,
            },
        )
    }

    /// Closes the client-to-backend copy stream and waits for command completion.
    pub(crate) fn push_copy_done(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'c'))
    }

    /// Aborts COPY IN with a frontend error string.
    ///
    /// # Errors
    ///
    /// Returns an error if the message contains a NUL byte.
    pub(crate) fn push_copy_fail(
        self,
        message: &[u8],
    ) -> io::Result<(Conn<S, AwaitingReady, C>, Frame)> {
        Ok((self.transition(), cstr_frame(b'f', message)?))
    }

    /// Projects an asynchronous backend failure while COPY IN data is being sent.
    ///
    /// This branch is reachable after cancellation or an early server-side COPY
    /// failure. Non-error messages leave the COPY IN connection unchanged.
    ///
    /// # Errors
    ///
    /// Returns the live connection and item when it is not an error response.
    pub(crate) fn offer(
        self,
        item: SessionItem,
    ) -> Result<CopyInTransition<S, C>, (Self, SessionItem)> {
        match (
            project_session_item(frontend::RuntimeState::CopyIn, &item),
            item,
        ) {
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => Ok(CopyInTransition::Error(self.transition(), error)),
            (_, item) => Err((self, item)),
        }
    }
}

impl<S, C> Conn<S, CopyBothClientDone, C> {
    /// Continues receiving after the frontend half has closed.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item for an illegal response.
    pub(crate) fn offer(
        self,
        item: SessionItem,
    ) -> Result<CopyBothClientDoneReceive<S, C>, (Self, SessionItem)> {
        match (
            project_session_item(frontend::RuntimeState::CopyBothClientDone, &item),
            item,
        ) {
            (
                Some(frontend::Event::ReceiveCopyData),
                SessionItem::Message(BackendMessage::CopyData(data)),
            ) => Ok(CopyBothClientDoneReceive::Data(self, data)),
            (
                Some(frontend::Event::ReceiveCopyDone),
                SessionItem::Message(BackendMessage::CopyDone),
            ) => Ok(CopyBothClientDoneReceive::Done(self.transition())),
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => Ok(CopyBothClientDoneReceive::Error(self.transition(), error)),
            (_, item) => Err((self, item)),
        }
    }
}

impl<S, C> CopyBothClientDoneReceive<S, C> {
    /// Decodes data received after the frontend half-close.
    ///
    /// # Errors
    ///
    /// Returns the connection with a decoding error for malformed known payloads.
    pub(crate) fn decode_replication(self) -> ReplicationClientDoneProjection<S, C> {
        match self {
            Self::Data(conn, data) => match BackendReplication::decode(data) {
                Ok(message) => Ok(ReplicationClientDoneReceive::Message(conn, message)),
                Err(error) => Err((conn, error)),
            },
            Self::Done(conn) => Ok(ReplicationClientDoneReceive::Done(conn)),
            Self::Error(conn, error) => Ok(ReplicationClientDoneReceive::Error(conn, error)),
        }
    }
}

impl<S, C> Conn<S, CopyBothServerDone, C> {
    /// Continues sending after the backend half has closed.
    pub(crate) fn push_copy_data(self, data: Bytes) -> (Self, Frame) {
        (
            self,
            Frame {
                tag: b'd',
                body: data,
            },
        )
    }

    /// Sends a structured standby message after the backend half-close.
    pub(crate) fn push_replication(self, message: &FrontendReplication) -> (Self, Frame) {
        self.push_copy_data(message.encode())
    }

    /// Closes the remaining frontend half and begins readiness processing.
    pub(crate) fn push_copy_done(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'c'))
    }
}

impl<S, C> Conn<S, CopyOut, C> {
    /// Advances COPY OUT using backend evidence.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item when it is illegal in COPY OUT.
    pub(crate) fn offer(
        self,
        item: SessionItem,
    ) -> Result<CopyOutTransition<S, C>, (Self, SessionItem)> {
        match (
            project_session_item(frontend::RuntimeState::CopyOut, &item),
            item,
        ) {
            (
                Some(frontend::Event::CopyData),
                SessionItem::Message(BackendMessage::CopyData(data)),
            ) => Ok(CopyOutTransition::Data(self, data)),
            (Some(frontend::Event::CopyDone), SessionItem::Message(BackendMessage::CopyDone)) => {
                Ok(CopyOutTransition::Done(self.transition()))
            }
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => Ok(CopyOutTransition::Error(self.transition(), error)),
            (_, item) => Err((self, item)),
        }
    }
}

impl<S, C> Conn<S, CopyBoth, C> {
    /// Sends one opaque data chunk while retaining both COPY directions.
    pub(crate) fn push_copy_data(self, data: Bytes) -> (Self, Frame) {
        (
            self,
            Frame {
                tag: b'd',
                body: data,
            },
        )
    }

    /// Sends a structured standby message in the walsender stream.
    pub(crate) fn push_replication(self, message: &FrontendReplication) -> (Self, Frame) {
        self.push_copy_data(message.encode())
    }

    /// Closes the client half while leaving the backend half readable.
    pub(crate) fn push_copy_done(self) -> (Conn<S, CopyBothClientDone, C>, Frame) {
        (self.transition(), empty_frame(b'c'))
    }

    /// Receives the backend half of a bidirectional COPY session.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item when it is illegal in COPY BOTH.
    pub(crate) fn offer(
        self,
        item: SessionItem,
    ) -> Result<CopyBothReceive<S, C>, (Self, SessionItem)> {
        match (
            project_session_item(frontend::RuntimeState::CopyBoth, &item),
            item,
        ) {
            (
                Some(frontend::Event::ReceiveCopyData),
                SessionItem::Message(BackendMessage::CopyData(data)),
            ) => Ok(CopyBothReceive::Data(self, data)),
            (
                Some(frontend::Event::ReceiveCopyDone),
                SessionItem::Message(BackendMessage::CopyDone),
            ) => Ok(CopyBothReceive::Done(self.transition())),
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => Ok(CopyBothReceive::Error(self.transition(), error)),
            (_, item) => Err((self, item)),
        }
    }
}

impl<S, C> CopyBothReceive<S, C> {
    /// Decodes a COPY BOTH data branch as a walsender message.
    ///
    /// # Errors
    ///
    /// Returns the connection with a decoding error for malformed known payloads.
    pub(crate) fn decode_replication(self) -> ReplicationProjection<S, C> {
        match self {
            Self::Data(conn, data) => match BackendReplication::decode(data) {
                Ok(message) => Ok(ReplicationReceive::Message(conn, message)),
                Err(error) => Err((conn, error)),
            },
            Self::Done(conn) => Ok(ReplicationReceive::Done(conn)),
            Self::Error(conn, error) => Ok(ReplicationReceive::Error(conn, error)),
        }
    }
}

impl<S, C> Conn<S, Draining, C> {
    /// `ReadyForQuery` is the sole exit from error draining.
    pub(crate) fn offer(self, item: SessionItem) -> DrainingTransition<S, C> {
        match (
            project_session_item(frontend::RuntimeState::Draining, &item),
            item,
        ) {
            (
                Some(frontend::Event::Ready),
                SessionItem::ReadyForQuery {
                    status,
                    parameters_changed,
                },
            ) => DrainingTransition::Ready(ready_state(self, status, parameters_changed)),
            (_, item) => DrainingTransition::Continue(self, item),
        }
    }
}

impl<S, C> Conn<S, AwaitingReady, C> {
    /// Consumes responses after Sync until `ReadyForQuery` proves readiness.
    pub(crate) fn offer(self, item: SessionItem) -> AwaitingReadyTransition<S, C> {
        match (
            project_session_item(frontend::RuntimeState::AwaitingReady, &item),
            item,
        ) {
            (
                Some(frontend::Event::Ready),
                SessionItem::ReadyForQuery {
                    status,
                    parameters_changed,
                },
            ) => AwaitingReadyTransition::Ready(ready_state(self, status, parameters_changed)),
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => AwaitingReadyTransition::Error(self.transition(), error),
            (_, item) => AwaitingReadyTransition::Continue(self, item),
        }
    }
}

impl<S> Conn<S, Resetting, Dirty> {
    /// Waits for evidence that `DISCARD ALL` itself completed.
    #[must_use]
    pub(crate) fn offer(self, item: SessionItem) -> ResettingTransition<S> {
        match (
            project_session_item(frontend::RuntimeState::Resetting, &item),
            item,
        ) {
            (Some(frontend::Event::DiscardComplete), SessionItem::CommandComplete { tag, .. })
                if tag == b"DISCARD ALL".as_slice() =>
            {
                ResettingTransition::Complete(self.transition())
            }
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => ResettingTransition::Error(self.transition(), error),
            (_, item) => ResettingTransition::Continue(self, item),
        }
    }
}

impl<S> Conn<S, ResetComplete, Dirty> {
    /// Restores `Pristine` only from idle readiness and the startup parameter baseline.
    #[must_use]
    pub(crate) fn offer(self, item: SessionItem) -> ResetCompleteTransition<S> {
        match (
            project_session_item(frontend::RuntimeState::ResetComplete, &item),
            item,
        ) {
            (
                Some(frontend::Event::ReadyClean),
                SessionItem::ReadyForQuery {
                    status: TransactionStatus::Idle,
                    parameters_changed: false,
                },
            ) => ResetCompleteTransition::Ready(self.transition()),
            (
                Some(frontend::Event::ReadyClean | frontend::Event::ReadyDirty),
                SessionItem::ReadyForQuery {
                    status,
                    parameters_changed,
                },
            ) => ResetCompleteTransition::Dirty {
                conn: self.transition(),
                status,
                parameters_changed,
            },
            (
                Some(frontend::Event::Error),
                SessionItem::Message(BackendMessage::ErrorResponse(error)),
            ) => ResetCompleteTransition::Error(self.transition(), error),
            (_, item) => ResetCompleteTransition::Continue(self, item),
        }
    }
}

impl<S, P> Conn<S, P, Pristine> {
    /// Conservatively records session-local state without changing protocol phase.
    pub(crate) fn mark_dirty(self) -> Conn<S, P, Dirty> {
        self.transition()
    }
}

fn project_session_item(
    state: frontend::RuntimeState,
    item: &SessionItem,
) -> Option<frontend::Event> {
    match item {
        SessionItem::Message(message) => frontend::project_external(state, message),
        SessionItem::CommandComplete { tag, .. } => {
            frontend::project_external(state, &BackendMessage::CommandComplete(tag.clone()))
        }
        SessionItem::ReadyForQuery { status, .. } => {
            frontend::project_external(state, &BackendMessage::ReadyForQuery(*status))
        }
    }
}

fn cstr_frame(tag: u8, value: &[u8]) -> io::Result<Frame> {
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message string contains a NUL byte",
        ));
    }
    let mut body = BytesMut::with_capacity(value.len() + 1);
    body.extend_from_slice(value);
    body.put_u8(0);
    Ok(Frame {
        tag,
        body: body.freeze(),
    })
}

fn empty_frame(tag: u8) -> Frame {
    Frame {
        tag,
        body: Bytes::new(),
    }
}

fn ready_state<S, P, C>(
    conn: Conn<S, P, C>,
    status: TransactionStatus,
    parameters_changed: bool,
) -> ReadyState<S, C> {
    if status == TransactionStatus::Idle && !parameters_changed {
        ReadyState::Clean(conn.transition())
    } else {
        ReadyState::Dirty {
            conn: conn.transition(),
            status,
            parameters_changed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_building_self_loops_then_syncs() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let building = ready.begin_extended();
        let (building, _) = building
            .push_parse(&Parse {
                statement: Bytes::from_static(b"statement"),
                query: Bytes::from_static(b"select $1"),
                parameter_types: vec![23],
            })
            .expect("valid Parse");
        let (bound, _) = building
            .push_bind(&Bind {
                portal: Bytes::from_static(b"portal"),
                statement: Bytes::from_static(b"statement"),
                parameter_formats: vec![0],
                parameters: vec![Some(Bytes::from_static(b"42"))],
                result_formats: vec![0],
            })
            .expect("valid Bind");
        let (bound, _) = bound
            .push_execute(&Execute {
                portal: Bytes::from_static(b"portal"),
                max_rows: 0,
            })
            .expect("valid Execute");
        let (awaiting_ready, sync) = bound.push_sync();
        assert_eq!(sync.tag, b'S');
        awaiting_ready.into_transport();
    }

    #[test]
    fn function_call_requires_result_then_ready() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let call = FunctionCall {
            function_oid: 42,
            argument_formats: vec![1],
            arguments: vec![Some(Bytes::from_static(b"argument"))],
            result_format: 1,
        };
        let (calling, frame) = ready.push_function_call(&call).unwrap();
        assert_eq!(frame.tag, b'F');

        let FunctionCallTransition::Response(awaiting_ready, result) = calling
            .offer(BackendMessage::FunctionCallResponse(Bytes::from_static(
                b"result",
            )))
            .unwrap()
        else {
            panic!("function result projected to the wrong branch")
        };
        assert_eq!(result, Bytes::from_static(b"result"));
        let AwaitingReadyTransition::Ready(ReadyState::Clean(ready)) =
            awaiting_ready.offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
        else {
            panic!("function call did not return to ready")
        };
        ready.into_transport();
    }

    #[test]
    fn ready_session_can_terminate_gracefully() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let (terminated, frame) = ready.push_terminate();
        assert_eq!(frame.tag, b'X');
        assert!(frame.body.is_empty());
        terminated.into_transport();
    }

    #[test]
    fn copy_both_waits_for_both_half_closes() {
        use crate::grammar::frontend::{Event, RuntimeFsm, RuntimeState};

        let mut client_first = RuntimeFsm::new();
        client_first.step(Event::Query).unwrap();
        client_first.step(Event::CopyBoth).unwrap();
        let open: Conn<(), CopyBoth> = Conn::new(()).transition();
        let (client_done, frame) = open.push_copy_done();
        client_first.step(Event::SendCopyDone).unwrap();
        assert_eq!(frame.tag, b'c');
        let CopyBothClientDoneReceive::Data(client_done, data) = client_done
            .offer(SessionItem::Message(BackendMessage::CopyData(
                Bytes::from_static(b"after client close"),
            )))
            .unwrap()
        else {
            panic!("backend data projected to the wrong branch")
        };
        client_first.step(Event::ReceiveCopyData).unwrap();
        assert_eq!(data, Bytes::from_static(b"after client close"));
        let CopyBothClientDoneReceive::Done(awaiting) = client_done
            .offer(SessionItem::Message(BackendMessage::CopyDone))
            .unwrap()
        else {
            panic!("backend close projected to the wrong branch")
        };
        client_first.step(Event::ReceiveCopyDone).unwrap();
        assert_eq!(client_first.state(), RuntimeState::AwaitingReady);
        awaiting.into_transport();

        let mut server_first = RuntimeFsm::new();
        server_first.step(Event::Query).unwrap();
        server_first.step(Event::CopyBoth).unwrap();
        let open: Conn<(), CopyBoth> = Conn::new(()).transition();
        let CopyBothReceive::Done(server_done) = open
            .offer(SessionItem::Message(BackendMessage::CopyDone))
            .unwrap()
        else {
            panic!("backend close projected to the wrong branch")
        };
        server_first.step(Event::ReceiveCopyDone).unwrap();
        let (server_done, data) =
            server_done.push_copy_data(Bytes::from_static(b"after server close"));
        server_first.step(Event::SendCopyData).unwrap();
        assert_eq!(data.tag, b'd');
        let (awaiting, done) = server_done.push_copy_done();
        server_first.step(Event::SendCopyDone).unwrap();
        assert_eq!(done.tag, b'c');
        assert_eq!(server_first.state(), RuntimeState::AwaitingReady);
        awaiting.into_transport();
    }

    #[test]
    fn copy_in_can_receive_an_early_backend_error() {
        let copy: Conn<(), CopyIn> = Conn::new(()).transition();
        let error = DiagnosticResponse {
            fields: vec![crate::codec::DiagnosticField {
                code: b'M',
                value: Bytes::from_static(b"copy cancelled"),
            }],
        };
        let CopyInTransition::Error(draining, received) = copy
            .offer(SessionItem::Message(BackendMessage::ErrorResponse(
                error.clone(),
            )))
            .unwrap();
        assert_eq!(received, error);

        let DrainingTransition::Ready(ReadyState::Clean(ready)) =
            draining.offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
        else {
            panic!("COPY failure did not drain to readiness")
        };
        ready.release();
    }

    #[test]
    fn copy_both_projects_typed_replication_without_losing_connection() {
        let open: Conn<(), CopyBoth> = Conn::new(()).transition();
        let status = FrontendReplication::StandbyStatus {
            written: 10,
            flushed: 9,
            applied: 8,
            client_time: 7,
            reply_requested: true,
        };
        let (open, frame) = open.push_replication(&status);
        assert_eq!(frame.body, status.encode());

        let keepalive = BackendReplication::PrimaryKeepalive {
            wal_end: 11,
            server_time: 12,
            reply_requested: true,
        };
        let receive = open
            .offer(SessionItem::Message(BackendMessage::CopyData(
                keepalive.encode(),
            )))
            .unwrap();
        let ReplicationReceive::Message(open, decoded) = receive.decode_replication().unwrap()
        else {
            panic!("keepalive projected to the wrong branch")
        };
        assert_eq!(decoded, keepalive);
        open.into_transport();

        let open: Conn<(), CopyBoth> = Conn::new(()).transition();
        let receive = open
            .offer(SessionItem::Message(BackendMessage::CopyData(
                Bytes::from_static(b"kshort"),
            )))
            .unwrap();
        let (open, _) = receive.decode_replication().unwrap_err();
        open.into_transport();
    }

    #[test]
    fn transaction_status_taints_ready_connection() {
        let query: Conn<(), SimpleQuery> = Conn::new(()).transition();
        let transition = query
            .offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::InTransaction,
                parameters_changed: false,
            })
            .expect("ReadyForQuery is valid evidence");
        let SimpleTransition::Ready(ReadyState::Dirty {
            conn,
            status: TransactionStatus::InTransaction,
            parameters_changed: false,
        }) = transition
        else {
            panic!("transaction should taint readiness")
        };
        conn.into_transport();
    }

    #[test]
    fn changed_parameters_taint_idle_connection() {
        let query: Conn<(), SimpleQuery> = Conn::new(()).transition();
        let transition = query
            .offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: true,
            })
            .expect("ReadyForQuery is valid evidence");
        let SimpleTransition::Ready(ReadyState::Dirty {
            conn,
            status: TransactionStatus::Idle,
            parameters_changed: true,
        }) = transition
        else {
            panic!("parameter change should taint readiness")
        };
        conn.into_transport();
    }

    #[test]
    fn simple_queries_are_dirty_unless_inspection_proves_them_stateless() {
        fn require_dirty<S>(conn: Conn<S, Ready, Dirty>) {
            conn.into_transport();
        }

        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let (query, _) = ready.push_query(b"LISTEN events").unwrap();
        let SimpleTransition::Ready(ReadyState::Clean(dirty)) = query
            .offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
            .unwrap()
        else {
            panic!("idle readiness should preserve the query's dirty evidence")
        };
        require_dirty(dirty);

        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let (query, _) = ready.push_stateless_query(b"SELECT 1").unwrap();
        let SimpleTransition::Ready(ReadyState::Clean(pristine)) = query
            .offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
            .unwrap()
        else {
            panic!("stateless query should retain pristine evidence")
        };
        pristine.release();
    }

    #[test]
    fn discard_all_evidence_recovers_pool_cleanliness() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let (resetting, frame) = ready.mark_dirty().begin_reset().unwrap();
        assert_eq!(frame.body, Bytes::from_static(b"ROLLBACK; DISCARD ALL\0"));
        let ResettingTransition::Continue(resetting, _) =
            resetting.offer(SessionItem::CommandComplete {
                tag: Bytes::from_static(b"ROLLBACK"),
                command: crate::demux::CommandIndex(0),
                notices: vec![],
            })
        else {
            panic!("ROLLBACK incorrectly completed reset")
        };
        let ResettingTransition::Complete(reset_complete) =
            resetting.offer(SessionItem::CommandComplete {
                tag: Bytes::from_static(b"DISCARD ALL"),
                command: crate::demux::CommandIndex(1),
                notices: vec![],
            })
        else {
            panic!("DISCARD ALL did not advance reset")
        };
        let ResetCompleteTransition::Ready(ready) =
            reset_complete.offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
        else {
            panic!("clean ready evidence did not restore pristine state")
        };
        ready.release();
    }
}
