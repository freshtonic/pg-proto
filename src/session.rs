//! Core query, COPY, and error-draining typestates.

use std::io;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    Conn, Dirty, Pristine,
    auth::Ready,
    codec::{
        BackendMessage, Bind, Close, CopyResponse, Describe, DiagnosticResponse, Execute, Frame,
        Parse, TransactionStatus,
    },
    demux::SessionItem,
};

#[derive(Debug)]
pub enum SimpleQuery {}

#[derive(Debug)]
pub enum Building {}

#[derive(Debug)]
pub enum BoundBuilding {}

#[derive(Debug)]
pub enum AwaitingReady {}

#[derive(Debug)]
pub enum CopyIn {}

#[derive(Debug)]
pub enum CopyOut {}

#[derive(Debug)]
pub enum CopyBoth {}

#[derive(Debug)]
pub enum Draining {}

pub type ErrorResponse = DiagnosticResponse;

pub type Fallible<T, S, C = Pristine> = Result<T, (Conn<S, Draining, C>, ErrorResponse)>;

#[derive(Debug)]
pub enum SimpleTransition<S, C> {
    Continue(Conn<S, SimpleQuery, C>, SessionItem),
    CopyIn(Conn<S, CopyIn, C>, CopyResponse),
    CopyOut(Conn<S, CopyOut, C>, CopyResponse),
    CopyBoth(Conn<S, CopyBoth, C>, CopyResponse),
    Ready(ReadyState<S, C>),
    Error(Conn<S, Draining, C>, ErrorResponse),
}

#[derive(Debug)]
pub enum AwaitingReadyTransition<S, C> {
    Continue(Conn<S, AwaitingReady, C>, SessionItem),
    Ready(ReadyState<S, C>),
    Error(Conn<S, Draining, C>, ErrorResponse),
}

#[derive(Debug)]
pub enum DrainingTransition<S, C> {
    Continue(Conn<S, Draining, C>, SessionItem),
    Ready(ReadyState<S, C>),
}

#[derive(Debug)]
pub enum CopyOutTransition<S, C> {
    Data(Conn<S, CopyOut, C>, Bytes),
    Done(Conn<S, AwaitingReady, C>),
    Error(Conn<S, Draining, C>, ErrorResponse),
}

#[derive(Debug)]
pub enum CopyBothReceive<S, C> {
    Data(Conn<S, CopyBoth, C>, Bytes),
    Done(Conn<S, AwaitingReady, C>),
    Error(Conn<S, Draining, C>, ErrorResponse),
}

#[derive(Debug)]
pub enum ReadyState<S, C> {
    Clean(Conn<S, Ready, C>),
    Dirty {
        conn: Conn<S, Ready, Dirty>,
        status: TransactionStatus,
        parameters_changed: bool,
    },
}

impl<S, C> Conn<S, Ready, C> {
    /// Buffers a simple query and enters its response phase.
    ///
    /// # Errors
    ///
    /// Returns an error if the query contains a NUL byte.
    pub fn push_query(self, query: &[u8]) -> io::Result<(Conn<S, SimpleQuery, C>, Frame)> {
        Ok((self.transition(), cstr_frame(b'Q', query)?))
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
    pub fn begin_extended(self) -> Conn<S, Building, C> {
        self.transition()
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
    pub fn release(self) -> S {
        self.into_transport()
    }
}

impl<S, C> Conn<S, Building, C> {
    /// Parse is a self-loop while constructing an extended-query pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_parse(self, message: &Parse) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// Describe is a self-loop while constructing an extended-query pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_describe(self, message: &Describe) -> io::Result<(Self, Frame)> {
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
    pub fn push_bind(self, message: &Bind) -> io::Result<(Conn<S, BoundBuilding, C>, Frame)> {
        Ok((self.transition(), message.to_frame()?))
    }

    /// Close is legal while building, but does not make a portal executable.
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_close(self, message: &Close) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    pub fn push_flush(self) -> (Self, Frame) {
        (self, empty_frame(b'H'))
    }

    pub fn push_sync(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'S'))
    }
}

impl<S, C> Conn<S, BoundBuilding, C> {
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_parse(self, message: &Parse) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_bind(self, message: &Bind) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_describe(self, message: &Describe) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// Execute is unavailable until a Bind transition has occurred.
    ///
    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_execute(self, message: &Execute) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    /// # Errors
    ///
    /// Returns an error if the structured message cannot be reconstructed.
    pub fn push_close(self, message: &Close) -> io::Result<(Self, Frame)> {
        Ok((self, message.to_frame()?))
    }

    pub fn push_flush(self) -> (Self, Frame) {
        (self, empty_frame(b'H'))
    }

    pub fn push_sync(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'S'))
    }
}

impl<S, C> Conn<S, SimpleQuery, C> {
    /// Advances a simple-query session using an actual projected backend item.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item if it is illegal in this phase.
    pub fn offer(self, item: SessionItem) -> Result<SimpleTransition<S, C>, (Self, SessionItem)> {
        match item {
            SessionItem::Message(BackendMessage::CopyInResponse(response)) => {
                Ok(SimpleTransition::CopyIn(self.transition(), response))
            }
            SessionItem::Message(BackendMessage::CopyOutResponse(response)) => {
                Ok(SimpleTransition::CopyOut(self.transition(), response))
            }
            SessionItem::Message(BackendMessage::CopyBothResponse(response)) => {
                Ok(SimpleTransition::CopyBoth(self.transition(), response))
            }
            SessionItem::ReadyForQuery {
                status,
                parameters_changed,
            } => Ok(SimpleTransition::Ready(ready_state(
                self,
                status,
                parameters_changed,
            ))),
            SessionItem::Message(BackendMessage::ErrorResponse(error)) => {
                Ok(SimpleTransition::Error(self.transition(), error))
            }
            item @ (SessionItem::CommandComplete { .. }
            | SessionItem::Message(
                BackendMessage::RowDescription(_)
                | BackendMessage::DataRow(_)
                | BackendMessage::EmptyQueryResponse,
            )) => Ok(SimpleTransition::Continue(self, item)),
            item => Err((self, item)),
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
    pub fn push_copy_data(self, data: Bytes) -> (Self, Frame) {
        (
            self,
            Frame {
                tag: b'd',
                body: data,
            },
        )
    }

    pub fn push_copy_done(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'c'))
    }

    /// Aborts COPY IN with a frontend error string.
    ///
    /// # Errors
    ///
    /// Returns an error if the message contains a NUL byte.
    pub fn push_copy_fail(self, message: &[u8]) -> io::Result<(Conn<S, AwaitingReady, C>, Frame)> {
        Ok((self.transition(), cstr_frame(b'f', message)?))
    }
}

impl<S, C> Conn<S, CopyOut, C> {
    /// Advances COPY OUT using backend evidence.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item when it is illegal in COPY OUT.
    pub fn offer(self, item: SessionItem) -> Result<CopyOutTransition<S, C>, (Self, SessionItem)> {
        match item {
            SessionItem::Message(BackendMessage::CopyData(data)) => {
                Ok(CopyOutTransition::Data(self, data))
            }
            SessionItem::Message(BackendMessage::CopyDone) => {
                Ok(CopyOutTransition::Done(self.transition()))
            }
            SessionItem::Message(BackendMessage::ErrorResponse(error)) => {
                Ok(CopyOutTransition::Error(self.transition(), error))
            }
            item => Err((self, item)),
        }
    }
}

impl<S, C> Conn<S, CopyBoth, C> {
    pub fn push_copy_data(self, data: Bytes) -> (Self, Frame) {
        (
            self,
            Frame {
                tag: b'd',
                body: data,
            },
        )
    }

    pub fn push_copy_done(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'c'))
    }

    /// Receives the backend half of a bidirectional COPY session.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item when it is illegal in COPY BOTH.
    pub fn offer(self, item: SessionItem) -> Result<CopyBothReceive<S, C>, (Self, SessionItem)> {
        match item {
            SessionItem::Message(BackendMessage::CopyData(data)) => {
                Ok(CopyBothReceive::Data(self, data))
            }
            SessionItem::Message(BackendMessage::CopyDone) => {
                Ok(CopyBothReceive::Done(self.transition()))
            }
            SessionItem::Message(BackendMessage::ErrorResponse(error)) => {
                Ok(CopyBothReceive::Error(self.transition(), error))
            }
            item => Err((self, item)),
        }
    }
}

impl<S, C> Conn<S, Draining, C> {
    /// `ReadyForQuery` is the sole exit from error draining.
    pub fn offer(self, item: SessionItem) -> DrainingTransition<S, C> {
        match item {
            SessionItem::ReadyForQuery {
                status,
                parameters_changed,
            } => DrainingTransition::Ready(ready_state(self, status, parameters_changed)),
            item => DrainingTransition::Continue(self, item),
        }
    }
}

impl<S, C> Conn<S, AwaitingReady, C> {
    /// Consumes responses after Sync until `ReadyForQuery` proves readiness.
    pub fn offer(self, item: SessionItem) -> AwaitingReadyTransition<S, C> {
        match item {
            SessionItem::ReadyForQuery {
                status,
                parameters_changed,
            } => AwaitingReadyTransition::Ready(ready_state(self, status, parameters_changed)),
            SessionItem::Message(BackendMessage::ErrorResponse(error)) => {
                AwaitingReadyTransition::Error(self.transition(), error)
            }
            item => AwaitingReadyTransition::Continue(self, item),
        }
    }
}

impl<S, P> Conn<S, P, Pristine> {
    /// Conservatively records session-local state without changing protocol phase.
    pub fn mark_dirty(self) -> Conn<S, P, Dirty> {
        self.transition()
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
        let (_awaiting_ready, sync) = bound.push_sync();
        assert_eq!(sync.tag, b'S');
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
        assert!(matches!(
            transition,
            SimpleTransition::Ready(ReadyState::Dirty {
                status: TransactionStatus::InTransaction,
                parameters_changed: false,
                ..
            })
        ));
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
        assert!(matches!(
            transition,
            SimpleTransition::Ready(ReadyState::Dirty {
                status: TransactionStatus::Idle,
                parameters_changed: true,
                ..
            })
        ));
    }
}
