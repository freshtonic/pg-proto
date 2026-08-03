//! Core query, COPY, and error-draining typestates.

use std::io;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    Conn, Dirty, Pristine,
    auth::Ready,
    codec::{BackendMessage, CopyResponse, DiagnosticResponse, Frame, TransactionStatus},
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
    Ready(Conn<S, Ready, C>, TransactionStatus),
    Error(Conn<S, Draining, C>, ErrorResponse),
}

#[derive(Debug)]
pub enum AwaitingReadyTransition<S, C> {
    Continue(Conn<S, AwaitingReady, C>, SessionItem),
    Ready(Conn<S, Ready, C>, TransactionStatus),
    Error(Conn<S, Draining, C>, ErrorResponse),
}

#[derive(Debug)]
pub enum DrainingTransition<S, C> {
    Continue(Conn<S, Draining, C>, SessionItem),
    Ready(Conn<S, Ready, C>, TransactionStatus),
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
    pub fn push_parse(self, body: Bytes) -> (Self, Frame) {
        (self, Frame { tag: b'P', body })
    }

    /// Describe is a self-loop while constructing an extended-query pipeline.
    pub fn push_describe(self, body: Bytes) -> (Self, Frame) {
        (self, Frame { tag: b'D', body })
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
    pub fn push_bind(self, body: Bytes) -> (Conn<S, BoundBuilding, C>, Frame) {
        (self.transition(), Frame { tag: b'B', body })
    }

    pub fn push_sync(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'S'))
    }
}

impl<S, C> Conn<S, BoundBuilding, C> {
    pub fn push_parse(self, body: Bytes) -> (Self, Frame) {
        (self, Frame { tag: b'P', body })
    }

    pub fn push_bind(self, body: Bytes) -> (Self, Frame) {
        (self, Frame { tag: b'B', body })
    }

    pub fn push_describe(self, body: Bytes) -> (Self, Frame) {
        (self, Frame { tag: b'D', body })
    }

    /// Execute is unavailable until a Bind transition has occurred.
    pub fn push_execute(self, body: Bytes) -> (Self, Frame) {
        (self, Frame { tag: b'E', body })
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
            SessionItem::Message(BackendMessage::ReadyForQuery(status)) => {
                Ok(SimpleTransition::Ready(self.transition(), status))
            }
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
}

impl<S, C> Conn<S, CopyOut, C> {
    pub fn receive_copy_data(self, _data: Bytes) -> Self {
        self
    }

    pub fn copy_done(self) -> Conn<S, AwaitingReady, C> {
        self.transition()
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

    pub fn receive_copy_data(self, _data: Bytes) -> Self {
        self
    }

    pub fn push_copy_done(self) -> (Conn<S, AwaitingReady, C>, Frame) {
        (self.transition(), empty_frame(b'c'))
    }
}

impl<S, C> Conn<S, Draining, C> {
    /// `ReadyForQuery` is the sole exit from error draining.
    pub fn offer(self, item: SessionItem) -> DrainingTransition<S, C> {
        match item {
            SessionItem::Message(BackendMessage::ReadyForQuery(status)) => {
                DrainingTransition::Ready(self.transition(), status)
            }
            item => DrainingTransition::Continue(self, item),
        }
    }
}

impl<S, C> Conn<S, AwaitingReady, C> {
    /// Consumes responses after Sync until `ReadyForQuery` proves readiness.
    pub fn offer(self, item: SessionItem) -> AwaitingReadyTransition<S, C> {
        match item {
            SessionItem::Message(BackendMessage::ReadyForQuery(status)) => {
                AwaitingReadyTransition::Ready(self.transition(), status)
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_building_self_loops_then_syncs() {
        let ready: Conn<(), Ready> = Conn::new(()).transition();
        let building = ready.begin_extended();
        let (building, _) = building.push_parse(Bytes::new());
        let (bound, _) = building.push_bind(Bytes::new());
        let (bound, _) = bound.push_execute(Bytes::new());
        let (_awaiting_ready, sync) = bound.push_sync();
        assert_eq!(sync.tag, b'S');
    }
}
