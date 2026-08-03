//! Session-typed `PostgreSQL` wire protocol primitives.

pub mod auth;
pub mod cancel;
pub mod codec;
pub mod demux;
pub mod grammar;
pub mod pre_startup;
pub mod server_auth;
pub mod server_session;
pub mod session;
pub mod startup;
pub mod tls;
pub mod transport;

use std::marker::PhantomData;

/// A connection whose legal operations are selected by `Phase` and `Cleanliness`.
#[must_use = "dropping a connection abandons the PostgreSQL session"]
#[derive(Debug)]
pub struct Conn<Transport, Phase, Cleanliness = Pristine> {
    transport: Option<Transport>,
    _state: PhantomData<(Phase, Cleanliness)>,
}

impl<Transport, Phase, Cleanliness> Conn<Transport, Phase, Cleanliness> {
    pub(crate) fn transition<NextPhase, NextCleanliness>(
        mut self,
    ) -> Conn<Transport, NextPhase, NextCleanliness> {
        Conn {
            transport: self.transport.take(),
            _state: PhantomData,
        }
    }

    /// Returns the underlying transport when deliberately leaving the typed API.
    ///
    /// # Panics
    ///
    /// Panics only if an internal transition has already moved the transport.
    pub fn into_transport(mut self) -> Transport {
        self.transport
            .take()
            .expect("live connection has a transport")
    }

    /// Changes transport representation without changing either state index.
    ///
    /// # Panics
    ///
    /// Panics only if an internal transition has already moved the transport.
    pub fn map_transport<Next>(
        mut self,
        map: impl FnOnce(Transport) -> Next,
    ) -> Conn<Next, Phase, Cleanliness> {
        Conn {
            transport: Some(map(self
                .transport
                .take()
                .expect("live connection has a transport"))),
            _state: PhantomData,
        }
    }

    pub(crate) const fn transport(&self) -> &Transport {
        match &self.transport {
            Some(transport) => transport,
            None => panic!("connection transport has already moved"),
        }
    }

    pub(crate) const fn transport_mut(&mut self) -> &mut Transport {
        match &mut self.transport {
            Some(transport) => transport,
            None => panic!("connection transport has already moved"),
        }
    }
}

impl<Transport> Conn<Transport, pre_startup::PreStartup, Pristine> {
    /// Starts a new connection before any startup packet has been sent.
    pub const fn new(transport: Transport) -> Self {
        Self {
            transport: Some(transport),
            _state: PhantomData,
        }
    }
}

#[cfg(debug_assertions)]
impl<Transport, Phase, Cleanliness> Drop for Conn<Transport, Phase, Cleanliness> {
    fn drop(&mut self) {
        assert!(
            self.transport.is_none() || std::thread::panicking(),
            "live PostgreSQL connection dropped before a terminal transition; call into_transport() to abort deliberately"
        );
    }
}

/// The connection has no known session-local changes.
#[derive(Debug)]
pub enum Pristine {}

/// The connection has state which prevents unconditional pool release.
#[derive(Debug)]
pub enum Dirty {}
