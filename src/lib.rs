//! Session-typed `PostgreSQL` wire protocol primitives.

pub mod auth;
pub mod codec;
pub mod demux;
pub mod pre_startup;
pub mod startup;

use std::marker::PhantomData;

/// A connection whose legal operations are selected by `Phase` and `Cleanliness`.
#[must_use = "dropping a connection abandons the PostgreSQL session"]
#[derive(Debug)]
pub struct Conn<Transport, Phase, Cleanliness = Pristine> {
    transport: Transport,
    _state: PhantomData<(Phase, Cleanliness)>,
}

impl<Transport, Phase, Cleanliness> Conn<Transport, Phase, Cleanliness> {
    pub(crate) fn transition<NextPhase, NextCleanliness>(
        self,
    ) -> Conn<Transport, NextPhase, NextCleanliness> {
        Conn {
            transport: self.transport,
            _state: PhantomData,
        }
    }

    /// Returns the underlying transport when deliberately leaving the typed API.
    pub fn into_transport(self) -> Transport {
        self.transport
    }

    pub(crate) const fn transport(&self) -> &Transport {
        &self.transport
    }
}

impl<Transport> Conn<Transport, pre_startup::PreStartup, Pristine> {
    /// Starts a new connection before any startup packet has been sent.
    pub const fn new(transport: Transport) -> Self {
        Self {
            transport,
            _state: PhantomData,
        }
    }
}

/// The connection has no known session-local changes.
#[derive(Debug)]
pub enum Pristine {}

/// The connection has state which prevents unconditional pool release.
#[derive(Debug)]
pub enum Dirty {}
