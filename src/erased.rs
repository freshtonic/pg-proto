//! Exact runtime erasure for storage and forwarding boundaries.

use std::{
    any::{TypeId, type_name},
    marker::PhantomData,
};

use crate::Conn;

/// A connection whose phase and cleanliness markers are retained as exact
/// runtime identities rather than generic parameters.
#[must_use = "dropping an erased connection abandons the PostgreSQL session"]
#[derive(Debug)]
pub(crate) struct ErasedConn<S> {
    transport: Option<S>,
    phase: TypeId,
    phase_name: &'static str,
    cleanliness: TypeId,
    cleanliness_name: &'static str,
}

impl<S> ErasedConn<S> {
    /// Reports the erased phase marker for diagnostics.
    #[must_use]
    pub(crate) const fn phase_name(&self) -> &'static str {
        self.phase_name
    }

    /// Reports the erased cleanliness marker for diagnostics.
    #[must_use]
    pub(crate) const fn cleanliness_name(&self) -> &'static str {
        self.cleanliness_name
    }

    /// Checks whether the exact requested phase marker was erased.
    #[must_use]
    pub(crate) fn phase_is<P: 'static>(&self) -> bool {
        self.phase == TypeId::of::<P>()
    }

    /// Checks whether the exact requested cleanliness marker was erased.
    #[must_use]
    pub(crate) fn cleanliness_is<C: 'static>(&self) -> bool {
        self.cleanliness == TypeId::of::<C>()
    }

    /// Re-enters the typed API only when both runtime identities exactly match.
    ///
    /// A failed attempt returns the unchanged erased connection.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection when either requested marker differs.
    pub(crate) fn try_reenter<P: 'static, C: 'static>(mut self) -> Result<Conn<S, P, C>, Self> {
        if !self.phase_is::<P>() || !self.cleanliness_is::<C>() {
            return Err(self);
        }
        Ok(Conn {
            transport: self.transport.take(),
            _state: PhantomData,
        })
    }

    /// Changes only the transport representation while retaining exact state
    /// identities.
    ///
    /// # Panics
    ///
    /// Panics only if an earlier internal operation has moved the transport.
    pub(crate) fn map_transport<T>(mut self, map: impl FnOnce(S) -> T) -> ErasedConn<T> {
        ErasedConn {
            transport: Some(map(self
                .transport
                .take()
                .expect("live erased connection has a transport"))),
            phase: self.phase,
            phase_name: self.phase_name,
            cleanliness: self.cleanliness,
            cleanliness_name: self.cleanliness_name,
        }
    }

    /// Irreversibly leaves state tracking and returns the underlying transport.
    ///
    /// # Panics
    ///
    /// Panics only if an earlier internal operation has moved the transport.
    pub(crate) fn into_transport(mut self) -> S {
        self.transport
            .take()
            .expect("live erased connection has a transport")
    }
}

impl<S, P: 'static, C: 'static> Conn<S, P, C> {
    /// Erases monomorphised state markers while retaining their exact runtime
    /// identities for checked re-entry.
    pub(crate) fn erase(mut self) -> ErasedConn<S> {
        ErasedConn {
            transport: self.transport.take(),
            phase: TypeId::of::<P>(),
            phase_name: type_name::<P>(),
            cleanliness: TypeId::of::<C>(),
            cleanliness_name: type_name::<C>(),
        }
    }
}

#[cfg(debug_assertions)]
impl<S> Drop for ErasedConn<S> {
    fn drop(&mut self) {
        assert!(
            self.transport.is_none() || std::thread::panicking(),
            "live erased PostgreSQL connection dropped; re-enter or extract its transport"
        );
    }
}

#[cfg(test)]
/// Tests for state erasure and checked re-entry.
mod tests {
    use crate::{Dirty, Pristine, auth::Ready, session::Building};

    use super::*;

    #[test]
    fn exact_state_can_be_erased_and_reentered() {
        let ready: Conn<_, Ready, Pristine> = Conn::new(42_u8).transition();
        let erased = ready.erase();
        assert!(erased.phase_is::<Ready>());
        assert!(erased.cleanliness_is::<Pristine>());

        let ready = erased
            .try_reenter::<Ready, Pristine>()
            .expect("exact state identities match");
        assert_eq!(ready.into_transport(), 42);
    }

    #[test]
    fn failed_reentry_preserves_the_erased_connection() {
        let building: Conn<_, Building, Dirty> = Conn::new(42_u8).transition();
        let erased = building.erase();

        let erased = erased
            .try_reenter::<Ready, Dirty>()
            .expect_err("wrong phase must not re-enter");
        let erased = erased
            .try_reenter::<Building, Pristine>()
            .expect_err("wrong cleanliness must not re-enter");
        let building = erased
            .try_reenter::<Building, Dirty>()
            .expect("both exact identities match");
        assert_eq!(building.into_transport(), 42);
    }

    #[test]
    fn transport_mapping_does_not_change_erased_state() {
        let ready: Conn<_, Ready, Pristine> = Conn::new(42_u8).transition();
        let erased = ready.erase().map_transport(u16::from);

        let ready = erased
            .try_reenter::<Ready, Pristine>()
            .expect("mapping retained exact identities");
        assert_eq!(ready.into_transport(), 42_u16);
    }
}
