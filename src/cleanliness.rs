//! Extensible evidence for application-owned connection reuse policy.

use bytes::Bytes;

use crate::codec::TransactionStatus;

/// Observable facts which may affect whether an upstream connection is reusable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CleanlinessEvent {
    /// The backend reported its current transaction state.
    TransactionStatus(TransactionStatus),
    /// A reportable run-time parameter changed.
    ParameterChanged {
        /// Parameter name.
        name: Bytes,
        /// New parameter value.
        value: Bytes,
    },
    /// The session began listening on a notification channel.
    Listen {
        /// Channel name.
        channel: Bytes,
    },
    /// The session stopped listening on one or all channels.
    Unlisten {
        /// Channel name, or `None` for every channel.
        channel: Option<Bytes>,
    },
    /// The session acquired an advisory lock.
    AdvisoryLockAcquired,
    /// The session released its advisory locks.
    AdvisoryLocksReleased,
    /// A portal became live.
    PortalOpened {
        /// Portal name.
        name: Bytes,
    },
    /// A portal was closed.
    PortalClosed {
        /// Portal name.
        name: Bytes,
    },
    /// A prepared statement became live.
    StatementPrepared {
        /// Prepared-statement name.
        name: Bytes,
    },
    /// A prepared statement was closed.
    StatementClosed {
        /// Prepared-statement name.
        name: Bytes,
    },
    /// A reset operation restored the application's clean baseline.
    ResetComplete,
    /// Evidence from application-specific SQL inspection.
    Application {
        /// Application-defined category.
        kind: Bytes,
        /// Application-defined supporting detail.
        detail: Bytes,
    },
}

/// Downstream policy which consumes cleanliness evidence.
///
/// The protocol library reports facts; the application decides whether they
/// prohibit pooling and what reset operation, if any, restores reusability.
pub(crate) trait CleanlinessPolicy {
    /// Incorporates one observed fact into the policy's state.
    fn observe(&mut self, event: &CleanlinessEvent);

    /// Reports whether the accumulated evidence permits connection reuse.
    fn reusable(&self) -> bool;
}

/// A no-op policy for applications which do not pool upstream connections.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IgnoreCleanliness;

impl CleanlinessPolicy for IgnoreCleanliness {
    fn observe(&mut self, _event: &CleanlinessEvent) {}

    fn reusable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RejectLocks(bool);

    impl CleanlinessPolicy for RejectLocks {
        fn observe(&mut self, event: &CleanlinessEvent) {
            match event {
                CleanlinessEvent::AdvisoryLockAcquired => self.0 = true,
                CleanlinessEvent::AdvisoryLocksReleased | CleanlinessEvent::ResetComplete => {
                    self.0 = false;
                }
                _ => {}
            }
        }

        fn reusable(&self) -> bool {
            !self.0
        }
    }

    #[test]
    fn application_policy_interprets_protocol_evidence() {
        let mut policy = RejectLocks::default();
        policy.observe(&CleanlinessEvent::AdvisoryLockAcquired);
        assert!(!policy.reusable());
        policy.observe(&CleanlinessEvent::AdvisoryLocksReleased);
        assert!(policy.reusable());
    }
}
