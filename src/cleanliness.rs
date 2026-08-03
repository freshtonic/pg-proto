//! Extensible evidence for application-owned connection reuse policy.

use bytes::Bytes;

use crate::codec::TransactionStatus;

/// Observable facts which may affect whether an upstream connection is reusable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanlinessEvent {
    TransactionStatus(TransactionStatus),
    ParameterChanged {
        name: Bytes,
        value: Bytes,
    },
    Listen {
        channel: Bytes,
    },
    Unlisten {
        channel: Option<Bytes>,
    },
    AdvisoryLockAcquired,
    AdvisoryLocksReleased,
    PortalOpened {
        name: Bytes,
    },
    PortalClosed {
        name: Bytes,
    },
    StatementPrepared {
        name: Bytes,
    },
    StatementClosed {
        name: Bytes,
    },
    ResetComplete,
    /// Evidence from application-specific SQL inspection.
    Application {
        kind: Bytes,
        detail: Bytes,
    },
}

/// Downstream policy which consumes cleanliness evidence.
///
/// The protocol library reports facts; the application decides whether they
/// prohibit pooling and what reset operation, if any, restores reusability.
pub trait CleanlinessPolicy {
    fn observe(&mut self, event: &CleanlinessEvent);

    fn reusable(&self) -> bool;
}

/// A no-op policy for applications which do not pool upstream connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct IgnoreCleanliness;

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
