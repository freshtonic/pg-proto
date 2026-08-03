//! Shows where application policy plugs into `pg-proto` without implementing it.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    cancel::{CancelKeyMap, CancelKeyRegistry},
    cleanliness::{CleanlinessEvent, CleanlinessPolicy},
    codec::FrontendMessage,
    demux::CancelKey,
    grammar::{backend, frontend},
    intermediary::Intermediary,
};

#[derive(Default)]
struct PoolPolicy {
    dirty: bool,
}

impl CleanlinessPolicy for PoolPolicy {
    fn observe(&mut self, event: &CleanlinessEvent) {
        self.dirty = !matches!(event, CleanlinessEvent::ResetComplete);
    }

    fn reusable(&self) -> bool {
        !self.dirty
    }
}

fn main() {
    // Real applications place independently authenticated, transport-carrying
    // typed sessions here. Neither side's phase or policy constrains the other.
    let downstream = backend::RuntimeFsm::new();
    let upstream = frontend::RuntimeFsm::new();
    let mut sessions = Intermediary::new(downstream, upstream);

    let message = FrontendMessage::Query(Bytes::from_static(b"select public_report()"));
    let inspected = sessions
        .inspect(message, |_downstream, _upstream, message| {
            // Routing, authorisation, SQL rewriting, and rejection live here.
            Ok::<_, Infallible>(message)
        })
        .unwrap();
    inspected.to_frame().unwrap();

    // Cancellation storage and connection-release decisions are also supplied
    // by the application, using protocol evidence exposed by the library.
    let client_key = CancelKey {
        process_id: 10,
        secret_key: Bytes::from_static(b"client-secret"),
    };
    let upstream_key = CancelKey {
        process_id: 20,
        secret_key: Bytes::from_static(b"upstream-secret"),
    };
    let mut cancellation = CancelKeyMap::new();
    cancellation
        .register_cancel_key(client_key.clone(), upstream_key)
        .unwrap();
    assert!(cancellation.resolve_cancel_key(&client_key).is_some());

    let mut pool = PoolPolicy::default();
    pool.observe(&CleanlinessEvent::StatementPrepared {
        name: Bytes::from_static(b"statement"),
    });
    assert!(!pool.reusable());
}
