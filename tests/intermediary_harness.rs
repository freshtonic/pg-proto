//! Integration coverage for composing independently typed proxy sides.

use bytes::Bytes;
use pg_proto::{
    cancel::{CancelKeyMap, CancelKeyRegistry},
    codec::{FrontendMessage, Parse},
    demux::CancelKey,
    grammar::{authentication, backend, frontend, server_authentication},
    intermediary::Intermediary,
    replication::{BackendReplication, FrontendReplication},
};

#[test]
fn neutral_intermediary_capabilities_compose_without_application_policy() {
    // Client-facing and upstream authentication deliberately choose different
    // mechanisms and advance independently.
    let mut authentication = Intermediary::new(
        server_authentication::RuntimeFsm::new(),
        authentication::RuntimeFsm::new(),
    );
    authentication
        .sides_mut()
        .0
        .step(server_authentication::Event::Begin)
        .unwrap();
    authentication
        .sides_mut()
        .0
        .step(server_authentication::Event::Cleartext)
        .unwrap();
    authentication
        .sides_mut()
        .1
        .step(authentication::Event::Sasl)
        .unwrap();

    // A downstream rewriter can replace a fully typed message before either
    // independently typed protocol side advances.
    let parse = FrontendMessage::Parse(Parse {
        statement: Bytes::from_static(b"client-statement"),
        query: Bytes::from_static(b"select value from report"),
        parameter_types: vec![],
    });
    let parse = authentication
        .inspect(parse, |_, _, message| {
            let FrontendMessage::Parse(mut parse) = message else {
                unreachable!()
            };
            parse.query = Bytes::from_static(b"select value from report where visible");
            Ok::<_, std::convert::Infallible>(FrontendMessage::Parse(parse))
        })
        .unwrap();
    parse.to_frame().unwrap();

    // COPY BOTH carries typed replication payloads in each direction.
    let mut copy = Intermediary::new(backend::RuntimeFsm::new(), frontend::RuntimeFsm::new());
    for event in [
        backend::Event::Query,
        backend::Event::CopyBoth,
        backend::Event::ReceiveDone,
        backend::Event::SendData,
        backend::Event::SendDone,
        backend::Event::CommandComplete,
        backend::Event::Ready,
    ] {
        copy.sides_mut().0.step(event).unwrap();
    }
    for event in [
        frontend::Event::Query,
        frontend::Event::CopyBoth,
        frontend::Event::SendCopyDone,
        frontend::Event::ReceiveCopyData,
        frontend::Event::ReceiveCopyDone,
        frontend::Event::Ready,
    ] {
        copy.sides_mut().1.step(event).unwrap();
    }
    let wal = BackendReplication::PrimaryKeepalive {
        wal_end: 99,
        server_time: 123,
        reply_requested: true,
    };
    assert_eq!(BackendReplication::decode(wal.encode()).unwrap(), wal);
    let reply = FrontendReplication::StandbyStatus {
        written: 99,
        flushed: 99,
        applied: 99,
        client_time: 124,
        reply_requested: false,
    };
    assert_eq!(FrontendReplication::decode(reply.encode()).unwrap(), reply);

    // Cancellation translation and clean reuse remain application-owned.
    let client_key = CancelKey {
        process_id: 1,
        secret_key: Bytes::from_static(b"client-key"),
    };
    let upstream_key = CancelKey {
        process_id: 2,
        secret_key: Bytes::from_static(b"upstream-key"),
    };
    let mut keys = CancelKeyMap::new();
    keys.register_cancel_key(client_key.clone(), upstream_key.clone())
        .unwrap();
    assert_eq!(keys.resolve_cancel_key(&client_key), Some(upstream_key));

    let mut reuse = frontend::RuntimeFsm::new();
    for event in [
        frontend::Event::Reset,
        frontend::Event::DiscardComplete,
        frontend::Event::ReadyClean,
    ] {
        reuse.step(event).unwrap();
    }
    assert_eq!(reuse.state(), frontend::RuntimeState::Ready);
}
