//! Runtime middleware behavior through the public builder facade.

use std::{cell::Cell, collections::BTreeMap, rc::Rc};

use bytes::Bytes;
use pg_proto::{
    Server, ServerAccept, ServerConnectionContext, ServerMiddleware, ServerTlsPolicy,
    TrustIdentity, TrustServerAuthentication,
    codec::FrontendMessage,
    pre_startup::PreStartupMessage,
    startup::{ProtocolVersion, StartupMessage},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct Records(&'static str);

impl ServerMiddleware<Vec<&'static str>, ServerConnectionContext<&'static str, TrustIdentity>>
    for Records
{
    fn frontend(
        &mut self,
        context: &ServerConnectionContext<&'static str, TrustIdentity>,
        state: &mut Vec<&'static str>,
        message: FrontendMessage,
    ) -> FrontendMessage {
        assert_eq!(context.peer(), &"peer-1");
        state.push(self.0);
        message
    }
}

#[tokio::test]
async fn builder_middleware_is_fresh_ordered_contextual_and_operational() {
    let creations = Rc::new(Cell::new(0));
    let first_creations = creations.clone();
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .middleware(
            move |context: &ServerConnectionContext<&'static str, TrustIdentity>| {
                assert_eq!(context.peer(), &"peer-1");
                first_creations.set(first_creations.get() + 1);
                Records("first")
            },
        )
        .middleware(|_: &ServerConnectionContext<&'static str, TrustIdentity>| Records("second"))
        .build()
        .unwrap();

    let (mut client, server_io) = tokio::io::duplex(4096);
    let peer = "peer-1";
    let client_task = async move {
        let startup = StartupMessage {
            version: ProtocolVersion::V3_2,
            parameters: BTreeMap::from([(
                Bytes::from_static(b"user"),
                Bytes::from_static(b"alice"),
            )]),
        };
        client.write_all(&startup.encode().unwrap()).await.unwrap();
        let mut established = [0; 15];
        client.read_exact(&mut established).await.unwrap();
        client
            .write_all(&[b'Q', 0, 0, 0, 6, b'x', 0])
            .await
            .unwrap();
    };
    let server_task = async {
        let ServerAccept::Session(mut connection) =
            server.accept(server_io, peer, Vec::new()).await.unwrap()
        else {
            panic!("expected session")
        };
        assert_eq!(
            connection.receive_wire().await.unwrap(),
            FrontendMessage::Query(Bytes::from_static(b"x"))
        );
        let (_, state, handler, _) = connection.teardown();
        assert_eq!(state, ["first", "second"]);
        assert_eq!(handler.0.1.0, "first");
    };
    tokio::join!(client_task, server_task);

    let (mut cancel_client, cancel_io) = tokio::io::duplex(256);
    cancel_client
        .write_all(
            &PreStartupMessage::CancelRequest {
                process_id: 7,
                secret_key: Bytes::from_static(b"key!"),
            }
            .to_packet()
            .unwrap(),
        )
        .await
        .unwrap();
    let ServerAccept::Cancellation(cancel) = server
        .accept(cancel_io, peer, vec!["cancel-state"])
        .await
        .unwrap()
    else {
        panic!("expected cancellation")
    };
    let (_, _, state, handler, context) = cancel.teardown();
    assert_eq!(state, ["cancel-state"]);
    assert_eq!(handler.0.1.0, "first");
    assert_eq!(context.peer(), &peer);
    assert_eq!(creations.get(), 2);
}
