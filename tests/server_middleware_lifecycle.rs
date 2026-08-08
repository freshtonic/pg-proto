//! Server middleware spans establishment, cancellation, and operational traffic.

use std::{collections::BTreeMap, convert::Infallible};

use bytes::Bytes;
use pg_proto::{
    CancellationRequest, NegotiatedServerTls, Server, ServerAccept, ServerAuthentication,
    ServerAuthenticationAction, ServerAuthenticationFuture, ServerAuthenticationProvider,
    ServerAuthenticationRequest, ServerAuthenticationResponse, ServerConnectionContext,
    ServerMiddleware, ServerTlsPolicy, TrustIdentity, TrustServerAuthentication,
    codec::{BackendMessage, FrontendMessage},
    pre_startup::PreStartupMessage,
    startup::{ProtocolVersion, StartupMessage},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone, Copy)]
struct Lifecycle;

impl ServerMiddleware<Vec<&'static str>, ServerConnectionContext<&'static str, TrustIdentity>>
    for Lifecycle
{
    fn pre_startup(
        &mut self,
        context: &ServerConnectionContext<&'static str, TrustIdentity>,
        state: &mut Vec<&'static str>,
        message: PreStartupMessage,
    ) -> PreStartupMessage {
        assert!(context.tls_if_known().is_none());
        assert!(context.identity_if_known().is_none());
        state.push("pre-startup");
        message
    }

    fn startup(
        &mut self,
        context: &ServerConnectionContext<&'static str, TrustIdentity>,
        state: &mut Vec<&'static str>,
        mut message: StartupMessage,
    ) -> StartupMessage {
        assert_eq!(context.tls(), &NegotiatedServerTls::Plaintext);
        assert!(context.identity_if_known().is_none());
        state.push("startup");
        message
            .parameters
            .insert(Bytes::from_static(b"user"), Bytes::from_static(b"bob"));
        message
    }

    fn cancellation(
        &mut self,
        context: &ServerConnectionContext<&'static str, TrustIdentity>,
        state: &mut Vec<&'static str>,
        request: CancellationRequest,
    ) -> CancellationRequest {
        assert_eq!(context.tls(), &NegotiatedServerTls::Plaintext);
        state.push("cancellation");
        request
    }

    fn frontend(
        &mut self,
        context: &ServerConnectionContext<&'static str, TrustIdentity>,
        state: &mut Vec<&'static str>,
        message: FrontendMessage,
    ) -> FrontendMessage {
        assert!(context.identity_if_known().is_some());
        state.push("frontend");
        match message {
            FrontendMessage::Query(_) => FrontendMessage::Query(Bytes::from_static(b"rewritten")),
            message => message,
        }
    }

    fn backend(
        &mut self,
        context: &ServerConnectionContext<&'static str, TrustIdentity>,
        state: &mut Vec<&'static str>,
        message: BackendMessage,
    ) -> BackendMessage {
        state.push(if context.identity_if_known().is_some() {
            "backend-operational"
        } else {
            "backend-establishing"
        });
        match message {
            BackendMessage::CommandComplete(_) => {
                BackendMessage::CommandComplete(Bytes::from_static(b"REWRITTEN"))
            }
            message => message,
        }
    }
}

struct PasswordFactory;
struct PasswordAuth;
impl ServerAuthenticationProvider for PasswordFactory {
    type Authentication = PasswordAuth;
    fn create(&self) -> Self::Authentication {
        PasswordAuth
    }
}
impl ServerAuthentication<()> for PasswordAuth {
    type Identity = Bytes;
    type Error = Infallible;
    fn start<'a>(
        &'a mut self,
        _: ServerAuthenticationRequest<'a, ()>,
    ) -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<Bytes>, Infallible> {
        Box::pin(async { Ok(ServerAuthenticationAction::CleartextPassword) })
    }
    fn respond<'a>(
        &'a mut self,
        _: ServerAuthenticationRequest<'a, ()>,
        response: ServerAuthenticationResponse,
    ) -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<Bytes>, Infallible> {
        Box::pin(async move {
            let ServerAuthenticationResponse::Password(password) = response else {
                unreachable!()
            };
            Ok(ServerAuthenticationAction::Accept(password))
        })
    }
}

struct AuthTraffic;
impl ServerMiddleware<Vec<&'static str>, ServerConnectionContext<(), Bytes>> for AuthTraffic {
    fn frontend(
        &mut self,
        _: &ServerConnectionContext<(), Bytes>,
        state: &mut Vec<&'static str>,
        message: FrontendMessage,
    ) -> FrontendMessage {
        state.push("credential-in");
        match message {
            FrontendMessage::PasswordResponse(_) => {
                FrontendMessage::PasswordResponse(Bytes::from_static(b"replaced\0"))
            }
            message => message,
        }
    }
    fn backend(
        &mut self,
        _: &ServerConnectionContext<(), Bytes>,
        state: &mut Vec<&'static str>,
        message: BackendMessage,
    ) -> BackendMessage {
        state.push("auth-out");
        message
    }
}

#[tokio::test]
async fn authentication_challenges_and_credentials_traverse_the_handler() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(PasswordFactory)
        .middleware(|_: &ServerConnectionContext<(), Bytes>| AuthTraffic)
        .build()
        .unwrap();
    let (mut client, io) = tokio::io::duplex(1024);
    let client_task = async move {
        let startup = StartupMessage {
            version: ProtocolVersion::V3_2,
            parameters: BTreeMap::new(),
        };
        client.write_all(&startup.encode().unwrap()).await.unwrap();
        let mut challenge = [0; 9];
        client.read_exact(&mut challenge).await.unwrap();
        assert_eq!(&challenge, &[b'R', 0, 0, 0, 8, 0, 0, 0, 3]);
        client
            .write_all(&[
                b'p', 0, 0, 0, 13, b'o', b'r', b'i', b'g', b'i', b'n', b'a', b'l', 0,
            ])
            .await
            .unwrap();
        let mut ready = [0; 15];
        client.read_exact(&mut ready).await.unwrap();
    };
    let server_task = async {
        let ServerAccept::Session(connection) = server.accept(io, (), Vec::new()).await.unwrap()
        else {
            panic!("session")
        };
        assert_eq!(
            connection.context().identity(),
            &Bytes::from_static(b"replaced")
        );
        let (_, state, _, _) = connection.teardown();
        assert_eq!(state, ["auth-out", "credential-in", "auth-out", "auth-out"]);
    };
    tokio::join!(client_task, server_task);
}

#[tokio::test]
async fn one_handler_observes_progressive_context_and_rewrites_owned_messages() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .middleware(|_: &ServerConnectionContext<&'static str, TrustIdentity>| Lifecycle)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(4096);

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
        let mut rewritten = [0; 15];
        client.read_exact(&mut rewritten).await.unwrap();
        assert_eq!(&rewritten[5..], b"REWRITTEN\0");
    };
    let server_task = async {
        let ServerAccept::Session(mut connection) =
            server.accept(server_io, "peer", Vec::new()).await.unwrap()
        else {
            panic!("expected session")
        };
        assert_eq!(
            connection.startup().parameters.get(b"user".as_slice()),
            Some(&Bytes::from_static(b"bob"))
        );
        assert_eq!(
            connection.receive_wire().await.unwrap(),
            FrontendMessage::Query(Bytes::from_static(b"rewritten"))
        );
        connection
            .send_wire(BackendMessage::CommandComplete(Bytes::from_static(
                b"ORIGINAL",
            )))
            .await
            .unwrap();
        let (_, state, _, context) = connection.teardown();
        assert_eq!(context.identity(), &TrustIdentity);
        assert_eq!(
            state,
            [
                "pre-startup",
                "startup",
                "backend-operational",
                "backend-operational",
                "frontend",
                "backend-operational",
            ]
        );
    };
    tokio::join!(client_task, server_task);
}

#[tokio::test]
async fn cancellation_uses_the_same_fresh_handler_and_mutable_state() {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .middleware(|_: &ServerConnectionContext<&'static str, TrustIdentity>| Lifecycle)
        .build()
        .unwrap();
    let (mut client, server_io) = tokio::io::duplex(256);
    client
        .write_all(
            &PreStartupMessage::CancelRequest {
                process_id: 9,
                secret_key: Bytes::from_static(b"key!"),
            }
            .to_packet()
            .unwrap(),
        )
        .await
        .unwrap();
    let ServerAccept::Cancellation(cancel) =
        server.accept(server_io, "peer", Vec::new()).await.unwrap()
    else {
        panic!("expected cancellation")
    };
    let (_, request, state, _, context) = cancel.teardown();
    assert_eq!(request.process_id(), 9);
    assert_eq!(state, ["pre-startup", "cancellation"]);
    assert_eq!(context.tls(), &NegotiatedServerTls::Plaintext);
}
