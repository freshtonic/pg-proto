//! Client runtime middleware spans establishment and operational traffic.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};

use bytes::Bytes;
use pg_proto::{
    Client, ClientAuthentication, ClientAuthenticationChallenge, ClientAuthenticationFuture,
    ClientAuthenticationResponse, ClientAuthenticationSession, ClientConnectionContext,
    ClientInitialContext, ClientMiddleware, ClientTlsPolicy, ClientTlsStatus, ConnectTarget,
    MiddlewareFactory, StartupParameters, TrustClientAuthentication,
    codec::{BackendMessage, FrontendMessage},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

#[derive(Debug)]
struct Recorder {
    id: usize,
}

struct Factory(Rc<Cell<usize>>);

#[derive(Clone, Copy, Debug)]
struct PasswordAuthentication;

impl ClientAuthentication for PasswordAuthentication {
    type Evidence = &'static str;
    type Session = Self;
    type Error = std::convert::Infallible;

    fn begin<'a>(
        &'a self,
        _target: &'a ConnectTarget,
    ) -> ClientAuthenticationFuture<'a, Self::Session, Self::Error> {
        Box::pin(async { Ok(*self) })
    }
}

impl ClientAuthenticationSession for PasswordAuthentication {
    type Evidence = &'static str;
    type Error = std::convert::Infallible;

    fn respond(
        &mut self,
        challenge: ClientAuthenticationChallenge,
    ) -> ClientAuthenticationFuture<'_, ClientAuthenticationResponse, Self::Error> {
        assert_eq!(challenge, ClientAuthenticationChallenge::CleartextPassword);
        Box::pin(async {
            Ok(ClientAuthenticationResponse::Password(Bytes::from_static(
                b"policy-secret",
            )))
        })
    }

    fn authenticated(self) -> ClientAuthenticationFuture<'static, Self::Evidence, Self::Error> {
        Box::pin(async { Ok("authenticated") })
    }
}

impl MiddlewareFactory<ClientInitialContext> for Factory {
    type Handler = Recorder;

    fn create(&self, context: &ClientInitialContext) -> Self::Handler {
        assert!(context.target().name().starts_with("connection-"));
        let id = self.0.get();
        self.0.set(id + 1);
        Recorder { id }
    }
}

impl<Evidence> ClientMiddleware<Vec<String>, ClientConnectionContext<Evidence>> for Recorder {
    fn startup(
        &mut self,
        context: &ClientConnectionContext<Evidence>,
        state: &mut Vec<String>,
        mut message: pg_proto::startup::StartupMessage,
    ) -> pg_proto::startup::StartupMessage {
        assert_eq!(context.tls(), Some(pg_proto::ClientTlsStatus::Plaintext));
        assert!(context.identity_if_known().is_none());
        state.push(format!("{}:startup", self.id));
        message.parameters.insert(
            Bytes::from_static(b"application_name"),
            Bytes::from(format!("middleware-{}", self.id)),
        );
        message
    }

    fn frontend(
        &mut self,
        context: &ClientConnectionContext<Evidence>,
        state: &mut Vec<String>,
        message: FrontendMessage,
    ) -> FrontendMessage {
        assert_eq!(context.tls(), Some(ClientTlsStatus::Plaintext));
        state.push(format!("{}:frontend", self.id));
        match message {
            FrontendMessage::Query(_) => {
                assert!(context.identity_if_known().is_some());
                FrontendMessage::Query(Bytes::from_static(b"rewritten"))
            }
            FrontendMessage::PasswordResponse(_) => {
                assert!(context.identity_if_known().is_none());
                FrontendMessage::PasswordResponse(Bytes::from_static(b"middleware-secret"))
            }
            message => message,
        }
    }

    fn backend(
        &mut self,
        context: &ClientConnectionContext<Evidence>,
        state: &mut Vec<String>,
        message: BackendMessage,
    ) -> BackendMessage {
        assert_eq!(context.tls(), Some(ClientTlsStatus::Plaintext));
        state.push(format!("{}:backend", self.id));
        match message {
            BackendMessage::CommandComplete(_) => {
                BackendMessage::CommandComplete(Bytes::from_static(b"MIDDLEWARE"))
            }
            message => message,
        }
    }
}

async fn peer(mut io: DuplexStream, expected_application_name: &'static [u8]) {
    let length = io.read_u32().await.unwrap();
    let mut body = vec![0; length as usize - 4];
    io.read_exact(&mut body).await.unwrap();
    let startup = pg_proto::startup::StartupMessage::decode(
        [length.to_be_bytes().as_slice(), body.as_slice()]
            .concat()
            .into(),
    )
    .unwrap();
    assert_eq!(
        startup
            .parameters
            .get(b"application_name".as_slice())
            .unwrap(),
        expected_application_name,
    );
    io.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
        .await
        .unwrap();
    io.flush().await.unwrap();
    assert_eq!(io.read_u8().await.unwrap(), b'Q');
    let query_length = io.read_u32().await.unwrap();
    let mut query = vec![0; query_length as usize - 4];
    io.read_exact(&mut query).await.unwrap();
    assert_eq!(query, b"rewritten\0");
    io.write_all(&[b'C', 0, 0, 0, 7, b'O', b'K', 0, b'Z', 0, 0, 0, 5, b'I'])
        .await
        .unwrap();
    io.flush().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn client_handlers_are_fresh_isolated_non_send_and_replace_owned_traffic() {
    let (client_a, peer_a) = tokio::io::duplex(4096);
    let (client_b, peer_b) = tokio::io::duplex(4096);
    let transports = Rc::new(RefCell::new(VecDeque::from([client_a, client_b])));
    let connector_transports = Rc::clone(&transports);
    let creations = Rc::new(Cell::new(0));
    let client = Client::builder()
        .connector(move |_| {
            let transport = connector_transports.borrow_mut().pop_front().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .middleware(Factory(Rc::clone(&creations)))
        .build()
        .unwrap();

    let client_side_a = async {
        client
            .connect(
                ConnectTarget::new("connection-a"),
                StartupParameters::new("alice"),
                Vec::new(),
            )
            .await
            .unwrap()
            .simple_query(b"ignored")
            .await
            .unwrap()
    };
    let client_side_b = async {
        client
            .connect(
                ConnectTarget::new("connection-b"),
                StartupParameters::new("bob"),
                Vec::new(),
            )
            .await
            .unwrap()
            .simple_query(b"ignored")
            .await
            .unwrap()
    };
    let ((connection_a, messages_a), (connection_b, messages_b), (), ()) = tokio::join!(
        client_side_a,
        client_side_b,
        peer(peer_a, b"middleware-0"),
        peer(peer_b, b"middleware-1"),
    );
    assert!(
        matches!(messages_a[0], BackendMessage::CommandComplete(ref tag) if tag == "MIDDLEWARE")
    );
    assert!(
        matches!(messages_b[0], BackendMessage::CommandComplete(ref tag) if tag == "MIDDLEWARE")
    );

    let (_, state_a, handler_a, context_a) = connection_a.into_parts();
    let (_, state_b, handler_b, context_b) = connection_b.into_parts();
    assert_eq!(handler_a.1.id, 0);
    assert_eq!(handler_b.1.id, 1);
    assert!(state_a.iter().all(|entry| entry.starts_with("0:")));
    assert!(state_b.iter().all(|entry| entry.starts_with("1:")));
    assert_eq!(context_a.target().name(), "connection-a");
    assert_eq!(context_b.target().name(), "connection-b");
    assert_eq!(creations.get(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn same_handler_intercepts_authentication_challenges_and_credential_responses() {
    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let transport = RefCell::new(Some(client_io));
    let creations = Rc::new(Cell::new(0));
    let client = Client::builder()
        .connector(|_| {
            let transport = transport.borrow_mut().take().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(PasswordAuthentication)
        .middleware(Factory(Rc::clone(&creations)))
        .build()
        .unwrap();

    let peer = async move {
        let length = peer_io.read_u32().await.unwrap();
        let mut startup = vec![0; length as usize - 4];
        peer_io.read_exact(&mut startup).await.unwrap();
        peer_io
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3])
            .await
            .unwrap();
        peer_io.flush().await.unwrap();
        assert_eq!(peer_io.read_u8().await.unwrap(), b'p');
        let length = peer_io.read_u32().await.unwrap();
        let mut password = vec![0; length as usize - 4];
        peer_io.read_exact(&mut password).await.unwrap();
        assert_eq!(password, b"middleware-secret\0");
        peer_io
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
            .await
            .unwrap();
        peer_io.flush().await.unwrap();
    };
    let connect = client.connect(
        ConnectTarget::new("connection-auth"),
        StartupParameters::new("alice"),
        Vec::new(),
    );
    let (connection, ()) = tokio::join!(connect, peer);
    let connection = connection.unwrap();
    assert_eq!(connection.context().identity(), &"authenticated");
    let (_, state, handler, _) = connection.into_parts();
    assert_eq!(handler.1.id, 0);
    assert!(state.iter().any(|entry| entry == "0:frontend"));
    // Cleartext challenge, AuthenticationOk, and ReadyForQuery all used this handler.
    assert_eq!(
        state.iter().filter(|entry| *entry == "0:backend").count(),
        3
    );
    assert_eq!(creations.get(), 1);
}
