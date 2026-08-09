//! Behavioural coverage for the operational intermediary facade.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    AuthenticatedRouteContext, AuthenticatedRoutePolicy, BackendMessage, Bind, BoundedPipeline,
    CancellationPolicy, Client, ClientConnectionContext, ClientInitialContext, ClientMiddleware,
    ClientTlsPolicy, ConnectTarget, CopyResponse, Execute, FrontendMessage, InitialServerContext,
    Intermediary, IntermediaryBuildError, IntermediaryMiddleware, Parse, Server,
    ServerConnectionContext, ServerMiddleware, ServerTlsPolicy, StartupParameters,
    StartupRouteResolver, TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct CandidateResolver;
impl StartupRouteResolver<String> for CandidateResolver {
    type Error = Infallible;
    fn resolve<'a>(
        &'a self,
        startup: StartupParameters,
        initial: InitialServerContext<'a, String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ConnectTarget, Self::Error>> + 'a>>
    {
        Box::pin(async move {
            assert_eq!(initial.peer(), "downstream-peer");
            assert_eq!(startup.user(), Some("alice"));
            Ok(ConnectTarget::new("candidate"))
        })
    }
}

struct RefineRoute;
impl AuthenticatedRoutePolicy<String, TrustIdentity> for RefineRoute {
    type Error = Infallible;
    fn route<'a>(
        &'a self,
        target: ConnectTarget,
        context: AuthenticatedRouteContext<'a, String, TrustIdentity>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ConnectTarget, Self::Error>> + 'a>>
    {
        Box::pin(async move {
            assert_eq!(target.name(), "candidate");
            assert_eq!(context.peer(), "downstream-peer");
            assert_eq!(context.identity(), &TrustIdentity);
            Ok(ConnectTarget::new("tenant-a"))
        })
    }
}

fn tagged_bytes(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn frontend_bytes(message: &FrontendMessage) -> Vec<u8> {
    let (tag, body) = match message {
        FrontendMessage::Query(query) => (b'Q', [query.as_ref(), b"\0"].concat()),
        FrontendMessage::CopyData(data) => (b'd', data.to_vec()),
        FrontendMessage::Parse(parse) => {
            let mut body = [parse.statement.as_ref(), b"\0", parse.query.as_ref(), b"\0"].concat();
            body.extend_from_slice(
                &u16::try_from(parse.parameter_types.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            for oid in &parse.parameter_types {
                body.extend_from_slice(&oid.to_be_bytes());
            }
            (b'P', body)
        }
        FrontendMessage::Bind(bind) => {
            let mut body = [bind.portal.as_ref(), b"\0", bind.statement.as_ref(), b"\0"].concat();
            body.extend_from_slice(
                &u16::try_from(bind.parameter_formats.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            for format in &bind.parameter_formats {
                body.extend_from_slice(&format.to_be_bytes());
            }
            body.extend_from_slice(&u16::try_from(bind.parameters.len()).unwrap().to_be_bytes());
            for parameter in &bind.parameters {
                match parameter {
                    None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
                    Some(value) => {
                        body.extend_from_slice(&i32::try_from(value.len()).unwrap().to_be_bytes());
                        body.extend_from_slice(value);
                    }
                }
            }
            body.extend_from_slice(
                &u16::try_from(bind.result_formats.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            for format in &bind.result_formats {
                body.extend_from_slice(&format.to_be_bytes());
            }
            (b'B', body)
        }
        FrontendMessage::Execute(execute) => {
            let mut body = [execute.portal.as_ref(), b"\0"].concat();
            body.extend_from_slice(&execute.max_rows.to_be_bytes());
            (b'E', body)
        }
        FrontendMessage::Sync => (b'S', Vec::new()),
        _ => panic!("test encoder does not support {message:?}"),
    };
    tagged_bytes(tag, &body)
}

fn backend_bytes(message: &BackendMessage) -> Vec<u8> {
    let (tag, body) = match message {
        BackendMessage::ParseComplete => (b'1', Vec::new()),
        BackendMessage::BindComplete => (b'2', Vec::new()),
        BackendMessage::CommandComplete(command) => (b'C', [command.as_ref(), b"\0"].concat()),
        BackendMessage::ReadyForQuery(status) => (
            b'Z',
            vec![match status {
                pg_proto::TransactionStatus::Idle => b'I',
                pg_proto::TransactionStatus::InTransaction => b'T',
                pg_proto::TransactionStatus::FailedTransaction => b'E',
            }],
        ),
        BackendMessage::CopyBothResponse(response) => {
            let mut body = vec![response.overall_format];
            body.extend_from_slice(
                &u16::try_from(response.column_formats.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            for format in &response.column_formats {
                body.extend_from_slice(&format.to_be_bytes());
            }
            (b'W', body)
        }
        BackendMessage::CopyData(data) => (b'd', data.to_vec()),
        _ => panic!("test encoder does not support {message:?}"),
    };
    tagged_bytes(tag, &body)
}

async fn read_tagged(stream: &mut tokio::io::DuplexStream) -> (u8, Vec<u8>) {
    let tag = stream.read_u8().await.unwrap();
    let length = stream.read_u32().await.unwrap();
    let mut body = vec![0; usize::try_from(length).unwrap() - 4];
    stream.read_exact(&mut body).await.unwrap();
    (tag, body)
}

#[derive(Clone, Copy)]
struct ServerOrder;
impl ServerMiddleware<Vec<&'static str>, ServerConnectionContext<String, TrustIdentity>>
    for ServerOrder
{
    fn frontend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        state: &mut Vec<&'static str>,
        message: FrontendMessage,
    ) -> FrontendMessage {
        state.push("server-frontend");
        message
    }
    fn backend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        state: &mut Vec<&'static str>,
        message: BackendMessage,
    ) -> BackendMessage {
        state.push("server-backend");
        message
    }
}

#[derive(Clone, Copy)]
struct ClientOrder;
impl ClientMiddleware<Vec<&'static str>, ClientConnectionContext<()>> for ClientOrder {
    fn frontend(
        &mut self,
        _: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        message: FrontendMessage,
    ) -> FrontendMessage {
        state.push("client-frontend");
        message
    }
    fn backend(
        &mut self,
        _: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        message: BackendMessage,
    ) -> BackendMessage {
        state.push("client-backend");
        message
    }
}

#[derive(Clone, Copy)]
struct BoundaryOrder;
impl
    IntermediaryMiddleware<
        Vec<&'static str>,
        ServerConnectionContext<String, TrustIdentity>,
        ClientConnectionContext<()>,
    > for BoundaryOrder
{
    fn frontend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        message: FrontendMessage,
    ) -> FrontendMessage {
        state.push("boundary-frontend");
        message
    }
    fn backend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        message: BackendMessage,
    ) -> BackendMessage {
        state.push("boundary-backend");
        message
    }
}

#[test]
fn intermediary_requires_complete_roles_routing_and_cancellation_policy() {
    assert_eq!(
        Intermediary::builder().build().unwrap_err(),
        IntermediaryBuildError::MissingServer
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn intermediary_routes_authenticates_and_forwards_a_simple_query() {
    let (downstream_transport, mut downstream_peer) = tokio::io::duplex(64 * 1024);
    let (upstream_transport, mut upstream_peer) = tokio::io::duplex(64 * 1024);
    let upstream_transport = std::sync::Mutex::new(Some(upstream_transport));

    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .middleware(|context: &ServerConnectionContext<String, TrustIdentity>| {
            assert_eq!(context.peer(), "downstream-peer");
            ServerOrder
        })
        .build()
        .unwrap();
    let client = Client::builder()
        .connector(move |target| {
            assert_eq!(target.name(), "tenant-a");
            let transport = upstream_transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, Infallible>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .middleware(|context: &ClientInitialContext| {
            assert_eq!(context.target().name(), "tenant-a");
            ClientOrder
        })
        .build()
        .unwrap();
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(CandidateResolver)
        .authenticated_route(RefineRoute)
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(1).unwrap())
        .middleware(
            |server: &ServerConnectionContext<String, TrustIdentity>,
             client: &ClientConnectionContext<()>| {
                assert_eq!(server.peer(), "downstream-peer");
                assert_eq!(client.target().name(), "tenant-a");
                BoundaryOrder
            },
        )
        .build()
        .unwrap();

    let downstream = tokio::spawn(async move {
        let startup = pg_proto::StartupMessage {
            version: pg_proto::ProtocolVersion::V3_2,
            parameters: std::iter::once((
                Bytes::from_static(b"user"),
                Bytes::from_static(b"alice"),
            ))
            .collect(),
        };
        downstream_peer
            .write_all(&startup.encode().unwrap())
            .await
            .unwrap();
        let mut authentication_and_ready = [0; 15];
        downstream_peer
            .read_exact(&mut authentication_and_ready)
            .await
            .unwrap();
        assert_eq!(authentication_and_ready[0], b'R');
        assert_eq!(downstream_peer.read_u8().await.unwrap(), b'S');
        let length = downstream_peer.read_u32().await.unwrap();
        let mut status = vec![0; usize::try_from(length).unwrap() - 4];
        downstream_peer.read_exact(&mut status).await.unwrap();
        assert_eq!(status, b"TimeZone\0UTC\0");
        downstream_peer
            .write_all(&[
                b'Q', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', 0, b'Q', 0, 0,
                0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'2', 0,
            ])
            .await
            .unwrap();
        for expected in [b"SELECT 1\0".as_slice(), b"SELECT 2\0".as_slice()] {
            let tag = downstream_peer.read_u8().await.unwrap();
            assert_eq!(tag, b'C');
            let length = downstream_peer.read_u32().await.unwrap();
            let mut body = vec![0; usize::try_from(length).unwrap() - 4];
            downstream_peer.read_exact(&mut body).await.unwrap();
            assert_eq!(body, expected);
            let mut ready = [0; 6];
            downstream_peer.read_exact(&mut ready).await.unwrap();
            assert_eq!(ready, [b'Z', 0, 0, 0, 5, b'I']);
        }
        let extended = [
            FrontendMessage::Parse(Parse {
                statement: Bytes::new(),
                query: Bytes::from_static(b"SELECT 3"),
                parameter_types: vec![],
            }),
            FrontendMessage::Bind(Bind {
                portal: Bytes::new(),
                statement: Bytes::new(),
                parameter_formats: vec![],
                parameters: vec![],
                result_formats: vec![],
            }),
            FrontendMessage::Execute(Execute {
                portal: Bytes::new(),
                max_rows: 0,
            }),
            FrontendMessage::Sync,
        ];
        for message in extended {
            downstream_peer
                .write_all(&frontend_bytes(&message))
                .await
                .unwrap();
        }
        for expected in *b"12CZ" {
            assert_eq!(read_tagged(&mut downstream_peer).await.0, expected);
        }
        downstream_peer
            .write_all(&frontend_bytes(&FrontendMessage::Query(
                Bytes::from_static(b"START_REPLICATION"),
            )))
            .await
            .unwrap();
        assert_eq!(read_tagged(&mut downstream_peer).await.0, b'W');
        let (tag, body) = read_tagged(&mut downstream_peer).await;
        assert_eq!((tag, body.as_slice()), (b'd', b"w-replication".as_slice()));
        downstream_peer
            .write_all(&frontend_bytes(&FrontendMessage::CopyData(
                Bytes::from_static(b"r-standby-status"),
            )))
            .await
            .unwrap();
    });
    let upstream = tokio::spawn(async move {
        let length = upstream_peer.read_u32().await.unwrap();
        let mut body = vec![0; usize::try_from(length).unwrap() - 4];
        upstream_peer.read_exact(&mut body).await.unwrap();
        let startup = pg_proto::StartupMessage::decode(
            [length.to_be_bytes().as_slice(), body.as_slice()]
                .concat()
                .into(),
        )
        .unwrap();
        assert_eq!(startup.parameters.get(b"user".as_slice()).unwrap(), "alice");
        upstream_peer
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
            .await
            .unwrap();
        upstream_peer
            .write_all(&[
                b'S', 0, 0, 0, 17, b'T', b'i', b'm', b'e', b'Z', b'o', b'n', b'e', 0, b'U', b'T',
                b'C', 0,
            ])
            .await
            .unwrap();
        for number in *b"12" {
            assert_eq!(upstream_peer.read_u8().await.unwrap(), b'Q');
            let length = upstream_peer.read_u32().await.unwrap();
            let mut body = vec![0; usize::try_from(length).unwrap() - 4];
            upstream_peer.read_exact(&mut body).await.unwrap();
            assert_eq!(body[body.len() - 2], number);
            upstream_peer
                .write_all(&[
                    b'C', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', number, 0, b'Z',
                    0, 0, 0, 5, b'I',
                ])
                .await
                .unwrap();
        }
        for (expected, response) in [
            (b'P', BackendMessage::ParseComplete),
            (b'B', BackendMessage::BindComplete),
            (
                b'E',
                BackendMessage::CommandComplete(Bytes::from_static(b"SELECT 3")),
            ),
            (
                b'S',
                BackendMessage::ReadyForQuery(pg_proto::TransactionStatus::Idle),
            ),
        ] {
            assert_eq!(read_tagged(&mut upstream_peer).await.0, expected);
            upstream_peer
                .write_all(&backend_bytes(&response))
                .await
                .unwrap();
        }
        assert_eq!(read_tagged(&mut upstream_peer).await.0, b'Q');
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::CopyBothResponse(
                CopyResponse {
                    overall_format: 0,
                    column_formats: vec![],
                },
            )))
            .await
            .unwrap();
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::CopyData(
                Bytes::from_static(b"w-replication"),
            )))
            .await
            .unwrap();
        let (tag, body) = read_tagged(&mut upstream_peer).await;
        assert_eq!(
            (tag, body.as_slice()),
            (b'd', b"r-standby-status".as_slice())
        );
    });

    let mut session = Box::pin(intermediary.accept(
        downstream_transport,
        "downstream-peer".to_owned(),
        vec!["shared-state"],
    ))
    .await
    .unwrap()
    .into_session();
    assert_eq!(session.target().name(), "tenant-a");
    assert_eq!(session.state().first(), Some(&"shared-state"));
    let establishment_entries = session.state().len();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(1), session.forward_next())
            .await
            .unwrap()
            .unwrap(),
        pg_proto::ForwardedMessage::Backend(BackendMessage::ParameterStatus { name, value })
            if name == "TimeZone" && value == "UTC"
    ));
    assert_eq!(
        &session.state()[establishment_entries..],
        ["client-backend", "boundary-backend", "server-backend"]
    );
    let traffic_entries = session.state().len();
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        FrontendMessage::Query(query) if query == "SELECT 1"
    ));
    assert!(matches!(
        session.forward_frontend().await,
        Err(pg_proto::ForwardError::Frontend(
            pg_proto::FrontendProjectionError::Capacity(_)
        ))
    ));
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        BackendMessage::CommandComplete(tag) if tag == "SELECT 1"
    ));
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        BackendMessage::ReadyForQuery(_)
    ));
    assert!(
        matches!(session.forward_frontend().await.unwrap(), FrontendMessage::Query(query) if query == "SELECT 2")
    );
    assert!(
        matches!(session.forward_backend().await.unwrap(), BackendMessage::CommandComplete(tag) if tag == "SELECT 2")
    );
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        BackendMessage::ReadyForQuery(_)
    ));
    for (frontend, backend) in [(b'P', b'1'), (b'B', b'2'), (b'E', b'C'), (b'S', b'Z')] {
        assert_eq!(
            frontend_bytes(&session.forward_frontend().await.unwrap())[0],
            frontend
        );
        assert_eq!(
            backend_bytes(&session.forward_backend().await.unwrap())[0],
            backend
        );
    }
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        FrontendMessage::Query(_)
    ));
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        BackendMessage::CopyBothResponse(_)
    ));
    assert!(
        matches!(session.forward_next().await.unwrap(), pg_proto::ForwardedMessage::Backend(BackendMessage::CopyData(data)) if data == "w-replication")
    );
    assert!(
        matches!(session.forward_next().await.unwrap(), pg_proto::ForwardedMessage::Frontend(FrontendMessage::CopyData(data)) if data == "r-standby-status")
    );
    let (_downstream, _upstream, state, _boundary, _handlers, contexts) = session.teardown();
    assert!(state[traffic_entries..].starts_with(&[
        "server-frontend",
        "boundary-frontend",
        "client-frontend",
        "server-frontend",
        "boundary-frontend",
        "client-frontend",
        "client-backend",
        "boundary-backend",
        "server-backend",
        "client-backend",
        "boundary-backend",
        "server-backend",
        "client-backend",
        "boundary-backend",
        "server-backend",
        "client-backend",
        "boundary-backend",
        "server-backend",
    ]));
    assert_eq!(contexts.server().peer(), "downstream-peer");
    assert_eq!(contexts.client().target().name(), "tenant-a");
    downstream.await.unwrap();
    upstream.await.unwrap();
}
