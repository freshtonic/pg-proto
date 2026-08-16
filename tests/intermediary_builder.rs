//! Behavioural coverage for the operational intermediary facade.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    AuthenticatedRouteContext, AuthenticatedRoutePolicy, BackendMessage, Bind, BoundedPipeline,
    CancellationPolicy, Client, ClientConnectionContext, ClientInitialContext, ClientMiddleware,
    ClientTlsPolicy, ConnectTarget, CopyResponse, Execute, FrontendMessage, InitialServerContext,
    Intermediary, IntermediaryAcceptError, IntermediaryBuildError, IntermediaryMiddleware,
    OperationId, Parse, ProtocolVersion, Server, ServerConnectionContext, ServerMiddleware,
    ServerTlsPolicy, StartupMessage, StartupParameters, StartupResolutionError,
    StartupRouteResolver, TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct CandidateResolver;
impl StartupRouteResolver<String> for CandidateResolver {
    type Error = Infallible;
    async fn resolve(
        &self,
        startup: StartupParameters,
        initial: InitialServerContext<'_, String>,
    ) -> Result<ConnectTarget, Self::Error> {
        assert_eq!(initial.peer(), "downstream-peer");
        assert_eq!(startup.user(), Some("alice"));
        Ok(ConnectTarget::new("candidate"))
    }
}

struct RefineRoute;
impl AuthenticatedRoutePolicy<String, TrustIdentity> for RefineRoute {
    type Error = Infallible;
    async fn route(
        &self,
        target: ConnectTarget,
        context: AuthenticatedRouteContext<'_, String, TrustIdentity>,
    ) -> Result<ConnectTarget, Self::Error> {
        assert_eq!(target.name(), "candidate");
        assert_eq!(context.peer(), "downstream-peer");
        assert_eq!(context.identity(), &TrustIdentity);
        Ok(ConnectTarget::new("tenant-a"))
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
        BackendMessage::DataRow(row) => {
            let mut body = u16::try_from(row.columns.len())
                .unwrap()
                .to_be_bytes()
                .to_vec();
            for column in &row.columns {
                match column {
                    None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
                    Some(value) => {
                        body.extend_from_slice(&i32::try_from(value.len()).unwrap().to_be_bytes());
                        body.extend_from_slice(value);
                    }
                }
            }
            (b'D', body)
        }
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

#[derive(Default)]
struct BoundaryOrder {
    frontend_operations: Vec<OperationId>,
    backend_operations: Vec<Option<OperationId>>,
}
impl
    IntermediaryMiddleware<
        Vec<&'static str>,
        ServerConnectionContext<String, TrustIdentity>,
        ClientConnectionContext<()>,
    > for BoundaryOrder
{
    type Error = Infallible;

    async fn frontend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        message: FrontendMessage,
    ) -> Result<pg_proto::FrontendMiddlewareOutput, Self::Error> {
        tokio::task::yield_now().await;
        state.push("boundary-frontend");
        Ok(pg_proto::FrontendMiddlewareOutput::Forward(message))
    }

    async fn frontend_operation(
        &mut self,
        server: &ServerConnectionContext<String, TrustIdentity>,
        client: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        operation: OperationId,
        message: FrontendMessage,
    ) -> Result<pg_proto::FrontendMiddlewareOutput, Self::Error> {
        self.frontend_operations.push(operation);
        self.frontend(server, client, state, message).await
    }

    async fn backend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        message: BackendMessage,
    ) -> Result<pg_proto::BackendMiddlewareOutput, Self::Error> {
        tokio::task::yield_now().await;
        state.push("boundary-backend");
        Ok(pg_proto::BackendMiddlewareOutput::Forward(message))
    }

    async fn backend_operation(
        &mut self,
        server: &ServerConnectionContext<String, TrustIdentity>,
        client: &ClientConnectionContext<()>,
        state: &mut Vec<&'static str>,
        operation: Option<OperationId>,
        message: BackendMessage,
    ) -> Result<pg_proto::BackendMiddlewareOutput, Self::Error> {
        self.backend_operations.push(operation);
        self.backend(server, client, state, message).await
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
async fn intermediary_rejects_non_utf8_startup_parameters_without_panicking() {
    for (parameters, expected) in [
        (
            std::iter::once((Bytes::from_static(b"\xff"), Bytes::from_static(b"value"))).collect(),
            "startup parameter name is not UTF-8",
        ),
        (
            std::iter::once((Bytes::from_static(b"user"), Bytes::from_static(b"\xff"))).collect(),
            "startup parameter value is not UTF-8",
        ),
    ] {
        let (mut downstream_peer, downstream_transport) = tokio::io::duplex(256);
        let (upstream_transport, _upstream_peer) = tokio::io::duplex(256);
        let upstream_transport = std::sync::Mutex::new(Some(upstream_transport));
        let server = Server::builder()
            .tls(ServerTlsPolicy::Disabled)
            .authentication(TrustServerAuthentication)
            .build()
            .unwrap();
        let client = Client::builder()
            .connector(move |_| {
                let transport = upstream_transport.lock().unwrap().take().unwrap();
                async move { Ok::<_, Infallible>(transport) }
            })
            .tls(ClientTlsPolicy::Disabled)
            .authentication(TrustClientAuthentication)
            .build()
            .unwrap();
        let intermediary = Intermediary::builder()
            .server(server)
            .client(client)
            .startup_resolver(CandidateResolver)
            .cancellation(CancellationPolicy::Reject)
            .build()
            .unwrap();
        downstream_peer
            .write_all(
                &StartupMessage {
                    version: ProtocolVersion::V3_2,
                    parameters,
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();

        let result =
            Box::pin(intermediary.accept(downstream_transport, "downstream-peer".to_owned(), ()))
                .await;
        let error = match result {
            Err(IntermediaryAcceptError::StartupRoute(StartupResolutionError::Parameters(
                error,
            ))) => error,
            Err(error) => panic!("unexpected establishment error: {error:?}"),
            Ok(_) => panic!("invalid UTF-8 startup was accepted"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), expected);
    }
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
                BoundaryOrder::default()
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
        pg_proto::FrontendForwarding::Forwarded(FrontendMessage::Query(query)) if query == "SELECT 1"
    ));
    assert!(matches!(
        session.forward_frontend().await,
        Err(pg_proto::ForwardError::Frontend(
            pg_proto::FrontendProjectionError::Capacity(_)
        ))
    ));
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        pg_proto::BackendForwarding::Forwarded(BackendMessage::CommandComplete(tag)) if tag == "SELECT 1"
    ));
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        pg_proto::BackendForwarding::Forwarded(BackendMessage::ReadyForQuery(_))
    ));
    assert!(
        matches!(session.forward_frontend().await.unwrap(), pg_proto::FrontendForwarding::Forwarded(FrontendMessage::Query(query)) if query == "SELECT 2")
    );
    assert!(
        matches!(session.forward_backend().await.unwrap(), pg_proto::BackendForwarding::Forwarded(BackendMessage::CommandComplete(tag)) if tag == "SELECT 2")
    );
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        pg_proto::BackendForwarding::Forwarded(BackendMessage::ReadyForQuery(_))
    ));
    for (frontend, backend) in [(b'P', b'1'), (b'B', b'2'), (b'E', b'C'), (b'S', b'Z')] {
        assert_eq!(
            frontend_bytes(&session.forward_frontend().await.unwrap().into_message())[0],
            frontend
        );
        assert_eq!(
            backend_bytes(&session.forward_backend().await.unwrap().into_message())[0],
            backend
        );
    }
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::Forwarded(FrontendMessage::Query(_))
    ));
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        pg_proto::BackendForwarding::Forwarded(BackendMessage::CopyBothResponse(_))
    ));
    assert!(
        matches!(session.forward_next().await.unwrap(), pg_proto::ForwardedMessage::Backend(BackendMessage::CopyData(data)) if data == "w-replication")
    );
    assert!(
        matches!(session.forward_next().await.unwrap(), pg_proto::ForwardedMessage::Frontend(FrontendMessage::CopyData(data)) if data == "r-standby-status")
    );
    let (_downstream, _upstream, state, boundary, _handlers, contexts) = session.teardown();
    let backend_operations: Vec<_> = boundary
        .backend_operations
        .iter()
        .copied()
        .flatten()
        .collect();
    assert!(boundary.backend_operations.iter().any(Option::is_none));
    assert_eq!(boundary.frontend_operations[0], backend_operations[0]);
    assert_eq!(boundary.frontend_operations[0], backend_operations[1]);
    assert_eq!(boundary.frontend_operations[1], backend_operations[2]);
    assert_eq!(boundary.frontend_operations[1], backend_operations[3]);
    assert!(
        state[traffic_entries..].starts_with(&[
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
        ]),
        "traffic order: {:?}",
        &state[traffic_entries..]
    );
    assert_eq!(contexts.server().peer(), "downstream-peer");
    assert_eq!(contexts.client().target().name(), "tenant-a");
    downstream.await.unwrap();
    upstream.await.unwrap();
}

#[derive(Debug, Eq, PartialEq)]
struct BoundaryFailure;

impl std::fmt::Display for BoundaryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("boundary failure")
    }
}

impl std::error::Error for BoundaryFailure {}

struct AsyncDecisions;

impl
    IntermediaryMiddleware<
        (),
        ServerConnectionContext<String, TrustIdentity>,
        ClientConnectionContext<()>,
    > for AsyncDecisions
{
    type Error = BoundaryFailure;

    async fn frontend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        (): &mut (),
        message: FrontendMessage,
    ) -> Result<pg_proto::FrontendMiddlewareOutput, Self::Error> {
        tokio::task::yield_now().await;
        match &message {
            FrontendMessage::Query(query) if query == "LOCAL" => {
                Ok(pg_proto::FrontendMiddlewareOutput::Respond {
                    request: message,
                    responses: vec![
                        BackendMessage::CommandComplete(Bytes::from_static(b"LOCAL")),
                        BackendMessage::ReadyForQuery(pg_proto::TransactionStatus::Idle),
                    ],
                })
            }
            FrontendMessage::Query(query) if query == "DROP" => {
                Ok(pg_proto::FrontendMiddlewareOutput::Suppress(message))
            }
            FrontendMessage::Query(query) if query == "FAIL" => Err(BoundaryFailure),
            _ => Ok(pg_proto::FrontendMiddlewareOutput::Forward(message)),
        }
    }

    async fn backend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        (): &mut (),
        message: BackendMessage,
    ) -> Result<pg_proto::BackendMiddlewareOutput, Self::Error> {
        tokio::task::yield_now().await;
        match message {
            BackendMessage::DataRow(_) => Ok(pg_proto::BackendMiddlewareOutput::Expand(vec![
                BackendMessage::DataRow(pg_proto::DataRow {
                    columns: vec![Some(Bytes::from_static(b"clear-one"))],
                }),
                BackendMessage::DataRow(pg_proto::DataRow {
                    columns: vec![Some(Bytes::from_static(b"clear-two"))],
                }),
            ])),
            other => Ok(pg_proto::BackendMiddlewareOutput::Forward(other)),
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn async_middleware_supports_suppression_local_responses_and_backend_fanout() {
    let (downstream_transport, mut downstream_peer) = tokio::io::duplex(16 * 1024);
    let (upstream_transport, mut upstream_peer) = tokio::io::duplex(16 * 1024);
    let upstream_transport = std::sync::Mutex::new(Some(upstream_transport));

    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let client = Client::builder()
        .connector(move |_| {
            let transport = upstream_transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, Infallible>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(CandidateResolver)
        .authenticated_route(RefineRoute)
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(2).unwrap())
        .middleware(
            |_: &ServerConnectionContext<String, TrustIdentity>,
             _: &ClientConnectionContext<()>| AsyncDecisions,
        )
        .build()
        .unwrap();

    let downstream = tokio::spawn(async move {
        let startup = pg_proto::StartupMessage {
            version: pg_proto::ProtocolVersion::V3_0,
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
        for query in [b"FIRST".as_slice(), b"LOCAL", b"DROP", b"FAIL"] {
            downstream_peer
                .write_all(&frontend_bytes(&FrontendMessage::Query(
                    Bytes::copy_from_slice(query),
                )))
                .await
                .unwrap();
        }
        for cleartext in [b"clear-one".as_slice(), b"clear-two"] {
            let (tag, body) = read_tagged(&mut downstream_peer).await;
            assert_eq!(tag, b'D');
            assert_eq!(&body[6..], cleartext);
        }
        for expected in [b"FIRST\0".as_slice(), b"LOCAL\0"] {
            let (tag, body) = read_tagged(&mut downstream_peer).await;
            assert_eq!((tag, body.as_slice()), (b'C', expected));
            assert_eq!(read_tagged(&mut downstream_peer).await.0, b'Z');
        }
    });
    let upstream = tokio::spawn(async move {
        let length = upstream_peer.read_u32().await.unwrap();
        let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
        upstream_peer.read_exact(&mut startup).await.unwrap();
        upstream_peer
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
            .await
            .unwrap();
        let (tag, body) = read_tagged(&mut upstream_peer).await;
        assert_eq!((tag, body.as_slice()), (b'Q', b"FIRST\0".as_slice()));
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::DataRow(
                pg_proto::DataRow {
                    columns: vec![Some(Bytes::from_static(b"encrypted-batch"))],
                },
            )))
            .await
            .unwrap();
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::CommandComplete(
                Bytes::from_static(b"FIRST"),
            )))
            .await
            .unwrap();
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::ReadyForQuery(
                pg_proto::TransactionStatus::Idle,
            )))
            .await
            .unwrap();
        let unexpected = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            upstream_peer.read_u8(),
        )
        .await;
        assert!(!matches!(unexpected, Ok(Ok(_))));
    });

    let mut session =
        Box::pin(intermediary.accept(downstream_transport, "downstream-peer".to_owned(), ()))
            .await
            .unwrap()
            .into_session();
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::Forwarded(FrontendMessage::Query(query)) if query == "FIRST"
    ));
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::LocallyHandled(FrontendMessage::Query(query)) if query == "LOCAL"
    ));
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        pg_proto::BackendForwarding::Expanded { messages, .. } if messages.len() == 2
    ));
    session.forward_backend().await.unwrap();
    session.forward_backend().await.unwrap();
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::Suppressed(FrontendMessage::Query(query)) if query == "DROP"
    ));
    assert!(matches!(
        session.forward_frontend().await,
        Err(pg_proto::ForwardError::Middleware(BoundaryFailure))
    ));
    let _ = session.teardown();
    downstream.await.unwrap();
    upstream.await.unwrap();
}

struct RejectParseLocally;

impl
    IntermediaryMiddleware<
        (),
        ServerConnectionContext<String, TrustIdentity>,
        ClientConnectionContext<()>,
    > for RejectParseLocally
{
    type Error = Infallible;

    async fn frontend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        (): &mut (),
        message: FrontendMessage,
    ) -> Result<pg_proto::FrontendMiddlewareOutput, Self::Error> {
        if matches!(&message, FrontendMessage::Parse(parse) if parse.query == "LOCAL ERROR") {
            return Ok(pg_proto::FrontendMiddlewareOutput::Respond {
                request: message,
                responses: vec![BackendMessage::ErrorResponse(
                    pg_proto::DiagnosticResponse { fields: vec![] },
                )],
            });
        }
        Ok(pg_proto::FrontendMiddlewareOutput::Forward(message))
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn local_extended_error_discards_messages_until_sync_and_reuses_connection() {
    let (downstream_transport, mut downstream_peer) = tokio::io::duplex(16 * 1024);
    let (upstream_transport, mut upstream_peer) = tokio::io::duplex(16 * 1024);
    let upstream_transport = std::sync::Mutex::new(Some(upstream_transport));

    let intermediary = Intermediary::builder()
        .server(
            Server::builder()
                .tls(ServerTlsPolicy::Disabled)
                .authentication(TrustServerAuthentication)
                .build()
                .unwrap(),
        )
        .client(
            Client::builder()
                .connector(move |_| {
                    let transport = upstream_transport.lock().unwrap().take().unwrap();
                    async move { Ok::<_, Infallible>(transport) }
                })
                .tls(ClientTlsPolicy::Disabled)
                .authentication(TrustClientAuthentication)
                .build()
                .unwrap(),
        )
        .startup_resolver(CandidateResolver)
        .authenticated_route(RefineRoute)
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(8).unwrap())
        .middleware(
            |_: &ServerConnectionContext<String, TrustIdentity>,
             _: &ClientConnectionContext<()>| RejectParseLocally,
        )
        .build()
        .unwrap();

    let downstream = tokio::spawn(async move {
        let startup = pg_proto::StartupMessage {
            version: pg_proto::ProtocolVersion::V3_0,
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

        for message in [
            FrontendMessage::Query(Bytes::from_static(b"BEFORE")),
            FrontendMessage::Parse(Parse {
                statement: Bytes::from_static(b"s1"),
                query: Bytes::from_static(b"LOCAL ERROR"),
                parameter_types: vec![],
            }),
            FrontendMessage::Bind(Bind {
                portal: Bytes::new(),
                statement: Bytes::from_static(b"s1"),
                parameter_formats: vec![],
                parameters: vec![],
                result_formats: vec![],
            }),
            FrontendMessage::Execute(Execute {
                portal: Bytes::new(),
                max_rows: 0,
            }),
            FrontendMessage::Sync,
        ] {
            downstream_peer
                .write_all(&frontend_bytes(&message))
                .await
                .unwrap();
        }
        for expected in *b"CZEZ" {
            assert_eq!(read_tagged(&mut downstream_peer).await.0, expected);
        }

        downstream_peer
            .write_all(&frontend_bytes(&FrontendMessage::Query(
                Bytes::from_static(b"AFTER"),
            )))
            .await
            .unwrap();
        assert_eq!(read_tagged(&mut downstream_peer).await.0, b'C');
        assert_eq!(read_tagged(&mut downstream_peer).await.0, b'Z');
    });

    let upstream = tokio::spawn(async move {
        let length = upstream_peer.read_u32().await.unwrap();
        let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
        upstream_peer.read_exact(&mut startup).await.unwrap();
        upstream_peer
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
            .await
            .unwrap();

        let (tag, body) = read_tagged(&mut upstream_peer).await;
        assert_eq!((tag, body.as_slice()), (b'Q', b"BEFORE\0".as_slice()));
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::CommandComplete(
                Bytes::from_static(b"BEFORE"),
            )))
            .await
            .unwrap();
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::ReadyForQuery(
                pg_proto::TransactionStatus::Idle,
            )))
            .await
            .unwrap();
        assert_eq!(read_tagged(&mut upstream_peer).await.0, b'S');
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::ReadyForQuery(
                pg_proto::TransactionStatus::Idle,
            )))
            .await
            .unwrap();
        let (tag, body) = read_tagged(&mut upstream_peer).await;
        assert_eq!((tag, body.as_slice()), (b'Q', b"AFTER\0".as_slice()));
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::CommandComplete(
                Bytes::from_static(b"AFTER"),
            )))
            .await
            .unwrap();
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::ReadyForQuery(
                pg_proto::TransactionStatus::Idle,
            )))
            .await
            .unwrap();
    });

    let mut session =
        Box::pin(intermediary.accept(downstream_transport, "downstream-peer".to_owned(), ()))
            .await
            .unwrap()
            .into_session();
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::Forwarded(FrontendMessage::Query(query)) if query == "BEFORE"
    ));
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::LocallyHandled(FrontendMessage::Parse(_))
    ));
    for _ in 0..2 {
        assert!(matches!(
            session.forward_frontend().await.unwrap(),
            pg_proto::FrontendForwarding::Suppressed(_)
        ));
    }
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::Forwarded(FrontendMessage::Sync)
    ));
    session.forward_backend().await.unwrap();
    session.forward_backend().await.unwrap();
    session.forward_backend().await.unwrap();
    assert!(matches!(
        session.forward_frontend().await.unwrap(),
        pg_proto::FrontendForwarding::Forwarded(FrontendMessage::Query(query)) if query == "AFTER"
    ));
    session.forward_backend().await.unwrap();
    session.forward_backend().await.unwrap();
    let _ = session.teardown();
    downstream.await.unwrap();
    upstream.await.unwrap();
}

#[derive(Default)]
struct OrderedBatch;

impl
    IntermediaryMiddleware<
        usize,
        ServerConnectionContext<String, TrustIdentity>,
        ClientConnectionContext<()>,
    > for OrderedBatch
{
    type Error = Infallible;

    async fn backend(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        _: &mut usize,
        message: BackendMessage,
    ) -> Result<pg_proto::BackendMiddlewareOutput, Self::Error> {
        if matches!(message, BackendMessage::DataRow(_)) {
            Ok(pg_proto::BackendMiddlewareOutput::Hold)
        } else {
            Ok(pg_proto::BackendMiddlewareOutput::Forward(message))
        }
    }

    async fn flush_backend_operations(
        &mut self,
        _: &ServerConnectionContext<String, TrustIdentity>,
        _: &ClientConnectionContext<()>,
        flushes: &mut usize,
        held: pg_proto::AttributedBackendMessages<'_>,
        reason: pg_proto::BackendFlushReason,
    ) -> Result<pg_proto::BackendBatchOutput, Self::Error> {
        assert_eq!(reason, pg_proto::BackendFlushReason::ProtocolBarrier);
        *flushes += 1;
        let operation_ids: Vec<_> = held.iter().map(|(operation, _)| operation).collect();
        assert!(operation_ids.iter().all(Option::is_some));
        assert!(operation_ids.windows(2).all(|ids| ids[0] == ids[1]));
        let replacements = held
            .messages()
            .iter()
            .map(|message| {
                let BackendMessage::DataRow(row) = message else {
                    panic!("batch contains a non-row")
                };
                let value = row.columns[0].as_ref().unwrap();
                let mut clear = b"clear-".to_vec();
                clear.extend_from_slice(value);
                BackendMessage::DataRow(pg_proto::DataRow {
                    columns: vec![Some(Bytes::from(clear))],
                })
            })
            .collect();
        Ok(pg_proto::BackendBatchOutput::ReplaceOneToOne(replacements))
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn held_rows_are_released_once_in_order_before_the_protocol_barrier() {
    let (downstream_transport, mut downstream_peer) = tokio::io::duplex(16 * 1024);
    let (upstream_transport, mut upstream_peer) = tokio::io::duplex(16 * 1024);
    let upstream_transport = std::sync::Mutex::new(Some(upstream_transport));
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let client = Client::builder()
        .connector(move |_| {
            let transport = upstream_transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, Infallible>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
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
            |_: &ServerConnectionContext<String, TrustIdentity>,
             _: &ClientConnectionContext<()>| OrderedBatch,
        )
        .backend_batching(pg_proto::BackendHoldLimits::new(8, 4096).unwrap())
        .build()
        .unwrap();

    let downstream = tokio::spawn(async move {
        let startup = pg_proto::StartupMessage {
            version: pg_proto::ProtocolVersion::V3_0,
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
        downstream_peer
            .write_all(&frontend_bytes(&FrontendMessage::Query(
                Bytes::from_static(b"SELECT"),
            )))
            .await
            .unwrap();
        for expected in [b"clear-one".as_slice(), b"clear-two", b"clear-three"] {
            let (tag, body) = read_tagged(&mut downstream_peer).await;
            assert_eq!(tag, b'D');
            assert_eq!(&body[6..], expected);
        }
        assert_eq!(read_tagged(&mut downstream_peer).await.0, b'C');
        assert_eq!(read_tagged(&mut downstream_peer).await.0, b'Z');
    });
    let upstream = tokio::spawn(async move {
        let length = upstream_peer.read_u32().await.unwrap();
        let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
        upstream_peer.read_exact(&mut startup).await.unwrap();
        upstream_peer
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
            .await
            .unwrap();
        assert_eq!(read_tagged(&mut upstream_peer).await.0, b'Q');
        for encrypted in [b"one".as_slice(), b"two", b"three"] {
            upstream_peer
                .write_all(&backend_bytes(&BackendMessage::DataRow(
                    pg_proto::DataRow {
                        columns: vec![Some(Bytes::copy_from_slice(encrypted))],
                    },
                )))
                .await
                .unwrap();
        }
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::CommandComplete(
                Bytes::from_static(b"SELECT 3"),
            )))
            .await
            .unwrap();
        upstream_peer
            .write_all(&backend_bytes(&BackendMessage::ReadyForQuery(
                pg_proto::TransactionStatus::Idle,
            )))
            .await
            .unwrap();
    });

    let mut session =
        Box::pin(intermediary.accept(downstream_transport, "downstream-peer".to_owned(), 0_usize))
            .await
            .unwrap()
            .into_session();
    session.forward_frontend().await.unwrap();
    for expected_len in 1..=3 {
        assert_eq!(
            session.forward_backend().await.unwrap(),
            pg_proto::BackendForwarding::Held
        );
        assert_eq!(session.held_backend_messages().len(), expected_len);
    }
    assert_eq!(*session.state(), 0);
    assert!(matches!(
        session.forward_backend().await.unwrap(),
        pg_proto::BackendForwarding::Forwarded(BackendMessage::CommandComplete(_))
    ));
    assert_eq!(*session.state(), 1);
    assert!(session.held_backend_messages().is_empty());
    session.forward_backend().await.unwrap();
    let _ = session.teardown();
    downstream.await.unwrap();
    upstream.await.unwrap();
}
