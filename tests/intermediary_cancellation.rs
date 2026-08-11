//! Cancellation mapping, forwarding, and conservative failure-policy coverage.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    convert::Infallible,
    fmt,
    rc::Rc,
};

use bytes::Bytes;
use pg_proto::{
    CancelKey, CancellationPolicy, CancellationRoute, Client, ClientTlsPolicy, ConnectTarget,
    EstablishmentFailurePolicy, InitialServerContext, Intermediary, IntermediaryAccept,
    IntermediaryCancellationRegistry, PreStartupMessage, Server, ServerConnectionContext,
    ServerMiddleware, ServerTlsPolicy, StartupParameters, StartupRouteResolver,
    TrustClientAuthentication, TrustServerAuthentication,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone, Debug)]
struct Registry(Rc<RefCell<HashMap<CancelKey, CancellationRoute>>>);

#[derive(Debug)]
struct Collision;
impl fmt::Display for Collision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cancellation key collision")
    }
}
impl std::error::Error for Collision {}

impl IntermediaryCancellationRegistry for Registry {
    type Error = Collision;
    fn register(&self, route: CancellationRoute) -> Result<CancelKey, Self::Error> {
        let client = CancelKey {
            process_id: 91,
            secret_key: Bytes::from_static(b"proxy-key"),
        };
        let mut routes = self.0.borrow_mut();
        if routes.contains_key(&client) {
            return Err(Collision);
        }
        routes.insert(client.clone(), route);
        Ok(client)
    }
    fn resolve(&self, client: &CancelKey) -> Option<CancellationRoute> {
        self.0.borrow().get(client).cloned()
    }
    fn detach(&self, client: &CancelKey) -> Option<CancellationRoute> {
        self.0.borrow_mut().remove(client)
    }
}

#[derive(Clone)]
struct Resolver(Rc<RefCell<usize>>);
impl StartupRouteResolver<&'static str> for Resolver {
    type Error = Infallible;
    async fn resolve(
        &self,
        _: StartupParameters,
        _: InitialServerContext<'_, &'static str>,
    ) -> Result<ConnectTarget, Self::Error> {
        *self.0.borrow_mut() += 1;
        Ok(ConnectTarget::new("db").with_metadata("tenant", "a"))
    }
}

struct FixedResolver;
impl StartupRouteResolver<()> for FixedResolver {
    type Error = Infallible;
    async fn resolve(
        &self,
        _: StartupParameters,
        _: InitialServerContext<'_, ()>,
    ) -> Result<ConnectTarget, Self::Error> {
        Ok(ConnectTarget::new("hidden-address"))
    }
}

#[derive(Clone)]
struct ObserveCancel(Rc<RefCell<Vec<&'static str>>>);
impl
    ServerMiddleware<
        Vec<&'static str>,
        ServerConnectionContext<&'static str, pg_proto::TrustIdentity>,
    > for ObserveCancel
{
    fn pre_startup(
        &mut self,
        _: &ServerConnectionContext<&'static str, pg_proto::TrustIdentity>,
        state: &mut Vec<&'static str>,
        message: PreStartupMessage,
    ) -> PreStartupMessage {
        state.push("pre-startup");
        self.0.borrow_mut().push("pre-startup");
        message
    }
    fn cancellation(
        &mut self,
        _: &ServerConnectionContext<&'static str, pg_proto::TrustIdentity>,
        state: &mut Vec<&'static str>,
        request: pg_proto::CancellationRequest,
    ) -> pg_proto::CancellationRequest {
        state.push("cancellation");
        self.0.borrow_mut().push("cancellation");
        request
    }
}

#[derive(Clone, Copy)]
struct RewriteObservedKey;
impl pg_proto::ClientMiddleware<Vec<&'static str>, pg_proto::ClientConnectionContext<()>>
    for RewriteObservedKey
{
    fn backend(
        &mut self,
        _: &pg_proto::ClientConnectionContext<()>,
        _: &mut Vec<&'static str>,
        message: pg_proto::BackendMessage,
    ) -> pg_proto::BackendMessage {
        if matches!(message, pg_proto::BackendMessage::BackendKeyData { .. }) {
            pg_proto::BackendMessage::BackendKeyData {
                process_id: 999,
                secret_key: Bytes::from_static(b"middleware-key"),
            }
        } else {
            message
        }
    }
}

fn cancel_packet(key: &CancelKey) -> Bytes {
    PreStartupMessage::CancelRequest {
        process_id: key.process_id,
        secret_key: key.secret_key.clone(),
    }
    .to_packet()
    .unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn records_rewrites_resolves_without_routing_and_detaches() {
    let (downstream_io, mut downstream) = tokio::io::duplex(4096);
    let (upstream_io, mut upstream) = tokio::io::duplex(4096);
    let (cancel_io, mut cancel_upstream) = tokio::io::duplex(4096);
    let transports = Rc::new(RefCell::new(VecDeque::from([upstream_io, cancel_io])));
    let resolver_calls = Rc::new(RefCell::new(0));
    let observed = Rc::new(RefCell::new(Vec::new()));
    let registry = Registry(Rc::new(RefCell::new(HashMap::new())));

    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .middleware({
            let observed = observed.clone();
            move |_: &ServerConnectionContext<&'static str, pg_proto::TrustIdentity>| {
                ObserveCancel(observed.clone())
            }
        })
        .build()
        .unwrap();
    let client = Client::builder()
        .connector({
            let transports = transports.clone();
            move |_| {
                let transport = transports.borrow_mut().pop_front().unwrap();
                async move { Ok::<_, Infallible>(transport) }
            }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .middleware(|_: &pg_proto::ClientInitialContext| RewriteObservedKey)
        .build()
        .unwrap();
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Resolver(resolver_calls.clone()))
        .cancellation_registry(registry.clone())
        .build()
        .unwrap();

    let downstream_task = tokio::spawn(async move {
        downstream
            .write_all(
                &pg_proto::StartupMessage {
                    version: pg_proto::ProtocolVersion::V3_2,
                    parameters: std::iter::once((
                        Bytes::from_static(b"user"),
                        Bytes::from_static(b"alice"),
                    ))
                    .collect(),
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(downstream.read_u8().await.unwrap(), b'R');
        assert_eq!(downstream.read_u32().await.unwrap(), 8);
        assert_eq!(downstream.read_u32().await.unwrap(), 0);
        let tag = downstream.read_u8().await.unwrap();
        assert_eq!(tag, b'K');
        assert_eq!(downstream.read_u32().await.unwrap(), 17);
        let process = downstream.read_u32().await.unwrap();
        let mut secret = [0; 9];
        downstream.read_exact(&mut secret).await.unwrap();
        assert_eq!(downstream.read_u8().await.unwrap(), b'Z');
        assert_eq!(downstream.read_u32().await.unwrap(), 5);
        assert_eq!(downstream.read_u8().await.unwrap(), b'I');
        CancelKey {
            process_id: process,
            secret_key: Bytes::copy_from_slice(&secret),
        }
    });
    let upstream_task = tokio::spawn(async move {
        let length = upstream.read_u32().await.unwrap();
        let mut startup = vec![0; length as usize - 4];
        upstream.read_exact(&mut startup).await.unwrap();
        upstream
            .write_all(&[
                b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'K', 0, 0, 0, 16, 0, 0, 0, 7, b'u', b'p', b's',
                b't', b'r', b'e', b'a', b'm', b'Z', 0, 0, 0, 5, b'I',
            ])
            .await
            .unwrap();
    });
    let accepted = Box::pin(intermediary.accept(downstream_io, "peer", Vec::new()))
        .await
        .unwrap();
    let session = accepted.into_session();
    let proxy_key = downstream_task.await.unwrap();
    upstream_task.await.unwrap();
    assert_eq!(session.cancellation_key(), Some(&proxy_key));
    assert_eq!(*resolver_calls.borrow(), 1);
    assert_eq!(
        registry
            .resolve(&proxy_key)
            .unwrap()
            .target()
            .metadata()
            .get("tenant")
            .unwrap(),
        "a"
    );
    let original_route = registry.resolve(&proxy_key).unwrap();
    assert!(registry.register(original_route.clone()).is_err());
    assert_eq!(registry.resolve(&proxy_key), Some(original_route));

    let (cancel_downstream_io, mut cancel_downstream) = tokio::io::duplex(256);
    cancel_downstream
        .write_all(&cancel_packet(&proxy_key))
        .await
        .unwrap();
    let outcome = Box::pin(intermediary.accept(cancel_downstream_io, "cancel-peer", Vec::new()))
        .await
        .unwrap();
    assert!(matches!(outcome, IntermediaryAccept::CancellationForwarded));
    let mut forwarded = vec![0; 12 + 8];
    cancel_upstream.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(&forwarded[8..12], &7_u32.to_be_bytes());
    assert_eq!(&forwarded[12..], b"upstream");
    assert_eq!(
        *resolver_calls.borrow(),
        1,
        "cancellation bypasses startup routing"
    );
    assert_eq!(
        &*observed.borrow(),
        &["pre-startup", "pre-startup", "cancellation"]
    );
    let _ = session.teardown();
    assert!(registry.resolve(&proxy_key).is_none());

    let (unknown_io, mut unknown_peer) = tokio::io::duplex(256);
    unknown_peer
        .write_all(&cancel_packet(&proxy_key))
        .await
        .unwrap();
    let Err(error) = Box::pin(intermediary.accept(unknown_io, "unknown-peer", Vec::new())).await
    else {
        panic!("detached cancellation key must be rejected");
    };
    assert!(matches!(
        error,
        pg_proto::IntermediaryAcceptError::CancellationRejected
    ));
    assert_eq!(*resolver_calls.borrow(), 1);
}

#[test]
fn conservative_failure_and_rejection_are_explicit() {
    assert_eq!(
        EstablishmentFailurePolicy::default(),
        EstablishmentFailurePolicy::Close
    );
    assert_eq!(CancellationPolicy::Reject, CancellationPolicy::Reject);
    assert_eq!(
        Intermediary::builder()
            .server(())
            .client(())
            .startup_resolver(())
            .cancellation(CancellationPolicy::Forward)
            .build()
            .unwrap_err(),
        pg_proto::IntermediaryBuildError::MissingCancellationPolicy,
    );
}

#[derive(Debug)]
struct SecretError;
impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("password target key material")
    }
}
impl std::error::Error for SecretError {}

#[test]
fn every_public_establishment_error_layer_has_a_safe_summary() {
    type Error = pg_proto::IntermediaryAcceptError<
        SecretError,
        SecretError,
        SecretError,
        SecretError,
        SecretError,
        SecretError,
    >;
    let errors = [
        Error::Server(SecretError),
        Error::StartupRoute(pg_proto::StartupResolutionError::Resolver(SecretError)),
        Error::CancellationRejected,
        Error::AuthenticatedRoute(SecretError),
        Error::Client(SecretError),
        Error::CancellationRegistry(SecretError),
        Error::ServerOutput(std::io::Error::other("password target key material")),
        Error::Cancellation(SecretError),
    ];
    for error in errors {
        assert!(!error.to_string().contains("password"));
        assert!(!format!("{error:?}").contains("password"));
    }
}

#[derive(Clone)]
struct CountDiagnostic(Rc<RefCell<usize>>);
impl ServerMiddleware<(), ServerConnectionContext<(), pg_proto::TrustIdentity>>
    for CountDiagnostic
{
    fn backend(
        &mut self,
        _: &ServerConnectionContext<(), pg_proto::TrustIdentity>,
        (): &mut (),
        message: pg_proto::BackendMessage,
    ) -> pg_proto::BackendMessage {
        if matches!(message, pg_proto::BackendMessage::ErrorResponse(_)) {
            *self.0.borrow_mut() += 1;
        }
        message
    }
}

#[tokio::test]
async fn safe_diagnostic_is_fixed_redacted_and_intercepted_once() {
    let (server_io, mut peer) = tokio::io::duplex(1024);
    let count = Rc::new(RefCell::new(0));
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .middleware({
            let count = count.clone();
            move |_: &ServerConnectionContext<(), pg_proto::TrustIdentity>| {
                CountDiagnostic(count.clone())
            }
        })
        .build()
        .unwrap();
    let client = Client::builder()
        .connector(|_| async { Err::<tokio::io::DuplexStream, _>("secret-address credential") })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(FixedResolver)
        .cancellation(CancellationPolicy::Reject)
        .establishment_failure(EstablishmentFailurePolicy::SafeDiagnostic)
        .build()
        .unwrap();
    peer.write_all(
        &pg_proto::StartupMessage {
            version: pg_proto::ProtocolVersion::V3_2,
            parameters: std::iter::once((
                Bytes::from_static(b"user"),
                Bytes::from_static(b"alice"),
            ))
            .collect(),
        }
        .encode()
        .unwrap(),
    )
    .await
    .unwrap();
    let Err(error) = Box::pin(intermediary.accept(server_io, (), ())).await else {
        panic!("connector must fail");
    };
    let debug = format!("{error:?}");
    assert!(debug.contains("Client([REDACTED])"));
    assert!(!debug.contains("secret-address"));
    assert!(!debug.contains("hidden-address"));
    let mut wire = Vec::new();
    peer.read_to_end(&mut wire).await.unwrap();
    assert!(
        wire.windows(b"connection establishment failed".len())
            .any(|window| window == b"connection establishment failed")
    );
    assert!(
        !wire
            .windows(b"secret-address".len())
            .any(|window| window == b"secret-address")
    );
    assert_eq!(*count.borrow(), 1);
}
