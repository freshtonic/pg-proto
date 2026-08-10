//! Builder-centred composition of the client-facing and PostgreSQL-facing roles.

use std::{collections::VecDeque, fmt, future::Future, io, pin::Pin};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    ConnectTarget, NoPipeline, StartupParameters,
    pipeline::{BackendAction, FrontendAction, FrontendHandling, Pipeline, PipelinePolicy},
};

fn is_backend_batch_barrier(message: &crate::codec::BackendMessage) -> bool {
    use crate::codec::BackendMessage as B;
    matches!(
        message,
        B::CommandComplete(_)
            | B::PortalSuspended
            | B::EmptyQueryResponse
            | B::ErrorResponse(_)
            | B::ReadyForQuery(_)
            | B::CopyInResponse(_)
            | B::CopyOutResponse(_)
            | B::CopyBothResponse(_)
            | B::CopyDone
            | B::NoticeResponse(_)
            | B::NotificationResponse { .. }
            | B::ParameterStatus { .. }
            | B::BackendKeyData { .. }
    )
}

/// Required posture for out-of-band cancellation connections.
///
/// Forwarding cancellation is implemented by issue #36. Until then the only
/// safe operational posture is an explicit rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationPolicy {
    /// Reject cancellation packets instead of silently routing them.
    Reject,
    /// Resolve and forward cancellation using the configured registry.
    Forward,
}

/// Disclosure-safe handling for failures after a downstream connection exists.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EstablishmentFailurePolicy {
    /// Silently close without exposing internal failure details.
    #[default]
    Close,
    /// Send one fixed, non-disclosing PostgreSQL diagnostic and then close.
    SafeDiagnostic,
}

fn safe_establishment_diagnostic() -> crate::codec::BackendMessage {
    crate::codec::BackendMessage::ErrorResponse(crate::codec::DiagnosticResponse {
        fields: vec![
            crate::codec::DiagnosticField {
                code: b'S',
                value: bytes::Bytes::from_static(b"ERROR"),
            },
            crate::codec::DiagnosticField {
                code: b'M',
                value: bytes::Bytes::from_static(b"connection establishment failed"),
            },
        ],
    })
}

/// A destination and upstream key retained independently of startup routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationRoute {
    target: ConnectTarget,
    upstream: crate::demux::CancelKey,
}

impl CancellationRoute {
    /// Creates a cancellation route.
    #[must_use]
    pub const fn new(target: ConnectTarget, upstream: crate::demux::CancelKey) -> Self {
        Self { target, upstream }
    }
    /// Returns the original destination, including application metadata.
    #[must_use]
    pub const fn target(&self) -> &ConnectTarget {
        &self.target
    }
    /// Returns the upstream cancellation key.
    #[must_use]
    pub const fn upstream_key(&self) -> &crate::demux::CancelKey {
        &self.upstream
    }
}

/// Application-owned concurrent cancellation mapping and key allocator.
///
/// Methods take `&self` so implementations can use an application-selected
/// lock, actor, shared store, or other concurrency mechanism. No global
/// `Send`, `Sync`, or `'static` requirement is imposed.
pub trait IntermediaryCancellationRegistry {
    /// Collision, allocation, or storage failure.
    type Error;
    /// Records a live route and returns the proxy key exposed downstream.
    ///
    /// # Errors
    ///
    /// Returns an application-defined allocation, collision, or storage error.
    fn register(&self, route: CancellationRoute) -> Result<crate::demux::CancelKey, Self::Error>;
    /// Resolves a later out-of-band request without consulting startup routing.
    fn resolve(&self, client: &crate::demux::CancelKey) -> Option<CancellationRoute>;
    /// Explicitly detaches a live client key.
    fn detach(&self, client: &crate::demux::CancelKey) -> Option<CancellationRoute>;
}

/// Marker registry used by explicit cancellation rejection.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectCancellation;
impl IntermediaryCancellationRegistry for RejectCancellation {
    type Error = std::convert::Infallible;
    fn register(&self, _: CancellationRoute) -> Result<crate::demux::CancelKey, Self::Error> {
        unreachable!()
    }
    fn resolve(&self, _: &crate::demux::CancelKey) -> Option<CancellationRoute> {
        None
    }
    fn detach(&self, _: &crate::demux::CancelKey) -> Option<CancellationRoute> {
        None
    }
}

/// Deterministic failure while assembling an intermediary component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntermediaryBuildError {
    /// No complete client-facing server role was supplied.
    MissingServer,
    /// No complete PostgreSQL-facing client role was supplied.
    MissingClient,
    /// No asynchronous startup resolver was supplied.
    MissingStartupResolver,
    /// Cancellation behavior was not selected explicitly.
    MissingCancellationPolicy,
}

impl fmt::Display for IntermediaryBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingServer => "an intermediary server component is required",
            Self::MissingClient => "an intermediary client component is required",
            Self::MissingStartupResolver => "an asynchronous startup resolver is required",
            Self::MissingCancellationPolicy => "an explicit cancellation policy is required",
        })
    }
}

impl std::error::Error for IntermediaryBuildError {}

/// Immutable server-side facts available before authentication begins.
#[derive(Clone, Copy, Debug)]
pub struct InitialServerContext<'a, Peer> {
    peer: &'a Peer,
    tls: &'a crate::NegotiatedServerTls,
}

impl<'a, Peer> InitialServerContext<'a, Peer> {
    pub(crate) const fn new(peer: &'a Peer, tls: &'a crate::NegotiatedServerTls) -> Self {
        Self { peer, tls }
    }

    /// Returns application-supplied peer metadata.
    #[must_use]
    pub const fn peer(&self) -> &Peer {
        self.peer
    }

    /// Returns transport security negotiated on the client-facing side.
    #[must_use]
    pub const fn tls(&self) -> &crate::NegotiatedServerTls {
        self.tls
    }
}

/// Required asynchronous startup routing policy.
pub trait StartupRouteResolver<Peer> {
    /// Application resolver failure.
    type Error;

    /// Selects a destination before client-facing authentication begins.
    fn resolve<'a>(
        &'a self,
        startup: StartupParameters,
        context: InitialServerContext<'a, Peer>,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectTarget, Self::Error>> + 'a>>;
}

/// Optional policy that validates or refines a destination after authentication.
pub trait AuthenticatedRoutePolicy<Peer, Identity> {
    /// Application policy failure.
    type Error;
    /// Validates or refines the startup-selected target using typed identity evidence.
    fn route<'a>(
        &'a self,
        target: ConnectTarget,
        context: AuthenticatedRouteContext<'a, Peer, Identity>,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectTarget, Self::Error>> + 'a>>;
}

/// Borrowed facts passed to authenticated route policy.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedRouteContext<'a, Peer, Identity> {
    peer: &'a Peer,
    identity: &'a Identity,
}

impl<Peer, Identity> AuthenticatedRouteContext<'_, Peer, Identity> {
    /// Returns application-supplied peer metadata.
    #[must_use]
    pub const fn peer(&self) -> &Peer {
        self.peer
    }

    /// Returns independently verified client-facing identity evidence.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        self.identity
    }
}

/// Identity authenticated-route policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllowAuthenticatedRoute;

impl<Peer, Identity> AuthenticatedRoutePolicy<Peer, Identity> for AllowAuthenticatedRoute {
    type Error = std::convert::Infallible;
    fn route<'a>(
        &'a self,
        target: ConnectTarget,
        _context: AuthenticatedRouteContext<'a, Peer, Identity>,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectTarget, Self::Error>> + 'a>> {
        Box::pin(async move { Ok(target) })
    }
}

/// Result of asynchronously intercepting a client-originated message.
#[derive(Debug, Eq, PartialEq)]
pub enum FrontendMiddlewareOutput {
    /// Forward this owned message to PostgreSQL.
    Forward(crate::codec::FrontendMessage),
    /// Consume the message without forwarding it or registering a response.
    Suppress(crate::codec::FrontendMessage),
    /// Handle the request locally and emit these responses in protocol order.
    Respond {
        /// Consumed client request.
        request: crate::codec::FrontendMessage,
        /// Responses generated for this request, in emission order.
        responses: Vec<crate::codec::BackendMessage>,
    },
}

/// Result of asynchronously intercepting a PostgreSQL-originated message.
#[derive(Debug, Eq, PartialEq)]
pub enum BackendMiddlewareOutput {
    /// Forward this owned message to the client.
    Forward(crate::codec::BackendMessage),
    /// Replace one PostgreSQL response with one or more ordered client responses.
    Expand(Vec<crate::codec::BackendMessage>),
    /// Consume the response after advancing protocol and pipeline state.
    Suppress(crate::codec::BackendMessage),
    /// Retain the unchanged current source without projection or output.
    Hold,
}

/// Ordered result of applying batch policy to retained backend messages.
#[derive(Debug, Eq, PartialEq)]
pub enum BackendBatchOutput {
    /// Leave the authoritative input span retained by the connection.
    KeepHolding,
    /// Replace every held input with one output at the same ordered position.
    ReplaceOneToOne(Vec<crate::codec::BackendMessage>),
}

/// Reason retained backend messages are offered to batch policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFlushReason {
    /// A configured message or byte limit was reached.
    Capacity,
    /// A protocol boundary must follow the held span.
    ProtocolBarrier,
    /// The application requested a latency or batch boundary.
    Explicit,
    /// The connection is being deliberately torn down.
    Teardown,
}

/// Non-zero bounds for connection-owned backend messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendHoldLimits {
    max_messages: usize,
    max_bytes: usize,
}

impl BackendHoldLimits {
    /// Creates message-count and retained-byte bounds.
    ///
    /// # Errors
    /// Returns an error when either bound is zero.
    pub const fn new(
        max_messages: usize,
        max_bytes: usize,
    ) -> Result<Self, BackendHoldConfigError> {
        if max_messages == 0 || max_bytes == 0 {
            Err(BackendHoldConfigError)
        } else {
            Ok(Self {
                max_messages,
                max_bytes,
            })
        }
    }
    /// Maximum retained message count.
    #[must_use]
    pub const fn max_messages(self) -> usize {
        self.max_messages
    }
    /// Maximum estimated retained wire bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

/// A zero backend hold bound is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendHoldConfigError;

impl fmt::Display for BackendHoldConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backend hold limits must be non-zero")
    }
}
impl std::error::Error for BackendHoldConfigError {}

/// Opaque ordered view of connection-owned backend messages.
#[derive(Clone, Copy, Debug)]
pub struct HeldBackendMessages<'a> {
    messages: &'a [crate::codec::BackendMessage],
    bytes: usize,
}

impl<'a> HeldBackendMessages<'a> {
    /// Number of held messages.
    #[must_use]
    pub const fn len(self) -> usize {
        self.messages.len()
    }
    /// Whether the view is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.messages.is_empty()
    }
    /// Estimated retained wire bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }
    /// Iterates over messages in receipt order.
    #[must_use]
    pub fn iter(self) -> impl ExactSizeIterator<Item = &'a crate::codec::BackendMessage> {
        self.messages.iter()
    }
}

/// Asynchronous, fallible middleware at the forwarding boundary.
pub trait IntermediaryMiddleware<State, ServerContext, ClientContext> {
    /// Application-defined interception failure.
    type Error;

    /// Intercepts a client-originated message after server-role middleware and
    /// before client-role middleware.
    fn frontend<'a>(
        &'a mut self,
        _server: &'a ServerContext,
        _client: &'a ClientContext,
        _state: &'a mut State,
        message: crate::codec::FrontendMessage,
    ) -> Pin<Box<dyn Future<Output = Result<FrontendMiddlewareOutput, Self::Error>> + 'a>> {
        Box::pin(async move { Ok(FrontendMiddlewareOutput::Forward(message)) })
    }

    /// Intercepts a PostgreSQL-originated message after client-role middleware
    /// and before server-role middleware.
    fn backend<'a>(
        &'a mut self,
        _server: &'a ServerContext,
        _client: &'a ClientContext,
        _state: &'a mut State,
        message: crate::codec::BackendMessage,
    ) -> Pin<Box<dyn Future<Output = Result<BackendMiddlewareOutput, Self::Error>> + 'a>> {
        Box::pin(async move { Ok(BackendMiddlewareOutput::Forward(message)) })
    }

    /// Applies policy to an ordered borrowed span of retained backend messages.
    fn flush_backend<'a>(
        &'a mut self,
        _server: &'a ServerContext,
        _client: &'a ClientContext,
        _state: &'a mut State,
        held: HeldBackendMessages<'a>,
        _reason: BackendFlushReason,
    ) -> Pin<Box<dyn Future<Output = Result<BackendBatchOutput, Self::Error>> + 'a>> {
        Box::pin(async move {
            Ok(BackendBatchOutput::ReplaceOneToOne(
                held.iter().cloned().collect(),
            ))
        })
    }
}

/// Identity forwarding-boundary middleware.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityIntermediaryMiddleware;

impl<State, ServerContext, ClientContext>
    IntermediaryMiddleware<State, ServerContext, ClientContext> for IdentityIntermediaryMiddleware
{
    type Error = std::convert::Infallible;
}

/// Creates fresh forwarding-boundary middleware for one established pair.
pub trait IntermediaryMiddlewareFactory<ServerContext, ClientContext> {
    /// Per-connection boundary handler.
    type Handler;
    /// Creates an isolated handler from both distinct role contexts.
    fn create(&self, server: &ServerContext, client: &ClientContext) -> Self::Handler;
}

impl<ServerContext, ClientContext, Handler, Factory>
    IntermediaryMiddlewareFactory<ServerContext, ClientContext> for Factory
where
    Factory: Fn(&ServerContext, &ClientContext) -> Handler,
{
    type Handler = Handler;
    fn create(&self, server: &ServerContext, client: &ClientContext) -> Handler {
        self(server, client)
    }
}

impl<ServerContext, ClientContext> IntermediaryMiddlewareFactory<ServerContext, ClientContext>
    for IdentityIntermediaryMiddleware
{
    type Handler = Self;
    fn create(&self, _server: &ServerContext, _client: &ClientContext) -> Self {
        *self
    }
}

/// A reusable operational intermediary configuration.
pub struct Intermediary<
    Server = (),
    Client = (),
    Resolver = (),
    Route = AllowAuthenticatedRoute,
    Policy = NoPipeline,
    Boundary = IdentityIntermediaryMiddleware,
    Cancellation = RejectCancellation,
> {
    pub(crate) server: Server,
    pub(crate) client: Client,
    pub(crate) resolver: Resolver,
    pub(crate) route: Route,
    pub(crate) pipeline: Policy,
    pub(crate) boundary: Boundary,
    pub(crate) cancellation: CancellationPolicy,
    pub(crate) cancellation_registry: Cancellation,
    pub(crate) failure_policy: EstablishmentFailurePolicy,
    pub(crate) backend_hold_limits: Option<BackendHoldLimits>,
}

impl Intermediary<()> {
    /// Starts composition of the two complete role configurations.
    #[must_use]
    pub fn builder() -> IntermediaryBuilder {
        IntermediaryBuilder::default()
    }
}

impl<S, C, R, A, P, B, K> fmt::Debug for Intermediary<S, C, R, A, P, B, K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Intermediary")
            .field("server", &"<configured>")
            .field("client", &"<configured>")
            .field("resolver", &"<redacted>")
            .field("authenticated_route", &"<redacted>")
            .field("cancellation", &self.cancellation)
            .finish_non_exhaustive()
    }
}

/// Progressive builder for [`Intermediary`].
pub struct IntermediaryBuilder<
    Server = (),
    Client = (),
    Resolver = (),
    Route = AllowAuthenticatedRoute,
    Policy = NoPipeline,
    Boundary = IdentityIntermediaryMiddleware,
    Cancellation = RejectCancellation,
> {
    server: Option<Server>,
    client: Option<Client>,
    resolver: Option<Resolver>,
    route: Route,
    pipeline: Policy,
    boundary: Boundary,
    cancellation: Option<CancellationPolicy>,
    cancellation_registry: Cancellation,
    failure_policy: EstablishmentFailurePolicy,
    backend_hold_limits: Option<BackendHoldLimits>,
}

impl Default for IntermediaryBuilder {
    fn default() -> Self {
        Self {
            server: None,
            client: None,
            resolver: None,
            route: AllowAuthenticatedRoute,
            pipeline: NoPipeline,
            boundary: IdentityIntermediaryMiddleware,
            cancellation: None,
            cancellation_registry: RejectCancellation,
            failure_policy: EstablishmentFailurePolicy::Close,
            backend_hold_limits: None,
        }
    }
}

impl<S, C, R, A, P, B, K> IntermediaryBuilder<S, C, R, A, P, B, K> {
    /// Supplies the complete client-facing role configuration.
    #[must_use]
    pub fn server<Next>(self, server: Next) -> IntermediaryBuilder<Next, C, R, A, P, B, K> {
        IntermediaryBuilder {
            server: Some(server),
            client: self.client,
            resolver: self.resolver,
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
            cancellation_registry: self.cancellation_registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        }
    }

    /// Supplies the complete PostgreSQL-facing role configuration.
    #[must_use]
    pub fn client<Next>(self, client: Next) -> IntermediaryBuilder<S, Next, R, A, P, B, K> {
        IntermediaryBuilder {
            server: self.server,
            client: Some(client),
            resolver: self.resolver,
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
            cancellation_registry: self.cancellation_registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        }
    }

    /// Supplies the required asynchronous startup resolver.
    #[must_use]
    pub fn startup_resolver<Next>(
        self,
        resolver: Next,
    ) -> IntermediaryBuilder<S, C, Next, A, P, B, K> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: Some(resolver),
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
            cancellation_registry: self.cancellation_registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        }
    }

    /// Supplies optional post-authentication routing policy.
    #[must_use]
    pub fn authenticated_route<Next>(
        self,
        route: Next,
    ) -> IntermediaryBuilder<S, C, R, Next, P, B, K> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: self.resolver,
            route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
            cancellation_registry: self.cancellation_registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        }
    }

    /// Selects lock-step or bounded request pipelining.
    #[must_use]
    pub fn pipeline<Next: PipelinePolicy>(
        self,
        pipeline: Next,
    ) -> IntermediaryBuilder<S, C, R, A, Next, B, K> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: self.resolver,
            route: self.route,
            pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
            cancellation_registry: self.cancellation_registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        }
    }

    /// Supplies middleware for the forwarding boundary.
    #[must_use]
    pub fn middleware<Next>(self, boundary: Next) -> IntermediaryBuilder<S, C, R, A, P, Next, K> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: self.resolver,
            route: self.route,
            pipeline: self.pipeline,
            boundary,
            cancellation: self.cancellation,
            cancellation_registry: self.cancellation_registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        }
    }

    /// Selects an explicit cancellation posture.
    #[must_use]
    pub fn cancellation(mut self, cancellation: CancellationPolicy) -> Self {
        self.cancellation = match cancellation {
            CancellationPolicy::Reject => Some(CancellationPolicy::Reject),
            CancellationPolicy::Forward => None,
        };
        self
    }

    /// Selects conservative close or one fixed safe diagnostic on establishment failure.
    #[must_use]
    pub fn establishment_failure(mut self, policy: EstablishmentFailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Enables bounded connection-owned backend message holding.
    #[must_use]
    pub fn backend_batching(mut self, limits: BackendHoldLimits) -> Self {
        self.backend_hold_limits = Some(limits);
        self
    }

    /// Enables forwarding through an application-owned concurrent registry.
    #[must_use]
    pub fn cancellation_registry<Next>(
        self,
        registry: Next,
    ) -> IntermediaryBuilder<S, C, R, A, P, B, Next> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: self.resolver,
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: Some(CancellationPolicy::Forward),
            cancellation_registry: registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        }
    }

    /// Validates composition and creates a reusable component.
    ///
    /// # Errors
    ///
    /// Returns the first missing mandatory role, resolver, or cancellation configuration.
    #[allow(clippy::type_complexity)]
    pub fn build(self) -> Result<Intermediary<S, C, R, A, P, B, K>, IntermediaryBuildError> {
        Ok(Intermediary {
            server: self.server.ok_or(IntermediaryBuildError::MissingServer)?,
            client: self.client.ok_or(IntermediaryBuildError::MissingClient)?,
            resolver: self
                .resolver
                .ok_or(IntermediaryBuildError::MissingStartupResolver)?,
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self
                .cancellation
                .ok_or(IntermediaryBuildError::MissingCancellationPolicy)?,
            cancellation_registry: self.cancellation_registry,
            failure_policy: self.failure_policy,
            backend_hold_limits: self.backend_hold_limits,
        })
    }
}

struct StartupResolverAdapter<'a, Resolver> {
    resolver: &'a Resolver,
}

/// Failure while decoding or resolving a startup route.
#[derive(Debug)]
pub enum StartupResolutionError<Error> {
    /// A startup parameter was not representable by the structured facade.
    Parameters(io::Error),
    /// The application resolver rejected the route.
    Resolver(Error),
}

impl<Error: fmt::Display> fmt::Display for StartupResolutionError<Error> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parameters(error) => error.fmt(formatter),
            Self::Resolver(error) => error.fmt(formatter),
        }
    }
}

impl<Error: std::error::Error + 'static> std::error::Error for StartupResolutionError<Error> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parameters(error) => Some(error),
            Self::Resolver(error) => Some(error),
        }
    }
}

impl<Resolver, State, Peer, Identity>
    crate::server_component::StartupResolver<State, Peer, Identity>
    for StartupResolverAdapter<'_, Resolver>
where
    Resolver: StartupRouteResolver<Peer>,
{
    type Route = ConnectTarget;
    type Error = StartupResolutionError<Resolver::Error>;

    fn defer_ready(&self) -> bool {
        true
    }

    fn resolve<'a>(
        &'a mut self,
        startup: &'a crate::startup::StartupMessage,
        context: &'a crate::ServerConnectionContext<Peer, Identity>,
        _state: &'a mut State,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Route, Self::Error>> + 'a>> {
        let parameters = StartupParameters::from_wire(startup);
        let initial = context
            .tls_if_known()
            .map(|tls| InitialServerContext::new(context.peer(), tls));
        let resolver = self.resolver;
        Box::pin(async move {
            let parameters = parameters.map_err(StartupResolutionError::Parameters)?;
            let initial = initial.expect("startup routing runs after TLS negotiation");
            resolver
                .resolve(parameters, initial)
                .await
                .map_err(StartupResolutionError::Resolver)
        })
    }
}

/// Failure while establishing both independently authenticated roles.
pub enum IntermediaryAcceptError<
    ServerError,
    ResolverError,
    RouteError,
    ClientError,
    RegistryError = std::convert::Infallible,
    CancellationError = std::convert::Infallible,
    MiddlewareError = std::convert::Infallible,
> {
    /// Client-facing TLS, startup, or authentication failed.
    Server(ServerError),
    /// Startup routing failed before client-facing authentication.
    StartupRoute(StartupResolutionError<ResolverError>),
    /// The explicit cancellation posture rejected an out-of-band request.
    CancellationRejected,
    /// Authenticated routing rejected or failed to refine the destination.
    AuthenticatedRoute(RouteError),
    /// PostgreSQL-facing connection, TLS, startup, or authentication failed.
    Client(ClientError),
    /// Cancellation-key allocation, collision detection, or storage failed.
    CancellationRegistry(RegistryError),
    /// A generated establishment message could not be written downstream.
    ServerOutput(io::Error),
    /// Opening or writing the one-shot upstream cancellation connection failed.
    Cancellation(CancellationError),
    /// Forwarding-boundary middleware rejected generated establishment output.
    Middleware(MiddlewareError),
}

impl<S, R, A, C, K, X, M> fmt::Debug for IntermediaryAcceptError<S, R, A, C, K, X, M> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Server(_) => "IntermediaryAcceptError::Server([REDACTED])",
            Self::StartupRoute(_) => "IntermediaryAcceptError::StartupRoute([REDACTED])",
            Self::CancellationRejected => "IntermediaryAcceptError::CancellationRejected",
            Self::AuthenticatedRoute(_) => {
                "IntermediaryAcceptError::AuthenticatedRoute([REDACTED])"
            }
            Self::Client(_) => "IntermediaryAcceptError::Client([REDACTED])",
            Self::CancellationRegistry(_) => {
                "IntermediaryAcceptError::CancellationRegistry([REDACTED])"
            }
            Self::ServerOutput(_) => "IntermediaryAcceptError::ServerOutput([REDACTED])",
            Self::Cancellation(_) => "IntermediaryAcceptError::Cancellation([REDACTED])",
            Self::Middleware(_) => "IntermediaryAcceptError::Middleware([REDACTED])",
        })
    }
}

impl<S, R, A, C, K, X, M> fmt::Display for IntermediaryAcceptError<S, R, A, C, K, X, M> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(_) => formatter.write_str("client-facing establishment failed"),
            Self::StartupRoute(_) => formatter.write_str("startup routing failed"),
            Self::CancellationRejected => {
                formatter.write_str("cancellation is explicitly rejected")
            }
            Self::AuthenticatedRoute(_) => formatter.write_str("authenticated routing failed"),
            Self::Client(_) => formatter.write_str("PostgreSQL-facing establishment failed"),
            Self::CancellationRegistry(_) => {
                formatter.write_str("cancellation registration failed")
            }
            Self::ServerOutput(_) => {
                formatter.write_str("client-facing establishment output failed")
            }
            Self::Cancellation(_) => formatter.write_str("cancellation forwarding failed"),
            Self::Middleware(_) => {
                formatter.write_str("forwarding middleware rejected establishment output")
            }
        }
    }
}

impl<S, R, A, C, K, X, M> std::error::Error for IntermediaryAcceptError<S, R, A, C, K, X, M>
where
    S: std::error::Error + 'static,
    R: std::error::Error + 'static,
    A: std::error::Error + 'static,
    C: std::error::Error + 'static,
    K: std::error::Error + 'static,
    X: std::error::Error + 'static,
    M: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Server(error) => Some(error),
            Self::StartupRoute(error) => Some(error),
            Self::CancellationRejected => None,
            Self::AuthenticatedRoute(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::CancellationRegistry(error) => Some(error),
            Self::ServerOutput(error) => Some(error),
            Self::Cancellation(error) => Some(error),
            Self::Middleware(error) => Some(error),
        }
    }
}

/// Both role contexts recovered during deliberate intermediary teardown.
#[derive(Debug)]
pub struct IntermediaryContexts<ServerContext, ClientContext> {
    server: ServerContext,
    client: ClientContext,
}

impl<ServerContext, ClientContext> IntermediaryContexts<ServerContext, ClientContext> {
    /// Returns the client-facing role context.
    #[must_use]
    pub const fn server(&self) -> &ServerContext {
        &self.server
    }
    /// Returns the PostgreSQL-facing role context.
    #[must_use]
    pub const fn client(&self) -> &ClientContext {
        &self.client
    }
}

/// One operational, independently authenticated intermediary session.
pub struct IntermediaryConnection<
    DT,
    UT,
    State,
    Peer,
    ServerIdentity,
    ClientEvidence,
    ServerHandler,
    ClientHandler,
    Boundary,
    Policy,
    Cancellation = RejectCancellation,
> {
    downstream:
        crate::server_component::ServerConnectionCore<DT, Peer, ServerIdentity, ServerHandler>,
    upstream: crate::client_component::ClientConnectionCore<
        crate::ClientTransport<UT>,
        crate::Pristine,
        ClientEvidence,
        ClientHandler,
    >,
    state: State,
    boundary: Boundary,
    pipeline: Pipeline<Policy>,
    target: ConnectTarget,
    pending_frontend: Option<crate::codec::FrontendMessage>,
    backend_hold: crate::backend_hold::BackendHold,
    backend_hold_limits: Option<BackendHoldLimits>,
    pending_local: VecDeque<PendingLocalResponses>,
    cancellation_registry: Cancellation,
    client_cancel_key: Option<crate::demux::CancelKey>,
}

struct PendingLocalResponses {
    operation: crate::pipeline::OperationId,
    messages: VecDeque<crate::codec::BackendMessage>,
}

/// Result of accepting either an ordinary session or an out-of-band request.
#[derive(Debug)]
pub enum IntermediaryAccept<Connection> {
    /// A fully established, independently authenticated session pair.
    Session(Connection),
    /// The resolved cancellation packet was rewritten and forwarded.
    CancellationForwarded,
}

impl<Connection> IntermediaryAccept<Connection> {
    /// Extracts the ordinary session branch.
    ///
    /// # Panics
    /// Panics when the accepted connection was cancellation-only.
    #[must_use]
    pub fn into_session(self) -> Connection {
        match self {
            Self::Session(connection) => connection,
            Self::CancellationForwarded => panic!("accepted cancellation has no session"),
        }
    }
}

/// Direction selected by one cancellation-safe duplex forwarding step.
#[derive(Debug)]
pub enum ForwardedMessage {
    /// A client-originated message was forwarded to PostgreSQL.
    Frontend(crate::codec::FrontendMessage),
    /// A PostgreSQL-originated message was forwarded to the client.
    Backend(crate::codec::BackendMessage),
    /// One PostgreSQL response expanded into ordered client responses.
    BackendExpanded {
        /// Response received from PostgreSQL.
        source: crate::codec::BackendMessage,
        /// Responses emitted to the client.
        messages: Vec<crate::codec::BackendMessage>,
    },
    /// A client-originated message was deliberately suppressed.
    FrontendSuppressed(crate::codec::FrontendMessage),
    /// A request was handled locally; responses were emitted or queued in order.
    FrontendLocallyHandled(crate::codec::FrontendMessage),
    /// A PostgreSQL-originated response advanced protocol state but was suppressed.
    BackendSuppressed(crate::codec::BackendMessage),
    /// A PostgreSQL response entered the connection-owned backend hold.
    BackendHeld,
}

/// Observable result of processing one client-originated message.
#[derive(Debug, Eq, PartialEq)]
pub enum FrontendForwarding {
    /// The message was sent to PostgreSQL.
    Forwarded(crate::codec::FrontendMessage),
    /// The message was consumed without being sent.
    Suppressed(crate::codec::FrontendMessage),
    /// The request was admitted as local and its responses were emitted or queued.
    LocallyHandled(crate::codec::FrontendMessage),
}

impl FrontendForwarding {
    /// Returns the owned client message represented by this outcome.
    #[must_use]
    pub fn into_message(self) -> crate::codec::FrontendMessage {
        match self {
            Self::Forwarded(message)
            | Self::Suppressed(message)
            | Self::LocallyHandled(message) => message,
        }
    }
}

/// Observable result of processing one PostgreSQL-originated response.
#[derive(Debug, Eq, PartialEq)]
pub enum BackendForwarding {
    /// The response was sent to the client.
    Forwarded(crate::codec::BackendMessage),
    /// One PostgreSQL response expanded into these ordered client responses.
    Expanded {
        /// Response received from PostgreSQL after client-role interception.
        source: crate::codec::BackendMessage,
        /// Responses emitted to the client after server-role interception.
        messages: Vec<crate::codec::BackendMessage>,
    },
    /// The response advanced protocol state but was not sent.
    Suppressed(crate::codec::BackendMessage),
    /// The response entered the connection-owned hold without projection.
    Held,
}

impl BackendForwarding {
    /// Returns the owned PostgreSQL response represented by this outcome.
    ///
    /// # Panics
    /// Panics for [`BackendForwarding::Held`] because the connection still owns
    /// that response.
    #[must_use]
    pub fn into_message(self) -> crate::codec::BackendMessage {
        match self {
            Self::Forwarded(message) | Self::Suppressed(message) => message,
            Self::Expanded { source, .. } => source,
            Self::Held => panic!("a held response remains owned by the connection"),
        }
    }
}

/// Observable result of explicitly applying backend batch policy.
#[derive(Debug, Eq, PartialEq)]
pub enum BackendBatchForwarding {
    /// The held span was atomically projected and emitted in order.
    Released(Vec<crate::codec::BackendMessage>),
    /// Batch policy elected to retain the unchanged span.
    Kept,
    /// No backend messages were held.
    Empty,
}

/// Validation failure for an ordered one-to-one backend replacement span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendBatchProjectionError {
    /// Replacement cardinality differed from the held span.
    Cardinality {
        /// Number of authoritative held inputs.
        expected: usize,
        /// Number of proposed replacements.
        actual: usize,
    },
    /// A held source was not attributable at this pipeline position.
    IllegalSource,
    /// A proposed replacement was illegal or not reconstructable.
    IllegalReplacement,
    /// Replacements would consume a different protocol span than the sources.
    DifferentSpan,
}

impl From<crate::pipeline::BackendSequenceError> for BackendBatchProjectionError {
    fn from(error: crate::pipeline::BackendSequenceError) -> Self {
        match error {
            crate::pipeline::BackendSequenceError::Cardinality { expected, actual } => {
                Self::Cardinality { expected, actual }
            }
            crate::pipeline::BackendSequenceError::Source(_) => Self::IllegalSource,
            crate::pipeline::BackendSequenceError::Replacement(_) => Self::IllegalReplacement,
            crate::pipeline::BackendSequenceError::DifferentSpan => Self::DifferentSpan,
        }
    }
}

impl<DT, UT, State, Peer, SI, CE, SH, CH, Boundary, Policy, K>
    IntermediaryConnection<DT, UT, State, Peer, SI, CE, SH, CH, Boundary, Policy, K>
where
    Policy: PipelinePolicy,
{
    /// Returns the authoritative destination selected for the client component.
    #[must_use]
    pub const fn target(&self) -> &ConnectTarget {
        &self.target
    }
    /// Returns the single caller-owned state shared by all three middleware layers.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }
    /// Returns the proxy-issued cancellation key for this live session.
    #[must_use]
    pub const fn cancellation_key(&self) -> Option<&crate::demux::CancelKey> {
        self.client_cancel_key.as_ref()
    }

    /// Returns an ordered borrowed view of retained backend messages.
    #[must_use]
    pub fn held_backend_messages(&self) -> HeldBackendMessages<'_> {
        HeldBackendMessages {
            messages: self.backend_hold.messages(),
            bytes: self.backend_hold.bytes(),
        }
    }

    /// Detaches this session's cancellation mapping explicitly.
    pub fn detach_cancellation(&mut self) -> Option<CancellationRoute>
    where
        K: IntermediaryCancellationRegistry,
    {
        self.client_cancel_key
            .take()
            .and_then(|key| self.cancellation_registry.detach(&key))
    }
}

impl<
    DT,
    UT,
    State,
    Peer,
    ServerIdentity,
    ClientEvidence,
    ServerHandler,
    ClientHandler,
    Boundary,
    Policy,
    K,
>
    IntermediaryConnection<
        DT,
        UT,
        State,
        Peer,
        ServerIdentity,
        ClientEvidence,
        ServerHandler,
        ClientHandler,
        Boundary,
        Policy,
        K,
    >
where
    DT: AsyncRead + AsyncWrite + Unpin,
    UT: AsyncRead + AsyncWrite + Unpin,
    ServerHandler:
        crate::ServerMiddleware<State, crate::ServerConnectionContext<Peer, ServerIdentity>>,
    ClientHandler: crate::ClientMiddleware<State, crate::ClientConnectionContext<ClientEvidence>>,
    Boundary: IntermediaryMiddleware<
            State,
            crate::ServerConnectionContext<Peer, ServerIdentity>,
            crate::ClientConnectionContext<ClientEvidence>,
        >,
    Policy: PipelinePolicy,
    K: IntermediaryCancellationRegistry,
{
    /// Receives one client message and reports whether it was forwarded,
    /// suppressed, or handled with pipeline-ordered local responses.
    ///
    /// # Errors
    ///
    /// Returns middleware, transport, protocol-legality, or capacity failures.
    pub async fn forward_frontend(
        &mut self,
    ) -> Result<FrontendForwarding, ForwardError<Boundary::Error>> {
        if let Some(message) = self.pending_frontend.take() {
            self.process_frontend(message, false).await
        } else {
            let message = self.downstream.receive_wire_raw().await?;
            self.process_frontend(message, true).await
        }
    }

    async fn process_frontend(
        &mut self,
        message: crate::codec::FrontendMessage,
        intercept_source_and_boundary: bool,
    ) -> Result<FrontendForwarding, ForwardError<Boundary::Error>> {
        let decision = if intercept_source_and_boundary {
            let message = self.downstream.intercept_frontend(&mut self.state, message);
            self.boundary
                .frontend(
                    self.downstream.context(),
                    self.upstream.context(),
                    &mut self.state,
                    message,
                )
                .await
                .map_err(ForwardError::Middleware)?
        } else {
            FrontendMiddlewareOutput::Forward(message)
        };
        let (message, handling) = match decision {
            FrontendMiddlewareOutput::Forward(message) => {
                let message = if intercept_source_and_boundary {
                    self.upstream.intercept_frontend(&mut self.state, message)
                } else {
                    message
                };
                (message, FrontendHandling::Forward)
            }
            FrontendMiddlewareOutput::Suppress(message) => {
                return Ok(FrontendForwarding::Suppressed(message));
            }
            FrontendMiddlewareOutput::Respond { request, responses } => {
                let admission = self
                    .pipeline
                    .accept_frontend(request.clone(), FrontendHandling::Local)
                    .map_err(ForwardError::Frontend)?;
                let FrontendAction::Discard { id } = admission.into_action() else {
                    unreachable!()
                };
                let messages = responses
                    .into_iter()
                    .map(|message| self.downstream.intercept_backend(&mut self.state, message))
                    .collect();
                self.pending_local.push_back(PendingLocalResponses {
                    operation: id,
                    messages,
                });
                self.flush_local_responses().await?;
                return Ok(FrontendForwarding::LocallyHandled(request));
            }
        };
        let admission = match self.pipeline.accept_frontend(message.clone(), handling) {
            Ok(admission) => admission,
            Err(error) => {
                self.pending_frontend = Some(message);
                return Err(ForwardError::Frontend(error));
            }
        };
        let FrontendAction::Forward { message, .. } = admission.into_action() else {
            unreachable!()
        };
        self.upstream.send_wire_raw(message.clone()).await?;
        Ok(FrontendForwarding::Forwarded(message))
    }

    /// Receives one legal PostgreSQL response and forwards it downstream in
    /// source-role, boundary, destination-role middleware order.
    ///
    /// # Errors
    ///
    /// Returns transport, framing, ordering, or protocol-legality failures.
    /// Receives one PostgreSQL response and reports whether it was forwarded,
    /// expanded, or suppressed.
    ///
    /// # Errors
    ///
    /// Returns middleware, transport, ordering, or protocol-legality failures.
    pub async fn forward_backend(
        &mut self,
    ) -> Result<BackendForwarding, ForwardError<Boundary::Error>> {
        if self.backend_hold.pending().is_some() {
            return self.process_pending_backend().await;
        }
        if self.backend_hold_is_full() {
            match self
                .flush_backend_hold_for(BackendFlushReason::Capacity)
                .await?
            {
                BackendBatchForwarding::Released(_) | BackendBatchForwarding::Empty => {}
                BackendBatchForwarding::Kept => return Err(ForwardError::BackendHoldCapacity),
            }
        }
        let message = self.upstream.receive_wire_raw().await?;
        self.process_backend(message).await
    }

    async fn process_backend(
        &mut self,
        message: crate::codec::BackendMessage,
    ) -> Result<BackendForwarding, ForwardError<Boundary::Error>> {
        let message = self.upstream.intercept_backend(&mut self.state, message);
        self.backend_hold.set_pending(message);
        if self
            .backend_hold
            .pending()
            .is_some_and(is_backend_batch_barrier)
            && !self.backend_hold.is_empty()
        {
            match self
                .flush_backend_hold_for(BackendFlushReason::ProtocolBarrier)
                .await?
            {
                BackendBatchForwarding::Released(_) | BackendBatchForwarding::Empty => {}
                BackendBatchForwarding::Kept => return Err(ForwardError::BackendHoldRefused),
            }
        }
        self.process_pending_backend().await
    }

    async fn process_pending_backend(
        &mut self,
    ) -> Result<BackendForwarding, ForwardError<Boundary::Error>> {
        let source = self
            .backend_hold
            .pending()
            .expect("pending backend processing requires a source")
            .clone();
        let decision = self
            .boundary
            .backend(
                self.downstream.context(),
                self.upstream.context(),
                &mut self.state,
                source.clone(),
            )
            .await
            .map_err(ForwardError::Middleware)?;
        let outcome = match decision {
            BackendMiddlewareOutput::Forward(message) => {
                let _ = self.backend_hold.take_pending();
                let message = self.downstream.intercept_backend(&mut self.state, message);
                let message = self.emit_backend(message).await?;
                BackendForwarding::Forwarded(message)
            }
            BackendMiddlewareOutput::Suppress(message) => {
                let _ = self.backend_hold.take_pending();
                let message = self.advance_backend(message)?;
                BackendForwarding::Suppressed(message)
            }
            BackendMiddlewareOutput::Expand(messages) => {
                if messages.is_empty() {
                    return Err(ForwardError::EmptyExpansion(source));
                }
                let _ = self.backend_hold.take_pending();
                let mut emitted = Vec::with_capacity(messages.len());
                for message in messages {
                    let message = self.downstream.intercept_backend(&mut self.state, message);
                    emitted.push(self.emit_backend(message).await?);
                }
                BackendForwarding::Expanded {
                    source,
                    messages: emitted,
                }
            }
            BackendMiddlewareOutput::Hold => {
                if self.backend_hold_limits.is_none() {
                    return Err(ForwardError::BackendHoldingDisabled(source));
                }
                self.backend_hold.hold_pending();
                BackendForwarding::Held
            }
        };
        self.flush_local_responses().await?;
        Ok(outcome)
    }

    fn backend_hold_is_full(&self) -> bool {
        self.backend_hold_limits.is_some_and(|limits| {
            self.backend_hold.len() >= limits.max_messages()
                || self.backend_hold.bytes() >= limits.max_bytes()
        })
    }

    /// Applies batch policy to held messages without reading another upstream frame.
    ///
    /// # Errors
    /// Returns middleware, encoding, projection, or transport failures while
    /// preserving the hold until projection commits.
    pub async fn flush_backend_hold(
        &mut self,
    ) -> Result<BackendBatchForwarding, ForwardError<Boundary::Error>> {
        self.flush_backend_hold_for(BackendFlushReason::Explicit)
            .await
    }

    /// Flushes retained messages for deliberate teardown without reading upstream.
    ///
    /// # Errors
    /// Returns an error when middleware fails, refuses release, proposes an
    /// invalid span, or output cannot be encoded or written.
    pub async fn prepare_backend_teardown(
        &mut self,
    ) -> Result<BackendBatchForwarding, ForwardError<Boundary::Error>> {
        let outcome = self
            .flush_backend_hold_for(BackendFlushReason::Teardown)
            .await?;
        if matches!(outcome, BackendBatchForwarding::Kept) {
            return Err(ForwardError::BackendHoldRefused);
        }
        Ok(outcome)
    }

    async fn flush_backend_hold_for(
        &mut self,
        reason: BackendFlushReason,
    ) -> Result<BackendBatchForwarding, ForwardError<Boundary::Error>> {
        if self.backend_hold.is_empty() {
            return Ok(BackendBatchForwarding::Empty);
        }
        let held = HeldBackendMessages {
            messages: self.backend_hold.messages(),
            bytes: self.backend_hold.bytes(),
        };
        let decision = self
            .boundary
            .flush_backend(
                self.downstream.context(),
                self.upstream.context(),
                &mut self.state,
                held,
                reason,
            )
            .await
            .map_err(ForwardError::Middleware)?;
        let BackendBatchOutput::ReplaceOneToOne(messages) = decision else {
            return Ok(BackendBatchForwarding::Kept);
        };
        let messages: Vec<_> = messages
            .into_iter()
            .map(|message| self.downstream.intercept_backend(&mut self.state, message))
            .collect();
        for message in &messages {
            message.to_frame().map_err(ForwardError::Io)?;
        }
        let prepared = self
            .pipeline
            .prepare_backend_replacements(self.backend_hold.messages(), &messages)
            .map_err(|error| ForwardError::BackendBatch {
                error: error.into(),
                proposed: messages.clone(),
            })?;
        self.pipeline = prepared;
        let _sources = self.backend_hold.clear();
        for message in &messages {
            self.downstream.send_wire_raw(message.clone()).await?;
        }
        self.flush_local_responses().await?;
        Ok(BackendBatchForwarding::Released(messages))
    }

    fn advance_backend(
        &mut self,
        message: crate::codec::BackendMessage,
    ) -> Result<crate::codec::BackendMessage, ForwardError<Boundary::Error>> {
        match self
            .pipeline
            .accept_backend(message)
            .map_err(ForwardError::Backend)?
        {
            BackendAction::Emit(message) => Ok(message),
            BackendAction::Deferred(message) => Err(ForwardError::Deferred(message)),
        }
    }

    async fn emit_backend(
        &mut self,
        message: crate::codec::BackendMessage,
    ) -> Result<crate::codec::BackendMessage, ForwardError<Boundary::Error>> {
        let message = self.advance_backend(message)?;
        self.downstream.send_wire_raw(message.clone()).await?;
        Ok(message)
    }

    async fn flush_local_responses(&mut self) -> Result<(), ForwardError<Boundary::Error>> {
        loop {
            let Some(pending) = self.pending_local.front_mut() else {
                return Ok(());
            };
            let Some(message) = pending.messages.pop_front() else {
                self.pending_local.pop_front();
                continue;
            };
            match self.pipeline.try_emit_local(pending.operation, message) {
                Ok(BackendAction::Emit(message)) => {
                    self.downstream.send_wire_raw(message).await?;
                }
                Ok(BackendAction::Deferred(message)) => {
                    pending.messages.push_front(message);
                    return Ok(());
                }
                Err(error) => return Err(ForwardError::Backend(error)),
            }
        }
    }

    /// Waits on both transports and forwards whichever legal message becomes
    /// available first. This is the duplex driver for asynchronous traffic,
    /// COPY BOTH, and physical replication.
    ///
    /// When frontend capacity is exhausted, the unchanged pending request is
    /// retained and only backend progress is polled until capacity recovers.
    ///
    /// # Errors
    ///
    /// Returns transport, framing, ordering, protocol-legality, or capacity failures.
    pub async fn forward_next(
        &mut self,
    ) -> Result<ForwardedMessage, ForwardError<Boundary::Error>> {
        if self.backend_hold.pending().is_some() {
            return self
                .process_pending_backend()
                .await
                .map(|outcome| match outcome {
                    BackendForwarding::Forwarded(message) => ForwardedMessage::Backend(message),
                    BackendForwarding::Expanded { source, messages } => {
                        ForwardedMessage::BackendExpanded { source, messages }
                    }
                    BackendForwarding::Suppressed(message) => {
                        ForwardedMessage::BackendSuppressed(message)
                    }
                    BackendForwarding::Held => ForwardedMessage::BackendHeld,
                });
        }
        if self.backend_hold_is_full() {
            match self
                .flush_backend_hold_for(BackendFlushReason::Capacity)
                .await?
            {
                BackendBatchForwarding::Released(_) | BackendBatchForwarding::Empty => {}
                BackendBatchForwarding::Kept => return Err(ForwardError::BackendHoldCapacity),
            }
        }
        if self.pending_frontend.is_some() {
            let message = self.upstream.receive_wire_raw().await?;
            return self
                .process_backend(message)
                .await
                .map(|outcome| match outcome {
                    BackendForwarding::Forwarded(message) => ForwardedMessage::Backend(message),
                    BackendForwarding::Expanded { source, messages } => {
                        ForwardedMessage::BackendExpanded { source, messages }
                    }
                    BackendForwarding::Suppressed(message) => {
                        ForwardedMessage::BackendSuppressed(message)
                    }
                    BackendForwarding::Held => ForwardedMessage::BackendHeld,
                });
        }
        tokio::select! {
            result = self.downstream.receive_wire_raw() => {
                let message = result?;
                self.process_frontend(message, true).await.map(|outcome| match outcome {
                    FrontendForwarding::Forwarded(message) => ForwardedMessage::Frontend(message),
                    FrontendForwarding::Suppressed(message) => ForwardedMessage::FrontendSuppressed(message),
                    FrontendForwarding::LocallyHandled(message) => ForwardedMessage::FrontendLocallyHandled(message),
                })
            }
            result = self.upstream.receive_wire_raw() => {
                let message = result?;
                self.process_backend(message).await.map(|outcome| match outcome {
                    BackendForwarding::Forwarded(message) => ForwardedMessage::Backend(message),
                    BackendForwarding::Expanded { source, messages } => {
                        ForwardedMessage::BackendExpanded { source, messages }
                    }
                    BackendForwarding::Suppressed(message) => ForwardedMessage::BackendSuppressed(message),
                    BackendForwarding::Held => ForwardedMessage::BackendHeld,
                })
            }
        }
    }

    /// Deliberately tears down both roles and recovers transports, handlers,
    /// contexts, boundary middleware, and the sole connection state.
    ///
    /// # Panics
    /// Panics when a backend source is pending or held. Call
    /// [`Self::prepare_backend_teardown`] first when batching is enabled.
    #[allow(clippy::type_complexity)]
    pub fn teardown(
        mut self,
    ) -> (
        crate::AcceptedServerTransport<DT>,
        crate::ClientTransport<UT>,
        State,
        Boundary,
        (ServerHandler, ClientHandler),
        IntermediaryContexts<
            crate::ServerConnectionContext<Peer, ServerIdentity>,
            crate::ClientConnectionContext<ClientEvidence>,
        >,
    ) {
        assert!(
            self.backend_hold.is_empty() && self.backend_hold.pending().is_none(),
            "backend messages remain held; call prepare_backend_teardown before teardown"
        );
        let _ = self.detach_cancellation();
        let (downstream, server_handler, server_context) = self.downstream.into_parts();
        let (upstream, client_handler, client_context) = self.upstream.into_parts();
        (
            downstream,
            upstream,
            self.state,
            self.boundary,
            (server_handler, client_handler),
            IntermediaryContexts {
                server: server_context,
                client: client_context,
            },
        )
    }
}

/// Operational forwarding or pipeline projection failure.
#[derive(Debug)]
pub enum ForwardError<MiddlewareError = std::convert::Infallible> {
    /// Transport, decoding, or encoding failure.
    Io(io::Error),
    /// Frontend backpressure or protocol-legality rejection.
    Frontend(crate::pipeline::FrontendProjectionError),
    /// Backend protocol-legality rejection.
    Backend(crate::pipeline::BackendProjectionError),
    /// A bounded response arrived before its operation became emittable.
    Deferred(crate::codec::BackendMessage),
    /// Backend fan-out did not contain a replacement response.
    EmptyExpansion(crate::codec::BackendMessage),
    /// Middleware requested holding without configured finite limits.
    BackendHoldingDisabled(crate::codec::BackendMessage),
    /// Batch policy kept a full hold, so no transport may be polled.
    BackendHoldCapacity,
    /// Batch policy refused a required protocol-boundary release.
    BackendHoldRefused,
    /// A proposed batch failed atomic protocol-span validation.
    BackendBatch {
        /// Validation failure.
        error: BackendBatchProjectionError,
        /// Unsent proposed replacements in order.
        proposed: Vec<crate::codec::BackendMessage>,
    },
    /// Forwarding-boundary middleware rejected a message.
    Middleware(MiddlewareError),
}

impl<E> fmt::Display for ForwardError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Frontend(_) => {
                formatter.write_str("frontend message violates pipeline legality or capacity")
            }
            Self::Backend(_) => formatter.write_str("backend message violates pipeline legality"),
            Self::Deferred(_) => formatter.write_str("backend response is not yet emittable"),
            Self::EmptyExpansion(_) => {
                formatter.write_str("backend expansion must contain at least one response")
            }
            Self::BackendHoldingDisabled(_) => {
                formatter.write_str("backend holding is not configured")
            }
            Self::BackendHoldCapacity => {
                formatter.write_str("backend hold is full and batch policy kept holding")
            }
            Self::BackendHoldRefused => {
                formatter.write_str("backend batch policy refused a required release")
            }
            Self::BackendBatch { .. } => formatter
                .write_str("backend batch replacement is not a legal one-to-one protocol span"),
            Self::Middleware(_) => formatter.write_str("forwarding middleware rejected a message"),
        }
    }
}

impl<E> std::error::Error for ForwardError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Middleware(error) => Some(error),
            Self::Frontend(_)
            | Self::Backend(_)
            | Self::Deferred(_)
            | Self::EmptyExpansion(_)
            | Self::BackendHoldingDisabled(_)
            | Self::BackendHoldCapacity
            | Self::BackendHoldRefused
            | Self::BackendBatch { .. } => None,
        }
    }
}

impl<E> From<io::Error> for ForwardError<E> {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl<ST, SA, SM, Connector, CT, CA, CM, Resolver, Route, Policy, Boundary, K>
    Intermediary<
        crate::Server<ST, SA, SM>,
        crate::Client<Connector, CT, CA, CM>,
        Resolver,
        Route,
        Policy,
        Boundary,
        K,
    >
where
    ST: crate::ServerTlsConfiguration,
    SA: crate::ServerAuthenticationProvider,
    CT: crate::client_component::ClientTlsConfiguration,
    CA: crate::ClientAuthentication,
    CM: crate::MiddlewareFactory<crate::ClientInitialContext>,
    Policy: PipelinePolicy,
    K: IntermediaryCancellationRegistry + Clone,
{
    /// Establishes both independently authenticated roles around one shared state.
    ///
    /// # Errors
    ///
    /// Returns the typed failure from either role or routing policy, or explicit
    /// cancellation rejection.
    #[allow(clippy::type_complexity, clippy::too_many_lines)]
    pub async fn accept<DT, State, Peer, CW, UT, CE>(
        &self,
        transport: DT,
        peer: Peer,
        state: State,
    ) -> Result<
        IntermediaryAccept<
            IntermediaryConnection<
                DT,
                UT,
                State,
                Peer,
                <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                CA::Evidence,
                <SM as crate::MiddlewareFactory<
                    crate::ServerConnectionContext<
                        Peer,
                        <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                    >,
                >>::Handler,
                <CM as crate::MiddlewareFactory<crate::ClientInitialContext>>::Handler,
                <Boundary as IntermediaryMiddlewareFactory<
                    crate::ServerConnectionContext<
                        Peer,
                        <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                    >,
                    crate::ClientConnectionContext<CA::Evidence>,
                >>::Handler,
                Policy,
                K,
            >,
        >,
        IntermediaryAcceptError<
            crate::AcceptError<
                <ST::Provider as crate::ServerIdentityProvider>::Error,
                <SA::Authentication as crate::ServerAuthentication<Peer>>::Error,
            >,
            Resolver::Error,
            Route::Error,
            crate::ConnectError<
                CE,
                crate::ClientTlsError<<CT::Provider as crate::ClientTlsProvider>::Error>,
                crate::ClientAuthenticationError<CA::Error>,
            >,
            K::Error,
            crate::CancelError<CE>,
            <<Boundary as IntermediaryMiddlewareFactory<
                crate::ServerConnectionContext<
                    Peer,
                    <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                >,
                crate::ClientConnectionContext<CA::Evidence>,
            >>::Handler as IntermediaryMiddleware<
                State,
                crate::ServerConnectionContext<
                    Peer,
                    <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                >,
                crate::ClientConnectionContext<CA::Evidence>,
            >>::Error,
        >,
    >
    where
        DT: AsyncRead + AsyncWrite + Unpin,
        UT: AsyncRead + AsyncWrite + Unpin,
        SA::Authentication: crate::ServerAuthentication<Peer>,
        SM: crate::MiddlewareFactory<
                crate::ServerConnectionContext<
                    Peer,
                    <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                >,
            >,
        <SM as crate::MiddlewareFactory<
            crate::ServerConnectionContext<
                Peer,
                <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
            >,
        >>::Handler: crate::ServerMiddleware<
                State,
                crate::ServerConnectionContext<
                    Peer,
                    <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                >,
            >,
        Resolver: StartupRouteResolver<Peer>,
        Connector: Fn(&ConnectTarget) -> CW,
        CW: Future<Output = Result<UT, CE>>,
        <CM as crate::MiddlewareFactory<crate::ClientInitialContext>>::Handler:
            crate::ClientMiddleware<State, crate::ClientConnectionContext<CA::Evidence>>,
        Route: AuthenticatedRoutePolicy<
                Peer,
                <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
            >,
        Boundary: IntermediaryMiddlewareFactory<
                crate::ServerConnectionContext<
                    Peer,
                    <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                >,
                crate::ClientConnectionContext<CA::Evidence>,
            >,
        <Boundary as IntermediaryMiddlewareFactory<
            crate::ServerConnectionContext<
                Peer,
                <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
            >,
            crate::ClientConnectionContext<CA::Evidence>,
        >>::Handler: IntermediaryMiddleware<
                State,
                crate::ServerConnectionContext<
                    Peer,
                    <SA::Authentication as crate::ServerAuthentication<Peer>>::Identity,
                >,
                crate::ClientConnectionContext<CA::Evidence>,
            >,
    {
        let mut resolver = StartupResolverAdapter {
            resolver: &self.resolver,
        };
        let (accepted, selected) = self
            .server
            .accept_routed(transport, peer, state, &mut resolver)
            .await
            .map_err(|error| match error {
                crate::server_component::RoutedAcceptError::Accept(error) => {
                    IntermediaryAcceptError::Server(error)
                }
                crate::server_component::RoutedAcceptError::Route(error) => {
                    IntermediaryAcceptError::StartupRoute(error)
                }
            })?;
        let mut downstream = match accepted {
            crate::ServerAccept::Session(downstream) => downstream,
            crate::ServerAccept::Cancellation(cancellation) => {
                if self.cancellation == CancellationPolicy::Reject {
                    let _ = cancellation.teardown();
                    return Err(IntermediaryAcceptError::CancellationRejected);
                }
                let request = cancellation.request();
                let client_key = crate::demux::CancelKey {
                    process_id: request.process_id(),
                    secret_key: bytes::Bytes::copy_from_slice(request.secret_key()),
                };
                let Some(route) = self.cancellation_registry.resolve(&client_key) else {
                    let _ = cancellation.teardown();
                    return Err(IntermediaryAcceptError::CancellationRejected);
                };
                if let Err(error) = self
                    .client
                    .cancel(route.target(), route.upstream_key())
                    .await
                {
                    let _ = cancellation.teardown();
                    return Err(IntermediaryAcceptError::Cancellation(error));
                }
                let _ = cancellation.teardown();
                return Ok(IntermediaryAccept::CancellationForwarded);
            }
        };
        let startup = match StartupParameters::from_wire(downstream.startup()) {
            Ok(startup) => startup,
            Err(error) => {
                if self.failure_policy == EstablishmentFailurePolicy::SafeDiagnostic {
                    let _ = downstream
                        .send_generated_error(safe_establishment_diagnostic())
                        .await;
                }
                let _ = downstream.teardown();
                return Err(IntermediaryAcceptError::StartupRoute(
                    StartupResolutionError::Parameters(error),
                ));
            }
        };
        let context = AuthenticatedRouteContext {
            peer: downstream.context().peer(),
            identity: downstream.context().identity(),
        };
        let Some(selected) = selected else {
            let _ = downstream.teardown();
            return Err(IntermediaryAcceptError::CancellationRejected);
        };
        let selected = match self.route.route(selected, context).await {
            Ok(target) => target,
            Err(error) => {
                if self.failure_policy == EstablishmentFailurePolicy::SafeDiagnostic {
                    let _ = downstream
                        .send_generated_error(safe_establishment_diagnostic())
                        .await;
                }
                let _ = downstream.teardown();
                return Err(IntermediaryAcceptError::AuthenticatedRoute(error));
            }
        };
        let (mut downstream, mut state) = downstream.into_core_and_state();
        let upstream = match self
            .client
            .connect_core(selected.clone(), startup, &mut state)
            .await
        {
            Ok(upstream) => upstream,
            Err(error) => {
                if self.failure_policy == EstablishmentFailurePolicy::SafeDiagnostic {
                    let diagnostic = safe_establishment_diagnostic();
                    let diagnostic = downstream.intercept_backend(&mut state, diagnostic);
                    if matches!(diagnostic, crate::codec::BackendMessage::ErrorResponse(_)) {
                        // A failed encode/write is a terminal close; do not recursively
                        // invoke failure handling or middleware.
                        let _ = downstream.send_wire_raw(diagnostic).await;
                    }
                }
                let _ = downstream.into_parts();
                return Err(IntermediaryAcceptError::Client(error));
            }
        };
        let boundary = self
            .boundary
            .create(downstream.context(), upstream.context());
        let (client_cancel_key, backend_key_message) =
            match (self.cancellation, upstream.context().backend_key().cloned()) {
                (CancellationPolicy::Forward, Some(upstream_key)) => {
                    let client_key = match self
                        .cancellation_registry
                        .register(CancellationRoute::new(selected.clone(), upstream_key))
                    {
                        Ok(key) => key,
                        Err(error) => {
                            if self.failure_policy == EstablishmentFailurePolicy::SafeDiagnostic {
                                let diagnostic = downstream
                                    .intercept_backend(&mut state, safe_establishment_diagnostic());
                                if matches!(
                                    diagnostic,
                                    crate::codec::BackendMessage::ErrorResponse(_)
                                ) {
                                    let _ = downstream.send_wire_raw(diagnostic).await;
                                }
                            }
                            let _ = downstream.into_parts();
                            let _ = upstream.into_parts();
                            return Err(IntermediaryAcceptError::CancellationRegistry(error));
                        }
                    };
                    let message = crate::codec::BackendMessage::BackendKeyData {
                        process_id: client_key.process_id,
                        secret_key: client_key.secret_key.clone(),
                    };
                    (Some(client_key), Some(message))
                }
                _ => (None, None),
            };
        let mut connection = IntermediaryConnection {
            downstream,
            upstream,
            state,
            boundary,
            pipeline: Pipeline::new(self.pipeline),
            target: selected,
            pending_frontend: None,
            backend_hold: crate::backend_hold::BackendHold::default(),
            backend_hold_limits: self.backend_hold_limits,
            pending_local: VecDeque::new(),
            cancellation_registry: self.cancellation_registry.clone(),
            client_cancel_key,
        };
        if let Some(message) = backend_key_message {
            let expected = message.clone();
            let message = connection
                .boundary
                .backend(
                    connection.downstream.context(),
                    connection.upstream.context(),
                    &mut connection.state,
                    message,
                )
                .await;
            let message = match message {
                Ok(BackendMiddlewareOutput::Forward(message)) => message,
                Ok(
                    BackendMiddlewareOutput::Suppress(_)
                    | BackendMiddlewareOutput::Expand(_)
                    | BackendMiddlewareOutput::Hold,
                ) => {
                    let _ = connection.detach_cancellation();
                    let _ = connection.teardown();
                    return Err(IntermediaryAcceptError::ServerOutput(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "middleware suppressed or expanded generated cancellation key",
                    )));
                }
                Err(error) => {
                    let _ = connection.detach_cancellation();
                    let _ = connection.teardown();
                    return Err(IntermediaryAcceptError::Middleware(error));
                }
            };
            let message = connection
                .downstream
                .intercept_backend(&mut connection.state, message);
            if message != expected {
                let _ = connection.detach_cancellation();
                let _ = connection.teardown();
                return Err(IntermediaryAcceptError::ServerOutput(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "middleware rejected generated cancellation key",
                )));
            }
            if let Err(error) = connection.downstream.send_wire_raw(message).await {
                let _ = connection.detach_cancellation();
                let _ = connection.teardown();
                return Err(IntermediaryAcceptError::ServerOutput(error));
            }
        }
        let ready = connection.downstream.intercept_backend(
            &mut connection.state,
            crate::codec::BackendMessage::ReadyForQuery(crate::codec::TransactionStatus::Idle),
        );
        if !matches!(ready, crate::codec::BackendMessage::ReadyForQuery(_)) {
            let _ = connection.detach_cancellation();
            let _ = connection.teardown();
            return Err(IntermediaryAcceptError::ServerOutput(io::Error::new(
                io::ErrorKind::InvalidData,
                "middleware rejected generated readiness",
            )));
        }
        if let Err(error) = connection.downstream.send_wire_raw(ready).await {
            let _ = connection.detach_cancellation();
            let _ = connection.teardown();
            return Err(IntermediaryAcceptError::ServerOutput(error));
        }
        Ok(IntermediaryAccept::Session(connection))
    }
}
