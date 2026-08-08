//! Builder-centred composition of the client-facing and PostgreSQL-facing roles.

use std::{fmt, future::Future, io, pin::Pin};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    ConnectTarget, NoPipeline, StartupParameters,
    pipeline::{BackendAction, FrontendAction, FrontendHandling, Pipeline, PipelinePolicy},
};

/// Required posture for out-of-band cancellation connections.
///
/// Forwarding cancellation is implemented by issue #36. Until then the only
/// safe operational posture is an explicit rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationPolicy {
    /// Reject cancellation packets instead of silently routing them.
    Reject,
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

/// Middleware at the forwarding boundary between the two role components.
pub trait IntermediaryMiddleware<State, ServerContext, ClientContext> {
    /// Intercepts a client-originated message after server-role middleware and
    /// before client-role middleware.
    fn frontend(
        &mut self,
        _server: &ServerContext,
        _client: &ClientContext,
        _state: &mut State,
        message: crate::codec::FrontendMessage,
    ) -> crate::codec::FrontendMessage {
        message
    }

    /// Intercepts a PostgreSQL-originated message after client-role middleware
    /// and before server-role middleware.
    fn backend(
        &mut self,
        _server: &ServerContext,
        _client: &ClientContext,
        _state: &mut State,
        message: crate::codec::BackendMessage,
    ) -> crate::codec::BackendMessage {
        message
    }
}

/// Identity forwarding-boundary middleware.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityIntermediaryMiddleware;

impl<State, ServerContext, ClientContext>
    IntermediaryMiddleware<State, ServerContext, ClientContext> for IdentityIntermediaryMiddleware
{
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
> {
    pub(crate) server: Server,
    pub(crate) client: Client,
    pub(crate) resolver: Resolver,
    pub(crate) route: Route,
    pub(crate) pipeline: Policy,
    pub(crate) boundary: Boundary,
    pub(crate) cancellation: CancellationPolicy,
}

impl Intermediary<()> {
    /// Starts composition of the two complete role configurations.
    #[must_use]
    pub fn builder() -> IntermediaryBuilder {
        IntermediaryBuilder::default()
    }
}

impl<S, C, R, A, P, B> fmt::Debug for Intermediary<S, C, R, A, P, B> {
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
> {
    server: Option<Server>,
    client: Option<Client>,
    resolver: Option<Resolver>,
    route: Route,
    pipeline: Policy,
    boundary: Boundary,
    cancellation: Option<CancellationPolicy>,
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
        }
    }
}

impl<S, C, R, A, P, B> IntermediaryBuilder<S, C, R, A, P, B> {
    /// Supplies the complete client-facing role configuration.
    #[must_use]
    pub fn server<Next>(self, server: Next) -> IntermediaryBuilder<Next, C, R, A, P, B> {
        IntermediaryBuilder {
            server: Some(server),
            client: self.client,
            resolver: self.resolver,
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
        }
    }

    /// Supplies the complete PostgreSQL-facing role configuration.
    #[must_use]
    pub fn client<Next>(self, client: Next) -> IntermediaryBuilder<S, Next, R, A, P, B> {
        IntermediaryBuilder {
            server: self.server,
            client: Some(client),
            resolver: self.resolver,
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
        }
    }

    /// Supplies the required asynchronous startup resolver.
    #[must_use]
    pub fn startup_resolver<Next>(
        self,
        resolver: Next,
    ) -> IntermediaryBuilder<S, C, Next, A, P, B> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: Some(resolver),
            route: self.route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
        }
    }

    /// Supplies optional post-authentication routing policy.
    #[must_use]
    pub fn authenticated_route<Next>(
        self,
        route: Next,
    ) -> IntermediaryBuilder<S, C, R, Next, P, B> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: self.resolver,
            route,
            pipeline: self.pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
        }
    }

    /// Selects lock-step or bounded request pipelining.
    #[must_use]
    pub fn pipeline<Next: PipelinePolicy>(
        self,
        pipeline: Next,
    ) -> IntermediaryBuilder<S, C, R, A, Next, B> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: self.resolver,
            route: self.route,
            pipeline,
            boundary: self.boundary,
            cancellation: self.cancellation,
        }
    }

    /// Supplies middleware for the forwarding boundary.
    #[must_use]
    pub fn middleware<Next>(self, boundary: Next) -> IntermediaryBuilder<S, C, R, A, P, Next> {
        IntermediaryBuilder {
            server: self.server,
            client: self.client,
            resolver: self.resolver,
            route: self.route,
            pipeline: self.pipeline,
            boundary,
            cancellation: self.cancellation,
        }
    }

    /// Selects an explicit cancellation posture.
    #[must_use]
    pub fn cancellation(mut self, cancellation: CancellationPolicy) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Validates composition and creates a reusable component.
    ///
    /// # Errors
    ///
    /// Returns the first missing mandatory role, resolver, or cancellation configuration.
    pub fn build(self) -> Result<Intermediary<S, C, R, A, P, B>, IntermediaryBuildError> {
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
#[derive(Debug)]
pub enum IntermediaryAcceptError<ServerError, ResolverError, RouteError, ClientError> {
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
}

impl<S: fmt::Display, R: fmt::Display, A: fmt::Display, C: fmt::Display> fmt::Display
    for IntermediaryAcceptError<S, R, A, C>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(error) => error.fmt(formatter),
            Self::StartupRoute(error) => error.fmt(formatter),
            Self::CancellationRejected => {
                formatter.write_str("cancellation is explicitly rejected")
            }
            Self::AuthenticatedRoute(error) => error.fmt(formatter),
            Self::Client(error) => error.fmt(formatter),
        }
    }
}

impl<S, R, A, C> std::error::Error for IntermediaryAcceptError<S, R, A, C>
where
    S: std::error::Error + 'static,
    R: std::error::Error + 'static,
    A: std::error::Error + 'static,
    C: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Server(error) => Some(error),
            Self::StartupRoute(error) => Some(error),
            Self::CancellationRejected => None,
            Self::AuthenticatedRoute(error) => Some(error),
            Self::Client(error) => Some(error),
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
}

/// Direction selected by one cancellation-safe duplex forwarding step.
#[derive(Debug)]
pub enum ForwardedMessage {
    /// A client-originated message was forwarded to PostgreSQL.
    Frontend(crate::codec::FrontendMessage),
    /// A PostgreSQL-originated message was forwarded to the client.
    Backend(crate::codec::BackendMessage),
}

impl<DT, UT, State, Peer, SI, CE, SH, CH, Boundary, Policy>
    IntermediaryConnection<DT, UT, State, Peer, SI, CE, SH, CH, Boundary, Policy>
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
    /// Returns the request/response legality and backpressure ledger.
    #[must_use]
    pub const fn pipeline(&self) -> &Pipeline<Policy> {
        &self.pipeline
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
{
    /// Receives one legal client message and forwards it upstream in
    /// source-role, boundary, destination-role middleware order.
    ///
    /// # Errors
    ///
    /// Returns transport, framing, protocol-legality, or capacity failures.
    pub async fn forward_frontend(
        &mut self,
    ) -> Result<crate::codec::FrontendMessage, ForwardError> {
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
    ) -> Result<crate::codec::FrontendMessage, ForwardError> {
        let message = if intercept_source_and_boundary {
            let message = self.downstream.intercept_frontend(&mut self.state, message);
            let message = self.boundary.frontend(
                self.downstream.context(),
                self.upstream.context(),
                &mut self.state,
                message,
            );
            self.upstream.intercept_frontend(&mut self.state, message)
        } else {
            message
        };
        let admission = match self
            .pipeline
            .accept_frontend(message.clone(), FrontendHandling::Forward)
        {
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
        Ok(message)
    }

    /// Receives one legal PostgreSQL response and forwards it downstream in
    /// source-role, boundary, destination-role middleware order.
    ///
    /// # Errors
    ///
    /// Returns transport, framing, ordering, or protocol-legality failures.
    pub async fn forward_backend(&mut self) -> Result<crate::codec::BackendMessage, ForwardError> {
        let message = self.upstream.receive_wire_raw().await?;
        self.process_backend(message).await
    }

    async fn process_backend(
        &mut self,
        message: crate::codec::BackendMessage,
    ) -> Result<crate::codec::BackendMessage, ForwardError> {
        let message = self.upstream.intercept_backend(&mut self.state, message);
        let message = self.boundary.backend(
            self.downstream.context(),
            self.upstream.context(),
            &mut self.state,
            message,
        );
        let message = self.downstream.intercept_backend(&mut self.state, message);
        let message = match self
            .pipeline
            .accept_backend(message)
            .map_err(ForwardError::Backend)?
        {
            BackendAction::Emit(message) => message,
            BackendAction::Deferred(message) => return Err(ForwardError::Deferred(message)),
        };
        self.downstream.send_wire_raw(message.clone()).await?;
        Ok(message)
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
    pub async fn forward_next(&mut self) -> Result<ForwardedMessage, ForwardError> {
        if self.pending_frontend.is_some() {
            let message = self.upstream.receive_wire_raw().await?;
            return self
                .process_backend(message)
                .await
                .map(ForwardedMessage::Backend);
        }
        tokio::select! {
            result = self.downstream.receive_wire_raw() => {
                let message = result?;
                self.process_frontend(message, true).await.map(ForwardedMessage::Frontend)
            }
            result = self.upstream.receive_wire_raw() => {
                let message = result?;
                self.process_backend(message).await.map(ForwardedMessage::Backend)
            }
        }
    }

    /// Deliberately tears down both roles and recovers transports, handlers,
    /// contexts, boundary middleware, and the sole connection state.
    #[allow(clippy::type_complexity)]
    pub fn teardown(
        self,
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
pub enum ForwardError {
    /// Transport, decoding, or encoding failure.
    Io(io::Error),
    /// Frontend backpressure or protocol-legality rejection.
    Frontend(crate::pipeline::FrontendProjectionError),
    /// Backend protocol-legality rejection.
    Backend(crate::pipeline::BackendProjectionError),
    /// A bounded response arrived before its operation became emittable.
    Deferred(crate::codec::BackendMessage),
}

impl fmt::Display for ForwardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Frontend(_) => {
                formatter.write_str("frontend message violates pipeline legality or capacity")
            }
            Self::Backend(_) => formatter.write_str("backend message violates pipeline legality"),
            Self::Deferred(_) => formatter.write_str("backend response is not yet emittable"),
        }
    }
}

impl std::error::Error for ForwardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ForwardError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl<ST, SA, SM, Connector, CT, CA, CM, Resolver, Route, Policy, Boundary>
    Intermediary<
        crate::Server<ST, SA, SM>,
        crate::Client<Connector, CT, CA, CM>,
        Resolver,
        Route,
        Policy,
        Boundary,
    >
where
    ST: crate::ServerTlsConfiguration,
    SA: crate::ServerAuthenticationProvider,
    CT: crate::client_component::ClientTlsConfiguration,
    CA: crate::ClientAuthentication,
    CM: crate::MiddlewareFactory<crate::ClientInitialContext>,
    Policy: PipelinePolicy,
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
        let crate::ServerAccept::Session(downstream) = accepted else {
            return Err(IntermediaryAcceptError::CancellationRejected);
        };
        let startup = match StartupParameters::from_wire(downstream.startup()) {
            Ok(startup) => startup,
            Err(error) => {
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
                let _ = downstream.teardown();
                return Err(IntermediaryAcceptError::AuthenticatedRoute(error));
            }
        };
        let (downstream, mut state) = downstream.into_core_and_state();
        let upstream = match self
            .client
            .connect_core(selected.clone(), startup, &mut state)
            .await
        {
            Ok(upstream) => upstream,
            Err(error) => {
                let _ = downstream.into_parts();
                return Err(IntermediaryAcceptError::Client(error));
            }
        };
        let boundary = self
            .boundary
            .create(downstream.context(), upstream.context());
        Ok(IntermediaryConnection {
            downstream,
            upstream,
            state,
            boundary,
            pipeline: Pipeline::new(self.pipeline),
            target: selected,
            pending_frontend: None,
        })
    }
}
