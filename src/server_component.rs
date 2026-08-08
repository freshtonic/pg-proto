//! Reusable construction and establishment for the client-facing server role.

use std::{fmt, future::Future, io, pin::Pin, sync::Arc};

use bytes::Bytes;
use rustls::{ServerConfig, pki_types::CertificateDer};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    Conn,
    auth::{Ready, TlsServerEndPoint},
    codec::{DEFAULT_MAX_FRAME_LEN, Frontend, FrontendMessage},
    pre_startup::{DEFAULT_MAX_PRE_STARTUP_PACKET_LEN, PreStartupOffer},
    server_auth::ServerProtocolOffer,
    startup::{ProtocolVersion, StartupMessage},
    tls::ServerTls,
    transport::Buffered,
};

/// A non-`Send` future returned by application-defined server authentication.
pub type ServerAuthenticationFuture<'a, Identity, Error> =
    Pin<Box<dyn Future<Output = Result<Identity, Error>> + 'a>>;

/// A reloadable server identity resolved for each TLS connection.
#[derive(Clone)]
pub struct ServerIdentity {
    config: Arc<ServerConfig>,
    leaf_certificate: CertificateDer<'static>,
}

impl ServerIdentity {
    /// Creates an identity from a rustls configuration and its leaf certificate.
    ///
    /// `leaf_certificate` must be the certificate selected by `config`; it is
    /// retained separately because rustls does not expose configured resolver
    /// certificates for PostgreSQL channel-binding derivation.
    #[must_use]
    pub const fn new(config: Arc<ServerConfig>, leaf_certificate: CertificateDer<'static>) -> Self {
        Self {
            config,
            leaf_certificate,
        }
    }
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerIdentity([REDACTED])")
    }
}

/// Application-owned source of the current TLS identity.
pub trait ServerIdentityProvider {
    /// Failure returned while resolving the current identity.
    type Error;

    /// Resolves the identity to use for one new connection.
    ///
    /// # Errors
    ///
    /// Returns the provider's error when no current identity is available.
    fn resolve(&self) -> Result<ServerIdentity, Self::Error>;
}

/// TLS facts recorded after pre-startup negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegotiatedServerTls {
    /// The connection is intentionally plaintext.
    Plaintext,
    /// TLS was negotiated and terminated by this server component.
    Tls {
        /// RFC 5929 `tls-server-end-point` channel-binding bytes.
        server_end_point: Bytes,
    },
}

/// Immutable inputs available to one authentication session.
pub struct ServerAuthenticationRequest<'a, Peer> {
    startup: &'a StartupMessage,
    tls: &'a NegotiatedServerTls,
    peer: &'a Peer,
}

impl<Peer> Copy for ServerAuthenticationRequest<'_, Peer> {}

impl<Peer> Clone for ServerAuthenticationRequest<'_, Peer> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Peer> ServerAuthenticationRequest<'_, Peer> {
    /// Returns the accepted startup message.
    #[must_use]
    pub const fn startup(&self) -> &StartupMessage {
        self.startup
    }

    /// Returns the negotiated transport security fact.
    #[must_use]
    pub const fn tls(&self) -> &NegotiatedServerTls {
        self.tls
    }

    /// Returns immutable caller-supplied peer facts.
    #[must_use]
    pub const fn peer(&self) -> &Peer {
        self.peer
    }
}

/// The next protocol action selected by application authentication policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerAuthenticationAction<Identity> {
    /// Authentication is complete with typed identity evidence.
    Accept(Identity),
    /// Request a PostgreSQL cleartext password response.
    CleartextPassword,
    /// Request a PostgreSQL MD5 password response using the supplied salt.
    Md5Password {
        /// Four-byte server challenge salt.
        salt: [u8; 4],
    },
    /// Offer SASL mechanisms and receive the client's initial response.
    Sasl {
        /// Mechanism names offered in preference order.
        mechanisms: Vec<Bytes>,
    },
    /// Send a recursive SASL challenge.
    SaslContinue(Bytes),
    /// Send SASL server-final data and complete with typed identity evidence.
    SaslFinal {
        /// Verified mechanism-specific server-final data.
        server_final: Bytes,
        /// Typed identity evidence produced by the policy.
        identity: Identity,
    },
    /// Request a Kerberos V5 response token.
    KerberosV5,
    /// Request a GSSAPI response token.
    Gss,
    /// Request an SSPI response token.
    Sspi,
    /// Send a recursive GSS continuation token.
    GssContinue(Bytes),
}

/// Owned client response supplied to application authentication policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerAuthenticationResponse {
    /// Cleartext or MD5 password response body.
    Password(Bytes),
    /// SASL mechanism selection and optional initial response.
    SaslInitial {
        /// Mechanism selected by the client.
        mechanism: Bytes,
        /// Optional mechanism-specific initial data.
        response: Option<Bytes>,
    },
    /// Recursive SASL response body.
    Sasl(Bytes),
    /// Kerberos, GSSAPI, or SSPI response token.
    Token(Bytes),
}

/// Per-connection asynchronous authentication policy.
pub trait ServerAuthentication<Peer> {
    /// Typed evidence produced by successful authentication.
    type Identity;
    /// Application-defined authentication failure.
    type Error;

    /// Starts the application-driven authentication conversation.
    fn start<'a>(
        &'a mut self,
        request: ServerAuthenticationRequest<'a, Peer>,
    ) -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<Self::Identity>, Self::Error>;

    /// Advances the conversation after one protocol response.
    fn respond<'a>(
        &'a mut self,
        request: ServerAuthenticationRequest<'a, Peer>,
        response: ServerAuthenticationResponse,
    ) -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<Self::Identity>, Self::Error>;
}

/// Factory creating one isolated authentication policy per connection.
pub trait ServerAuthenticationProvider {
    /// Per-connection policy type.
    type Authentication;

    /// Creates a fresh policy instance.
    fn create(&self) -> Self::Authentication;
}

/// Typed evidence for an explicitly trusted connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustIdentity;

/// Deterministic failures while constructing a reusable server component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildServerError {
    /// No TLS posture was selected.
    MissingTlsPolicy,
    /// No authentication posture was selected.
    MissingAuthenticationPolicy,
    /// A protocol limit cannot support server-role establishment.
    InvalidProtocolLimits,
}

impl fmt::Display for BuildServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingTlsPolicy => "server TLS policy is required",
            Self::MissingAuthenticationPolicy => "server authentication policy is required",
            Self::InvalidProtocolLimits => {
                "server protocol limits cannot support connection establishment"
            }
        })
    }
}

impl std::error::Error for BuildServerError {}

/// Failures while establishing a live server-role connection.
#[derive(Debug)]
pub enum AcceptError<TlsError = NoServerIdentity, AuthenticationError = std::convert::Infallible> {
    /// The transport failed or the peer sent invalid wire data.
    Io(io::Error),
    /// The startup packet requested an unsupported protocol major version.
    UnsupportedProtocolVersion,
    /// The configured policy requires TLS before startup.
    TlsRequired,
    /// The current TLS identity could not be resolved.
    TlsIdentity(TlsError),
    /// Application authentication rejected the connection.
    Authentication(AuthenticationError),
    /// The client sent a message invalid for the selected authentication mechanism.
    AuthenticationProtocol,
}

impl<TlsError, AuthenticationError> fmt::Display for AcceptError<TlsError, AuthenticationError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::UnsupportedProtocolVersion => {
                formatter.write_str("unsupported PostgreSQL protocol version")
            }
            Self::TlsRequired => formatter.write_str("TLS is required before startup"),
            Self::TlsIdentity(_) => formatter.write_str("server TLS identity is unavailable"),
            Self::Authentication(_) => formatter.write_str("authentication rejected"),
            Self::AuthenticationProtocol => formatter.write_str("invalid authentication response"),
        }
    }
}

impl<TlsError, AuthenticationError> std::error::Error for AcceptError<TlsError, AuthenticationError>
where
    TlsError: std::error::Error + 'static,
    AuthenticationError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::TlsIdentity(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::UnsupportedProtocolVersion | Self::TlsRequired | Self::AuthenticationProtocol => {
                None
            }
        }
    }
}

/// Namespace for explicit server-side TLS policy values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerTlsPolicy;

impl ServerTlsPolicy {
    /// Deliberately serve plaintext and decline encryption negotiation.
    #[allow(non_upper_case_globals)]
    pub const Disabled: DisabledServerTls = DisabledServerTls;

    /// Accepts plaintext or terminates TLS using identities from `provider`.
    #[allow(non_snake_case)]
    pub const fn Optional<Provider>(provider: Provider) -> OptionalServerTls<Provider> {
        OptionalServerTls(provider)
    }

    /// Requires TLS using identities from `provider`.
    #[allow(non_snake_case)]
    pub const fn Required<Provider>(provider: Provider) -> RequiredServerTls<Provider> {
        RequiredServerTls(provider)
    }
}

/// Explicit plaintext-only server TLS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisabledServerTls;

/// Optional server TLS termination backed by a reloadable identity provider.
#[derive(Clone)]
pub struct OptionalServerTls<Provider>(Provider);

/// Required server TLS termination backed by a reloadable identity provider.
#[derive(Clone)]
pub struct RequiredServerTls<Provider>(Provider);

impl<Provider> fmt::Debug for OptionalServerTls<Provider> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OptionalServerTls([REDACTED])")
    }
}

impl<Provider> fmt::Debug for RequiredServerTls<Provider> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequiredServerTls([REDACTED])")
    }
}

/// Marker provider used by the disabled TLS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoServerIdentityProvider;

/// Error returned by the marker provider, which has no identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoServerIdentity;

impl fmt::Display for NoServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("disabled TLS has no identity")
    }
}

impl std::error::Error for NoServerIdentity {}

impl ServerIdentityProvider for NoServerIdentityProvider {
    type Error = NoServerIdentity;

    fn resolve(&self) -> Result<ServerIdentity, Self::Error> {
        Err(NoServerIdentity)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// TLS configuration implemented by the facade policy values.
#[doc(hidden)]
pub trait ServerTlsConfiguration: sealed::Sealed {
    /// Identity provider associated with this policy.
    type Provider: ServerIdentityProvider;
    /// Returns the provider when this policy can terminate TLS.
    fn provider(&self) -> Option<&Self::Provider>;
    /// Reports whether plaintext startup must be rejected.
    fn required(&self) -> bool;
    /// Returns a non-sensitive structural category for diagnostics.
    fn category(&self) -> &'static str;
}

impl sealed::Sealed for DisabledServerTls {}
impl<Provider> sealed::Sealed for OptionalServerTls<Provider> {}
impl<Provider> sealed::Sealed for RequiredServerTls<Provider> {}

impl ServerTlsConfiguration for DisabledServerTls {
    type Provider = NoServerIdentityProvider;
    fn provider(&self) -> Option<&Self::Provider> {
        None
    }
    fn required(&self) -> bool {
        false
    }
    fn category(&self) -> &'static str {
        "disabled"
    }
}

impl<Provider: ServerIdentityProvider> ServerTlsConfiguration for OptionalServerTls<Provider> {
    type Provider = Provider;
    fn provider(&self) -> Option<&Self::Provider> {
        Some(&self.0)
    }
    fn required(&self) -> bool {
        false
    }
    fn category(&self) -> &'static str {
        "optional"
    }
}

impl<Provider: ServerIdentityProvider> ServerTlsConfiguration for RequiredServerTls<Provider> {
    type Provider = Provider;
    fn provider(&self) -> Option<&Self::Provider> {
        Some(&self.0)
    }
    fn required(&self) -> bool {
        true
    }
    fn category(&self) -> &'static str {
        "required"
    }
}

/// Explicit trust authentication, which accepts every protocol-compatible client.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrustServerAuthentication;

impl ServerAuthenticationProvider for TrustServerAuthentication {
    type Authentication = Self;

    fn create(&self) -> Self::Authentication {
        *self
    }
}

impl<Peer> ServerAuthentication<Peer> for TrustServerAuthentication {
    type Identity = TrustIdentity;
    type Error = std::convert::Infallible;

    fn start<'a>(
        &'a mut self,
        _request: ServerAuthenticationRequest<'a, Peer>,
    ) -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<Self::Identity>, Self::Error>
    {
        Box::pin(async { Ok(ServerAuthenticationAction::Accept(TrustIdentity)) })
    }

    fn respond<'a>(
        &'a mut self,
        _request: ServerAuthenticationRequest<'a, Peer>,
        _response: ServerAuthenticationResponse,
    ) -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<Self::Identity>, Self::Error>
    {
        unreachable!("trust authentication accepts before a response")
    }
}

/// Conservative allocation limits applied to newly accepted transports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerProtocolLimits {
    max_frame_len: usize,
    max_pre_startup_packet_len: usize,
}

impl ServerProtocolLimits {
    /// Returns limits with a different maximum tagged-frame length.
    #[must_use]
    pub const fn with_max_frame_len(mut self, bytes: usize) -> Self {
        self.max_frame_len = bytes;
        self
    }

    /// Returns limits with a different maximum untagged startup-packet length.
    #[must_use]
    pub const fn with_max_pre_startup_packet_len(mut self, bytes: usize) -> Self {
        self.max_pre_startup_packet_len = bytes;
        self
    }

    const fn is_valid(self) -> bool {
        self.max_frame_len >= 9
            && self.max_frame_len <= i32::MAX as usize
            && self.max_pre_startup_packet_len >= 8
            && self.max_pre_startup_packet_len <= i32::MAX as usize
    }
}

impl Default for ServerProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            max_pre_startup_packet_len: DEFAULT_MAX_PRE_STARTUP_PACKET_LEN,
        }
    }
}

/// Reusable client-facing PostgreSQL server component.
#[derive(Clone)]
pub struct Server<Tls = DisabledServerTls, Authentication = TrustServerAuthentication> {
    tls: Tls,
    authentication: Authentication,
    limits: ServerProtocolLimits,
}

impl Server {
    /// Starts configuration of a reusable server component.
    #[must_use]
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }
}

impl<Tls: ServerTlsConfiguration, Authentication> fmt::Debug for Server<Tls, Authentication> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Server")
            .field("tls", &self.tls.category())
            .field("authentication", &"<redacted>")
            .field("limits", &self.limits)
            .finish()
    }
}

/// Builder for a reusable [`Server`].
#[derive(Clone)]
pub struct ServerBuilder<Tls = (), Authentication = ()> {
    tls: Option<Tls>,
    authentication: Option<Authentication>,
    limits: ServerProtocolLimits,
}

impl<Tls, Authentication> fmt::Debug for ServerBuilder<Tls, Authentication> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerBuilder")
            .field("tls_configured", &self.tls.is_some())
            .field("authentication_configured", &self.authentication.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            tls: None,
            authentication: None,
            limits: ServerProtocolLimits::default(),
        }
    }
}

impl<Tls, Authentication> ServerBuilder<Tls, Authentication> {
    /// Selects the client-facing TLS posture explicitly.
    #[must_use]
    pub fn tls<Next>(self, policy: Next) -> ServerBuilder<Next, Authentication> {
        ServerBuilder {
            tls: Some(policy),
            authentication: self.authentication,
            limits: self.limits,
        }
    }

    /// Replaces the authentication policy used for each accepted connection.
    #[must_use]
    pub fn authentication<Next>(self, policy: Next) -> ServerBuilder<Tls, Next> {
        ServerBuilder {
            tls: self.tls,
            authentication: Some(policy),
            limits: self.limits,
        }
    }

    /// Replaces the conservative protocol limits.
    #[must_use]
    pub fn limits(mut self, limits: ServerProtocolLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Validates configuration and creates an immutable reusable component.
    ///
    /// # Errors
    ///
    /// Returns an error when either security policy is omitted or a protocol
    /// limit cannot be represented by the PostgreSQL wire format.
    pub fn build(self) -> Result<Server<Tls, Authentication>, BuildServerError> {
        let tls = self.tls.ok_or(BuildServerError::MissingTlsPolicy)?;
        let authentication = self
            .authentication
            .ok_or(BuildServerError::MissingAuthenticationPolicy)?;
        if !self.limits.is_valid() {
            return Err(BuildServerError::InvalidProtocolLimits);
        }
        Ok(Server {
            tls,
            authentication,
            limits: self.limits,
        })
    }
}

/// Immutable facts known about a client-facing connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConnectionContext<Peer, Identity> {
    peer: Peer,
    tls: NegotiatedServerTls,
    identity: Identity,
}

impl<Peer, Identity> ServerConnectionContext<Peer, Identity> {
    /// Returns caller-provided peer metadata.
    #[must_use]
    pub const fn peer(&self) -> &Peer {
        &self.peer
    }

    /// Returns the negotiated TLS fact.
    #[must_use]
    pub const fn tls(&self) -> &NegotiatedServerTls {
        &self.tls
    }

    /// Returns typed evidence from application authentication.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }
}

/// Identity handler used until contextual middleware is configured.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityServerHandler;

/// A decoded out-of-band PostgreSQL cancellation request.
#[derive(Clone, Eq, PartialEq)]
pub struct CancellationRequest {
    process_id: u32,
    secret_key: Bytes,
}

impl fmt::Debug for CancellationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationRequest")
            .field("process_id", &self.process_id)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl CancellationRequest {
    /// Returns the backend process identifier supplied by the client.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Returns the opaque cancellation key supplied by the client.
    #[must_use]
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

/// Result of accepting one caller-established transport.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ServerAccept<Transport, State, Peer, Identity = TrustIdentity> {
    /// Authentication completed and the connection is operational.
    Session(ServerConnection<Transport, State, Peer, Identity>),
    /// The first packet was an out-of-band cancellation request.
    Cancellation(ServerCancellation<Transport, State, Peer>),
}

/// Non-`Send` future returned while accepting one server-role connection.
pub type ServerAcceptFuture<'a, Transport, State, Peer, Identity, TlsError, AuthenticationError> =
    Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ServerAccept<Transport, State, Peer, Identity>,
                        AcceptError<TlsError, AuthenticationError>,
                    >,
                > + 'a,
        >,
    >;

/// An operational server-role connection with all per-connection ownership.
#[derive(Debug)]
pub struct ServerConnection<Transport, State, Peer, Identity = TrustIdentity> {
    conn: ServerConnectionInner<Transport>,
    startup: StartupMessage,
    state: State,
    handler: IdentityServerHandler,
    context: ServerConnectionContext<Peer, Identity>,
}

#[derive(Debug)]
enum ServerConnectionInner<Transport> {
    Plaintext(Box<Conn<Buffered<Transport, Frontend>, Ready>>),
    Tls(Box<Conn<Buffered<ServerTls<Transport>, Frontend>, Ready>>),
}

/// Transport recovered when a server connection is explicitly torn down.
#[derive(Debug)]
pub enum AcceptedServerTransport<Transport> {
    /// The original plaintext transport.
    Plaintext(Transport),
    /// A TLS stream over the original transport.
    Tls(Box<ServerTls<Transport>>),
}

impl<Transport, State, Peer, Identity> ServerConnection<Transport, State, Peer, Identity> {
    /// Returns immutable connection facts.
    #[must_use]
    pub const fn context(&self) -> &ServerConnectionContext<Peer, Identity> {
        &self.context
    }

    /// Returns the caller-owned connection state.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Returns the accepted startup parameters.
    #[must_use]
    pub const fn startup(&self) -> &StartupMessage {
        &self.startup
    }

    /// Receives one operational frontend wire message without advancing the
    /// typed session projection.
    ///
    /// This is the inspection boundary: application policy may inspect or
    /// rewrite the owned message before a later facade operation projects it.
    ///
    /// # Errors
    ///
    /// Returns a transport, decoding, or configured frame-limit error.
    pub async fn receive_wire(&mut self) -> io::Result<FrontendMessage>
    where
        Transport: AsyncRead + AsyncWrite + Unpin,
    {
        match &mut self.conn {
            ServerConnectionInner::Plaintext(conn) => conn.receive_frontend_wire().await,
            ServerConnectionInner::Tls(conn) => conn.receive_frontend_wire().await,
        }
    }

    /// Deliberately ends typed ownership and recovers every connection part.
    #[must_use]
    pub fn teardown(
        self,
    ) -> (
        AcceptedServerTransport<Transport>,
        State,
        IdentityServerHandler,
        ServerConnectionContext<Peer, Identity>,
    ) {
        let transport = match self.conn {
            ServerConnectionInner::Plaintext(conn) => {
                AcceptedServerTransport::Plaintext(conn.into_transport().into_inner())
            }
            ServerConnectionInner::Tls(conn) => {
                AcceptedServerTransport::Tls(Box::new(conn.into_transport().into_inner()))
            }
        };
        (transport, self.state, self.handler, self.context)
    }
}

/// A cancellation branch retaining all caller and handler ownership.
#[derive(Debug)]
pub struct ServerCancellation<Transport, State, Peer> {
    transport: AcceptedServerTransport<Transport>,
    request: CancellationRequest,
    state: State,
    handler: IdentityServerHandler,
    context: ServerConnectionContext<Peer, ()>,
}

impl<Transport, State, Peer> ServerCancellation<Transport, State, Peer> {
    /// Returns the decoded request.
    #[must_use]
    pub const fn request(&self) -> &CancellationRequest {
        &self.request
    }

    /// Recovers every owned cancellation-connection part.
    #[must_use]
    pub fn teardown(
        self,
    ) -> (
        AcceptedServerTransport<Transport>,
        CancellationRequest,
        State,
        IdentityServerHandler,
        ServerConnectionContext<Peer, ()>,
    ) {
        (
            self.transport,
            self.request,
            self.state,
            self.handler,
            self.context,
        )
    }
}

impl<Tls, Authentication> Server<Tls, Authentication>
where
    Tls: ServerTlsConfiguration,
    Authentication: ServerAuthenticationProvider,
{
    /// Accepts one transport through TLS negotiation and application authentication.
    ///
    /// The caller retains listener and task ownership. `state` and `peer` become
    /// owned parts of either returned branch.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::Io`] for transport or wire failures,
    /// [`AcceptError::UnsupportedProtocolVersion`] for unsupported startup,
    /// [`AcceptError::TlsRequired`] when required TLS was bypassed,
    /// [`AcceptError::TlsIdentity`] with the provider's typed error when the
    /// current identity cannot be resolved, [`AcceptError::Authentication`]
    /// with the policy's typed error when authentication rejects the client,
    /// or [`AcceptError::AuthenticationProtocol`] for an invalid response to
    /// the selected wire mechanism.
    #[allow(clippy::type_complexity)]
    pub fn accept<'a, Transport, State, Peer>(
        &'a self,
        transport: Transport,
        peer: Peer,
        state: State,
    ) -> ServerAcceptFuture<
        'a,
        Transport,
        State,
        Peer,
        <Authentication::Authentication as ServerAuthentication<Peer>>::Identity,
        <Tls::Provider as ServerIdentityProvider>::Error,
        <Authentication::Authentication as ServerAuthentication<Peer>>::Error,
    >
    where
        Transport: AsyncRead + AsyncWrite + Unpin + 'a,
        State: 'a,
        Peer: 'a,
        Authentication::Authentication: ServerAuthentication<Peer>,
    {
        Box::pin(self.accept_inner(transport, peer, state))
    }

    async fn accept_inner<Transport, State, Peer>(
        &self,
        transport: Transport,
        peer: Peer,
        state: State,
    ) -> Result<
        ServerAccept<
            Transport,
            State,
            Peer,
            <Authentication::Authentication as ServerAuthentication<Peer>>::Identity,
        >,
        AcceptError<
            <Tls::Provider as ServerIdentityProvider>::Error,
            <Authentication::Authentication as ServerAuthentication<Peer>>::Error,
        >,
    >
    where
        Transport: AsyncRead + AsyncWrite + Unpin,
        Authentication::Authentication: ServerAuthentication<Peer>,
    {
        let handler = IdentityServerHandler;
        let buffered = self.buffer_transport(transport).map_err(AcceptError::Io)?;
        let mut conn = Conn::new(buffered);

        loop {
            let message = match conn.receive_pre_startup_wire().await {
                Ok(message) => message,
                Err(error) => {
                    let _ = conn.into_transport();
                    return Err(AcceptError::Io(error));
                }
            };
            match conn.offer_pre_startup(message) {
                PreStartupOffer::Ssl(decision) => match self.tls.provider() {
                    None => {
                        conn = decision.decline_ssl();
                        conn = flush_or_abort(conn).await?;
                    }
                    Some(provider) => {
                        let identity = match provider.resolve() {
                            Ok(identity) => identity,
                            Err(error) => {
                                let _ = decision.into_transport();
                                return Err(AcceptError::TlsIdentity(error));
                            }
                        };
                        let handshake = decision.approve_ssl();
                        let handshake = flush_or_abort(handshake).await?;
                        let encrypted = handshake
                            .accept_tls(identity.config, identity.leaf_certificate)
                            .await
                            .map_err(AcceptError::Io)?;
                        return accept_encrypted(
                            encrypted,
                            peer,
                            state,
                            handler,
                            &self.authentication,
                        )
                        .await;
                    }
                },
                PreStartupOffer::Gss(decision) => {
                    conn = decision.decline_gss();
                    conn = flush_or_abort(conn).await?;
                }
                PreStartupOffer::Cancel {
                    conn: terminal,
                    process_id,
                    secret_key,
                } => {
                    return Ok(ServerAccept::Cancellation(ServerCancellation {
                        transport: AcceptedServerTransport::Plaintext(
                            terminal.into_transport().into_inner(),
                        ),
                        request: CancellationRequest {
                            process_id,
                            secret_key,
                        },
                        state,
                        handler,
                        context: ServerConnectionContext {
                            peer,
                            tls: NegotiatedServerTls::Plaintext,
                            identity: (),
                        },
                    }));
                }
                PreStartupOffer::Startup {
                    conn: startup_conn,
                    message,
                } => {
                    if self.tls.required() {
                        let _ = startup_conn.into_transport();
                        return Err(AcceptError::TlsRequired);
                    }
                    let (ready, identity) = complete_auth(
                        startup_conn,
                        &message,
                        &NegotiatedServerTls::Plaintext,
                        &peer,
                        &self.authentication,
                    )
                    .await?;
                    return Ok(ServerAccept::Session(ServerConnection {
                        conn: ServerConnectionInner::Plaintext(Box::new(ready)),
                        startup: message,
                        state,
                        handler,
                        context: ServerConnectionContext {
                            peer,
                            tls: NegotiatedServerTls::Plaintext,
                            identity,
                        },
                    }));
                }
            }
        }
    }

    fn buffer_transport<Transport>(
        &self,
        transport: Transport,
    ) -> io::Result<Buffered<Transport, Frontend>> {
        Buffered::with_limits_frontend(
            transport,
            self.limits.max_frame_len,
            self.limits.max_pre_startup_packet_len,
        )
    }
}

async fn accept_encrypted<Transport, State, Peer, Authentication, TlsError>(
    mut conn: Conn<Buffered<ServerTls<Transport>, Frontend>, crate::pre_startup::PreStartup>,
    peer: Peer,
    state: State,
    handler: IdentityServerHandler,
    authentication: &Authentication,
) -> Result<
    ServerAccept<
        Transport,
        State,
        Peer,
        <Authentication::Authentication as ServerAuthentication<Peer>>::Identity,
    >,
    AcceptError<TlsError, <Authentication::Authentication as ServerAuthentication<Peer>>::Error>,
>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
    Authentication: ServerAuthenticationProvider,
    Authentication::Authentication: ServerAuthentication<Peer>,
{
    let negotiated_tls = NegotiatedServerTls::Tls {
        server_end_point: Bytes::copy_from_slice(conn.transport().get_ref().tls_server_end_point()),
    };
    loop {
        let message = match conn.receive_pre_startup_wire().await {
            Ok(message) => message,
            Err(error) => {
                let _ = conn.into_transport();
                return Err(AcceptError::Io(error));
            }
        };
        match conn.offer_pre_startup(message) {
            PreStartupOffer::Ssl(decision) => {
                conn = decision.decline_ssl();
                conn = flush_or_abort(conn).await?;
            }
            PreStartupOffer::Gss(decision) => {
                conn = decision.decline_gss();
                conn = flush_or_abort(conn).await?;
            }
            PreStartupOffer::Cancel {
                conn: terminal,
                process_id,
                secret_key,
            } => {
                return Ok(ServerAccept::Cancellation(ServerCancellation {
                    transport: AcceptedServerTransport::Tls(Box::new(
                        terminal.into_transport().into_inner(),
                    )),
                    request: CancellationRequest {
                        process_id,
                        secret_key,
                    },
                    state,
                    handler,
                    context: ServerConnectionContext {
                        peer,
                        tls: negotiated_tls.clone(),
                        identity: (),
                    },
                }));
            }
            PreStartupOffer::Startup {
                conn: startup_conn,
                message,
            } => {
                let (ready, identity) = complete_auth(
                    startup_conn,
                    &message,
                    &negotiated_tls,
                    &peer,
                    authentication,
                )
                .await?;
                return Ok(ServerAccept::Session(ServerConnection {
                    conn: ServerConnectionInner::Tls(Box::new(ready)),
                    startup: message,
                    state,
                    handler,
                    context: ServerConnectionContext {
                        peer,
                        tls: negotiated_tls,
                        identity,
                    },
                }));
            }
        }
    }
}

async fn complete_auth<I, Authentication, Peer, TlsError>(
    startup_conn: Conn<Buffered<I, Frontend>, crate::pre_startup::Startup>,
    message: &StartupMessage,
    tls: &NegotiatedServerTls,
    peer: &Peer,
    provider: &Authentication,
) -> Result<
    (
        Conn<Buffered<I, Frontend>, Ready>,
        <Authentication::Authentication as ServerAuthentication<Peer>>::Identity,
    ),
    AcceptError<TlsError, <Authentication::Authentication as ServerAuthentication<Peer>>::Error>,
>
where
    I: AsyncRead + AsyncWrite + Unpin,
    Authentication: ServerAuthenticationProvider,
    Authentication::Authentication: ServerAuthentication<Peer>,
{
    let validated = match startup_conn.validate_protocol(message.clone(), ProtocolVersion::V3_2) {
        ServerProtocolOffer::Supported { conn, .. } => conn,
        ServerProtocolOffer::Rejected { conn, .. } => {
            let _ = conn.into_transport();
            return Err(AcceptError::UnsupportedProtocolVersion);
        }
    };
    let mut policy = provider.create();
    let auth = validated.begin_server_auth();
    let request = ServerAuthenticationRequest {
        startup: message,
        tls,
        peer,
    };
    let action = match policy.start(request).await {
        Ok(action) => action,
        Err(error) => {
            let _ = auth.into_transport();
            return Err(AcceptError::Authentication(error));
        }
    };
    let (auth, identity, final_frame) = match action {
        ServerAuthenticationAction::Accept(identity) => (auth, identity, None),
        action @ (ServerAuthenticationAction::CleartextPassword
        | ServerAuthenticationAction::Md5Password { .. }) => {
            let (waiting, frame) = match action {
                ServerAuthenticationAction::CleartextPassword => auth.request_cleartext(),
                ServerAuthenticationAction::Md5Password { salt } => auth.request_md5(salt),
                _ => unreachable!("matched password action"),
            }
            .map_err(AcceptError::Io)?;
            let waiting = push_or_abort(waiting, frame)?;
            let waiting = flush_or_abort(waiting).await?;
            let (waiting, wire) = receive_frontend_or_abort(waiting).await?;
            let (auth, credential) = match waiting.receive_password(wire) {
                Ok(response) => response,
                Err(rejected) => {
                    let (waiting, _) = *rejected;
                    let _ = waiting.into_transport();
                    return Err(AcceptError::AuthenticationProtocol);
                }
            };
            match policy
                .respond(request, ServerAuthenticationResponse::Password(credential))
                .await
            {
                Ok(ServerAuthenticationAction::Accept(identity)) => (auth, identity, None),
                Ok(_) => {
                    let _ = auth.into_transport();
                    return Err(AcceptError::AuthenticationProtocol);
                }
                Err(error) => {
                    let _ = auth.into_transport();
                    return Err(AcceptError::Authentication(error));
                }
            }
        }
        ServerAuthenticationAction::Sasl { mechanisms } => {
            authenticate_sasl(auth, mechanisms, &mut policy, request).await?
        }
        action @ (ServerAuthenticationAction::KerberosV5
        | ServerAuthenticationAction::Gss
        | ServerAuthenticationAction::Sspi) => {
            authenticate_token(auth, action, &mut policy, request).await?
        }
        ServerAuthenticationAction::SaslContinue(_)
        | ServerAuthenticationAction::SaslFinal { .. }
        | ServerAuthenticationAction::GssContinue(_) => {
            let _ = auth.into_transport();
            return Err(AcceptError::AuthenticationProtocol);
        }
    };
    let (mut startup_ready, authentication_ok) =
        auth.authentication_ok().map_err(AcceptError::Io)?;
    if let Some(final_frame) = final_frame {
        startup_ready = push_or_abort(startup_ready, final_frame)?;
    }
    let startup_ready = push_or_abort(startup_ready, authentication_ok)?;
    let (ready, ready_frame) = startup_ready.ready().map_err(AcceptError::Io)?;
    let ready = push_or_abort(ready, ready_frame)?;
    let ready = flush_or_abort(ready).await?;
    Ok((ready, identity))
}

async fn authenticate_sasl<I, Policy, Peer, TlsError>(
    auth: Conn<Buffered<I, Frontend>, crate::server_auth::ServerAuth>,
    mechanisms: Vec<Bytes>,
    policy: &mut Policy,
    request: ServerAuthenticationRequest<'_, Peer>,
) -> Result<
    (
        Conn<Buffered<I, Frontend>, crate::server_auth::ServerAuth>,
        Policy::Identity,
        Option<crate::codec::Frame>,
    ),
    AcceptError<TlsError, Policy::Error>,
>
where
    I: AsyncRead + AsyncWrite + Unpin,
    Policy: ServerAuthentication<Peer>,
{
    if mechanisms.iter().any(|mechanism| mechanism.contains(&0)) {
        let _ = auth.into_transport();
        return Err(AcceptError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SASL mechanism contains NUL",
        )));
    }
    let (initial, frame) = auth.request_sasl(mechanisms).map_err(AcceptError::Io)?;
    let initial = push_or_abort(initial, frame)?;
    let initial = flush_or_abort(initial).await?;
    let (initial, wire) = receive_frontend_or_abort(initial).await?;
    let (mut sasl, initial_response) = match initial.receive_initial(wire) {
        Ok(response) => response,
        Err(rejected) => {
            let (initial, _) = *rejected;
            let _ = initial.into_transport();
            return Err(AcceptError::AuthenticationProtocol);
        }
    };
    let mut action = match policy
        .respond(
            request,
            ServerAuthenticationResponse::SaslInitial {
                mechanism: initial_response.mechanism,
                response: initial_response.response,
            },
        )
        .await
    {
        Ok(action) => action,
        Err(error) => {
            let _ = sasl.into_transport();
            return Err(AcceptError::Authentication(error));
        }
    };
    loop {
        match action {
            ServerAuthenticationAction::SaslContinue(challenge) => {
                let (waiting, frame) = sasl.continue_with(challenge).map_err(AcceptError::Io)?;
                let waiting = push_or_abort(waiting, frame)?;
                let waiting = flush_or_abort(waiting).await?;
                let (waiting, wire) = receive_frontend_or_abort(waiting).await?;
                let (next, response) = match waiting.receive_response(wire) {
                    Ok(response) => response,
                    Err(rejected) => {
                        let (waiting, _) = *rejected;
                        let _ = waiting.into_transport();
                        return Err(AcceptError::AuthenticationProtocol);
                    }
                };
                sasl = next;
                action = match policy
                    .respond(request, ServerAuthenticationResponse::Sasl(response))
                    .await
                {
                    Ok(action) => action,
                    Err(error) => {
                        let _ = sasl.into_transport();
                        return Err(AcceptError::Authentication(error));
                    }
                };
            }
            ServerAuthenticationAction::SaslFinal {
                server_final,
                identity,
            } => {
                let (auth, frame) = sasl.finish(server_final).map_err(AcceptError::Io)?;
                return Ok((auth, identity, Some(frame)));
            }
            _ => {
                let _ = sasl.into_transport();
                return Err(AcceptError::AuthenticationProtocol);
            }
        }
    }
}

async fn authenticate_token<I, Policy, Peer, TlsError>(
    auth: Conn<Buffered<I, Frontend>, crate::server_auth::ServerAuth>,
    initial_action: ServerAuthenticationAction<Policy::Identity>,
    policy: &mut Policy,
    request: ServerAuthenticationRequest<'_, Peer>,
) -> Result<
    (
        Conn<Buffered<I, Frontend>, crate::server_auth::ServerAuth>,
        Policy::Identity,
        Option<crate::codec::Frame>,
    ),
    AcceptError<TlsError, Policy::Error>,
>
where
    I: AsyncRead + AsyncWrite + Unpin,
    Policy: ServerAuthentication<Peer>,
{
    let (waiting, frame) = match initial_action {
        ServerAuthenticationAction::KerberosV5 => auth.request_kerberos_v5(),
        ServerAuthenticationAction::Gss => auth.request_gss(),
        ServerAuthenticationAction::Sspi => auth.request_sspi(),
        _ => unreachable!("matched initial token action"),
    }
    .map_err(AcceptError::Io)?;
    let waiting = push_or_abort(waiting, frame)?;
    let mut waiting = flush_or_abort(waiting).await?;
    loop {
        let received = receive_frontend_or_abort(waiting).await?;
        waiting = received.0;
        let wire = received.1;
        let (decision, token) = match waiting.receive_response(wire) {
            Ok(response) => response,
            Err(rejected) => {
                let (waiting, _) = *rejected;
                let _ = waiting.into_transport();
                return Err(AcceptError::AuthenticationProtocol);
            }
        };
        let action = match policy
            .respond(request, ServerAuthenticationResponse::Token(token))
            .await
        {
            Ok(action) => action,
            Err(error) => {
                let _ = decision.into_transport();
                return Err(AcceptError::Authentication(error));
            }
        };
        match action {
            ServerAuthenticationAction::Accept(identity) => {
                return Ok((decision.verified(), identity, None));
            }
            ServerAuthenticationAction::GssContinue(token) => {
                let (next, frame) = decision.continue_gss(token).map_err(AcceptError::Io)?;
                let next = push_or_abort(next, frame)?;
                waiting = flush_or_abort(next).await?;
            }
            _ => {
                let _ = decision.into_transport();
                return Err(AcceptError::AuthenticationProtocol);
            }
        }
    }
}

async fn flush_or_abort<I, D, Phase, TlsError, AuthenticationError>(
    mut conn: Conn<Buffered<I, D>, Phase>,
) -> Result<Conn<Buffered<I, D>, Phase>, AcceptError<TlsError, AuthenticationError>>
where
    I: AsyncWrite + Unpin,
{
    if let Err(error) = conn.flush().await {
        let _ = conn.into_transport();
        return Err(AcceptError::Io(error));
    }
    Ok(conn)
}

fn push_or_abort<I, D, Phase, TlsError, AuthenticationError>(
    mut conn: Conn<Buffered<I, D>, Phase>,
    frame: crate::codec::Frame,
) -> Result<Conn<Buffered<I, D>, Phase>, AcceptError<TlsError, AuthenticationError>> {
    if let Err(error) = conn.push_frame(frame) {
        let _ = conn.into_transport();
        return Err(AcceptError::Io(error));
    }
    Ok(conn)
}

async fn receive_frontend_or_abort<I, Phase, TlsError, AuthenticationError>(
    mut conn: Conn<Buffered<I, Frontend>, Phase>,
) -> Result<
    (Conn<Buffered<I, Frontend>, Phase>, FrontendMessage),
    AcceptError<TlsError, AuthenticationError>,
>
where
    I: AsyncRead + Unpin,
{
    match conn.receive_frontend_wire().await {
        Ok(message) => Ok((conn, message)),
        Err(error) => {
            let _ = conn.into_transport();
            Err(AcceptError::Io(error))
        }
    }
}
