//! Reusable construction and establishment for the client-facing server role.

use std::{fmt, io};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    Conn,
    auth::Ready,
    codec::{DEFAULT_MAX_FRAME_LEN, Frontend, FrontendMessage},
    pre_startup::{DEFAULT_MAX_PRE_STARTUP_PACKET_LEN, PreStartupOffer},
    server_auth::ServerProtocolOffer,
    startup::{ProtocolVersion, StartupMessage},
    transport::Buffered,
};

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
pub enum AcceptError {
    /// The transport failed or the peer sent invalid wire data.
    Io(io::Error),
    /// The startup packet requested an unsupported protocol major version.
    UnsupportedProtocolVersion,
}

impl fmt::Display for AcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::UnsupportedProtocolVersion => {
                formatter.write_str("unsupported PostgreSQL protocol version")
            }
        }
    }
}

impl std::error::Error for AcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::UnsupportedProtocolVersion => None,
        }
    }
}

/// Server-side TLS posture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerTlsPolicy {
    /// Deliberately serve plaintext and decline encryption negotiation.
    Disabled,
}

/// Explicit trust authentication, which accepts every protocol-compatible client.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrustServerAuthentication;

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
pub struct Server<Authentication = TrustServerAuthentication> {
    tls: ServerTlsPolicy,
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

impl<Authentication> fmt::Debug for Server<Authentication> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Server")
            .field("tls", &self.tls)
            .field("authentication", &"<redacted>")
            .field("limits", &self.limits)
            .finish()
    }
}

/// Builder for a reusable [`Server`].
#[derive(Clone, Debug)]
pub struct ServerBuilder<Authentication = ()> {
    tls: Option<ServerTlsPolicy>,
    authentication: Option<Authentication>,
    limits: ServerProtocolLimits,
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

impl<Authentication> ServerBuilder<Authentication> {
    /// Selects the client-facing TLS posture explicitly.
    #[must_use]
    pub fn tls(mut self, policy: ServerTlsPolicy) -> Self {
        self.tls = Some(policy);
        self
    }

    /// Replaces the authentication policy used for each accepted connection.
    #[must_use]
    pub fn authentication<Next>(self, policy: Next) -> ServerBuilder<Next> {
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
    pub fn build(self) -> Result<Server<Authentication>, BuildServerError> {
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
pub struct ServerConnectionContext<Peer> {
    peer: Peer,
}

impl<Peer> ServerConnectionContext<Peer> {
    /// Returns caller-provided peer metadata.
    #[must_use]
    pub const fn peer(&self) -> &Peer {
        &self.peer
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
pub enum ServerAccept<Transport, State, Peer> {
    /// Authentication completed and the connection is operational.
    Session(ServerConnection<Transport, State, Peer>),
    /// The first packet was an out-of-band cancellation request.
    Cancellation(ServerCancellation<Transport, State, Peer>),
}

/// An operational server-role connection with all per-connection ownership.
#[derive(Debug)]
pub struct ServerConnection<Transport, State, Peer> {
    conn: Conn<Buffered<Transport, Frontend>, Ready>,
    startup: StartupMessage,
    state: State,
    handler: IdentityServerHandler,
    context: ServerConnectionContext<Peer>,
}

impl<Transport, State, Peer> ServerConnection<Transport, State, Peer> {
    /// Returns immutable connection facts.
    #[must_use]
    pub const fn context(&self) -> &ServerConnectionContext<Peer> {
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
        Transport: AsyncRead + Unpin,
    {
        self.conn.receive_frontend_wire().await
    }

    /// Deliberately ends typed ownership and recovers every connection part.
    #[must_use]
    pub fn teardown(
        self,
    ) -> (
        Transport,
        State,
        IdentityServerHandler,
        ServerConnectionContext<Peer>,
    ) {
        let transport = self.conn.into_transport().into_inner();
        (transport, self.state, self.handler, self.context)
    }
}

/// A cancellation branch retaining all caller and handler ownership.
#[derive(Debug)]
pub struct ServerCancellation<Transport, State, Peer> {
    transport: Transport,
    request: CancellationRequest,
    state: State,
    handler: IdentityServerHandler,
    context: ServerConnectionContext<Peer>,
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
        Transport,
        CancellationRequest,
        State,
        IdentityServerHandler,
        ServerConnectionContext<Peer>,
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

impl Server<TrustServerAuthentication> {
    /// Accepts one plaintext transport through startup and trust authentication.
    ///
    /// The caller retains listener and task ownership. `state` and `peer` become
    /// owned parts of either returned branch.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::Io`] for transport or wire failures and
    /// [`AcceptError::UnsupportedProtocolVersion`] for unsupported startup.
    pub async fn accept<Transport, State, Peer>(
        &self,
        transport: Transport,
        peer: Peer,
        state: State,
    ) -> Result<ServerAccept<Transport, State, Peer>, AcceptError>
    where
        Transport: AsyncRead + AsyncWrite + Unpin,
    {
        let ServerTlsPolicy::Disabled = self.tls;
        let TrustServerAuthentication = self.authentication;
        let context = ServerConnectionContext { peer };
        let handler = IdentityServerHandler;
        let buffered = Buffered::with_limits_frontend(
            transport,
            self.limits.max_frame_len,
            self.limits.max_pre_startup_packet_len,
        )
        .map_err(AcceptError::Io)?;
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
                PreStartupOffer::Ssl(decision) => {
                    conn = decision.decline_ssl();
                    if let Err(error) = conn.flush().await {
                        let _ = conn.into_transport();
                        return Err(AcceptError::Io(error));
                    }
                }
                PreStartupOffer::Gss(decision) => {
                    conn = decision.decline_gss();
                    if let Err(error) = conn.flush().await {
                        let _ = conn.into_transport();
                        return Err(AcceptError::Io(error));
                    }
                }
                PreStartupOffer::Cancel {
                    conn: terminal,
                    process_id,
                    secret_key,
                } => {
                    return Ok(ServerAccept::Cancellation(ServerCancellation {
                        transport: terminal.into_transport().into_inner(),
                        request: CancellationRequest {
                            process_id,
                            secret_key,
                        },
                        state,
                        handler,
                        context,
                    }));
                }
                PreStartupOffer::Startup {
                    conn: startup_conn,
                    message,
                } => {
                    let validated = match startup_conn
                        .validate_protocol(message.clone(), ProtocolVersion::V3_2)
                    {
                        ServerProtocolOffer::Supported { conn, .. } => conn,
                        ServerProtocolOffer::Rejected { conn, .. } => {
                            let _ = conn.into_transport();
                            return Err(AcceptError::UnsupportedProtocolVersion);
                        }
                    };
                    let auth = validated.begin_server_auth();
                    let (mut startup_ready, authentication_ok) =
                        auth.authentication_ok().map_err(AcceptError::Io)?;
                    startup_ready
                        .push_frame(authentication_ok)
                        .map_err(AcceptError::Io)?;
                    let (mut ready, ready_frame) =
                        startup_ready.ready().map_err(AcceptError::Io)?;
                    ready.push_frame(ready_frame).map_err(AcceptError::Io)?;
                    if let Err(error) = ready.flush().await {
                        let _ = ready.into_transport();
                        return Err(AcceptError::Io(error));
                    }
                    return Ok(ServerAccept::Session(ServerConnection {
                        conn: ready,
                        startup: message,
                        state,
                        handler,
                        context,
                    }));
                }
            }
        }
    }
}
