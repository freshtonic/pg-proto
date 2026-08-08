//! Builder-centred client-role component.

use std::{collections::BTreeMap, fmt, future::Future, io};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    Conn, Dirty, Pristine,
    auth::{AuthEvent, AuthOffer, Ready},
    codec::Backend,
    demux::SessionItem,
    session::{ReadyState, SimpleTransition},
    startup::{ProtocolVersion, StartupMessage},
    transport::Buffered,
};

/// A deterministic client component configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// No transport connector was configured.
    MissingConnector,
    /// No explicit TLS policy was configured.
    MissingTls,
    /// No explicit authentication policy was configured.
    MissingAuthentication,
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingConnector => "client connector is required",
            Self::MissingTls => "an explicit client TLS policy is required",
            Self::MissingAuthentication => "an explicit client authentication policy is required",
        })
    }
}

impl std::error::Error for BuildError {}

/// Explicit client-role TLS policy available in the plaintext tracer slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTlsPolicy {
    /// Intentionally use plaintext transport.
    Disabled,
}

/// Explicit client authentication policy which accepts only `AuthenticationOk`.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct TrustClientAuthentication;

impl fmt::Debug for TrustClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Trust")
    }
}

/// Application-defined destination supplied to the connector.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectTarget {
    name: String,
    metadata: BTreeMap<String, String>,
}

impl fmt::Debug for ConnectTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectTarget(<redacted>)")
    }
}

impl ConnectTarget {
    /// Creates a named destination.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            metadata: BTreeMap::new(),
        }
    }

    /// Returns its application-defined name or address.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Adds routing metadata retained in the connection context.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Structured startup fields and extension parameters.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct StartupParameters {
    user: Option<String>,
    database: Option<String>,
    extensions: BTreeMap<String, String>,
}

impl fmt::Debug for StartupParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupParameters")
            .field("user", &self.user.as_ref().map(|_| "<redacted>"))
            .field("database", &self.database.as_ref().map(|_| "<redacted>"))
            .field("extensions", &"<redacted>")
            .finish()
    }
}

impl StartupParameters {
    /// Creates parameters containing a PostgreSQL user.
    #[must_use]
    pub fn new(user: impl Into<String>) -> Self {
        Self {
            user: Some(user.into()),
            ..Self::default()
        }
    }

    /// Overrides the database field.
    #[must_use]
    pub fn database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }

    /// Adds a non-standard startup extension parameter.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is a structured standard field.
    pub fn extension(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, StartupParameterError> {
        let name = name.into();
        if matches!(name.as_str(), "user" | "database") {
            return Err(StartupParameterError::ReservedExtension(name));
        }
        self.extensions.insert(name, value.into());
        Ok(self)
    }

    fn merged_with(mut self, overrides: Self) -> Self {
        if overrides.user.is_some() {
            self.user = overrides.user;
        }
        if overrides.database.is_some() {
            self.database = overrides.database;
        }
        self.extensions.extend(overrides.extensions);
        self
    }

    fn into_message(self) -> Result<StartupMessage, StartupParameterError> {
        let user = self.user.ok_or(StartupParameterError::MissingUser)?;
        let mut parameters = self
            .extensions
            .into_iter()
            .map(|(key, value)| (Bytes::from(key), Bytes::from(value)))
            .collect::<BTreeMap<_, _>>();
        parameters.insert(Bytes::from_static(b"user"), Bytes::from(user));
        if let Some(database) = self.database {
            parameters.insert(Bytes::from_static(b"database"), Bytes::from(database));
        }
        Ok(StartupMessage {
            version: ProtocolVersion::V3_2,
            parameters,
        })
    }
}

/// Invalid structured startup configuration.
#[derive(Clone, Eq, PartialEq)]
pub enum StartupParameterError {
    /// A standard structured field was supplied through the extension map.
    ReservedExtension(String),
    /// Neither reusable defaults nor per-call overrides supplied a user.
    MissingUser,
}

impl fmt::Debug for StartupParameterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReservedExtension(_) => "ReservedExtension(<redacted>)",
            Self::MissingUser => "MissingUser",
        })
    }
}

impl fmt::Display for StartupParameterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedExtension(name) => {
                write!(formatter, "startup extension name `{name}` is reserved")
            }
            Self::MissingUser => formatter.write_str("startup user is required"),
        }
    }
}

impl std::error::Error for StartupParameterError {}

/// Conservative protocol allocation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
    max_frame_len: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_len: 1024 * 1024,
        }
    }
}

impl ProtocolLimits {
    /// Sets the maximum complete tagged frame size.
    ///
    /// # Errors
    ///
    /// Returns an error outside PostgreSQL's tagged-frame range.
    pub fn max_frame_len(mut self, limit: usize) -> Result<Self, ProtocolLimitError> {
        if !(5..=i32::MAX as usize + 1).contains(&limit) {
            return Err(ProtocolLimitError);
        }
        self.max_frame_len = limit;
        Ok(self)
    }

    /// Explicitly selects the largest tagged frame PostgreSQL can encode.
    #[must_use]
    pub fn without_frame_limit(mut self) -> Self {
        self.max_frame_len = i32::MAX as usize + 1;
        self
    }
}

/// Invalid protocol limit configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimitError;

impl fmt::Display for ProtocolLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("frame limit is outside PostgreSQL's tagged-frame range")
    }
}

impl std::error::Error for ProtocolLimitError {}

/// Immutable facts retained by a client-role connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConnectionContext {
    target: ConnectTarget,
}

impl ClientConnectionContext {
    /// Returns the destination used for this connection.
    #[must_use]
    pub const fn target(&self) -> &ConnectTarget {
        &self.target
    }
}

/// Identity middleware handler used until middleware configuration is introduced.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityHandler;

/// Reusable client-role component.
pub struct Client<Connector = ()> {
    connector: Connector,
    tls: ClientTlsPolicy,
    authentication: TrustClientAuthentication,
    defaults: StartupParameters,
    limits: ProtocolLimits,
}

impl<Connector: Clone> Clone for Client<Connector> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            tls: self.tls,
            authentication: self.authentication,
            defaults: self.defaults.clone(),
            limits: self.limits,
        }
    }
}

impl Client<()> {
    /// Starts client-role configuration.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }
}

impl<Connector> fmt::Debug for Client<Connector> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("tls", &self.tls)
            .field("authentication", &self.authentication)
            .finish_non_exhaustive()
    }
}

/// Ordinary generic builder for a reusable client-role component.
pub struct ClientBuilder<Connector = ()> {
    connector: Option<Connector>,
    tls: Option<ClientTlsPolicy>,
    authentication: Option<TrustClientAuthentication>,
    defaults: StartupParameters,
    limits: ProtocolLimits,
}

impl Default for ClientBuilder<()> {
    fn default() -> Self {
        Self {
            connector: None,
            tls: None,
            authentication: None,
            defaults: StartupParameters::default(),
            limits: ProtocolLimits::default(),
        }
    }
}

impl ClientBuilder<()> {
    /// Configures the reusable application-supplied connector.
    #[must_use]
    pub fn connector<Next, Work, Transport, Error>(self, connector: Next) -> ClientBuilder<Next>
    where
        Next: Fn(&ConnectTarget) -> Work,
        Work: Future<Output = Result<Transport, Error>>,
    {
        ClientBuilder {
            connector: Some(connector),
            tls: self.tls,
            authentication: self.authentication,
            defaults: self.defaults,
            limits: self.limits,
        }
    }
}

impl<Connector> ClientBuilder<Connector> {
    /// Selects an explicit TLS policy.
    #[must_use]
    pub fn tls(mut self, tls: ClientTlsPolicy) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Selects explicit trust authentication.
    #[must_use]
    pub fn authentication(mut self, authentication: TrustClientAuthentication) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Sets reusable startup defaults which per-call values override explicitly.
    #[must_use]
    pub fn startup_parameters(mut self, defaults: StartupParameters) -> Self {
        self.defaults = defaults;
        self
    }

    /// Replaces conservative protocol limits with an explicit policy.
    #[must_use]
    pub fn protocol_limits(mut self, limits: ProtocolLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Validates and creates the reusable component.
    ///
    /// # Errors
    ///
    /// Returns the first missing mandatory configuration category.
    pub fn build(self) -> Result<Client<Connector>, BuildError> {
        Ok(Client {
            connector: self.connector.ok_or(BuildError::MissingConnector)?,
            tls: self.tls.ok_or(BuildError::MissingTls)?,
            authentication: self
                .authentication
                .ok_or(BuildError::MissingAuthentication)?,
            defaults: self.defaults,
            limits: self.limits,
        })
    }
}

/// Failure while establishing a client-role connection, distinct from [`BuildError`].
#[derive(Debug)]
pub enum ConnectError<ConnectorError> {
    /// The application-supplied connector failed.
    Connector(ConnectorError),
    /// Structured startup values were invalid before network establishment.
    Startup(StartupParameterError),
    /// PostgreSQL framing, startup, authentication, or readiness failed.
    Protocol(io::Error),
}

impl<ConnectorError: fmt::Display> fmt::Display for ConnectError<ConnectorError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connector(error) => error.fmt(f),
            Self::Startup(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
        }
    }
}
impl<ConnectorError: std::error::Error + 'static> std::error::Error
    for ConnectError<ConnectorError>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connector(error) => Some(error),
            Self::Startup(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

/// Operational client-role connection.
pub struct ClientConnection<Transport, State, Cleanliness = Pristine> {
    connection: Conn<Buffered<Transport, Backend>, Ready, Cleanliness>,
    state: State,
    handler: IdentityHandler,
    context: ClientConnectionContext,
}

impl<Transport, State, Cleanliness> ClientConnection<Transport, State, Cleanliness> {
    /// Returns immutable connection facts.
    #[must_use]
    pub const fn context(&self) -> &ClientConnectionContext {
        &self.context
    }

    /// Returns the caller-owned connection state.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Receives one backend message at the operational inspection boundary.
    ///
    /// # Errors
    ///
    /// Returns a transport, decoding, or configured frame-limit error.
    pub async fn receive_wire(&mut self) -> io::Result<crate::codec::BackendMessage>
    where
        Transport: AsyncRead + Unpin,
    {
        self.connection.receive_backend_wire().await
    }

    /// Recovers every owned connection part deliberately.
    pub fn into_parts(self) -> (Transport, State, IdentityHandler, ClientConnectionContext) {
        (
            self.connection.into_transport().into_inner(),
            self.state,
            self.handler,
            self.context,
        )
    }
}

/// Failure while executing an operational client-role action.
#[derive(Debug)]
pub struct QueryError(io::Error);

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl<Transport, State, Cleanliness> ClientConnection<Transport, State, Cleanliness>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
{
    /// Executes a simple query through typed completion back to operational readiness.
    ///
    /// The returned connection is conservatively marked dirty because arbitrary
    /// SQL may retain session-local state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid query text, I/O or framing failure, an
    /// illegal peer transition, COPY entry, or a backend error response.
    pub async fn simple_query(
        self,
        query: &[u8],
    ) -> Result<
        (
            ClientConnection<Transport, State, Dirty>,
            Vec<crate::codec::BackendMessage>,
        ),
        QueryError,
    > {
        let Self {
            connection,
            state,
            handler,
            context,
        } = self;
        let (mut query_connection, frame) = connection.push_query(query).map_err(QueryError)?;
        if let Err(error) = query_connection.push_frame(frame) {
            let _ = query_connection.into_transport();
            return Err(QueryError(error));
        }
        if let Err(error) = query_connection.flush().await {
            let _ = query_connection.into_transport();
            return Err(QueryError(error));
        }
        let mut messages = Vec::new();
        loop {
            let item = match query_connection.receive().await {
                Ok(item) => item,
                Err(error) => {
                    let _ = query_connection.into_transport();
                    return Err(QueryError(error));
                }
            };
            messages.push(item.clone().into_backend_message());
            match query_connection.offer(item) {
                Ok(SimpleTransition::Continue(connection, _)) => query_connection = connection,
                Ok(SimpleTransition::Ready(
                    ReadyState::Clean(connection)
                    | ReadyState::Dirty {
                        conn: connection, ..
                    },
                )) => {
                    return Ok((
                        ClientConnection {
                            connection,
                            state,
                            handler,
                            context,
                        },
                        messages,
                    ));
                }
                Ok(SimpleTransition::Error(connection, _)) => {
                    let _ = connection.into_transport();
                    return Err(QueryError(io::Error::other(
                        "backend rejected simple query",
                    )));
                }
                Ok(SimpleTransition::CopyIn(connection, _)) => {
                    let _ = connection.into_transport();
                    return Err(QueryError(io::Error::other("simple query entered COPY IN")));
                }
                Ok(SimpleTransition::CopyOut(connection, _)) => {
                    let _ = connection.into_transport();
                    return Err(QueryError(io::Error::other(
                        "simple query entered COPY OUT",
                    )));
                }
                Ok(SimpleTransition::CopyBoth(connection, _)) => {
                    let _ = connection.into_transport();
                    return Err(QueryError(io::Error::other(
                        "simple query entered COPY BOTH",
                    )));
                }
                Err((connection, _)) => {
                    let _ = connection.into_transport();
                    return Err(QueryError(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "illegal simple-query response",
                    )));
                }
            }
        }
    }
}

impl<Connector, Work, Transport, Error> Client<Connector>
where
    Connector: Fn(&ConnectTarget) -> Work,
    Work: Future<Output = Result<Transport, Error>>,
    Transport: AsyncRead + AsyncWrite + Unpin,
{
    /// Establishes transport, startup, and trust authentication before returning.
    ///
    /// Per-call startup values explicitly override component defaults.
    ///
    /// # Errors
    ///
    /// Returns a connection-time error for connector, startup, framing,
    /// authentication, or readiness failures.
    pub async fn connect<State>(
        &self,
        target: ConnectTarget,
        overrides: StartupParameters,
        state: State,
    ) -> Result<ClientConnection<Transport, State>, ConnectError<Error>> {
        let startup = self
            .defaults
            .clone()
            .merged_with(overrides)
            .into_message()
            .map_err(ConnectError::Startup)?;
        let transport = (self.connector)(&target)
            .await
            .map_err(ConnectError::Connector)?;
        let buffered = Buffered::with_max_frame_len(transport, self.limits.max_frame_len)
            .map_err(ConnectError::Protocol)?;
        let (mut startup_connection, packet) = Conn::new(buffered)
            .startup(&startup)
            .map_err(ConnectError::Protocol)?;
        startup_connection.push_startup_packet(&packet);
        let mut authentication = startup_connection.authentication();
        if let Err(error) = authentication.flush().await {
            let _ = authentication.into_transport();
            return Err(ConnectError::Protocol(error));
        }
        let awaiting_ready = loop {
            let message = match authentication.receive_backend_wire().await {
                Ok(message) => message,
                Err(error) => {
                    let _ = authentication.into_transport();
                    return Err(ConnectError::Protocol(error));
                }
            };
            match authentication.offer_backend(message) {
                Ok(AuthEvent::Authentication(AuthOffer::Ok(connection))) => break connection,
                Ok(AuthEvent::Negotiate { conn, .. }) => authentication = conn,
                Ok(AuthEvent::Authentication(offer)) => {
                    abort_auth_offer(offer);
                    return Err(ConnectError::Protocol(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "trust authentication received a credential challenge",
                    )));
                }
                Ok(AuthEvent::Error { conn, .. }) => {
                    let _ = conn.into_transport();
                    return Err(ConnectError::Protocol(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "server rejected authentication",
                    )));
                }
                Err((conn, _, source)) => {
                    authentication = conn;
                    if let Some(source) = source {
                        let _ = authentication.into_transport();
                        return Err(ConnectError::Protocol(source));
                    }
                }
            }
        };
        let mut awaiting_ready = awaiting_ready;
        let ready = loop {
            let item = match awaiting_ready.receive().await {
                Ok(item) => item,
                Err(error) => {
                    let _ = awaiting_ready.into_transport();
                    return Err(ConnectError::Protocol(error));
                }
            };
            match awaiting_ready.offer_ready(item) {
                Ok(ready) => break ready,
                Err((connection, SessionItem::Message(_))) => awaiting_ready = connection,
                Err((connection, _)) => {
                    let _ = connection.into_transport();
                    return Err(ConnectError::Protocol(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "startup did not reach an idle operational phase",
                    )));
                }
            }
        };
        Ok(ClientConnection {
            connection: ready,
            state,
            handler: IdentityHandler,
            context: ClientConnectionContext { target },
        })
    }
}

fn abort_auth_offer<Transport>(offer: AuthOffer<Transport>) {
    match offer {
        AuthOffer::Ok(connection) => {
            let _ = connection.into_transport();
        }
        AuthOffer::Cleartext(connection) => {
            let _ = connection.into_transport();
        }
        AuthOffer::Md5 { conn, .. } => {
            let _ = conn.into_transport();
        }
        AuthOffer::Sasl { conn, .. } => {
            let _ = conn.into_transport();
        }
        AuthOffer::Gss(connection)
        | AuthOffer::Sspi(connection)
        | AuthOffer::KerberosV5(connection) => {
            let _ = connection.into_transport();
        }
    }
}
