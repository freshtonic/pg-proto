//! Builder-centred client-role component.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::ClientMiddleware as _;
use crate::{
    Conn, Pristine,
    auth::{AuthEvent, AuthOffer, Ready},
    codec::{Backend, FrontendMessage},
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

/// Explicit libpq-compatible TLS policy and its reloadable configuration provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTlsPolicy {
    /// Intentionally use plaintext transport.
    Disabled,
}

impl ClientTlsPolicy {
    /// Configures a libpq-compatible SSL mode and reloadable provider.
    #[must_use]
    pub fn libpq<Provider>(
        mode: crate::pre_startup::SslMode,
        provider: Provider,
    ) -> ReloadableClientTls<Provider> {
        ReloadableClientTls { mode, provider }
    }
}

/// A libpq-compatible policy backed by application-owned reloadable TLS material.
#[derive(Clone)]
pub struct ReloadableClientTls<Provider> {
    mode: crate::pre_startup::SslMode,
    provider: Provider,
}

impl<Provider> fmt::Debug for ReloadableClientTls<Provider> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Libpq")
            .field("mode", &self.mode)
            .field("provider", &"<redacted>")
            .finish()
    }
}

/// Internal shape shared by disabled and reloadable TLS policies.
pub trait ClientTlsConfiguration {
    /// Reloadable provider type.
    type Provider: ClientTlsProvider;

    /// Returns the libpq mode and provider, or `None` for explicit plaintext.
    fn configured(&self) -> Option<(crate::pre_startup::SslMode, &Self::Provider)>;
}

impl ClientTlsConfiguration for ClientTlsPolicy {
    type Provider = ();

    fn configured(&self) -> Option<(crate::pre_startup::SslMode, &Self::Provider)> {
        None
    }
}

impl<Provider: ClientTlsProvider> ClientTlsConfiguration for ReloadableClientTls<Provider> {
    type Provider = Provider;

    fn configured(&self) -> Option<(crate::pre_startup::SslMode, &Self::Provider)> {
        Some((self.mode, &self.provider))
    }
}

/// Application-owned TLS material resolved afresh for a connection attempt.
///
/// The application owns reload and rotation of destination names and trust
/// anchors. `pg-proto` deliberately constructs the final rustls verifier from
/// the selected [`SslMode`](crate::SslMode), so a provider cannot silently
/// weaken `VerifyCa` or `VerifyFull`.
#[derive(Clone)]
pub struct ClientTlsConfig {
    server_name: rustls::pki_types::ServerName<'static>,
    roots: rustls::RootCertStore,
}

impl ClientTlsConfig {
    /// Creates resolved TLS material.
    #[must_use]
    pub fn new(
        server_name: rustls::pki_types::ServerName<'static>,
        roots: rustls::RootCertStore,
    ) -> Self {
        Self { server_name, roots }
    }
}

impl fmt::Debug for ClientTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientTlsConfig(<redacted>)")
    }
}

/// Application-owned source of reloadable client TLS material.
///
/// Resolution futures are [`Send`] so connection establishment can run on a
/// multithreaded executor.
pub trait ClientTlsProvider {
    /// Provider resolution failure.
    type Error;

    /// Resolves material for one connection attempt.
    fn resolve(
        &self,
        target: &ConnectTarget,
    ) -> impl Future<Output = Result<ClientTlsConfig, Self::Error>> + Send;
}

/// Failure while resolving or establishing client TLS.
#[derive(Debug)]
pub enum ClientTlsError<ProviderError> {
    /// The application-owned reloadable provider failed.
    Provider(ProviderError),
    /// PostgreSQL negotiation or the TLS handshake failed.
    Handshake(io::Error),
}

impl<ProviderError: fmt::Display> fmt::Display for ClientTlsError<ProviderError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => error.fmt(formatter),
            Self::Handshake(error) => error.fmt(formatter),
        }
    }
}

impl<ProviderError: std::error::Error + 'static> std::error::Error
    for ClientTlsError<ProviderError>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::Handshake(error) => Some(error),
        }
    }
}

impl ClientTlsProvider for () {
    type Error = Infallible;

    async fn resolve(&self, _target: &ConnectTarget) -> Result<ClientTlsConfig, Self::Error> {
        unreachable!("disabled TLS never resolves a provider")
    }
}

/// Transport selected by libpq-compatible negotiation.
#[derive(Debug)]
pub enum ClientTransport<Transport> {
    /// Unencrypted PostgreSQL transport.
    Plain(Transport),
    /// TLS-protected PostgreSQL transport.
    Tls(Box<crate::tls::ClientTls<Transport>>),
}

impl<Transport: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientTransport<Transport> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl<Transport: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientTransport<Transport> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn negotiate_client_tls<Transport, Provider, State, Handler, Evidence>(
    mut transport: Transport,
    mode: crate::pre_startup::SslMode,
    provider: &Provider,
    target: &ConnectTarget,
    context: &mut ClientConnectionContext<Evidence>,
    state: &mut State,
    handler: &mut Handler,
) -> Result<ClientTransport<Transport>, ClientTlsError<Provider::Error>>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
    Provider: ClientTlsProvider,
    Handler: crate::ClientMiddleware<State, ClientConnectionContext<Evidence>>,
{
    if !mode.strategy().request_on_first_connection {
        context.tls = Some(ClientTlsStatus::Plaintext);
        return Ok(ClientTransport::Plain(transport));
    }
    let request = handler.pre_startup(
        context,
        state,
        crate::pre_startup::PreStartupMessage::SslRequest,
    );
    let crate::pre_startup::PreStartupMessage::SslRequest = request else {
        return Err(ClientTlsError::Handshake(io::Error::new(
            io::ErrorKind::InvalidData,
            "middleware replaced SSLRequest with an incompatible packet",
        )));
    };
    transport
        .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
        .await
        .map_err(ClientTlsError::Handshake)?;
    transport.flush().await.map_err(ClientTlsError::Handshake)?;
    match transport
        .read_u8()
        .await
        .map_err(ClientTlsError::Handshake)?
    {
        b'S' => {
            let resolved = provider
                .resolve(target)
                .await
                .map_err(ClientTlsError::Provider)?;
            let config = Arc::new(crate::tls::client_config(mode, resolved.roots));
            let stream = crate::tls::connect(transport, resolved.server_name, config)
                .await
                .map_err(ClientTlsError::Handshake)?;
            context.tls = Some(ClientTlsStatus::Encrypted);
            Ok(ClientTransport::Tls(Box::new(stream)))
        }
        b'N' if mode.strategy().allow_server_rejection => {
            context.tls = Some(ClientTlsStatus::Plaintext);
            Ok(ClientTransport::Plain(transport))
        }
        b'N' => Err(ClientTlsError::Handshake(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "server rejected required TLS",
        ))),
        b'E' => Err(ClientTlsError::Handshake(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "server terminated TLS negotiation",
        ))),
        _ => Err(ClientTlsError::Handshake(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS negotiation response",
        ))),
    }
}

/// Explicit client authentication policy which accepts only `AuthenticationOk`.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct TrustClientAuthentication;

/// An authentication request offered by a PostgreSQL server.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientAuthenticationChallenge {
    /// The server requested a cleartext password response.
    CleartextPassword,
    /// The server requested a PostgreSQL MD5 password response.
    Md5Password([u8; 4]),
    /// The server offered SASL mechanisms.
    Sasl(Vec<Bytes>),
    /// The server supplied another SASL challenge.
    SaslContinue(Bytes),
    /// The server supplied the SASL verifier.
    SaslFinal(Bytes),
    /// The server requested an opaque GSS token.
    Gss,
    /// The server requested an opaque SSPI token.
    Sspi,
    /// The server requested Kerberos V5 authentication.
    KerberosV5,
    /// The server supplied another opaque token challenge.
    TokenContinue(Bytes),
}

/// An application authentication policy's wire response.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientAuthenticationResponse {
    /// Send a cleartext or precomputed MD5 password.
    Password(Bytes),
    /// Begin SASL using the named mechanism and initial response.
    SaslInitial {
        /// Selected SASL mechanism name.
        mechanism: Bytes,
        /// Mechanism-specific initial response.
        response: Bytes,
    },
    /// Continue a SASL exchange.
    Sasl(Bytes),
    /// Send an opaque GSS, SSPI, or Kerberos token.
    Token(Bytes),
    /// Accept a verified SASL final message without sending another frame.
    Verified,
}

/// Factory for asynchronous, fallible per-connection authentication sessions.
///
/// Authentication futures are [`Send`] so connection establishment can run
/// on a multithreaded executor.
pub trait ClientAuthentication {
    /// Typed identity evidence produced after server confirmation.
    type Evidence;
    /// Per-connection mutable authentication state.
    type Session: ClientAuthenticationSession<Evidence = Self::Evidence, Error = Self::Error>;
    /// Application authentication failure.
    type Error;

    /// Creates fresh authentication state using the selected route.
    fn begin(
        &self,
        target: &ConnectTarget,
    ) -> impl Future<Output = Result<Self::Session, Self::Error>> + Send;
}

/// Mutable authentication policy state owned by one connection attempt.
///
/// Authentication futures are [`Send`] so connection establishment can run
/// on a multithreaded executor.
pub trait ClientAuthenticationSession {
    /// Typed identity evidence produced after server confirmation.
    type Evidence;
    /// Application authentication failure.
    type Error;

    /// Answers one server authentication challenge.
    fn respond(
        &mut self,
        challenge: ClientAuthenticationChallenge,
    ) -> impl Future<Output = Result<ClientAuthenticationResponse, Self::Error>> + Send;

    /// Produces identity evidence after `AuthenticationOk` was received.
    fn authenticated(self) -> impl Future<Output = Result<Self::Evidence, Self::Error>> + Send;
}

/// Failure while running an application authentication policy.
#[derive(Debug)]
pub enum ClientAuthenticationError<PolicyError> {
    /// Application policy creation or evaluation failed.
    Policy(PolicyError),
    /// The PostgreSQL server rejected authentication.
    Rejected,
    /// The policy returned a response illegal for the active challenge.
    InvalidResponse,
}

impl<PolicyError: fmt::Display> fmt::Display for ClientAuthenticationError<PolicyError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(formatter),
            Self::Rejected => formatter.write_str("server rejected authentication"),
            Self::InvalidResponse => {
                formatter.write_str("authentication policy rejected the credential challenge")
            }
        }
    }
}

impl<PolicyError: std::error::Error + 'static> std::error::Error
    for ClientAuthenticationError<PolicyError>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Rejected | Self::InvalidResponse => None,
        }
    }
}

enum AuthenticationDriveError<PolicyError> {
    Policy(PolicyError),
    Rejected,
    InvalidResponse,
    Protocol(io::Error),
}

impl ClientAuthentication for TrustClientAuthentication {
    type Evidence = ();
    type Session = Self;
    type Error = Infallible;

    async fn begin(&self, _target: &ConnectTarget) -> Result<Self::Session, Self::Error> {
        Ok(Self)
    }
}

impl ClientAuthenticationSession for TrustClientAuthentication {
    type Evidence = ();
    type Error = Infallible;

    async fn respond(
        &mut self,
        _challenge: ClientAuthenticationChallenge,
    ) -> Result<ClientAuthenticationResponse, Self::Error> {
        Ok(ClientAuthenticationResponse::Verified)
    }

    async fn authenticated(self) -> Result<Self::Evidence, Self::Error> {
        Ok(())
    }
}

impl fmt::Debug for TrustClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Trust")
    }
}

/// Username and password authentication for PostgreSQL server challenges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticClientCredentials {
    username: Bytes,
    password: Bytes,
}

impl StaticClientCredentials {
    /// Creates credentials reused by each connection attempt.
    #[must_use]
    pub fn new(username: impl Into<Bytes>, password: impl Into<Bytes>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// Per-connection static credential exchange.
pub struct StaticClientCredentialSession {
    username: Bytes,
    password: Bytes,
    scram: Option<postgres_protocol::authentication::sasl::ScramSha256>,
}

/// Failure while answering a static credential challenge.
#[derive(Debug)]
pub enum StaticCredentialError {
    /// The server requested an authentication mechanism this adapter does not support.
    UnsupportedAuthentication,
    /// The server sent a challenge out of sequence.
    InvalidChallengeSequence,
    /// A SCRAM message was invalid or failed verification.
    Scram(io::Error),
    /// The supplied password did not match.
    AuthenticationFailed,
}

impl fmt::Display for StaticCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAuthentication => {
                formatter.write_str("unsupported authentication mechanism")
            }
            Self::InvalidChallengeSequence => {
                formatter.write_str("authentication challenge is out of sequence")
            }
            Self::Scram(error) => error.fmt(formatter),
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
        }
    }
}

impl std::error::Error for StaticCredentialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scram(error) => Some(error),
            _ => None,
        }
    }
}

impl ClientAuthentication for StaticClientCredentials {
    type Evidence = ();
    type Session = StaticClientCredentialSession;
    type Error = StaticCredentialError;

    async fn begin(&self, _: &ConnectTarget) -> Result<Self::Session, Self::Error> {
        Ok(StaticClientCredentialSession {
            username: self.username.clone(),
            password: self.password.clone(),
            scram: None,
        })
    }
}

impl ClientAuthenticationSession for StaticClientCredentialSession {
    type Evidence = ();
    type Error = StaticCredentialError;

    async fn respond(
        &mut self,
        challenge: ClientAuthenticationChallenge,
    ) -> Result<ClientAuthenticationResponse, Self::Error> {
        use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
        match challenge {
            ClientAuthenticationChallenge::CleartextPassword => Ok(
                ClientAuthenticationResponse::Password(self.password.clone()),
            ),
            ClientAuthenticationChallenge::Md5Password(salt) => {
                Ok(ClientAuthenticationResponse::Password(Bytes::from(
                    crate::credentials::md5_response(&self.username, &self.password, salt),
                )))
            }
            ClientAuthenticationChallenge::Sasl(mechanisms)
                if mechanisms
                    .iter()
                    .any(|mechanism| mechanism.as_ref() == b"SCRAM-SHA-256") =>
            {
                let scram = self.scram.insert(ScramSha256::new(
                    &self.password,
                    ChannelBinding::unsupported(),
                ));
                Ok(ClientAuthenticationResponse::SaslInitial {
                    mechanism: Bytes::from_static(b"SCRAM-SHA-256"),
                    response: Bytes::copy_from_slice(scram.message()),
                })
            }
            ClientAuthenticationChallenge::Sasl(_) => {
                Err(StaticCredentialError::UnsupportedAuthentication)
            }
            ClientAuthenticationChallenge::SaslContinue(message) => {
                let scram = self
                    .scram
                    .as_mut()
                    .ok_or(StaticCredentialError::InvalidChallengeSequence)?;
                scram
                    .update(&message)
                    .map_err(StaticCredentialError::Scram)?;
                Ok(ClientAuthenticationResponse::Sasl(Bytes::copy_from_slice(
                    scram.message(),
                )))
            }
            ClientAuthenticationChallenge::SaslFinal(message) => {
                let scram = self
                    .scram
                    .as_mut()
                    .ok_or(StaticCredentialError::InvalidChallengeSequence)?;
                scram
                    .finish(&message)
                    .map_err(StaticCredentialError::Scram)?;
                Ok(ClientAuthenticationResponse::Verified)
            }
            _ => Err(StaticCredentialError::UnsupportedAuthentication),
        }
    }

    async fn authenticated(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
/// Tests for the static client credential implementation.
mod static_credential_tests {
    use super::*;

    #[tokio::test]
    async fn answers_cleartext_and_md5_challenges() {
        let credentials = StaticClientCredentials::new("alice", "secret");
        let mut session = credentials
            .begin(&ConnectTarget::new("database"))
            .await
            .unwrap();
        assert_eq!(
            session
                .respond(ClientAuthenticationChallenge::CleartextPassword)
                .await
                .unwrap(),
            ClientAuthenticationResponse::Password(Bytes::from_static(b"secret"))
        );

        let salt = [1, 2, 3, 4];
        assert_eq!(
            session
                .respond(ClientAuthenticationChallenge::Md5Password(salt))
                .await
                .unwrap(),
            ClientAuthenticationResponse::Password(Bytes::from(crate::credentials::md5_response(
                b"alice", b"secret", salt
            )))
        );
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
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Returns application-owned routing metadata.
    #[must_use]
    pub const fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
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

    /// Returns the configured user, when present.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Returns the configured database, when present.
    #[must_use]
    pub fn database_name(&self) -> Option<&str> {
        self.database.as_deref()
    }

    pub(crate) fn from_wire(message: &StartupMessage) -> io::Result<Self> {
        let mut parameters = Self::default();
        for (name, value) in &message.parameters {
            let name = std::str::from_utf8(name).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup parameter name is not UTF-8",
                )
            })?;
            let value = std::str::from_utf8(value).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup parameter value is not UTF-8",
                )
            })?;
            match name {
                "user" => parameters.user = Some(value.to_owned()),
                "database" => parameters.database = Some(value.to_owned()),
                _ => {
                    parameters
                        .extensions
                        .insert(name.to_owned(), value.to_owned());
                }
            }
        }
        Ok(parameters)
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
pub struct ClientConnectionContext<Evidence = ()> {
    target: ConnectTarget,
    tls: Option<ClientTlsStatus>,
    identity: Option<Evidence>,
    backend_key: Option<crate::demux::CancelKey>,
}

/// Progressively discovered transport security for a client connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTlsStatus {
    /// The connection uses explicitly selected plaintext.
    Plaintext,
    /// The connection is protected by TLS.
    Encrypted,
}

impl<Evidence> ClientConnectionContext<Evidence> {
    /// Returns the destination used for this connection.
    #[must_use]
    pub const fn target(&self) -> &ConnectTarget {
        &self.target
    }

    /// Returns transport security once negotiation has completed.
    #[must_use]
    pub const fn tls(&self) -> Option<ClientTlsStatus> {
        self.tls
    }

    /// Returns application-defined evidence from the authentication policy.
    ///
    /// # Panics
    ///
    /// Panics when called from middleware before authentication has completed.
    #[must_use]
    pub const fn identity(&self) -> &Evidence {
        match &self.identity {
            Some(identity) => identity,
            None => panic!("identity is not known before authentication"),
        }
    }

    /// Returns evidence only after authentication has enriched the context.
    #[must_use]
    pub const fn identity_if_known(&self) -> Option<&Evidence> {
        self.identity.as_ref()
    }

    /// Returns the upstream cancellation key captured during startup readiness.
    #[must_use]
    pub const fn backend_key(&self) -> Option<&crate::demux::CancelKey> {
        self.backend_key.as_ref()
    }
}

/// Identity middleware handler.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityHandler;
impl<C> crate::MiddlewareFactory<C> for IdentityHandler {
    type Handler = Self;
    fn create(&self, _: &C) -> Self {
        *self
    }
}
impl<S, C> crate::ClientMiddleware<S, C> for IdentityHandler {}

/// Immutable facts available when a client middleware handler is created.
pub struct ClientInitialContext {
    target: ConnectTarget,
}
impl ClientInitialContext {
    /// Destination selected for this connection.
    #[must_use]
    pub const fn target(&self) -> &ConnectTarget {
        &self.target
    }
}

/// Reusable client-role component.
pub struct Client<
    Connector = (),
    Tls = ClientTlsPolicy,
    Authentication = TrustClientAuthentication,
    Middleware = IdentityHandler,
> {
    connector: Connector,
    tls: Tls,
    authentication: Authentication,
    defaults: StartupParameters,
    limits: ProtocolLimits,
    middleware: Middleware,
}

impl<Connector: Clone, Tls: Clone, Authentication: Clone, Middleware: Clone> Clone
    for Client<Connector, Tls, Authentication, Middleware>
{
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            tls: self.tls.clone(),
            authentication: self.authentication.clone(),
            defaults: self.defaults.clone(),
            limits: self.limits,
            middleware: self.middleware.clone(),
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

impl<Connector, Tls: fmt::Debug, Authentication: fmt::Debug, Middleware> fmt::Debug
    for Client<Connector, Tls, Authentication, Middleware>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("tls", &self.tls)
            .field("authentication", &self.authentication)
            .finish_non_exhaustive()
    }
}

/// Ordinary generic builder for a reusable client-role component.
pub struct ClientBuilder<
    Connector = (),
    Tls = (),
    Authentication = (),
    Middleware = IdentityHandler,
> {
    connector: Option<Connector>,
    tls: Option<Tls>,
    authentication: Option<Authentication>,
    defaults: StartupParameters,
    limits: ProtocolLimits,
    middleware: Middleware,
}

impl Default for ClientBuilder<()> {
    fn default() -> Self {
        Self {
            connector: None,
            tls: None,
            authentication: None,
            defaults: StartupParameters::default(),
            limits: ProtocolLimits::default(),
            middleware: IdentityHandler,
        }
    }
}

impl ClientBuilder<()> {
    /// Configures the reusable application-supplied connector.
    #[must_use]
    pub fn connector<Next, Work, Transport, Error>(
        self,
        connector: Next,
    ) -> ClientBuilder<Next, (), ()>
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
            middleware: self.middleware,
        }
    }
}

impl<Connector, Tls, Authentication, Middleware>
    ClientBuilder<Connector, Tls, Authentication, Middleware>
{
    /// Selects an explicit TLS policy.
    #[must_use]
    pub fn tls<Next>(
        self,
        tls: Next,
    ) -> ClientBuilder<Connector, Next, Authentication, Middleware> {
        ClientBuilder {
            connector: self.connector,
            tls: Some(tls),
            authentication: self.authentication,
            defaults: self.defaults,
            limits: self.limits,
            middleware: self.middleware,
        }
    }

    /// Selects explicit trust authentication.
    #[must_use]
    pub fn authentication<Next>(
        self,
        authentication: Next,
    ) -> ClientBuilder<Connector, Tls, Next, Middleware> {
        ClientBuilder {
            connector: self.connector,
            tls: self.tls,
            authentication: Some(authentication),
            defaults: self.defaults,
            limits: self.limits,
            middleware: self.middleware,
        }
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

    /// Appends a middleware factory. Stages run in declaration order.
    #[must_use]
    pub fn middleware<Next>(
        self,
        factory: Next,
    ) -> ClientBuilder<Connector, Tls, Authentication, crate::MiddlewareChain<Middleware, Next>>
    {
        ClientBuilder {
            connector: self.connector,
            tls: self.tls,
            authentication: self.authentication,
            defaults: self.defaults,
            limits: self.limits,
            middleware: crate::MiddlewareChain(self.middleware, factory),
        }
    }

    /// Validates and creates the reusable component.
    ///
    /// # Errors
    ///
    /// Returns the first missing mandatory configuration category.
    pub fn build(self) -> Result<Client<Connector, Tls, Authentication, Middleware>, BuildError> {
        Ok(Client {
            connector: self.connector.ok_or(BuildError::MissingConnector)?,
            tls: self.tls.ok_or(BuildError::MissingTls)?,
            authentication: self
                .authentication
                .ok_or(BuildError::MissingAuthentication)?,
            defaults: self.defaults,
            limits: self.limits,
            middleware: self.middleware,
        })
    }
}

/// Failure while establishing a client-role connection, distinct from [`BuildError`].
#[derive(Debug)]
pub enum ConnectError<ConnectorError, TlsError = Infallible, AuthenticationError = Infallible> {
    /// The application-supplied connector failed.
    Connector(ConnectorError),
    /// The reloadable TLS provider or handshake failed.
    Tls(TlsError),
    /// The application authentication policy failed.
    Authentication(AuthenticationError),
    /// Structured startup values were invalid before network establishment.
    Startup(StartupParameterError),
    /// PostgreSQL framing, startup, authentication, or readiness failed.
    Protocol(io::Error),
}

/// Failure while sending a one-shot PostgreSQL cancellation packet.
#[derive(Debug)]
pub enum CancelError<ConnectorError> {
    /// The configured connector could not open the cancellation transport.
    Connector(ConnectorError),
    /// The key could not be encoded or the raw packet could not be written.
    Protocol(io::Error),
}

impl<E: fmt::Display> fmt::Display for CancelError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connector(error) => error.fmt(formatter),
            Self::Protocol(error) => error.fmt(formatter),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for CancelError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connector(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

impl<ConnectorError: fmt::Display, TlsError: fmt::Display, AuthenticationError: fmt::Display>
    fmt::Display for ConnectError<ConnectorError, TlsError, AuthenticationError>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connector(error) => error.fmt(f),
            Self::Tls(error) => error.fmt(f),
            Self::Authentication(error) => error.fmt(f),
            Self::Startup(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
        }
    }
}
impl<ConnectorError, TlsError, AuthenticationError> std::error::Error
    for ConnectError<ConnectorError, TlsError, AuthenticationError>
where
    ConnectorError: std::error::Error + 'static,
    TlsError: std::error::Error + 'static,
    AuthenticationError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connector(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::Startup(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

/// Evidence that a connection has not performed a state-changing operation.
#[derive(Debug)]
pub enum ConnectionClean {}

/// Evidence that an operation may have changed session-local state.
#[derive(Debug)]
pub enum ConnectionChanged {}

/// Operational client-role connection.
pub struct ClientConnection<
    Transport,
    State,
    Cleanliness = ConnectionClean,
    Evidence = (),
    Handler = IdentityHandler,
> {
    core: ClientConnectionCore<Transport, Cleanliness, Evidence, Handler>,
    state: State,
}

pub(crate) struct ClientConnectionCore<Transport, Cleanliness, Evidence, Handler> {
    connection: Conn<Buffered<Transport, Backend>, Ready, Cleanliness>,
    handler: Handler,
    context: ClientConnectionContext<Evidence>,
}

impl<Transport, State, Cleanliness, Evidence, Handler>
    ClientConnection<Transport, State, Cleanliness, Evidence, Handler>
{
    /// Returns immutable connection facts.
    #[must_use]
    pub const fn context(&self) -> &ClientConnectionContext<Evidence> {
        &self.core.context
    }

    /// Returns the caller-owned connection state.
    ///
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Receives one backend message at the operational inspection boundary.
    ///
    /// # Errors
    ///
    /// Returns a transport, decoding, or configured frame-limit error.
    ///
    pub async fn receive_wire(&mut self) -> io::Result<crate::codec::BackendMessage>
    where
        Transport: AsyncRead + Unpin,
        Handler: crate::ClientMiddleware<State, ClientConnectionContext<Evidence>>,
    {
        let message = self.core.receive_wire_raw().await?;
        Ok(self.core.intercept_backend(&mut self.state, message))
    }

    /// Recovers every owned connection part deliberately.
    ///
    pub fn into_parts(self) -> (Transport, State, Handler, ClientConnectionContext<Evidence>) {
        (
            self.core.connection.into_transport().into_inner(),
            self.state,
            self.core.handler,
            self.core.context,
        )
    }
}

impl<Transport, Cleanliness, Evidence, Handler>
    ClientConnectionCore<Transport, Cleanliness, Evidence, Handler>
where
    Transport: AsyncRead + Unpin,
{
    pub(crate) fn pop_parameter_status(&mut self) -> Option<crate::codec::BackendMessage> {
        self.connection.pop_parameter_status().map(|status| {
            crate::codec::BackendMessage::ParameterStatus {
                name: status.name,
                value: status.value,
            }
        })
    }
}

impl<Transport, Cleanliness, Evidence, Handler>
    ClientConnectionCore<Transport, Cleanliness, Evidence, Handler>
{
    pub(crate) const fn context(&self) -> &ClientConnectionContext<Evidence> {
        &self.context
    }
    pub(crate) async fn receive_wire_raw(&mut self) -> io::Result<crate::codec::BackendMessage>
    where
        Transport: AsyncRead + Unpin,
    {
        self.connection.receive_backend_wire().await
    }

    pub(crate) fn intercept_backend<State>(
        &mut self,
        state: &mut State,
        message: crate::codec::BackendMessage,
    ) -> crate::codec::BackendMessage
    where
        Handler: crate::ClientMiddleware<State, ClientConnectionContext<Evidence>>,
    {
        self.handler.backend(&self.context, state, message)
    }

    pub(crate) fn intercept_frontend<State>(
        &mut self,
        state: &mut State,
        message: FrontendMessage,
    ) -> FrontendMessage
    where
        Handler: crate::ClientMiddleware<State, ClientConnectionContext<Evidence>>,
    {
        self.handler.frontend(&self.context, state, message)
    }

    pub(crate) async fn send_wire_raw(&mut self, message: FrontendMessage) -> io::Result<()>
    where
        Transport: AsyncWrite + Unpin,
    {
        self.connection.push_frame(message.to_frame()?)?;
        self.connection.flush().await
    }

    pub(crate) fn into_parts(self) -> (Transport, Handler, ClientConnectionContext<Evidence>) {
        (
            self.connection.into_transport().into_inner(),
            self.handler,
            self.context,
        )
    }
}

fn intercept_auth_response<State, Evidence, Handler>(
    handler: &mut Handler,
    context: &ClientConnectionContext<Evidence>,
    state: &mut State,
    response: Bytes,
) -> Result<Bytes, AuthenticationDriveError<Infallible>>
where
    Handler: crate::ClientMiddleware<State, ClientConnectionContext<Evidence>>,
{
    match handler.frontend(
        context,
        state,
        crate::codec::FrontendMessage::PasswordResponse(response),
    ) {
        crate::codec::FrontendMessage::PasswordResponse(response) => Ok(response),
        _ => Err(AuthenticationDriveError::InvalidResponse),
    }
}

async fn complete_password<Transport, Policy, State, Handler>(
    connection: Conn<Buffered<Transport, Backend>, crate::auth::PasswordResponse>,
    challenge: ClientAuthenticationChallenge,
    policy: &mut Policy,
    context: &ClientConnectionContext<Policy::Evidence>,
    state: &mut State,
    handler: &mut Handler,
) -> Result<
    Conn<Buffered<Transport, Backend>, crate::auth::AwaitingStartupReady>,
    AuthenticationDriveError<Policy::Error>,
>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
    Policy: ClientAuthenticationSession,
    Handler: crate::ClientMiddleware<State, ClientConnectionContext<Policy::Evidence>>,
{
    let response = policy
        .respond(challenge)
        .await
        .map_err(AuthenticationDriveError::Policy)?;
    let ClientAuthenticationResponse::Password(password) = response else {
        let _ = connection.into_transport();
        return Err(AuthenticationDriveError::InvalidResponse);
    };
    let password = intercept_auth_response(handler, context, state, password)
        .map_err(|_| AuthenticationDriveError::InvalidResponse)?;
    let (mut awaiting, frame) = connection
        .password(&password)
        .map_err(AuthenticationDriveError::Protocol)?;
    awaiting
        .push_frame(frame)
        .map_err(AuthenticationDriveError::Protocol)?;
    awaiting
        .flush()
        .await
        .map_err(AuthenticationDriveError::Protocol)?;
    let message = awaiting
        .receive_backend_wire()
        .await
        .map_err(AuthenticationDriveError::Protocol)?;
    let message = handler.backend(context, state, message);
    match awaiting.offer(message) {
        Ok(crate::auth::AuthCompletion::Ok(connection)) => Ok(connection),
        Ok(crate::auth::AuthCompletion::Error { conn, .. }) => {
            let _ = conn.into_transport();
            Err(AuthenticationDriveError::Rejected)
        }
        Err((conn, _)) => {
            let _ = conn.into_transport();
            Err(AuthenticationDriveError::Protocol(io::Error::new(
                io::ErrorKind::InvalidData,
                "illegal authentication completion",
            )))
        }
    }
}

async fn complete_sasl<Transport, Policy, State, Handler>(
    connection: Conn<Buffered<Transport, Backend>, crate::auth::SaslInitial>,
    mechanisms: Vec<Bytes>,
    policy: &mut Policy,
    context: &ClientConnectionContext<Policy::Evidence>,
    state: &mut State,
    handler: &mut Handler,
) -> Result<
    Conn<Buffered<Transport, Backend>, crate::auth::AwaitingStartupReady>,
    AuthenticationDriveError<Policy::Error>,
>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
    Policy: ClientAuthenticationSession,
    Handler: crate::ClientMiddleware<State, ClientConnectionContext<Policy::Evidence>>,
{
    let response = policy
        .respond(ClientAuthenticationChallenge::Sasl(mechanisms))
        .await
        .map_err(AuthenticationDriveError::Policy)?;
    let ClientAuthenticationResponse::SaslInitial {
        mechanism,
        response,
    } = response
    else {
        let _ = connection.into_transport();
        return Err(AuthenticationDriveError::InvalidResponse);
    };
    let response = intercept_auth_response(handler, context, state, response)
        .map_err(|_| AuthenticationDriveError::InvalidResponse)?;
    let (mut sasl, frame) = connection
        .sasl(&mechanism, &response)
        .map_err(AuthenticationDriveError::Protocol)?;
    sasl.push_frame(frame)
        .map_err(AuthenticationDriveError::Protocol)?;
    sasl.flush()
        .await
        .map_err(AuthenticationDriveError::Protocol)?;
    loop {
        let message = sasl
            .receive_backend_wire()
            .await
            .map_err(AuthenticationDriveError::Protocol)?;
        let message = handler.backend(context, state, message);
        match sasl.offer_backend(message) {
            Ok(crate::auth::SaslEvent::Continue { conn, challenge }) => {
                let response = policy
                    .respond(ClientAuthenticationChallenge::SaslContinue(challenge))
                    .await
                    .map_err(AuthenticationDriveError::Policy)?;
                let ClientAuthenticationResponse::Sasl(response) = response else {
                    let _ = conn.into_transport();
                    return Err(AuthenticationDriveError::InvalidResponse);
                };
                let response = intercept_auth_response(handler, context, state, response)
                    .map_err(|_| AuthenticationDriveError::InvalidResponse)?;
                let (mut next, frame) = conn.respond(response);
                next.push_frame(frame)
                    .map_err(AuthenticationDriveError::Protocol)?;
                next.flush()
                    .await
                    .map_err(AuthenticationDriveError::Protocol)?;
                sasl = next;
            }
            Ok(crate::auth::SaslEvent::Final { conn, server_final }) => {
                let response = policy
                    .respond(ClientAuthenticationChallenge::SaslFinal(server_final))
                    .await
                    .map_err(AuthenticationDriveError::Policy)?;
                if response != ClientAuthenticationResponse::Verified {
                    let _ = conn.into_transport();
                    return Err(AuthenticationDriveError::InvalidResponse);
                }
                let mut awaiting = conn.verified();
                let message = awaiting
                    .receive_backend_wire()
                    .await
                    .map_err(AuthenticationDriveError::Protocol)?;
                let message = handler.backend(context, state, message);
                return match awaiting.offer(message) {
                    Ok(crate::auth::AuthCompletion::Ok(connection)) => Ok(connection),
                    Ok(crate::auth::AuthCompletion::Error { conn, .. }) => {
                        let _ = conn.into_transport();
                        Err(AuthenticationDriveError::Rejected)
                    }
                    Err((conn, _)) => {
                        let _ = conn.into_transport();
                        Err(AuthenticationDriveError::Protocol(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "illegal SASL authentication completion",
                        )))
                    }
                };
            }
            Ok(crate::auth::SaslEvent::Error { conn, .. }) => {
                let _ = conn.into_transport();
                return Err(AuthenticationDriveError::Rejected);
            }
            Err((conn, _)) => {
                let _ = conn.into_transport();
                return Err(AuthenticationDriveError::Protocol(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "illegal SASL authentication message",
                )));
            }
        }
    }
}

async fn complete_token<Transport, Policy, State, Handler>(
    connection: Conn<Buffered<Transport, Backend>, crate::auth::TokenResponse>,
    challenge: ClientAuthenticationChallenge,
    policy: &mut Policy,
    context: &ClientConnectionContext<Policy::Evidence>,
    state: &mut State,
    handler: &mut Handler,
) -> Result<
    Conn<Buffered<Transport, Backend>, crate::auth::AwaitingStartupReady>,
    AuthenticationDriveError<Policy::Error>,
>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
    Policy: ClientAuthenticationSession,
    Handler: crate::ClientMiddleware<State, ClientConnectionContext<Policy::Evidence>>,
{
    let response = policy
        .respond(challenge)
        .await
        .map_err(AuthenticationDriveError::Policy)?;
    let ClientAuthenticationResponse::Token(token) = response else {
        let _ = connection.into_transport();
        return Err(AuthenticationDriveError::InvalidResponse);
    };
    let token = intercept_auth_response(handler, context, state, token)
        .map_err(|_| AuthenticationDriveError::InvalidResponse)?;
    let (mut waiting, frame) = connection.respond(token);
    waiting
        .push_frame(frame)
        .map_err(AuthenticationDriveError::Protocol)?;
    waiting
        .flush()
        .await
        .map_err(AuthenticationDriveError::Protocol)?;
    loop {
        let message = waiting
            .receive_backend_wire()
            .await
            .map_err(AuthenticationDriveError::Protocol)?;
        let message = handler.backend(context, state, message);
        match waiting.offer(message) {
            Ok(crate::auth::TokenAuthEvent::Continue { conn, token }) => {
                let response = policy
                    .respond(ClientAuthenticationChallenge::TokenContinue(token))
                    .await
                    .map_err(AuthenticationDriveError::Policy)?;
                let ClientAuthenticationResponse::Token(token) = response else {
                    let _ = conn.into_transport();
                    return Err(AuthenticationDriveError::InvalidResponse);
                };
                let token = intercept_auth_response(handler, context, state, token)
                    .map_err(|_| AuthenticationDriveError::InvalidResponse)?;
                let (mut next, frame) = conn.respond(token);
                next.push_frame(frame)
                    .map_err(AuthenticationDriveError::Protocol)?;
                next.flush()
                    .await
                    .map_err(AuthenticationDriveError::Protocol)?;
                waiting = next;
            }
            Ok(crate::auth::TokenAuthEvent::Ok(connection)) => return Ok(connection),
            Ok(crate::auth::TokenAuthEvent::Error { conn, .. }) => {
                let _ = conn.into_transport();
                return Err(AuthenticationDriveError::Rejected);
            }
            Err((conn, _)) => {
                let _ = conn.into_transport();
                return Err(AuthenticationDriveError::Protocol(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "illegal token authentication message",
                )));
            }
        }
    }
}

enum SessionEstablishError<AuthenticationError> {
    Authentication(ClientAuthenticationError<AuthenticationError>),
    Protocol(io::Error),
}

fn replace_session_item(
    item: SessionItem,
    replacement: crate::codec::BackendMessage,
) -> Option<SessionItem> {
    match (item, replacement) {
        (SessionItem::Message(_), message) => Some(SessionItem::Message(message)),
        (
            SessionItem::ReadyForQuery {
                parameters_changed, ..
            },
            crate::codec::BackendMessage::ReadyForQuery(status),
        ) => Some(SessionItem::ReadyForQuery {
            status,
            parameters_changed,
        }),
        (
            SessionItem::CommandComplete {
                command, notices, ..
            },
            crate::codec::BackendMessage::CommandComplete(tag),
        ) => Some(SessionItem::CommandComplete {
            tag,
            command,
            notices,
        }),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Typestate plus middleware lifecycle.
async fn establish_client_session<Transport, Authentication, State, Handler>(
    transport: ClientTransport<Transport>,
    startup: &StartupMessage,
    target: &ConnectTarget,
    authentication_policy: &Authentication,
    max_frame_len: usize,
    context: &ClientConnectionContext<Authentication::Evidence>,
    state: &mut State,
    handler: &mut Handler,
) -> Result<
    (
        Conn<Buffered<ClientTransport<Transport>, Backend>, Ready>,
        Authentication::Evidence,
        Option<crate::demux::CancelKey>,
    ),
    SessionEstablishError<Authentication::Error>,
>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
    Authentication: ClientAuthentication,
    Handler: crate::ClientMiddleware<State, ClientConnectionContext<Authentication::Evidence>>,
{
    let mut policy = authentication_policy.begin(target).await.map_err(|error| {
        SessionEstablishError::Authentication(ClientAuthenticationError::Policy(error))
    })?;
    let buffered = Buffered::with_max_frame_len(transport, max_frame_len)
        .map_err(SessionEstablishError::Protocol)?;
    let (mut startup_connection, packet) = Conn::new(buffered)
        .startup(startup)
        .map_err(SessionEstablishError::Protocol)?;
    startup_connection.push_startup_packet(&packet);
    let mut authentication = startup_connection.authentication();
    if let Err(error) = authentication.flush().await {
        let _ = authentication.into_transport();
        return Err(SessionEstablishError::Protocol(error));
    }
    let awaiting_ready = loop {
        let message = match authentication.receive_backend_wire().await {
            Ok(message) => message,
            Err(error) => {
                let _ = authentication.into_transport();
                return Err(SessionEstablishError::Protocol(error));
            }
        };
        let message = handler.backend(context, state, message);
        match authentication.offer_backend(message) {
            Ok(AuthEvent::Authentication(AuthOffer::Ok(connection))) => break connection,
            Ok(AuthEvent::Negotiate { conn, .. }) => authentication = conn,
            Ok(AuthEvent::Authentication(AuthOffer::Cleartext(connection))) => {
                break complete_password(
                    connection,
                    ClientAuthenticationChallenge::CleartextPassword,
                    &mut policy,
                    context,
                    state,
                    handler,
                )
                .await
                .map_err(session_authentication_error)?;
            }
            Ok(AuthEvent::Authentication(AuthOffer::Md5 { conn, salt })) => {
                break complete_password(
                    conn,
                    ClientAuthenticationChallenge::Md5Password(salt),
                    &mut policy,
                    context,
                    state,
                    handler,
                )
                .await
                .map_err(session_authentication_error)?;
            }
            Ok(AuthEvent::Authentication(AuthOffer::Sasl { conn, mechanisms })) => {
                break complete_sasl(conn, mechanisms, &mut policy, context, state, handler)
                    .await
                    .map_err(session_authentication_error)?;
            }
            Ok(AuthEvent::Authentication(AuthOffer::Gss(conn))) => {
                break complete_token(
                    conn,
                    ClientAuthenticationChallenge::Gss,
                    &mut policy,
                    context,
                    state,
                    handler,
                )
                .await
                .map_err(session_authentication_error)?;
            }
            Ok(AuthEvent::Authentication(AuthOffer::Sspi(conn))) => {
                break complete_token(
                    conn,
                    ClientAuthenticationChallenge::Sspi,
                    &mut policy,
                    context,
                    state,
                    handler,
                )
                .await
                .map_err(session_authentication_error)?;
            }
            Ok(AuthEvent::Authentication(AuthOffer::KerberosV5(conn))) => {
                break complete_token(
                    conn,
                    ClientAuthenticationChallenge::KerberosV5,
                    &mut policy,
                    context,
                    state,
                    handler,
                )
                .await
                .map_err(session_authentication_error)?;
            }
            Ok(AuthEvent::Error { conn, .. }) => {
                let _ = conn.into_transport();
                return Err(SessionEstablishError::Authentication(
                    ClientAuthenticationError::Rejected,
                ));
            }
            Err((conn, _, source)) => {
                authentication = conn;
                if let Some(source) = source {
                    let _ = authentication.into_transport();
                    return Err(SessionEstablishError::Protocol(source));
                }
            }
        }
    };
    let mut awaiting_ready = awaiting_ready;
    let mut backend_key = None;
    let ready = loop {
        let item = match awaiting_ready.receive().await {
            Ok(item) => item,
            Err(error) => {
                let _ = awaiting_ready.into_transport();
                return Err(SessionEstablishError::Protocol(error));
            }
        };
        if let crate::codec::BackendMessage::BackendKeyData {
            process_id,
            secret_key,
        } = item.clone().into_backend_message()
        {
            backend_key = Some(crate::demux::CancelKey {
                process_id,
                secret_key,
            });
        }
        let replacement = handler.backend(context, state, item.clone().into_backend_message());
        let Some(item) = replace_session_item(item, replacement) else {
            let _ = awaiting_ready.into_transport();
            return Err(SessionEstablishError::Protocol(io::Error::new(
                io::ErrorKind::InvalidData,
                "middleware replacement during startup readiness is not phase-compatible",
            )));
        };
        match awaiting_ready.offer_ready(item) {
            Ok(ready) => break ready,
            Err((connection, SessionItem::Message(_))) => awaiting_ready = connection,
            Err((connection, _)) => {
                let _ = connection.into_transport();
                return Err(SessionEstablishError::Protocol(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup did not reach an idle operational phase",
                )));
            }
        }
    };
    let identity = policy.authenticated().await.map_err(|error| {
        SessionEstablishError::Authentication(ClientAuthenticationError::Policy(error))
    })?;
    Ok((ready, identity, backend_key))
}

fn session_authentication_error<Error>(
    error: AuthenticationDriveError<Error>,
) -> SessionEstablishError<Error> {
    match error {
        AuthenticationDriveError::Policy(error) => {
            SessionEstablishError::Authentication(ClientAuthenticationError::Policy(error))
        }
        AuthenticationDriveError::Rejected => {
            SessionEstablishError::Authentication(ClientAuthenticationError::Rejected)
        }
        AuthenticationDriveError::InvalidResponse => {
            SessionEstablishError::Authentication(ClientAuthenticationError::InvalidResponse)
        }
        AuthenticationDriveError::Protocol(error) => SessionEstablishError::Protocol(error),
    }
}

fn map_session_error<ConnectorError, TlsError, AuthenticationError>(
    error: SessionEstablishError<AuthenticationError>,
) -> ConnectError<ConnectorError, TlsError, ClientAuthenticationError<AuthenticationError>> {
    match error {
        SessionEstablishError::Authentication(error) => ConnectError::Authentication(error),
        SessionEstablishError::Protocol(error) => ConnectError::Protocol(error),
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

impl<Transport, State, Cleanliness, Evidence, Handler>
    ClientConnection<Transport, State, Cleanliness, Evidence, Handler>
where
    Transport: AsyncRead + AsyncWrite + Unpin,
    Handler: crate::ClientMiddleware<State, ClientConnectionContext<Evidence>>,
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
    ///
    #[allow(clippy::too_many_lines)]
    pub async fn simple_query(
        self,
        query: &[u8],
    ) -> Result<
        (
            ClientConnection<Transport, State, ConnectionChanged, Evidence, Handler>,
            Vec<crate::codec::BackendMessage>,
        ),
        QueryError,
    > {
        let Self {
            core:
                ClientConnectionCore {
                    connection,
                    mut handler,
                    context,
                },
            mut state,
        } = self;
        let outbound = handler.frontend(
            &context,
            &mut state,
            crate::codec::FrontendMessage::Query(Bytes::copy_from_slice(query)),
        );
        let crate::codec::FrontendMessage::Query(query) = outbound else {
            let _ = connection.into_transport();
            return Err(QueryError(io::Error::new(
                io::ErrorKind::InvalidData,
                "middleware replaced Query with an incompatible message",
            )));
        };
        let (mut query_connection, frame) = connection.push_query(&query).map_err(QueryError)?;
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
            let observed =
                handler.backend(&context, &mut state, item.clone().into_backend_message());
            let Some(item) = replace_session_item(item, observed.clone()) else {
                let _ = query_connection.into_transport();
                return Err(QueryError(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "middleware replacement during simple query is not phase-compatible",
                )));
            };
            messages.push(observed);
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
                            core: ClientConnectionCore {
                                connection: connection.transition(),
                                handler,
                                context,
                            },
                            state,
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

impl<Connector, Tls, Authentication, Middleware, Work, Transport, Error>
    Client<Connector, Tls, Authentication, Middleware>
where
    Connector: Fn(&ConnectTarget) -> Work,
    Work: Future<Output = Result<Transport, Error>>,
    Transport: AsyncRead + AsyncWrite + Unpin,
    Authentication: ClientAuthentication,
    Tls: ClientTlsConfiguration,
    Middleware: crate::MiddlewareFactory<ClientInitialContext>,
{
    /// Establishes transport, startup, and configured authentication before returning.
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
        mut state: State,
    ) -> Result<
        ClientConnection<
            ClientTransport<Transport>,
            State,
            ConnectionClean,
            Authentication::Evidence,
            <Middleware as crate::MiddlewareFactory<ClientInitialContext>>::Handler,
        >,
        ConnectError<
            Error,
            ClientTlsError<<Tls::Provider as ClientTlsProvider>::Error>,
            ClientAuthenticationError<Authentication::Error>,
        >,
    >
    where
        <Middleware as crate::MiddlewareFactory<ClientInitialContext>>::Handler:
            crate::ClientMiddleware<State, ClientConnectionContext<Authentication::Evidence>>,
    {
        let core = self.connect_core(target, overrides, &mut state).await?;
        Ok(ClientConnection {
            core: ClientConnectionCore {
                connection: core.connection.transition(),
                handler: core.handler,
                context: core.context,
            },
            state,
        })
    }

    /// Establishes a client role while borrowing facade-owned state, ensuring
    /// the state remains recoverable on every connection failure.
    pub(crate) async fn connect_core<State>(
        &self,
        target: ConnectTarget,
        overrides: StartupParameters,
        state: &mut State,
    ) -> Result<
        ClientConnectionCore<
            ClientTransport<Transport>,
            Pristine,
            Authentication::Evidence,
            <Middleware as crate::MiddlewareFactory<ClientInitialContext>>::Handler,
        >,
        ConnectError<
            Error,
            ClientTlsError<<Tls::Provider as ClientTlsProvider>::Error>,
            ClientAuthenticationError<Authentication::Error>,
        >,
    >
    where
        <Middleware as crate::MiddlewareFactory<ClientInitialContext>>::Handler:
            crate::ClientMiddleware<State, ClientConnectionContext<Authentication::Evidence>>,
    {
        let mut handler = self.middleware.create(&ClientInitialContext {
            target: target.clone(),
        });
        let startup = self
            .defaults
            .clone()
            .merged_with(overrides)
            .into_message()
            .map_err(ConnectError::Startup)?;
        let mut context = ClientConnectionContext {
            target: target.clone(),
            tls: None,
            identity: None,
            backend_key: None,
        };
        let transport = (self.connector)(&target)
            .await
            .map_err(ConnectError::Connector)?;
        let configured_tls = self.tls.configured();
        let transport = match configured_tls {
            None => {
                context.tls = Some(ClientTlsStatus::Plaintext);
                ClientTransport::Plain(transport)
            }
            Some((mode, provider)) => negotiate_client_tls(
                transport,
                mode,
                provider,
                &target,
                &mut context,
                state,
                &mut handler,
            )
            .await
            .map_err(ConnectError::Tls)?,
        };
        let first_startup = handler.startup(&context, state, startup.clone());
        let first = establish_client_session(
            transport,
            &first_startup,
            &target,
            &self.authentication,
            self.limits.max_frame_len,
            &context,
            state,
            &mut handler,
        )
        .await;
        let retry_provider = match configured_tls {
            Some((crate::pre_startup::SslMode::Allow, provider)) if first.is_err() => {
                Some(provider)
            }
            _ => None,
        };
        let (ready, identity, backend_key) = if let Some(provider) = retry_provider {
            let transport = (self.connector)(&target)
                .await
                .map_err(ConnectError::Connector)?;
            // The retry is a new transport attempt within the same logical
            // connection; do not expose the failed plaintext attempt as its
            // current transport fact.
            context.tls = None;
            let transport = negotiate_client_tls(
                transport,
                crate::pre_startup::SslMode::Require,
                provider,
                &target,
                &mut context,
                state,
                &mut handler,
            )
            .await
            .map_err(ConnectError::Tls)?;
            let retry_startup = handler.startup(&context, state, startup);
            establish_client_session(
                transport,
                &retry_startup,
                &target,
                &self.authentication,
                self.limits.max_frame_len,
                &context,
                state,
                &mut handler,
            )
            .await
            .map_err(map_session_error)?
        } else {
            first.map_err(map_session_error)?
        };
        Ok(ClientConnectionCore {
            connection: ready,
            handler,
            context: {
                context.identity = Some(identity);
                context.backend_key = backend_key;
                context
            },
        })
    }
}

impl<Connector, Tls, Authentication, Middleware, Work, Transport, Error>
    Client<Connector, Tls, Authentication, Middleware>
where
    Connector: Fn(&ConnectTarget) -> Work,
    Work: Future<Output = Result<Transport, Error>>,
    Transport: AsyncWrite + Unpin,
{
    /// Opens a fresh transport and writes exactly one raw cancellation packet.
    ///
    /// Cancellation deliberately performs neither TLS negotiation nor startup
    /// authentication, as required by PostgreSQL's out-of-band protocol.
    ///
    /// # Errors
    ///
    /// Returns the connector's typed error or a cancellation encode/write error.
    pub async fn cancel(
        &self,
        target: &ConnectTarget,
        key: &crate::demux::CancelKey,
    ) -> Result<(), CancelError<Error>> {
        let mut transport = (self.connector)(target)
            .await
            .map_err(CancelError::Connector)?;
        let packet = crate::pre_startup::PreStartupMessage::CancelRequest {
            process_id: key.process_id,
            secret_key: key.secret_key.clone(),
        }
        .to_packet()
        .map_err(CancelError::Protocol)?;
        tokio::io::AsyncWriteExt::write_all(&mut transport, &packet)
            .await
            .map_err(CancelError::Protocol)?;
        tokio::io::AsyncWriteExt::shutdown(&mut transport)
            .await
            .map_err(CancelError::Protocol)
    }
}
