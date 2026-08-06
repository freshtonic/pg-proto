//! Stateful, composable interception of owned protocol messages.
//!
//! Middleware receives ownership of a decoded message and a mutable reference to
//! caller-defined state. Returning the input unchanged is a no-op; implementations
//! may instead mutate it or return another message of the same type. Protocol
//! session APIs remain responsible for checking that the result is legal in their
//! current state before advancing.

use std::marker::PhantomData;
use std::{convert::Infallible, io};

use crate::{
    codec::{BackendMessage, FrontendMessage},
    demux::Demux,
    grammar::{
        authentication, backend, frontend, pre_startup, server_authentication, server_pre_startup,
    },
    pre_startup::{EncryptionReply, PreStartupMessage},
};

/// State-aware validation of one directional protocol message type.
pub trait AcceptsMessage<Message> {
    /// Reports whether `message` is legal without advancing this state.
    fn accepts(&self, message: &Message) -> bool;
}

/// A protocol message which can verify that it has a valid wire representation.
pub trait ReconstructableMessage {
    /// Reports whether this typed value can be encoded on the wire.
    fn is_reconstructable(&self) -> bool;
}

impl ReconstructableMessage for FrontendMessage {
    fn is_reconstructable(&self) -> bool {
        self.to_frame().is_ok()
    }
}

impl ReconstructableMessage for BackendMessage {
    fn is_reconstructable(&self) -> bool {
        self.to_frame().is_ok()
    }
}

impl ReconstructableMessage for PreStartupMessage {
    fn is_reconstructable(&self) -> bool {
        self.to_packet().is_ok()
    }
}

impl ReconstructableMessage for EncryptionReply {
    fn is_reconstructable(&self) -> bool {
        true
    }
}

/// Validated backend traffic which does not advance the current protocol phase.
pub struct AsynchronousBackendMessage(BackendMessage);

impl AsynchronousBackendMessage {
    /// Borrows the decoded asynchronous backend message.
    #[must_use]
    pub const fn as_wire(&self) -> &BackendMessage {
        &self.0
    }

    /// Returns the decoded asynchronous backend message.
    #[must_use]
    pub fn into_wire(self) -> BackendMessage {
        self.0
    }
}

impl TryFrom<BackendMessage> for AsynchronousBackendMessage {
    type Error = BackendMessage;

    fn try_from(message: BackendMessage) -> Result<Self, Self::Error> {
        if Demux::is_asynchronous(&message) {
            Ok(Self(message))
        } else {
            Err(message)
        }
    }
}

/// Any server message legal in a phase, including non-advancing asynchronous traffic.
pub enum TypedBackendMessage<ProtocolMessage> {
    /// A message represented by a transition in the current grammar phase.
    Protocol(ProtocolMessage),
    /// An asynchronous message which leaves the current grammar phase unchanged.
    Asynchronous(AsynchronousBackendMessage),
}

impl<ProtocolMessage> AsRef<BackendMessage> for TypedBackendMessage<ProtocolMessage>
where
    ProtocolMessage: AsRef<BackendMessage>,
{
    fn as_ref(&self) -> &BackendMessage {
        match self {
            Self::Protocol(message) => message.as_ref(),
            Self::Asynchronous(message) => message.as_wire(),
        }
    }
}

impl<ProtocolMessage> TryFrom<BackendMessage> for TypedBackendMessage<ProtocolMessage>
where
    ProtocolMessage: TryFrom<BackendMessage, Error = BackendMessage>,
{
    type Error = BackendMessage;

    fn try_from(message: BackendMessage) -> Result<Self, Self::Error> {
        match AsynchronousBackendMessage::try_from(message) {
            Ok(message) => Ok(Self::Asynchronous(message)),
            Err(message) => ProtocolMessage::try_from(message).map(Self::Protocol),
        }
    }
}

impl<ProtocolMessage> From<TypedBackendMessage<ProtocolMessage>> for BackendMessage
where
    ProtocolMessage: Into<Self>,
{
    fn from(message: TypedBackendMessage<ProtocolMessage>) -> Self {
        match message {
            TypedBackendMessage::Protocol(message) => message.into(),
            TypedBackendMessage::Asynchronous(message) => message.into_wire(),
        }
    }
}

macro_rules! projected_messages {
    ($state:path, $internal:ty, $external:ty, $project_internal:path, $project_external:path) => {
        impl AcceptsMessage<$internal> for $state {
            fn accepts(&self, message: &$internal) -> bool {
                $project_internal(*self, message).is_some()
            }
        }

        impl AcceptsMessage<$external> for $state {
            fn accepts(&self, message: &$external) -> bool {
                $project_external(*self, message).is_some()
            }
        }
    };
}

projected_messages!(
    pre_startup::RuntimeState,
    PreStartupMessage,
    EncryptionReply,
    pre_startup::project_internal,
    pre_startup::project_external
);
projected_messages!(
    server_pre_startup::RuntimeState,
    EncryptionReply,
    PreStartupMessage,
    server_pre_startup::project_internal,
    server_pre_startup::project_external
);
projected_messages!(
    authentication::RuntimeState,
    FrontendMessage,
    BackendMessage,
    authentication::project_internal,
    authentication::project_external
);
projected_messages!(
    server_authentication::RuntimeState,
    BackendMessage,
    FrontendMessage,
    server_authentication::project_internal,
    server_authentication::project_external
);

impl AcceptsMessage<FrontendMessage> for frontend::RuntimeState {
    fn accepts(&self, message: &FrontendMessage) -> bool {
        frontend::project_internal(*self, message).is_some()
    }
}

impl AcceptsMessage<BackendMessage> for frontend::RuntimeState {
    fn accepts(&self, message: &BackendMessage) -> bool {
        Demux::is_asynchronous(message) || frontend::project_external(*self, message).is_some()
    }
}

impl AcceptsMessage<BackendMessage> for backend::RuntimeState {
    fn accepts(&self, message: &BackendMessage) -> bool {
        Demux::is_asynchronous(message) || backend::project_internal(*self, message).is_some()
    }
}

impl AcceptsMessage<FrontendMessage> for backend::RuntimeState {
    fn accepts(&self, message: &FrontendMessage) -> bool {
        backend::project_external(*self, message).is_some()
    }
}

/// Asynchronously intercepts an owned message with access to caller-defined state.
///
/// The message type determines the direction at compile time: middleware over
/// `FrontendMessage` cannot accidentally return a `BackendMessage`, and vice
/// versa.
#[allow(async_fn_in_trait)]
pub trait MessageMiddleware<Message, State> {
    /// An error which prevents the message from continuing through the chain.
    type Error;

    /// Observes, mutates, or replaces one message and may await external policy,
    /// storage, or telemetry work before returning it.
    ///
    /// # Errors
    ///
    /// Returns a policy-defined error to stop message processing.
    async fn intercept(
        &mut self,
        state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error>;
}

/// Marker for middleware handling messages sent by a PostgreSQL client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRole {}

/// Marker for middleware handling messages sent by a PostgreSQL server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerRole {}

/// Associates a connection typestate with its generated legal message type.
///
/// Implementations are provided only for matching sender roles and decoded wire
/// directions. This is the bridge which lets [`crate::Conn`] infer middleware's
/// `Role`, `ProtocolPhase`, and `Message` indices from its own phase parameter.
pub trait TypedPhase<Role, Wire> {
    /// Generated grammar phase corresponding to the connection typestate.
    type ProtocolPhase;
    /// Opaque set of decoded messages legal for this role and phase.
    type Message: AsRef<Wire> + TryFrom<Wire, Error = Wire> + Into<Wire>;
}

/// Associates a connection typestate with messages its local role may send.
///
/// Unlike [`TypedPhase`], which describes peer-selected input, this trait indexes
/// the generated internal message set used before a locally generated value is
/// encoded and sent.
pub trait TypedOutboundPhase<Role, Wire> {
    /// Generated grammar phase corresponding to the connection typestate.
    type ProtocolPhase;
    /// Opaque set of locally generated messages legal in this phase.
    type Message: AsRef<Wire> + TryFrom<Wire, Error = Wire> + Into<Wire>;
}

macro_rules! typed_outbound_phase {
    ($role:ty, $wire:ty; $($connection:ty => $protocol:path, $message:path);+ $(;)?) => {
        $(
            impl TypedOutboundPhase<$role, $wire> for $connection {
                type ProtocolPhase = $protocol;
                type Message = $message;
            }
        )+
    };
}

macro_rules! typed_outbound_backend_phase {
    ($($connection:ty => $protocol:path, $message:path);+ $(;)?) => {
        $(
            impl TypedOutboundPhase<ServerRole, BackendMessage> for $connection {
                type ProtocolPhase = $protocol;
                type Message = TypedBackendMessage<$message>;
            }
        )+
    };
}

typed_outbound_phase!(ClientRole, PreStartupMessage;
    crate::pre_startup::PreStartup => pre_startup::PreStartup, pre_startup::PreStartupInternalMessage;
);

typed_outbound_phase!(ClientRole, FrontendMessage;
    crate::auth::PasswordResponse => authentication::PasswordResponse, authentication::PasswordResponseInternalMessage;
    crate::auth::TokenResponse => authentication::TokenResponse, authentication::TokenResponseInternalMessage;
    crate::auth::SaslInitial => authentication::SaslInitial, authentication::SaslInitialInternalMessage;
    crate::auth::SaslChallenge => authentication::SaslChallenge, authentication::SaslChallengeInternalMessage;
    crate::auth::Ready => frontend::Ready, frontend::ReadyInternalMessage;
    crate::session::Building => frontend::Building, frontend::BuildingInternalMessage;
    crate::session::BoundBuilding => frontend::BoundBuilding, frontend::BoundBuildingInternalMessage;
    crate::session::CopyIn => frontend::CopyIn, frontend::CopyInInternalMessage;
    crate::session::CopyBoth => frontend::CopyBoth, frontend::CopyBothInternalMessage;
    crate::session::CopyBothServerDone => frontend::CopyBothServerDone, frontend::CopyBothServerDoneInternalMessage;
);

typed_outbound_phase!(ServerRole, EncryptionReply;
    crate::pre_startup::ServerSslDecision => server_pre_startup::SslDecision, server_pre_startup::SslDecisionInternalMessage;
    crate::pre_startup::ServerGssDecision => server_pre_startup::GssDecision, server_pre_startup::GssDecisionInternalMessage;
);

typed_outbound_backend_phase!(
    crate::server_auth::ServerStartupRejected => server_authentication::Startup, server_authentication::StartupInternalMessage;
    crate::server_auth::ServerAuth => server_authentication::Auth, server_authentication::AuthInternalMessage;
    crate::server_auth::ServerSasl => server_authentication::Sasl, server_authentication::SaslInternalMessage;
    crate::server_auth::ServerAuthResponse => server_authentication::TokenPolicy, server_authentication::TokenPolicyInternalMessage;
    crate::server_auth::ServerStartupReady => server_authentication::StartupReady, server_authentication::StartupReadyInternalMessage;
    crate::server_session::ServerSimpleQuery => backend::Simple, backend::SimpleInternalMessage;
    crate::server_session::ServerSimpleError => backend::SimpleError, backend::SimpleErrorInternalMessage;
    crate::server_session::ServerFunctionCall => backend::FunctionResponse, backend::FunctionResponseInternalMessage;
    crate::server_session::ServerFunctionCallDone => backend::FunctionReady, backend::FunctionReadyInternalMessage;
    crate::server_session::ServerFunctionCallError => backend::FunctionReady, backend::FunctionReadyInternalMessage;
    crate::server_session::ServerParse => backend::ParseResponse, backend::ParseResponseInternalMessage;
    crate::server_session::ServerBind => backend::BindResponse, backend::BindResponseInternalMessage;
    crate::server_session::ServerDescribe => backend::DescribeResponse, backend::DescribeResponseInternalMessage;
    crate::server_session::ServerExecute => backend::ExecuteResponse, backend::ExecuteResponseInternalMessage;
    crate::server_session::ServerClose => backend::CloseResponse, backend::CloseResponseInternalMessage;
    crate::server_session::ServerSync => backend::SyncResponse, backend::SyncResponseInternalMessage;
    crate::server_session::ServerCopyInDone<crate::server_session::CopySimple> => backend::SimpleCopyInDone, backend::SimpleCopyInDoneInternalMessage;
    crate::server_session::ServerCopyInDone<crate::server_session::CopyExtended> => backend::ExtendedCopyInDone, backend::ExtendedCopyInDoneInternalMessage;
    crate::server_session::ServerCopyInFailed<crate::server_session::CopySimple> => backend::SimpleCopyInFailed, backend::SimpleCopyInFailedInternalMessage;
    crate::server_session::ServerCopyInFailed<crate::server_session::CopyExtended> => backend::ExtendedCopyInFailed, backend::ExtendedCopyInFailedInternalMessage;
    crate::server_session::ServerCopyOut<crate::server_session::CopySimple> => backend::SimpleCopyOut, backend::SimpleCopyOutInternalMessage;
    crate::server_session::ServerCopyOut<crate::server_session::CopyExtended> => backend::ExtendedCopyOut, backend::ExtendedCopyOutInternalMessage;
    crate::server_session::ServerCopyOutDone<crate::server_session::CopySimple> => backend::SimpleCopyOutDone, backend::SimpleCopyOutDoneInternalMessage;
    crate::server_session::ServerCopyOutDone<crate::server_session::CopyExtended> => backend::ExtendedCopyOutDone, backend::ExtendedCopyOutDoneInternalMessage;
    crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothOpen> => backend::SimpleCopyBoth, backend::SimpleCopyBothInternalMessage;
    crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothOpen> => backend::ExtendedCopyBoth, backend::ExtendedCopyBothInternalMessage;
    crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothClientDone> => backend::SimpleCopyBothClientDone, backend::SimpleCopyBothClientDoneInternalMessage;
    crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothClientDone> => backend::ExtendedCopyBothClientDone, backend::ExtendedCopyBothClientDoneInternalMessage;
    crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothDone> => backend::SimpleCopyBothDone, backend::SimpleCopyBothDoneInternalMessage;
    crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothDone> => backend::ExtendedCopyBothDone, backend::ExtendedCopyBothDoneInternalMessage;
    crate::server_session::ServerCopyBothFailed<crate::server_session::CopySimple> => backend::SimpleCopyBothFailed, backend::SimpleCopyBothFailedInternalMessage;
    crate::server_session::ServerCopyBothFailed<crate::server_session::CopyExtended> => backend::ExtendedCopyBothFailed, backend::ExtendedCopyBothFailedInternalMessage;
);

impl TypedPhase<ServerRole, BackendMessage> for crate::auth::Ready {
    type ProtocolPhase = frontend::Ready;
    type Message = TypedBackendMessage<frontend::ReadyExternalMessage>;
}

impl TypedPhase<ClientRole, FrontendMessage> for crate::auth::Ready {
    type ProtocolPhase = backend::Ready;
    type Message = backend::ReadyExternalMessage;
}

impl TypedPhase<ClientRole, PreStartupMessage> for crate::pre_startup::PreStartup {
    type ProtocolPhase = server_pre_startup::PreStartup;
    type Message = server_pre_startup::PreStartupExternalMessage;
}

impl TypedPhase<ServerRole, EncryptionReply> for crate::pre_startup::AwaitingSslReply {
    type ProtocolPhase = pre_startup::AwaitingSslReply;
    type Message = pre_startup::AwaitingSslReplyExternalMessage;
}

impl TypedPhase<ServerRole, EncryptionReply> for crate::pre_startup::AwaitingGssReply {
    type ProtocolPhase = pre_startup::AwaitingGssReply;
    type Message = pre_startup::AwaitingGssReplyExternalMessage;
}

macro_rules! typed_backend_phase {
    ($connection:path => $protocol:path, $message:path) => {
        impl TypedPhase<ServerRole, BackendMessage> for $connection {
            type ProtocolPhase = $protocol;
            type Message = TypedBackendMessage<$message>;
        }
    };
}

typed_backend_phase!(crate::auth::Auth => authentication::Auth, authentication::AuthExternalMessage);
typed_backend_phase!(crate::auth::TokenChallenge => authentication::TokenChallenge, authentication::TokenChallengeExternalMessage);
typed_backend_phase!(crate::auth::Sasl => authentication::Sasl, authentication::SaslExternalMessage);
typed_backend_phase!(crate::auth::AwaitingAuthOk => authentication::AwaitingAuthOk, authentication::AwaitingAuthOkExternalMessage);
typed_backend_phase!(crate::auth::AwaitingStartupReady => authentication::AwaitingStartupReady, authentication::AwaitingStartupReadyExternalMessage);
typed_backend_phase!(crate::session::SimpleQuery => frontend::Simple, frontend::SimpleExternalMessage);
typed_backend_phase!(crate::session::FunctionCalling => frontend::FunctionCalling, frontend::FunctionCallingExternalMessage);
typed_backend_phase!(crate::session::Building => frontend::Building, frontend::BuildingExternalMessage);
typed_backend_phase!(crate::session::BoundBuilding => frontend::BoundBuilding, frontend::BoundBuildingExternalMessage);
typed_backend_phase!(crate::session::AwaitingReady => frontend::AwaitingReady, frontend::AwaitingReadyExternalMessage);
typed_backend_phase!(crate::session::CopyIn => frontend::CopyIn, frontend::CopyInExternalMessage);
typed_backend_phase!(crate::session::CopyOut => frontend::CopyOut, frontend::CopyOutExternalMessage);
typed_backend_phase!(crate::session::CopyBoth => frontend::CopyBoth, frontend::CopyBothExternalMessage);
typed_backend_phase!(crate::session::CopyBothClientDone => frontend::CopyBothClientDone, frontend::CopyBothClientDoneExternalMessage);
typed_backend_phase!(crate::session::CopyBothServerDone => frontend::CopyBothServerDone, frontend::CopyBothServerDoneExternalMessage);
typed_backend_phase!(crate::session::Draining => frontend::Draining, frontend::DrainingExternalMessage);
typed_backend_phase!(crate::session::Resetting => frontend::Resetting, frontend::ResettingExternalMessage);
typed_backend_phase!(crate::session::ResetComplete => frontend::ResetComplete, frontend::ResetCompleteExternalMessage);

macro_rules! typed_frontend_phase {
    ($connection:ty => $protocol:path, $message:path) => {
        impl TypedPhase<ClientRole, FrontendMessage> for $connection {
            type ProtocolPhase = $protocol;
            type Message = $message;
        }
    };
}

typed_frontend_phase!(crate::server_auth::ServerAuth => server_authentication::Auth, server_authentication::AuthExternalMessage);
typed_frontend_phase!(crate::server_auth::ServerPassword => server_authentication::PasswordResponse, server_authentication::PasswordResponseExternalMessage);
typed_frontend_phase!(crate::server_auth::ServerSaslInitial => server_authentication::SaslInitial, server_authentication::SaslInitialExternalMessage);
typed_frontend_phase!(crate::server_auth::ServerSasl => server_authentication::SaslResponse, server_authentication::SaslResponseExternalMessage);
typed_frontend_phase!(crate::server_auth::ServerAuthResponse => server_authentication::TokenResponse, server_authentication::TokenResponseExternalMessage);
typed_frontend_phase!(crate::server_auth::ServerStartupReady => server_authentication::StartupReady, server_authentication::StartupReadyExternalMessage);
typed_frontend_phase!(crate::server_session::ServerBuilding => backend::Building, backend::BuildingExternalMessage);
typed_frontend_phase!(crate::server_session::ServerExtendedError => backend::ExtendedError, backend::ExtendedErrorExternalMessage);
typed_frontend_phase!(crate::server_session::ServerCopyIn<crate::server_session::CopySimple> => backend::SimpleCopyIn, backend::SimpleCopyInExternalMessage);
typed_frontend_phase!(crate::server_session::ServerCopyIn<crate::server_session::CopyExtended> => backend::ExtendedCopyIn, backend::ExtendedCopyInExternalMessage);
typed_frontend_phase!(crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothOpen> => backend::SimpleCopyBoth, backend::SimpleCopyBothExternalMessage);
typed_frontend_phase!(crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothOpen> => backend::ExtendedCopyBoth, backend::ExtendedCopyBothExternalMessage);
typed_frontend_phase!(crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothServerDone> => backend::SimpleCopyBothServerDone, backend::SimpleCopyBothServerDoneExternalMessage);
typed_frontend_phase!(crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothServerDone> => backend::ExtendedCopyBothServerDone, backend::ExtendedCopyBothServerDoneExternalMessage);

/// Async middleware whose role, protocol phase, and legal message set are type indexed.
///
/// `Message` should be a phase-specific message type generated by
/// [`pg_proto_fsm::protocol`]. Such values can only be obtained after a decoded
/// wire message has been projected into a legal transition for `Phase`, so an
/// implementation cannot return a replacement from another role or phase.
#[allow(async_fn_in_trait)]
pub trait TypedMiddleware<Role, Phase, Message, State> {
    /// An error which prevents the message from continuing through the chain.
    type Error;

    /// Observes, mutates, or replaces one phase-legal message and may await while
    /// borrowing both the handler and caller-defined state.
    ///
    /// # Errors
    ///
    /// Returns a policy-defined error to stop message processing.
    async fn intercept_typed(
        &mut self,
        state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error>;
}

/// Adapts one direction-wide wire middleware to every generated typed phase.
///
/// Messages returned by the wrapped middleware are re-projected into the same
/// phase-specific `Message` type. This provides a pass-through default for
/// policies which inspect only selected wire families; a replacement which is
/// illegal in the inferred phase is returned as an error.
pub struct WireAdapter<Wire, Handler> {
    handler: Handler,
    _wire: PhantomData<fn(Wire) -> Wire>,
}

impl<Wire, Handler> WireAdapter<Wire, Handler> {
    /// Wraps direction-wide wire middleware for use at typed interception points.
    pub const fn new(handler: Handler) -> Self {
        Self {
            handler,
            _wire: PhantomData,
        }
    }

    /// Returns the wrapped wire middleware.
    pub fn into_inner(self) -> Handler {
        self.handler
    }
}

/// Failure from direction-wide middleware adapted to a typed phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireAdapterError<Error, Wire> {
    /// The wrapped middleware rejected the message according to its policy.
    Middleware(Error),
    /// The wrapped middleware returned a wire message illegal in the typed phase.
    IllegalReplacement(Wire),
}

impl<Role, Phase, Message, State, Wire, Handler> TypedMiddleware<Role, Phase, Message, State>
    for WireAdapter<Wire, Handler>
where
    Message: Into<Wire> + TryFrom<Wire, Error = Wire>,
    Handler: MessageMiddleware<Wire, State>,
{
    type Error = WireAdapterError<Handler::Error, Wire>;

    async fn intercept_typed(
        &mut self,
        state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error> {
        let message = self
            .handler
            .intercept(state, message.into())
            .await
            .map_err(WireAdapterError::Middleware)?;
        Message::try_from(message).map_err(WireAdapterError::IllegalReplacement)
    }
}

impl<Role, Phase, Message, State, Error, F> TypedMiddleware<Role, Phase, Message, State> for F
where
    F: for<'a> AsyncFnMut(&'a mut State, Message) -> Result<Message, Error>,
{
    type Error = Error;

    async fn intercept_typed(
        &mut self,
        state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error> {
        self(state, message).await
    }
}

/// Adds composition to every sized middleware implementation.
pub trait MessageMiddlewareExt: Sized {
    /// Runs this value followed by `next` whenever both implement middleware for
    /// the intercepted message and state types.
    fn then<Next>(self, next: Next) -> Then<Self, Next> {
        Then {
            first: self,
            second: next,
        }
    }
}

impl<Handler> MessageMiddlewareExt for Handler {}

impl<Message, State, Error, F> MessageMiddleware<Message, State> for F
where
    F: for<'a> AsyncFnMut(&'a mut State, Message) -> Result<Message, Error>,
{
    type Error = Error;

    async fn intercept(
        &mut self,
        state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error> {
        self(state, message).await
    }
}

/// Middleware which returns every message unchanged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Identity;

impl<Message, State> MessageMiddleware<Message, State> for Identity {
    type Error = Infallible;

    async fn intercept(
        &mut self,
        _state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error> {
        Ok(message)
    }
}

impl<Role, Phase, Message, State> TypedMiddleware<Role, Phase, Message, State> for Identity {
    type Error = Infallible;

    async fn intercept_typed(
        &mut self,
        _state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error> {
        Ok(message)
    }
}

/// Two middleware stages evaluated from `first` to `second`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Then<First, Second> {
    first: First,
    second: Second,
}

impl<First, Second> Then<First, Second> {
    pub(crate) fn parts_mut(&mut self) -> (&mut First, &mut Second) {
        (&mut self.first, &mut self.second)
    }
}

impl<Message, State, First, Second> MessageMiddleware<Message, State> for Then<First, Second>
where
    First: MessageMiddleware<Message, State>,
    Second: MessageMiddleware<Message, State>,
{
    type Error = ChainError<First::Error, Second::Error>;

    async fn intercept(
        &mut self,
        state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error> {
        let message = self
            .first
            .intercept(state, message)
            .await
            .map_err(ChainError::First)?;
        self.second
            .intercept(state, message)
            .await
            .map_err(ChainError::Second)
    }
}

impl<Role, Phase, Message, State, First, Second> TypedMiddleware<Role, Phase, Message, State>
    for Then<First, Second>
where
    First: TypedMiddleware<Role, Phase, Message, State>,
    Second: TypedMiddleware<Role, Phase, Message, State>,
{
    type Error = ChainError<First::Error, Second::Error>;

    async fn intercept_typed(
        &mut self,
        state: &mut State,
        message: Message,
    ) -> Result<Message, Self::Error> {
        let message = self
            .first
            .intercept_typed(state, message)
            .await
            .map_err(ChainError::First)?;
        self.second
            .intercept_typed(state, message)
            .await
            .map_err(ChainError::Second)
    }
}

/// Identifies which stage of a two-part middleware chain failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError<First, Second> {
    /// The first stage rejected the message.
    First(First),
    /// The second stage rejected the message.
    Second(Second),
}

/// Failure while applying or validating middleware output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterceptError<Error, Message> {
    /// Middleware rejected the message according to its own policy.
    Middleware(Error),
    /// Middleware returned a message which is illegal in the supplied state.
    Invalid(Message),
}

/// I/O or interception failure while receiving a middleware-checked message.
#[derive(Debug)]
pub enum ReceiveError<Error, Message> {
    /// Reading or decoding the message failed.
    Io(io::Error),
    /// Middleware rejected the message or produced an illegal replacement.
    Intercept(InterceptError<Error, Message>),
}

/// Failure while receiving through compile-time phase-checked middleware.
#[derive(Debug)]
pub enum TypedReceiveError<Error, Wire> {
    /// Reading or decoding the message failed.
    Io(io::Error),
    /// The peer sent a decoded message which is illegal in the connection phase.
    Illegal(Wire),
    /// Middleware rejected the phase-legal message according to its policy.
    Middleware(Error),
    /// Middleware produced a phase-legal value with an invalid wire shape.
    InvalidWire(Wire),
}

/// Owns user state and middleware as one reusable interception unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Middleware<State, Handler> {
    state: State,
    handler: Handler,
}

impl<State, Handler> Middleware<State, Handler> {
    /// Creates middleware with its connection- or application-local state.
    pub const fn new(state: State, handler: Handler) -> Self {
        Self { state, handler }
    }

    /// Borrows the accumulated user state.
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Mutably borrows the accumulated user state.
    pub const fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    /// Borrows the middleware implementation.
    pub const fn handler(&self) -> &Handler {
        &self.handler
    }

    /// Mutably borrows the middleware implementation.
    pub const fn handler_mut(&mut self) -> &mut Handler {
        &mut self.handler
    }

    /// Separates the accumulated state from its middleware implementation.
    pub fn into_parts(self) -> (State, Handler) {
        (self.state, self.handler)
    }

    pub(crate) fn parts_mut(&mut self) -> (&mut State, &mut Handler) {
        (&mut self.state, &mut self.handler)
    }

    /// Intercepts one owned message.
    ///
    /// # Errors
    ///
    /// Returns the middleware's policy-defined error.
    pub async fn intercept<Message>(&mut self, message: Message) -> Result<Message, Handler::Error>
    where
        Handler: MessageMiddleware<Message, State>,
    {
        self.handler.intercept(&mut self.state, message).await
    }

    /// Intercepts a message whose role and legal protocol phase are type indexed.
    ///
    /// This operation performs no dynamic protocol-state check: `Role`, `Phase`,
    /// and the generated `Message` type are selected together by the typed caller.
    /// Wire-shape validation remains a separate runtime boundary after converting
    /// the result back into its decoded wire representation.
    ///
    /// # Errors
    ///
    /// Returns the middleware's policy-defined error.
    pub async fn intercept_typed<Role, Phase, Message>(
        &mut self,
        message: Message,
    ) -> Result<Message, Handler::Error>
    where
        Handler: TypedMiddleware<Role, Phase, Message, State>,
    {
        self.handler.intercept_typed(&mut self.state, message).await
    }

    /// Intercepts a message and checks the result against `protocol_state` at runtime.
    ///
    /// The compiler enforces the message direction and requires `ProtocolState`
    /// to implement [`AcceptsMessage`] for that message type. The replacement's
    /// concrete variant and the supplied generated [`crate::grammar`] runtime
    /// state value are dynamic, however, so protocol legality and wire
    /// reconstructability are checked at runtime after the complete middleware
    /// chain. Call this immediately before projecting and advancing the same
    /// protocol state.
    ///
    /// # Errors
    ///
    /// Returns a middleware policy error, or the unchanged replacement when it
    /// is not legal in `protocol_state`.
    pub async fn intercept_checked<Message, ProtocolState>(
        &mut self,
        protocol_state: &ProtocolState,
        message: Message,
    ) -> Result<Message, InterceptError<Handler::Error, Message>>
    where
        Message: ReconstructableMessage,
        Handler: MessageMiddleware<Message, State>,
        ProtocolState: AcceptsMessage<Message>,
    {
        let message = self
            .intercept(message)
            .await
            .map_err(InterceptError::Middleware)?;
        if message.is_reconstructable() && protocol_state.accepts(&message) {
            Ok(message)
        } else {
            Err(InterceptError::Invalid(message))
        }
    }
}

impl<Transport, Phase, Cleanliness> crate::Conn<Transport, Phase, Cleanliness> {
    /// Intercepts one locally generated message indexed by this connection phase.
    ///
    /// The returned generated enum may select a different legal transition in
    /// the same phase. Match it and apply the corresponding existing typestate
    /// operation before encoding or forwarding the value.
    ///
    /// # Errors
    ///
    /// Returns a middleware policy error or an invalid replacement wire shape.
    pub async fn intercept_outbound_typed<Role, Wire, State, Handler>(
        &self,
        middleware: &mut Middleware<State, Handler>,
        message: <Phase as TypedOutboundPhase<Role, Wire>>::Message,
    ) -> Result<
        <Phase as TypedOutboundPhase<Role, Wire>>::Message,
        TypedReceiveError<Handler::Error, Wire>,
    >
    where
        Phase: TypedOutboundPhase<Role, Wire>,
        Wire: ReconstructableMessage,
        Handler: TypedMiddleware<
                Role,
                <Phase as TypedOutboundPhase<Role, Wire>>::ProtocolPhase,
                <Phase as TypedOutboundPhase<Role, Wire>>::Message,
                State,
            >,
    {
        let message = middleware
            .intercept_typed::<Role, <Phase as TypedOutboundPhase<Role, Wire>>::ProtocolPhase, _>(
                message,
            )
            .await
            .map_err(TypedReceiveError::Middleware)?;
        if message.as_ref().is_reconstructable() {
            Ok(message)
        } else {
            Err(TypedReceiveError::InvalidWire(message.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;

    use super::{
        AcceptsMessage as _, ChainError, ClientRole, Identity, InterceptError,
        MessageMiddlewareExt as _, Middleware, WireAdapter,
    };
    use crate::{
        Conn,
        codec::{FrontendMessage, Parse},
        grammar::{
            backend, pre_startup as pre_startup_grammar, server_authentication, server_pre_startup,
        },
        pre_startup::PreStartupMessage,
    };

    #[tokio::test]
    async fn identity_is_a_no_op() {
        let mut middleware = Middleware::new((), Identity);
        assert_eq!(
            middleware.intercept(String::from("message")).await,
            Ok(String::from("message"))
        );
    }

    #[tokio::test]
    async fn closure_can_replace_message_and_accumulate_state() {
        let mut middleware = Middleware::new(
            Vec::new(),
            async |seen: &mut Vec<String>, message: String| {
                seen.push(message.clone());
                Ok::<_, &'static str>(message.to_uppercase())
            },
        );

        assert_eq!(
            middleware.intercept(String::from("hello")).await,
            Ok(String::from("HELLO"))
        );
        assert_eq!(middleware.state(), &[String::from("hello")]);
    }

    #[tokio::test]
    async fn connection_phase_indexes_locally_generated_typed_middleware() {
        let conn = Conn::new(());
        let message =
            pre_startup_grammar::PreStartupInternalMessage::try_from(PreStartupMessage::SslRequest)
                .expect("SSLRequest is legal before startup");
        let mut middleware = Middleware::new(
            Vec::new(),
            async |seen: &mut Vec<&'static str>,
                   _message: pre_startup_grammar::PreStartupInternalMessage| {
                seen.push("outbound");
                Ok::<_, Infallible>(
                    pre_startup_grammar::PreStartupInternalMessage::try_from(
                        PreStartupMessage::GssEncRequest,
                    )
                    .expect("GSSENCRequest is another legal pre-startup choice"),
                )
            },
        );

        let output = conn
            .intercept_outbound_typed::<ClientRole, PreStartupMessage, _, _>(
                &mut middleware,
                message,
            )
            .await
            .expect("replacement remains legal in the connection phase");

        assert!(matches!(output.as_ref(), PreStartupMessage::GssEncRequest));
        assert_eq!(middleware.state(), &["outbound"]);
        conn.into_transport();
    }

    #[tokio::test]
    async fn middleware_can_borrow_user_state_across_await() {
        let handler = async |steps: &mut Vec<&'static str>, message: String| {
            steps.push("before");
            tokio::task::yield_now().await;
            steps.push("after");
            Ok::<_, Infallible>(message)
        };
        let mut middleware = Middleware::new(Vec::new(), handler);

        assert_eq!(
            middleware.intercept(String::from("message")).await,
            Ok(String::from("message"))
        );
        assert_eq!(middleware.state(), &["before", "after"]);
    }

    #[tokio::test]
    async fn typed_closure_replaces_only_within_its_role_and_phase() {
        let handler = async |seen: &mut usize, _message: backend::ReadyExternalMessage| {
            *seen += 1;
            backend::ReadyExternalMessage::try_from(FrontendMessage::Terminate)
                .map_err(|_| "terminate must be legal while ready")
        };
        let mut middleware = Middleware::new(0, handler);
        let Ok(input) = backend::ReadyExternalMessage::try_from(FrontendMessage::Query(
            Bytes::from_static(b"select 1"),
        )) else {
            panic!("query must be legal while ready");
        };

        let output = middleware
            .intercept_typed::<ClientRole, backend::Ready, _>(input)
            .await
            .expect("middleware accepts the message");

        assert_eq!(output.event(), backend::Event::Terminate);
        assert!(matches!(output.into_wire(), FrontendMessage::Terminate));
        assert_eq!(*middleware.state(), 1);
    }

    #[tokio::test]
    async fn typed_chain_is_ordered_and_threads_shared_state() {
        let first = async |order: &mut Vec<&'static str>,
                           message: backend::ReadyExternalMessage| {
            order.push("first");
            Ok::<_, Infallible>(message)
        };
        let second = async |order: &mut Vec<&'static str>,
                            message: backend::ReadyExternalMessage| {
            order.push("second");
            Ok::<_, Infallible>(message)
        };
        let mut middleware = Middleware::new(Vec::new(), first.then(second));
        let Ok(input) = backend::ReadyExternalMessage::try_from(FrontendMessage::Terminate) else {
            panic!("terminate must be legal while ready");
        };

        let output = middleware
            .intercept_typed::<ClientRole, backend::Ready, _>(input)
            .await
            .expect("both typed stages accept the message");

        assert_eq!(output.event(), backend::Event::Terminate);
        assert_eq!(middleware.state(), &["first", "second"]);
    }

    #[tokio::test]
    async fn wire_adapter_passes_unhandled_families_through_multiple_phases() {
        let handler = async |seen: &mut usize, message: FrontendMessage| {
            *seen += 1;
            Ok::<_, Infallible>(message)
        };
        let mut middleware = Middleware::new(0, WireAdapter::new(handler));

        let Ok(ready) = backend::ReadyExternalMessage::try_from(FrontendMessage::Terminate) else {
            panic!("terminate must be legal while ready");
        };
        middleware
            .intercept_typed::<ClientRole, backend::Ready, _>(ready)
            .await
            .expect("ready pass-through");

        let Ok(building) = backend::BuildingExternalMessage::try_from(FrontendMessage::Sync) else {
            panic!("sync must be legal while building");
        };
        middleware
            .intercept_typed::<ClientRole, backend::Building, _>(building)
            .await
            .expect("building pass-through");

        assert_eq!(*middleware.state(), 2);
    }

    #[tokio::test]
    async fn chain_passes_replacement_to_next_stage_in_order() {
        let first = async |order: &mut Vec<&'static str>, mut message: String| {
            order.push("first");
            message.push('1');
            Ok::<_, &'static str>(message)
        };
        let second = async |order: &mut Vec<&'static str>, mut message: String| {
            order.push("second");
            message.push('2');
            Ok::<_, u8>(message)
        };
        let mut middleware = Middleware::new(Vec::new(), first.then(second));

        assert_eq!(
            middleware.intercept(String::from("m")).await,
            Ok(String::from("m12"))
        );
        assert_eq!(middleware.state(), &["first", "second"]);
    }

    #[tokio::test]
    async fn chain_stops_after_first_error() {
        let first = async |calls: &mut usize, _message: String| {
            *calls += 1;
            Err::<String, _>("rejected")
        };
        let second = async |calls: &mut usize, message: String| {
            *calls += 1;
            Ok::<_, u8>(message)
        };
        let mut middleware = Middleware::new(0, first.then(second));

        assert_eq!(
            middleware.intercept(String::from("message")).await,
            Err(ChainError::First("rejected"))
        );
        assert_eq!(*middleware.state(), 1);
    }

    #[tokio::test]
    async fn checked_interception_accepts_a_legal_replacement() {
        let mut middleware =
            Middleware::new((), async |_state: &mut (), _message: FrontendMessage| {
                Ok::<_, Infallible>(FrontendMessage::Terminate)
            });

        assert_eq!(
            middleware
                .intercept_checked(
                    &backend::RuntimeState::Ready,
                    FrontendMessage::Query(Bytes::from_static(b"select 1")),
                )
                .await,
            Ok(FrontendMessage::Terminate)
        );
    }

    #[tokio::test]
    async fn checked_interception_returns_an_illegal_replacement() {
        let replacement = FrontendMessage::Parse(Parse {
            statement: Bytes::new(),
            query: Bytes::from_static(b"select 2"),
            parameter_types: Vec::new(),
        });
        let expected = replacement.clone();
        let mut middleware = Middleware::new(
            (),
            async move |_state: &mut (), _message: FrontendMessage| {
                Ok::<_, Infallible>(replacement.clone())
            },
        );

        assert_eq!(
            middleware
                .intercept_checked(
                    &backend::RuntimeState::Simple,
                    FrontendMessage::Query(Bytes::from_static(b"select 1")),
                )
                .await,
            Err(InterceptError::Invalid(expected))
        );
    }

    #[test]
    fn generated_states_cover_authentication_extended_query_copy_and_replication() {
        let password = FrontendMessage::PasswordResponse(Bytes::from_static(b"secret"));
        assert!(server_authentication::RuntimeState::PasswordResponse.accepts(&password));
        assert!(
            !server_authentication::RuntimeState::PasswordResponse
                .accepts(&FrontendMessage::Query(Bytes::from_static(b"select 1")))
        );

        let parse = FrontendMessage::Parse(Parse {
            statement: Bytes::from_static(b"statement"),
            query: Bytes::from_static(b"select 1"),
            parameter_types: Vec::new(),
        });
        assert!(backend::RuntimeState::Building.accepts(&parse));
        assert!(
            !backend::RuntimeState::Building
                .accepts(&FrontendMessage::Query(Bytes::from_static(b"select 1")))
        );
        assert!(backend::RuntimeState::ExtendedError.accepts(&parse));
        assert!(backend::RuntimeState::ExtendedError.accepts(&FrontendMessage::Sync));

        let copy = FrontendMessage::CopyData(Bytes::from_static(b"data"));
        assert!(backend::RuntimeState::SimpleCopyIn.accepts(&copy));
        assert!(backend::RuntimeState::ExtendedCopyBoth.accepts(&copy));
        assert!(
            !backend::RuntimeState::ExtendedCopyBoth
                .accepts(&FrontendMessage::Query(Bytes::from_static(b"select 1")))
        );

        assert!(
            server_pre_startup::RuntimeState::PreStartup.accepts(&PreStartupMessage::SslRequest)
        );
        assert!(
            !server_pre_startup::RuntimeState::SslDecision.accepts(&PreStartupMessage::SslRequest)
        );
    }

    #[tokio::test]
    async fn checked_interception_rejects_an_unencodable_message() {
        let invalid = FrontendMessage::Parse(Parse {
            statement: Bytes::from_static(b"invalid\0name"),
            query: Bytes::from_static(b"select 1"),
            parameter_types: Vec::new(),
        });
        let expected = invalid.clone();
        let mut middleware = Middleware::new((), async move |_state: &mut (), _message| {
            Ok::<_, Infallible>(invalid.clone())
        });

        assert_eq!(
            middleware
                .intercept_checked(&backend::RuntimeState::Ready, FrontendMessage::Terminate)
                .await,
            Err(InterceptError::Invalid(expected))
        );
    }
}
