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
pub(crate) trait AcceptsMessage<Message> {
    /// Reports whether `message` is legal without advancing this state.
    fn accepts(&self, message: &Message) -> bool;
}

/// A protocol message which can verify that it has a valid wire representation.
pub(crate) trait ReconstructableMessage {
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
pub(crate) trait MessageMiddleware<Message, State> {
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
pub(crate) enum ClientRole {}

/// Marker for middleware handling messages sent by a PostgreSQL server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServerRole {}

/// Marker selecting associations for messages received from a peer.
pub(crate) enum Inbound {}

/// Marker selecting associations for messages sent by the local role.
pub(crate) enum Outbound {}

/// Associates a connection typestate with a generated protocol phase and legal message set.
///
/// Grammar declarations generate all implementations. The direction, sender role, and decoded
/// wire type remain explicit indices so callers can use one interface for inbound and outbound
/// capabilities without exposing generated association machinery.
pub(crate) trait PhaseAssociation<Direction, Role, Wire>:
    phase_association_seal::Sealed<Direction, Role, Wire>
{
    /// Generated grammar phase corresponding to the connection typestate.
    type ProtocolPhase;
    /// Opaque set of messages legal for this direction, role, and phase.
    type Message: AsRef<Wire> + TryFrom<Wire, Error = Wire> + Into<Wire>;
}

/// Seals [`PhaseAssociation`] while remaining nameable by generated grammar implementations.
#[doc(hidden)]
/// Seals generated phase associations to this crate.
pub(crate) mod phase_association_seal {
    /// Implemented alongside each generated phase association.
    pub(crate) trait Sealed<Direction, Role, Wire> {}
}

/// Async middleware whose role, protocol phase, and legal message set are type indexed.
///
/// `Message` should be a phase-specific message type generated by
/// [`pg_proto_fsm::protocol`]. Such values can only be obtained after a decoded
/// wire message has been projected into a legal transition for `Phase`, so an
/// implementation cannot return a replacement from another role or phase.
#[allow(async_fn_in_trait)]
pub(crate) trait TypedMiddleware<Role, Phase, Message, State> {
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
pub(crate) struct WireAdapter<Wire, Handler> {
    handler: Handler,
    _wire: PhantomData<fn(Wire) -> Wire>,
}

impl<Wire, Handler> WireAdapter<Wire, Handler> {
    /// Wraps direction-wide wire middleware for use at typed interception points.
    pub(crate) const fn new(handler: Handler) -> Self {
        Self {
            handler,
            _wire: PhantomData,
        }
    }

    /// Returns the wrapped wire middleware.
    pub(crate) fn into_inner(self) -> Handler {
        self.handler
    }
}

/// Failure from direction-wide middleware adapted to a typed phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WireAdapterError<Error, Wire> {
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
pub(crate) trait MessageMiddlewareExt: Sized {
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
pub(crate) struct Identity;

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
pub(crate) struct Then<First, Second> {
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
pub(crate) enum ChainError<First, Second> {
    /// The first stage rejected the message.
    First(First),
    /// The second stage rejected the message.
    Second(Second),
}

/// Failure while applying or validating middleware output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterceptError<Error, Message> {
    /// Middleware rejected the message according to its own policy.
    Middleware(Error),
    /// Middleware returned a message which is illegal in the supplied state.
    Invalid(Message),
}

/// I/O or interception failure while receiving a middleware-checked message.
#[derive(Debug)]
pub(crate) enum ReceiveError<Error, Message> {
    /// Reading or decoding the message failed.
    Io(io::Error),
    /// Middleware rejected the message or produced an illegal replacement.
    Intercept(InterceptError<Error, Message>),
}

/// Failure while receiving through compile-time phase-checked middleware.
#[derive(Debug)]
pub(crate) enum TypedReceiveError<Error, Wire> {
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
pub(crate) struct Middleware<State, Handler> {
    state: State,
    handler: Handler,
}

impl<State, Handler> Middleware<State, Handler> {
    /// Creates middleware with its connection- or application-local state.
    pub(crate) const fn new(state: State, handler: Handler) -> Self {
        Self { state, handler }
    }

    /// Borrows the accumulated user state.
    pub(crate) const fn state(&self) -> &State {
        &self.state
    }

    /// Mutably borrows the accumulated user state.
    pub(crate) const fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    /// Borrows the middleware implementation.
    pub(crate) const fn handler(&self) -> &Handler {
        &self.handler
    }

    /// Mutably borrows the middleware implementation.
    pub(crate) const fn handler_mut(&mut self) -> &mut Handler {
        &mut self.handler
    }

    /// Separates the accumulated state from its middleware implementation.
    pub(crate) fn into_parts(self) -> (State, Handler) {
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
    pub(crate) async fn intercept<Message>(
        &mut self,
        message: Message,
    ) -> Result<Message, Handler::Error>
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
    pub(crate) async fn intercept_typed<Role, Phase, Message>(
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
    pub(crate) async fn intercept_checked<Message, ProtocolState>(
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
    pub(crate) async fn intercept_outbound_typed<Role, Wire, State, Handler>(
        &self,
        middleware: &mut Middleware<State, Handler>,
        message: <Phase as PhaseAssociation<Outbound, Role, Wire>>::Message,
    ) -> Result<
        <Phase as PhaseAssociation<Outbound, Role, Wire>>::Message,
        TypedReceiveError<Handler::Error, Wire>,
    >
    where
        Phase: PhaseAssociation<Outbound, Role, Wire>,
        Wire: ReconstructableMessage,
        Handler: TypedMiddleware<
                Role,
                <Phase as PhaseAssociation<Outbound, Role, Wire>>::ProtocolPhase,
                <Phase as PhaseAssociation<Outbound, Role, Wire>>::Message,
                State,
            >,
    {
        let message = middleware
            .intercept_typed::<Role, <Phase as PhaseAssociation<Outbound, Role, Wire>>::ProtocolPhase, _>(
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
/// Tests for typed and wire-level middleware composition.
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;

    use super::{
        AcceptsMessage as _, ChainError, ClientRole, Identity, Inbound, InterceptError,
        MessageMiddlewareExt as _, Middleware, Outbound, PhaseAssociation, ServerRole, WireAdapter,
    };
    use crate::{
        Conn,
        codec::{BackendMessage, FrontendMessage, Parse},
        grammar::{
            authentication, backend, frontend, pre_startup as pre_startup_grammar,
            server_authentication, server_pre_startup,
        },
        middleware::TypedBackendMessage,
        pre_startup::{EncryptionReply, PreStartupMessage},
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn grammar_associations_cover_inbound_and_outbound_typestate_indices() {
        fn inbound<Connection, Role, Wire>()
        where
            Connection: PhaseAssociation<Inbound, Role, Wire>,
        {
        }
        fn outbound<Connection, Role, Wire>()
        where
            Connection: PhaseAssociation<Outbound, Role, Wire>,
        {
        }
        fn exact<Connection, Direction, Role, Wire, ProtocolPhase, Message>()
        where
            Connection: PhaseAssociation<
                    Direction,
                    Role,
                    Wire,
                    ProtocolPhase = ProtocolPhase,
                    Message = Message,
                >,
            Message: AsRef<Wire> + TryFrom<Wire, Error = Wire> + Into<Wire>,
        {
        }

        exact::<
            crate::auth::Ready,
            Inbound,
            ServerRole,
            BackendMessage,
            frontend::Ready,
            TypedBackendMessage<frontend::ReadyExternalMessage>,
        >();
        exact::<
            crate::auth::Ready,
            Outbound,
            ClientRole,
            FrontendMessage,
            frontend::Ready,
            frontend::ReadyInternalMessage,
        >();
        exact::<
            crate::auth::Ready,
            Inbound,
            ClientRole,
            FrontendMessage,
            backend::Ready,
            backend::ReadyExternalMessage,
        >();
        exact::<
            crate::server_session::ServerFunctionCallDone,
            Outbound,
            ServerRole,
            BackendMessage,
            backend::FunctionReady,
            TypedBackendMessage<backend::FunctionReadyInternalMessage>,
        >();
        exact::<
            crate::pre_startup::AwaitingSslReply,
            Inbound,
            ServerRole,
            EncryptionReply,
            pre_startup_grammar::AwaitingSslReply,
            pre_startup_grammar::AwaitingSslReplyExternalMessage,
        >();
        exact::<
            crate::pre_startup::PreStartup,
            Outbound,
            ClientRole,
            PreStartupMessage,
            pre_startup_grammar::PreStartup,
            pre_startup_grammar::PreStartupInternalMessage,
        >();
        exact::<
            crate::pre_startup::PreStartup,
            Inbound,
            ClientRole,
            PreStartupMessage,
            server_pre_startup::PreStartup,
            server_pre_startup::PreStartupExternalMessage,
        >();
        exact::<
            crate::pre_startup::ServerSslDecision,
            Outbound,
            ServerRole,
            EncryptionReply,
            server_pre_startup::SslDecision,
            server_pre_startup::SslDecisionInternalMessage,
        >();
        exact::<
            crate::auth::Auth,
            Inbound,
            ServerRole,
            BackendMessage,
            authentication::Auth,
            TypedBackendMessage<authentication::AuthExternalMessage>,
        >();
        exact::<
            crate::auth::PasswordResponse,
            Outbound,
            ClientRole,
            FrontendMessage,
            authentication::PasswordResponse,
            authentication::PasswordResponseInternalMessage,
        >();
        exact::<
            crate::server_auth::ServerAuth,
            Inbound,
            ClientRole,
            FrontendMessage,
            server_authentication::Auth,
            server_authentication::AuthExternalMessage,
        >();
        exact::<
            crate::server_auth::ServerAuth,
            Outbound,
            ServerRole,
            BackendMessage,
            server_authentication::Auth,
            TypedBackendMessage<server_authentication::AuthInternalMessage>,
        >();

        inbound::<crate::auth::Ready, ServerRole, BackendMessage>();
        inbound::<crate::auth::Ready, ClientRole, FrontendMessage>();
        outbound::<crate::auth::Ready, ClientRole, FrontendMessage>();
        inbound::<crate::pre_startup::PreStartup, ClientRole, PreStartupMessage>();
        outbound::<crate::pre_startup::PreStartup, ClientRole, PreStartupMessage>();
        inbound::<crate::server_auth::ServerAuth, ClientRole, FrontendMessage>();
        outbound::<crate::server_auth::ServerAuth, ServerRole, BackendMessage>();
        inbound::<crate::session::CopyBoth, ServerRole, BackendMessage>();
        outbound::<crate::session::CopyBoth, ClientRole, FrontendMessage>();

        inbound::<crate::auth::Auth, ServerRole, BackendMessage>();
        inbound::<crate::auth::TokenChallenge, ServerRole, BackendMessage>();
        inbound::<crate::auth::Sasl, ServerRole, BackendMessage>();
        inbound::<crate::auth::AwaitingAuthOk, ServerRole, BackendMessage>();
        inbound::<crate::auth::AwaitingStartupReady, ServerRole, BackendMessage>();
        inbound::<crate::session::SimpleQuery, ServerRole, BackendMessage>();
        inbound::<crate::session::FunctionCalling, ServerRole, BackendMessage>();
        inbound::<crate::session::Building, ServerRole, BackendMessage>();
        inbound::<crate::session::BoundBuilding, ServerRole, BackendMessage>();
        inbound::<crate::session::AwaitingReady, ServerRole, BackendMessage>();
        inbound::<crate::session::CopyIn, ServerRole, BackendMessage>();
        inbound::<crate::session::CopyOut, ServerRole, BackendMessage>();
        inbound::<crate::session::CopyBothClientDone, ServerRole, BackendMessage>();
        inbound::<crate::session::CopyBothServerDone, ServerRole, BackendMessage>();
        inbound::<crate::session::Draining, ServerRole, BackendMessage>();
        inbound::<crate::session::Resetting, ServerRole, BackendMessage>();
        inbound::<crate::session::ResetComplete, ServerRole, BackendMessage>();

        outbound::<crate::auth::PasswordResponse, ClientRole, FrontendMessage>();
        outbound::<crate::auth::TokenResponse, ClientRole, FrontendMessage>();
        outbound::<crate::auth::SaslInitial, ClientRole, FrontendMessage>();
        outbound::<crate::auth::SaslChallenge, ClientRole, FrontendMessage>();
        outbound::<crate::session::Building, ClientRole, FrontendMessage>();
        outbound::<crate::session::BoundBuilding, ClientRole, FrontendMessage>();
        outbound::<crate::session::CopyIn, ClientRole, FrontendMessage>();
        outbound::<crate::session::CopyBothServerDone, ClientRole, FrontendMessage>();
        outbound::<crate::pre_startup::ServerSslDecision, ServerRole, EncryptionReply>();
        outbound::<crate::pre_startup::ServerGssDecision, ServerRole, EncryptionReply>();

        inbound::<crate::pre_startup::AwaitingSslReply, ServerRole, EncryptionReply>();
        inbound::<crate::pre_startup::AwaitingGssReply, ServerRole, EncryptionReply>();
        inbound::<crate::server_auth::ServerPassword, ClientRole, FrontendMessage>();
        inbound::<crate::server_auth::ServerSaslInitial, ClientRole, FrontendMessage>();
        inbound::<crate::server_auth::ServerSaslResponse, ClientRole, FrontendMessage>();
        inbound::<crate::server_auth::ServerAuthResponse, ClientRole, FrontendMessage>();
        inbound::<crate::server_auth::ServerStartupReady, ClientRole, FrontendMessage>();
        inbound::<crate::server_session::ServerBuilding, ClientRole, FrontendMessage>();
        inbound::<crate::server_session::ServerExtendedError, ClientRole, FrontendMessage>();
        inbound::<
            crate::server_session::ServerCopyIn<crate::server_session::CopySimple>,
            ClientRole,
            FrontendMessage,
        >();
        inbound::<
            crate::server_session::ServerCopyIn<crate::server_session::CopyExtended>,
            ClientRole,
            FrontendMessage,
        >();
        inbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopySimple,
                crate::server_session::BothOpen,
            >,
            ClientRole,
            FrontendMessage,
        >();
        inbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopyExtended,
                crate::server_session::BothOpen,
            >,
            ClientRole,
            FrontendMessage,
        >();
        inbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopySimple,
                crate::server_session::BothServerDone,
            >,
            ClientRole,
            FrontendMessage,
        >();
        inbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopyExtended,
                crate::server_session::BothServerDone,
            >,
            ClientRole,
            FrontendMessage,
        >();

        outbound::<crate::server_auth::ServerStartupRejected, ServerRole, BackendMessage>();
        outbound::<crate::server_auth::ServerPassword, ServerRole, BackendMessage>();
        outbound::<crate::server_auth::ServerSaslInitial, ServerRole, BackendMessage>();
        outbound::<crate::server_auth::ServerSasl, ServerRole, BackendMessage>();
        outbound::<crate::server_auth::ServerSaslResponse, ServerRole, BackendMessage>();
        outbound::<crate::server_auth::ServerAuthResponse, ServerRole, BackendMessage>();
        outbound::<crate::server_auth::ServerAuthPolicy, ServerRole, BackendMessage>();
        outbound::<crate::server_auth::ServerStartupReady, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerSimpleQuery, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerSimpleError, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerFunctionCall, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerFunctionCallDone, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerFunctionCallError, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerParse, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerBind, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerDescribe, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerExecute, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerClose, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerSync, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerBuilding, ServerRole, BackendMessage>();
        outbound::<crate::server_session::ServerExtendedError, ServerRole, BackendMessage>();
        outbound::<
            crate::server_session::ServerCopyIn<crate::server_session::CopySimple>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyIn<crate::server_session::CopyExtended>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyInDone<crate::server_session::CopySimple>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyInDone<crate::server_session::CopyExtended>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyInFailed<crate::server_session::CopySimple>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyInFailed<crate::server_session::CopyExtended>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyOut<crate::server_session::CopySimple>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyOut<crate::server_session::CopyExtended>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyOutDone<crate::server_session::CopySimple>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyOutDone<crate::server_session::CopyExtended>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopySimple,
                crate::server_session::BothOpen,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopyExtended,
                crate::server_session::BothOpen,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopySimple,
                crate::server_session::BothClientDone,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopyExtended,
                crate::server_session::BothClientDone,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopySimple,
                crate::server_session::BothServerDone,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopyExtended,
                crate::server_session::BothServerDone,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopySimple,
                crate::server_session::BothDone,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBoth<
                crate::server_session::CopyExtended,
                crate::server_session::BothDone,
            >,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBothFailed<crate::server_session::CopySimple>,
            ServerRole,
            BackendMessage,
        >();
        outbound::<
            crate::server_session::ServerCopyBothFailed<crate::server_session::CopyExtended>,
            ServerRole,
            BackendMessage,
        >();
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
