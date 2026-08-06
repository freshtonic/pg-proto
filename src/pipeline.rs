//! Bounded, payload-free orchestration for proxy request pipelines.
//!
//! The ledger in this module records protocol obligations, not wire messages.
//! Applications retain ownership of decoded messages until [`FrontendAction`] or
//! [`BackendAction`] tells them to forward, emit, retry, or discard the value.
//! Upstream transports may continue using [`Demux`]: drain its ordered async
//! events before passing each returned [`SessionItem`] to
//! [`Pipeline::accept_session_item`]. This retains the existing notice tagging,
//! parameter map, notification queue, cancellation key, and transaction evidence.

use std::{collections::VecDeque, convert::Infallible, marker::PhantomData, sync::Arc};

use tokio::sync::Notify;

use crate::{
    codec::{BackendMessage, FrontendMessage},
    demux::{Demux, SessionItem},
    grammar::backend,
    middleware::{
        AsynchronousBackendMessage, MessageMiddleware, Middleware, ReconstructableMessage as _,
    },
};

/// Stable identity of an accepted frontend operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(u64);

/// Pipeline policy which preserves the historical lock-step behaviour.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoPipeline;

/// Configuration for a bounded frontend operation pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedPipeline {
    max_operations: usize,
}

impl BoundedPipeline {
    /// Creates a pipeline with a non-zero operation-count limit.
    ///
    /// # Errors
    ///
    /// Returns an error when `max_operations` is zero.
    pub fn new(max_operations: usize) -> Result<Self, PipelineConfigError> {
        if max_operations == 0 {
            return Err(PipelineConfigError);
        }
        Ok(Self { max_operations })
    }

    /// Returns the maximum number of incomplete operations.
    #[must_use]
    pub const fn max_operations(self) -> usize {
        self.max_operations
    }
}

/// A zero operation-count limit is not a usable pipeline configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineConfigError;

impl std::fmt::Display for PipelineConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("pipeline operation limit must be non-zero")
    }
}

impl std::error::Error for PipelineConfigError {}

mod private {
    pub trait Sealed {}
}

/// Configuration accepted by [`Pipeline`].
pub trait PipelinePolicy: private::Sealed + Copy {
    /// Maximum number of incomplete operation records.
    fn operation_limit(self) -> usize;
}

impl private::Sealed for NoPipeline {}
impl PipelinePolicy for NoPipeline {
    fn operation_limit(self) -> usize {
        1
    }
}

impl private::Sealed for BoundedPipeline {}
impl PipelinePolicy for BoundedPipeline {
    fn operation_limit(self) -> usize {
        self.max_operations
    }
}

/// Whether an accepted frontend operation is locally handled or forwarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontendHandling {
    /// Send the returned message to the upstream connection.
    Forward,
    /// Do not send the request upstream; application code will synthesize its response.
    Local,
}

/// Application action for one successfully projected frontend message.
#[derive(Debug, Eq, PartialEq)]
pub enum FrontendAction {
    /// Forward the owned message upstream.
    Forward {
        /// Accepted operation identity.
        id: OperationId,
        /// Original, unretained frontend message.
        message: FrontendMessage,
    },
    /// The operation is locally handled and the message can be discarded.
    Discard {
        /// Accepted operation identity.
        id: OperationId,
    },
    /// Capacity is exhausted; pause reads and retry this unchanged message.
    Backpressure(FrontendMessage),
}

/// Position of a successfully accepted operation.
#[derive(Debug, Eq, PartialEq)]
pub enum FrontendAdmission {
    /// Nothing earlier prevents this operation's response from being emitted.
    Immediate(FrontendAction),
    /// The operation was accepted but an earlier response must be emitted first.
    Waiting(FrontendAction),
}

impl FrontendAdmission {
    /// Returns the application action, discarding only the positional annotation.
    #[must_use]
    pub fn into_action(self) -> FrontendAction {
        match self {
            Self::Immediate(action) | Self::Waiting(action) => action,
        }
    }
}

/// Why a frontend message could not be accepted.
#[derive(Debug, Eq, PartialEq)]
pub enum FrontendProjectionError {
    /// The bounded ledger is full; the unchanged message may be retried.
    Capacity(Box<FrontendMessage>),
    /// The message is not legal in the projected frontend protocol state.
    Illegal {
        /// Projected state at rejection.
        state: PipelineState,
        /// Unchanged illegal message.
        message: Box<FrontendMessage>,
    },
}

/// Application action for a backend message.
#[derive(Debug, Eq, PartialEq)]
pub enum BackendAction {
    /// Emit this owned message to the downstream client now.
    Emit(BackendMessage),
    /// An earlier operation must complete; retry this unchanged message later.
    Deferred(BackendMessage),
}

/// A backend message was not legal for any outstanding operation.
#[derive(Debug, Eq, PartialEq)]
pub struct BackendProjectionError {
    /// Current response-side state.
    pub state: PipelineState,
    /// Unchanged illegal message.
    pub message: BackendMessage,
}

/// Public summary of the pipeline's projected frontend state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineState {
    /// A simple or extended cycle may begin.
    Ready,
    /// Extended-query messages are being accepted.
    Extended,
    /// An extended error discards messages through `Sync`.
    ExtendedError,
    /// COPY IN accepts frontend data.
    CopyIn,
    /// COPY OUT accepts only backend data.
    CopyOut,
    /// COPY BOTH accepts data in both directions.
    CopyBoth,
    /// The connection has terminated.
    Terminated,
}

/// Type markers for backend response phases selected by the pipeline ledger.
pub mod phase {
    macro_rules! response_phases {
        ($($name:ident),+ $(,)?) => {
            $(
                #[doc = concat!("Backend responses associated with a pending `", stringify!($name), "` operation.")]
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub enum $name {}
            )+
        };
    }

    response_phases!(
        Query,
        FunctionCall,
        Parse,
        Bind,
        Describe,
        Execute,
        Close,
        Sync,
        CopyDone,
        CopyFail,
    );
}

mod response_phase_private {
    pub trait Sealed {}
}

/// A sealed backend response phase understood by [`Pipeline`].
pub trait PipelineResponsePhase: response_phase_private::Sealed {
    #[doc(hidden)]
    fn accepts(message: &BackendMessage) -> bool;
}

macro_rules! response_phase_impls {
    ($($phase:ident => $kind:ident),+ $(,)?) => {
        $(
            impl response_phase_private::Sealed for phase::$phase {}

            impl PipelineResponsePhase for phase::$phase {
                fn accepts(message: &BackendMessage) -> bool {
                    response_fits(OperationKind::$kind, message)
                }
            }
        )+
    };
}

response_phase_impls!(
    Query => Query,
    FunctionCall => FunctionCall,
    Parse => Parse,
    Bind => Bind,
    Describe => Describe,
    Execute => Execute,
    Close => Close,
    Sync => Sync,
    CopyDone => CopyDone,
    CopyFail => CopyFail,
);

/// An owned backend message legal for one pending pipeline operation.
///
/// Construction is fallible, so middleware cannot return a response outside
/// this operation's valid response set without passing the phase check.
pub struct PipelineBackendMessage<Phase> {
    message: BackendMessage,
    _phase: PhantomData<fn(Phase) -> Phase>,
}

impl<Phase> PipelineBackendMessage<Phase> {
    /// Borrows the decoded backend message.
    #[must_use]
    pub const fn as_wire(&self) -> &BackendMessage {
        &self.message
    }

    /// Returns the decoded backend message.
    #[must_use]
    pub fn into_wire(self) -> BackendMessage {
        self.message
    }

    /// Mutates or replaces the wire value while preserving this response phase.
    ///
    /// # Errors
    ///
    /// Returns the replacement when it is not legal for `Phase`.
    pub fn try_map_wire(
        self,
        map: impl FnOnce(BackendMessage) -> BackendMessage,
    ) -> Result<Self, BackendMessage>
    where
        Phase: PipelineResponsePhase,
    {
        Self::try_from(map(self.message))
    }
}

impl<Phase: PipelineResponsePhase> TryFrom<BackendMessage> for PipelineBackendMessage<Phase> {
    type Error = BackendMessage;

    fn try_from(message: BackendMessage) -> Result<Self, Self::Error> {
        if Phase::accepts(&message) && message.is_reconstructable() {
            Ok(Self {
                message,
                _phase: PhantomData,
            })
        } else {
            Err(message)
        }
    }
}

impl<Phase> AsRef<BackendMessage> for PipelineBackendMessage<Phase> {
    fn as_ref(&self) -> &BackendMessage {
        self.as_wire()
    }
}

impl<Phase> From<PipelineBackendMessage<Phase>> for BackendMessage {
    fn from(message: PipelineBackendMessage<Phase>) -> Self {
        message.into_wire()
    }
}

/// Error returned while dispatching a pipeline message through typed middleware.
#[derive(Debug)]
pub enum PipelineMiddlewareError<MiddlewareError, ProjectionError> {
    /// Middleware rejected the phase-typed message.
    Middleware(MiddlewareError),
    /// The pipeline rejected the original or rewritten message.
    Projection(ProjectionError),
}

macro_rules! typed_backend_hooks {
    ($($method:ident => $phase:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Intercepts backend responses for a pending `", stringify!($phase), "` operation.")]
            async fn $method(
                &mut self,
                _state: &mut State,
                message: PipelineBackendMessage<phase::$phase>,
            ) -> Result<PipelineBackendMessage<phase::$phase>, Self::Error> {
                Ok(message)
            }
        )+
    };
}

/// Async middleware selected by [`Pipeline`] from its runtime ledger phase.
///
/// Every method defaults to identity, so implementations override only the
/// phases they inspect. Inputs and outputs remain phase-specific even though
/// the pipeline chooses which method to call at runtime.
#[allow(async_fn_in_trait)]
pub trait TypedPipelineMiddleware<State> {
    /// An error which prevents the message from continuing through the pipeline.
    type Error;

    /// Intercepts a frontend message while the request ledger is ready.
    async fn frontend_ready(
        &mut self,
        _state: &mut State,
        message: backend::ReadyExternalMessage,
    ) -> Result<backend::ReadyExternalMessage, Self::Error> {
        Ok(message)
    }

    /// Intercepts a frontend message while building an extended pipeline.
    async fn frontend_building(
        &mut self,
        _state: &mut State,
        message: backend::BuildingExternalMessage,
    ) -> Result<backend::BuildingExternalMessage, Self::Error> {
        Ok(message)
    }

    /// Intercepts a frontend message while discarding through `Sync`.
    async fn frontend_extended_error(
        &mut self,
        _state: &mut State,
        message: backend::ExtendedErrorExternalMessage,
    ) -> Result<backend::ExtendedErrorExternalMessage, Self::Error> {
        Ok(message)
    }

    /// Intercepts frontend COPY-IN traffic entered by a simple query.
    async fn frontend_simple_copy_in(
        &mut self,
        _state: &mut State,
        message: backend::SimpleCopyInExternalMessage,
    ) -> Result<backend::SimpleCopyInExternalMessage, Self::Error> {
        Ok(message)
    }

    /// Intercepts frontend COPY-IN traffic entered by an extended Execute.
    async fn frontend_extended_copy_in(
        &mut self,
        _state: &mut State,
        message: backend::ExtendedCopyInExternalMessage,
    ) -> Result<backend::ExtendedCopyInExternalMessage, Self::Error> {
        Ok(message)
    }

    /// Intercepts frontend COPY-BOTH traffic entered by a simple query.
    async fn frontend_simple_copy_both(
        &mut self,
        _state: &mut State,
        message: backend::SimpleCopyBothExternalMessage,
    ) -> Result<backend::SimpleCopyBothExternalMessage, Self::Error> {
        Ok(message)
    }

    /// Intercepts frontend COPY-BOTH traffic entered by an extended Execute.
    async fn frontend_extended_copy_both(
        &mut self,
        _state: &mut State,
        message: backend::ExtendedCopyBothExternalMessage,
    ) -> Result<backend::ExtendedCopyBothExternalMessage, Self::Error> {
        Ok(message)
    }

    /// Intercepts asynchronous backend traffic without advancing the ledger.
    async fn backend_asynchronous(
        &mut self,
        _state: &mut State,
        message: AsynchronousBackendMessage,
    ) -> Result<AsynchronousBackendMessage, Self::Error> {
        Ok(message)
    }

    typed_backend_hooks!(
        backend_query => Query,
        backend_function_call => FunctionCall,
        backend_parse => Parse,
        backend_bind => Bind,
        backend_describe => Describe,
        backend_execute => Execute,
        backend_close => Close,
        backend_sync => Sync,
        backend_copy_done => CopyDone,
        backend_copy_fail => CopyFail,
    );
}

impl<State> TypedPipelineMiddleware<State> for crate::middleware::Identity {
    type Error = Infallible;
}

/// Adapts direction-wide async middleware to every typed pipeline hook.
pub struct PipelineWireAdapter<Handler> {
    handler: Handler,
}

impl<Handler> PipelineWireAdapter<Handler> {
    /// Wraps direction-wide middleware for runtime phase dispatch.
    pub const fn new(handler: Handler) -> Self {
        Self { handler }
    }

    /// Returns the wrapped direction-wide middleware.
    pub fn into_inner(self) -> Handler {
        self.handler
    }
}

/// Failure from direction-wide middleware adapted to typed pipeline dispatch.
#[derive(Debug)]
pub enum PipelineWireAdapterError<FrontendError, BackendError> {
    /// The wrapped middleware rejected a frontend message.
    FrontendMiddleware(FrontendError),
    /// The wrapped middleware rejected a backend message.
    BackendMiddleware(BackendError),
    /// The wrapped middleware returned a frontend message illegal in the selected phase.
    IllegalFrontend(FrontendMessage),
    /// The wrapped middleware returned a backend message illegal in the selected phase.
    IllegalBackend(BackendMessage),
}

macro_rules! pipeline_adapter_frontend_hooks {
    ($($method:ident => $message:ty),+ $(,)?) => {
        $(
            async fn $method(
                &mut self,
                state: &mut State,
                message: $message,
            ) -> Result<$message, Self::Error> {
                let message: FrontendMessage = message.into();
                let message = self
                    .handler
                    .intercept(state, message)
                    .await
                    .map_err(PipelineWireAdapterError::FrontendMiddleware)?;
                <$message>::try_from(message)
                    .map_err(PipelineWireAdapterError::IllegalFrontend)
            }
        )+
    };
}

macro_rules! pipeline_adapter_backend_hooks {
    ($($method:ident => $phase:ty),+ $(,)?) => {
        $(
            async fn $method(
                &mut self,
                state: &mut State,
                message: PipelineBackendMessage<$phase>,
            ) -> Result<PipelineBackendMessage<$phase>, Self::Error> {
                let message = self
                    .handler
                    .intercept(state, message.into_wire())
                    .await
                    .map_err(PipelineWireAdapterError::BackendMiddleware)?;
                PipelineBackendMessage::try_from(message)
                    .map_err(PipelineWireAdapterError::IllegalBackend)
            }
        )+
    };
}

impl<State, Handler> TypedPipelineMiddleware<State> for PipelineWireAdapter<Handler>
where
    Handler: MessageMiddleware<FrontendMessage, State> + MessageMiddleware<BackendMessage, State>,
{
    type Error = PipelineWireAdapterError<
        <Handler as MessageMiddleware<FrontendMessage, State>>::Error,
        <Handler as MessageMiddleware<BackendMessage, State>>::Error,
    >;

    pipeline_adapter_frontend_hooks!(
        frontend_ready => backend::ReadyExternalMessage,
        frontend_building => backend::BuildingExternalMessage,
        frontend_extended_error => backend::ExtendedErrorExternalMessage,
        frontend_simple_copy_in => backend::SimpleCopyInExternalMessage,
        frontend_extended_copy_in => backend::ExtendedCopyInExternalMessage,
        frontend_simple_copy_both => backend::SimpleCopyBothExternalMessage,
        frontend_extended_copy_both => backend::ExtendedCopyBothExternalMessage,
    );

    async fn backend_asynchronous(
        &mut self,
        state: &mut State,
        message: AsynchronousBackendMessage,
    ) -> Result<AsynchronousBackendMessage, Self::Error> {
        let message = self
            .handler
            .intercept(state, message.into_wire())
            .await
            .map_err(PipelineWireAdapterError::BackendMiddleware)?;
        AsynchronousBackendMessage::try_from(message)
            .map_err(PipelineWireAdapterError::IllegalBackend)
    }

    pipeline_adapter_backend_hooks!(
        backend_query => phase::Query,
        backend_function_call => phase::FunctionCall,
        backend_parse => phase::Parse,
        backend_bind => phase::Bind,
        backend_describe => phase::Describe,
        backend_execute => phase::Execute,
        backend_close => phase::Close,
        backend_sync => phase::Sync,
        backend_copy_done => phase::CopyDone,
        backend_copy_fail => phase::CopyFail,
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestState {
    Ready,
    Extended { bound: bool },
    ExtendedError,
    CopyIn,
    CopyOut,
    CopyBoth,
    Terminated,
}

impl RequestState {
    const fn public(self) -> PipelineState {
        match self {
            Self::Ready => PipelineState::Ready,
            Self::Extended { .. } => PipelineState::Extended,
            Self::ExtendedError => PipelineState::ExtendedError,
            Self::CopyIn => PipelineState::CopyIn,
            Self::CopyOut => PipelineState::CopyOut,
            Self::CopyBoth => PipelineState::CopyBoth,
            Self::Terminated => PipelineState::Terminated,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin {
    Forwarded,
    Local,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationKind {
    Query,
    FunctionCall,
    Parse,
    Bind,
    Describe,
    Execute,
    Close,
    Flush,
    Sync,
    CopyData,
    CopyDone,
    CopyFail,
    Terminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseDisposition {
    Asynchronous,
    Emit(OperationKind),
    Deferred,
    Illegal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Operation {
    id: OperationId,
    kind: OperationKind,
    origin: Origin,
    discarded: bool,
}

/// A bounded ledger coordinating independently owned frontend and backend values.
#[derive(Debug)]
pub struct Pipeline<P = NoPipeline> {
    policy: P,
    operations: VecDeque<Operation>,
    request_state: RequestState,
    response_state: Option<PipelineState>,
    next_id: u64,
    changed: Arc<Notify>,
}

impl Default for Pipeline<NoPipeline> {
    fn default() -> Self {
        Self::new(NoPipeline)
    }
}

impl<P: PipelinePolicy> Pipeline<P> {
    /// Creates an empty pipeline using `policy`.
    #[must_use]
    pub fn new(policy: P) -> Self {
        Self {
            policy,
            operations: VecDeque::new(),
            request_state: RequestState::Ready,
            response_state: None,
            next_id: 0,
            changed: Arc::new(Notify::new()),
        }
    }

    /// Returns the projected frontend protocol state.
    #[must_use]
    pub fn state(&self) -> PipelineState {
        self.response_state
            .unwrap_or_else(|| self.request_state.public())
    }

    /// Returns the number of incomplete lightweight operation records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Reports whether no operations remain outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Projects and accepts one frontend message without retaining its payload.
    ///
    /// Capacity and legality failures return the original owned message. A
    /// capacity failure does not mutate either projected state or the ledger.
    ///
    /// # Errors
    ///
    /// Returns the unchanged boxed message when capacity is exhausted or the
    /// message is illegal in the projected state.
    pub fn accept_frontend(
        &mut self,
        message: FrontendMessage,
        handling: FrontendHandling,
    ) -> Result<FrontendAdmission, FrontendProjectionError> {
        self.remove_inert_heads();
        if self.operations.len() == self.policy.operation_limit() {
            return Err(FrontendProjectionError::Capacity(Box::new(message)));
        }

        let Some((kind, next_state)) = project_frontend(self.request_state, &message) else {
            return Err(FrontendProjectionError::Illegal {
                state: self.state(),
                message: Box::new(message),
            });
        };
        let waiting = !self.operations.is_empty();
        let id = OperationId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.request_state = next_state;
        let origin = match handling {
            FrontendHandling::Forward => Origin::Forwarded,
            FrontendHandling::Local => Origin::Local,
        };
        self.operations.push_back(Operation {
            id,
            kind,
            origin,
            discarded: matches!(self.request_state, RequestState::ExtendedError)
                && kind != OperationKind::Sync,
        });
        let action = match handling {
            FrontendHandling::Forward => FrontendAction::Forward { id, message },
            FrontendHandling::Local => FrontendAction::Discard { id },
        };
        Ok(if waiting {
            FrontendAdmission::Waiting(action)
        } else {
            FrontendAdmission::Immediate(action)
        })
    }

    /// Convenience projection which reports capacity as [`FrontendAction::Backpressure`].
    ///
    /// # Errors
    ///
    /// Returns the unchanged message for capacity or protocol illegality.
    pub fn project_frontend(
        &mut self,
        message: FrontendMessage,
        handling: FrontendHandling,
    ) -> Result<FrontendAdmission, FrontendProjectionError> {
        self.accept_frontend(message, handling)
    }

    /// Projects a frontend value into the compact application-action vocabulary.
    ///
    /// Use [`Self::accept_frontend`] when the caller also needs to distinguish an
    /// immediately emittable operation from an accepted waiting operation.
    ///
    /// # Errors
    ///
    /// Returns an illegal message; capacity is represented as a successful
    /// [`FrontendAction::Backpressure`] action.
    pub fn frontend_action(
        &mut self,
        message: FrontendMessage,
        handling: FrontendHandling,
    ) -> Result<FrontendAction, FrontendProjectionError> {
        match self.accept_frontend(message, handling) {
            Ok(admission) => Ok(admission.into_action()),
            Err(FrontendProjectionError::Capacity(message)) => {
                Ok(FrontendAction::Backpressure(*message))
            }
            Err(error @ FrontendProjectionError::Illegal { .. }) => Err(error),
        }
    }

    /// Projects, asynchronously intercepts, and accepts one frontend message.
    ///
    /// The ledger selects the phase-specific middleware hook at runtime. The
    /// selected hook can only return a message legal in that same phase.
    /// Middleware is not invoked when capacity is exhausted.
    ///
    /// # Errors
    ///
    /// Returns a middleware error, an illegal original or replacement message,
    /// or the unchanged message when capacity is exhausted.
    pub async fn accept_frontend_typed<State, Handler>(
        &mut self,
        middleware: &mut Middleware<State, Handler>,
        message: FrontendMessage,
        handling: FrontendHandling,
    ) -> Result<FrontendAdmission, PipelineMiddlewareError<Handler::Error, FrontendProjectionError>>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        self.remove_inert_heads();
        if self.operations.len() == self.policy.operation_limit() {
            return Err(PipelineMiddlewareError::Projection(
                FrontendProjectionError::Capacity(Box::new(message)),
            ));
        }
        if project_frontend(self.request_state, &message).is_none() {
            return Err(PipelineMiddlewareError::Projection(
                FrontendProjectionError::Illegal {
                    state: self.state(),
                    message: Box::new(message),
                },
            ));
        }

        let message = self
            .intercept_frontend(middleware, message)
            .await
            .map_err(PipelineMiddlewareError::Middleware)?;
        if !message.is_reconstructable() {
            return Err(PipelineMiddlewareError::Projection(
                FrontendProjectionError::Illegal {
                    state: self.state(),
                    message: Box::new(message),
                },
            ));
        }
        self.accept_frontend(message, handling)
            .map_err(PipelineMiddlewareError::Projection)
    }

    /// Typed-middleware counterpart to [`Self::project_frontend`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::accept_frontend_typed`].
    pub async fn project_frontend_typed<State, Handler>(
        &mut self,
        middleware: &mut Middleware<State, Handler>,
        message: FrontendMessage,
        handling: FrontendHandling,
    ) -> Result<FrontendAdmission, PipelineMiddlewareError<Handler::Error, FrontendProjectionError>>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        self.accept_frontend_typed(middleware, message, handling)
            .await
    }

    /// Typed-middleware counterpart to [`Self::frontend_action`].
    ///
    /// Capacity is returned as [`FrontendAction::Backpressure`] without running
    /// middleware. Accepted messages are dispatched to their phase-specific hook.
    ///
    /// # Errors
    ///
    /// Returns a middleware error or an illegal original or replacement message.
    pub async fn frontend_action_typed<State, Handler>(
        &mut self,
        middleware: &mut Middleware<State, Handler>,
        message: FrontendMessage,
        handling: FrontendHandling,
    ) -> Result<FrontendAction, PipelineMiddlewareError<Handler::Error, FrontendProjectionError>>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        match self
            .accept_frontend_typed(middleware, message, handling)
            .await
        {
            Ok(admission) => Ok(admission.into_action()),
            Err(PipelineMiddlewareError::Projection(FrontendProjectionError::Capacity(
                message,
            ))) => Ok(FrontendAction::Backpressure(*message)),
            Err(error) => Err(error),
        }
    }

    /// Projects one upstream backend message and preserves response order.
    ///
    /// # Errors
    ///
    /// Returns an unchanged response which cannot belong to any outstanding operation.
    pub fn accept_backend(
        &mut self,
        message: BackendMessage,
    ) -> Result<BackendAction, BackendProjectionError> {
        self.accept_response(None, message)
    }

    /// Intercepts an emittable backend response through its operation-typed hook.
    ///
    /// Responses belonging to a later operation are returned unchanged as
    /// [`BackendAction::Deferred`] and are intercepted only when retried at the
    /// response head. Asynchronous messages use their non-advancing hook.
    ///
    /// # Errors
    ///
    /// Returns a middleware error or an unchanged response which cannot belong
    /// to any outstanding operation.
    pub async fn accept_backend_typed<State, Handler>(
        &mut self,
        middleware: &mut Middleware<State, Handler>,
        message: BackendMessage,
    ) -> Result<BackendAction, PipelineMiddlewareError<Handler::Error, BackendProjectionError>>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        self.accept_response_typed(None, middleware, message).await
    }

    /// Projects one protocol-advancing item returned by the existing [`Demux`].
    ///
    /// Before calling this method, forward any values from
    /// [`Demux::pop_async_event`] in queue order. Command notices remain available
    /// through the demux's notice queue; the ledger itself stores no notice payload.
    ///
    /// # Errors
    ///
    /// Returns an unchanged reconstructed response which cannot belong to any
    /// outstanding operation.
    pub fn accept_session_item(
        &mut self,
        item: SessionItem,
    ) -> Result<BackendAction, BackendProjectionError> {
        let message = match item {
            SessionItem::Message(message) => message,
            SessionItem::ReadyForQuery { status, .. } => BackendMessage::ReadyForQuery(status),
            SessionItem::CommandComplete { tag, .. } => BackendMessage::CommandComplete(tag),
        };
        self.accept_backend(message)
    }

    /// Typed-middleware counterpart to [`Self::accept_session_item`].
    ///
    /// # Errors
    ///
    /// Returns a middleware or backend projection error.
    pub async fn accept_session_item_typed<State, Handler>(
        &mut self,
        middleware: &mut Middleware<State, Handler>,
        item: SessionItem,
    ) -> Result<BackendAction, PipelineMiddlewareError<Handler::Error, BackendProjectionError>>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        let message = match item {
            SessionItem::Message(message) => message,
            SessionItem::ReadyForQuery { status, .. } => BackendMessage::ReadyForQuery(status),
            SessionItem::CommandComplete { tag, .. } => BackendMessage::CommandComplete(tag),
        };
        self.accept_backend_typed(middleware, message).await
    }

    /// Attempts to register and emit a locally synthesized response.
    ///
    /// The message is returned as [`BackendAction::Deferred`] when `id` has not
    /// reached the head. No backend payload is retained by the ledger.
    ///
    /// # Errors
    ///
    /// Returns the unchanged message when it is illegal for the named operation.
    pub fn try_emit_local(
        &mut self,
        id: OperationId,
        message: BackendMessage,
    ) -> Result<BackendAction, BackendProjectionError> {
        self.accept_response(Some(id), message)
    }

    /// Typed-middleware counterpart to [`Self::try_emit_local`].
    ///
    /// Deferred local responses are not intercepted until their operation reaches
    /// the response head.
    ///
    /// # Errors
    ///
    /// Returns a middleware error or an illegal response for the named operation.
    pub async fn try_emit_local_typed<State, Handler>(
        &mut self,
        middleware: &mut Middleware<State, Handler>,
        id: OperationId,
        message: BackendMessage,
    ) -> Result<BackendAction, PipelineMiddlewareError<Handler::Error, BackendProjectionError>>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        self.accept_response_typed(Some(id), middleware, message)
            .await
    }

    /// Waits until a local operation reaches the response head.
    ///
    /// Cancellation is safe: polling this future never reserves or removes a
    /// ledger entry. The caller should then invoke [`Self::try_emit_local`].
    pub async fn wait_until_emittable(&self, id: OperationId) {
        loop {
            let notified = self.changed.notified();
            if self
                .operations
                .front()
                .is_some_and(|operation| operation.id == id)
            {
                return;
            }
            notified.await;
        }
    }

    async fn intercept_frontend<State, Handler>(
        &self,
        middleware: &mut Middleware<State, Handler>,
        message: FrontendMessage,
    ) -> Result<FrontendMessage, Handler::Error>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        macro_rules! dispatch {
            ($message:expr, $type:path, $handler:ident, $state:ident, $method:ident) => {{
                let Ok(typed) = <$type>::try_from($message) else {
                    unreachable!("frontend message was prevalidated for pipeline phase")
                };
                $handler.$method($state, typed).await?.into()
            }};
        }

        let request_state = self.request_state;
        let response_head = self.operations.front().map(|operation| operation.kind);
        let (state, handler) = middleware.parts_mut();
        Ok(match request_state {
            RequestState::Ready => dispatch!(
                message,
                backend::ReadyExternalMessage,
                handler,
                state,
                frontend_ready
            ),
            RequestState::Extended { .. } => dispatch!(
                message,
                backend::BuildingExternalMessage,
                handler,
                state,
                frontend_building
            ),
            RequestState::ExtendedError => dispatch!(
                message,
                backend::ExtendedErrorExternalMessage,
                handler,
                state,
                frontend_extended_error
            ),
            RequestState::CopyIn => match response_head {
                Some(OperationKind::Query) => dispatch!(
                    message,
                    backend::SimpleCopyInExternalMessage,
                    handler,
                    state,
                    frontend_simple_copy_in
                ),
                Some(OperationKind::Execute) => dispatch!(
                    message,
                    backend::ExtendedCopyInExternalMessage,
                    handler,
                    state,
                    frontend_extended_copy_in
                ),
                _ => unreachable!("COPY-IN must belong to Query or Execute"),
            },
            RequestState::CopyBoth => match response_head {
                Some(OperationKind::Query) => dispatch!(
                    message,
                    backend::SimpleCopyBothExternalMessage,
                    handler,
                    state,
                    frontend_simple_copy_both
                ),
                Some(OperationKind::Execute) => dispatch!(
                    message,
                    backend::ExtendedCopyBothExternalMessage,
                    handler,
                    state,
                    frontend_extended_copy_both
                ),
                _ => unreachable!("COPY-BOTH must belong to Query or Execute"),
            },
            RequestState::CopyOut | RequestState::Terminated => {
                unreachable!("frontend message was prevalidated for an accepting pipeline phase")
            }
        })
    }

    async fn accept_response_typed<State, Handler>(
        &mut self,
        local_id: Option<OperationId>,
        middleware: &mut Middleware<State, Handler>,
        message: BackendMessage,
    ) -> Result<BackendAction, PipelineMiddlewareError<Handler::Error, BackendProjectionError>>
    where
        Handler: TypedPipelineMiddleware<State>,
    {
        self.remove_inert_heads();
        let disposition = self.classify_response(local_id, &message);
        if disposition == ResponseDisposition::Deferred {
            return Ok(BackendAction::Deferred(message));
        }
        if disposition == ResponseDisposition::Illegal {
            return Err(PipelineMiddlewareError::Projection(
                BackendProjectionError {
                    state: self.state(),
                    message,
                },
            ));
        }

        let (state, handler) = middleware.parts_mut();
        let message = match disposition {
            ResponseDisposition::Asynchronous => {
                let Ok(typed) = AsynchronousBackendMessage::try_from(message) else {
                    unreachable!("asynchronous response was prevalidated")
                };
                handler
                    .backend_asynchronous(state, typed)
                    .await
                    .map_err(PipelineMiddlewareError::Middleware)?
                    .into_wire()
            }
            ResponseDisposition::Emit(kind) => {
                macro_rules! dispatch {
                    ($phase:ty, $method:ident) => {{
                        let typed = match PipelineBackendMessage::<$phase>::try_from(message) {
                            Ok(typed) => typed,
                            Err(message) => {
                                return Err(PipelineMiddlewareError::Projection(
                                    BackendProjectionError {
                                        state: self.state(),
                                        message,
                                    },
                                ));
                            }
                        };
                        handler
                            .$method(state, typed)
                            .await
                            .map_err(PipelineMiddlewareError::Middleware)?
                            .into_wire()
                    }};
                }

                match kind {
                    OperationKind::Query => dispatch!(phase::Query, backend_query),
                    OperationKind::FunctionCall => {
                        dispatch!(phase::FunctionCall, backend_function_call)
                    }
                    OperationKind::Parse => dispatch!(phase::Parse, backend_parse),
                    OperationKind::Bind => dispatch!(phase::Bind, backend_bind),
                    OperationKind::Describe => dispatch!(phase::Describe, backend_describe),
                    OperationKind::Execute => dispatch!(phase::Execute, backend_execute),
                    OperationKind::Close => dispatch!(phase::Close, backend_close),
                    OperationKind::Sync => dispatch!(phase::Sync, backend_sync),
                    OperationKind::CopyDone => dispatch!(phase::CopyDone, backend_copy_done),
                    OperationKind::CopyFail => dispatch!(phase::CopyFail, backend_copy_fail),
                    OperationKind::Flush | OperationKind::CopyData | OperationKind::Terminate => {
                        unreachable!("inert operations cannot become response heads")
                    }
                }
            }
            ResponseDisposition::Deferred | ResponseDisposition::Illegal => unreachable!(),
        };

        if !message.is_reconstructable() {
            return Err(PipelineMiddlewareError::Projection(
                BackendProjectionError {
                    state: self.state(),
                    message,
                },
            ));
        }
        self.accept_response(local_id, message)
            .map_err(PipelineMiddlewareError::Projection)
    }

    fn classify_response(
        &self,
        local_id: Option<OperationId>,
        message: &BackendMessage,
    ) -> ResponseDisposition {
        if is_asynchronous(message) {
            return ResponseDisposition::Asynchronous;
        }
        let Some(head) = self.operations.front().copied() else {
            return ResponseDisposition::Illegal;
        };
        if let Some(id) = local_id {
            if head.id != id {
                return ResponseDisposition::Deferred;
            }
            if head.origin != Origin::Local {
                return ResponseDisposition::Illegal;
            }
        } else if head.origin == Origin::Local {
            return if self.operations.iter().skip(1).any(|operation| {
                operation.origin == Origin::Forwarded && response_fits(operation.kind, message)
            }) {
                ResponseDisposition::Deferred
            } else {
                ResponseDisposition::Illegal
            };
        }
        if head.discarded || !response_fits(head.kind, message) {
            return if self
                .operations
                .iter()
                .skip(1)
                .any(|operation| response_fits(operation.kind, message))
            {
                ResponseDisposition::Deferred
            } else {
                ResponseDisposition::Illegal
            };
        }
        ResponseDisposition::Emit(head.kind)
    }

    fn accept_response(
        &mut self,
        local_id: Option<OperationId>,
        message: BackendMessage,
    ) -> Result<BackendAction, BackendProjectionError> {
        if is_asynchronous(&message) {
            return Ok(BackendAction::Emit(message));
        }
        self.remove_inert_heads();
        let Some(head) = self.operations.front().copied() else {
            return Err(BackendProjectionError {
                state: self.state(),
                message,
            });
        };
        if let Some(id) = local_id {
            if head.id != id {
                return Ok(BackendAction::Deferred(message));
            }
            if head.origin != Origin::Local {
                return Err(BackendProjectionError {
                    state: self.state(),
                    message,
                });
            }
        } else if head.origin == Origin::Local {
            if self.operations.iter().skip(1).any(|operation| {
                operation.origin == Origin::Forwarded && response_fits(operation.kind, &message)
            }) {
                return Ok(BackendAction::Deferred(message));
            }
            return Err(BackendProjectionError {
                state: self.state(),
                message,
            });
        }
        if head.discarded || !response_fits(head.kind, &message) {
            if self
                .operations
                .iter()
                .skip(1)
                .any(|operation| response_fits(operation.kind, &message))
            {
                return Ok(BackendAction::Deferred(message));
            }
            return Err(BackendProjectionError {
                state: self.state(),
                message,
            });
        }

        let terminal = response_is_terminal(head.kind, &message);
        let error = matches!(message, BackendMessage::ErrorResponse(_));
        let copy_state = copy_state(&message);
        if terminal {
            self.operations.pop_front();
            if error && is_extended_kind(head.kind) {
                self.enter_extended_error();
            }
        }
        if let Some(state) = copy_state {
            self.response_state = Some(state.public());
            if matches!(state, RequestState::CopyIn | RequestState::CopyBoth) {
                self.request_state = state;
            }
        }
        if terminal {
            self.response_state = None;
            match head.kind {
                OperationKind::Sync | OperationKind::Query => {
                    self.request_state = RequestState::Ready;
                }
                OperationKind::Execute if !error => {
                    self.request_state = RequestState::Extended { bound: true };
                }
                _ => {}
            }
        }
        self.remove_inert_heads();
        self.changed.notify_waiters();
        Ok(BackendAction::Emit(message))
    }

    fn enter_extended_error(&mut self) {
        self.request_state = RequestState::ExtendedError;
        self.response_state = None;
        for operation in &mut self.operations {
            if operation.kind == OperationKind::Sync {
                break;
            }
            operation.discarded = true;
        }
    }

    fn remove_inert_heads(&mut self) {
        let previous_len = self.operations.len();
        while self.operations.front().is_some_and(|operation| {
            operation.kind == OperationKind::Flush
                || operation.kind == OperationKind::CopyData
                || operation.kind == OperationKind::CopyDone
                || operation.kind == OperationKind::CopyFail
                || operation.kind == OperationKind::Terminate
                || operation.discarded
        }) {
            self.operations.pop_front();
        }
        if self.operations.len() != previous_len {
            self.changed.notify_waiters();
        }
    }
}

fn project_frontend(
    state: RequestState,
    message: &FrontendMessage,
) -> Option<(OperationKind, RequestState)> {
    use FrontendMessage as F;
    use OperationKind as O;
    use RequestState as S;
    let generated_state = match state {
        S::Ready => backend::RuntimeState::Ready,
        S::Extended { .. } => backend::RuntimeState::Building,
        S::ExtendedError => backend::RuntimeState::ExtendedError,
        S::CopyIn => backend::RuntimeState::ExtendedCopyIn,
        S::CopyOut => backend::RuntimeState::ExtendedCopyOut,
        S::CopyBoth => backend::RuntimeState::ExtendedCopyBoth,
        S::Terminated => backend::RuntimeState::Terminated,
    };
    backend::project_external(generated_state, message)?;

    match (state, message) {
        (S::Ready, F::Query(_)) => Some((O::Query, S::Ready)),
        (S::Ready, F::FunctionCall(_)) => Some((O::FunctionCall, S::Ready)),
        (S::Ready, F::Parse(_)) => Some((O::Parse, S::Extended { bound: false })),
        (S::Ready | S::Extended { .. }, F::Bind(_)) => Some((O::Bind, S::Extended { bound: true })),
        (S::Ready, F::Describe(_)) => Some((O::Describe, S::Extended { bound: false })),
        (S::Ready | S::Extended { .. }, F::Execute(_)) => {
            Some((O::Execute, S::Extended { bound: true }))
        }
        (S::Ready, F::Close(_)) => Some((O::Close, S::Extended { bound: false })),
        (S::Ready, F::Terminate) => Some((O::Terminate, S::Terminated)),
        (S::Extended { bound }, F::Parse(_)) => Some((O::Parse, S::Extended { bound })),
        (S::Extended { bound }, F::Describe(_)) => Some((O::Describe, S::Extended { bound })),
        (S::Extended { bound }, F::Close(_)) => Some((O::Close, S::Extended { bound })),
        (S::Extended { bound }, F::Flush) => Some((O::Flush, S::Extended { bound })),
        (S::Extended { .. } | S::ExtendedError, F::Sync) => Some((O::Sync, S::Ready)),
        (S::ExtendedError, _) => Some((classify_discard(message)?, S::ExtendedError)),
        (S::CopyIn, F::CopyData(_)) => Some((O::CopyData, S::CopyIn)),
        (S::CopyIn, F::CopyDone) => Some((O::CopyDone, S::Extended { bound: true })),
        (S::CopyIn, F::CopyFail(_)) => Some((O::CopyFail, S::ExtendedError)),
        (S::CopyBoth, F::CopyData(_)) => Some((O::CopyData, S::CopyBoth)),
        (S::CopyBoth, F::CopyDone) => Some((O::CopyDone, S::CopyBoth)),
        _ => None,
    }
}

fn classify_discard(message: &FrontendMessage) -> Option<OperationKind> {
    Some(match message {
        FrontendMessage::Parse(_) => OperationKind::Parse,
        FrontendMessage::Bind(_) => OperationKind::Bind,
        FrontendMessage::Describe(_) => OperationKind::Describe,
        FrontendMessage::Execute(_) => OperationKind::Execute,
        FrontendMessage::Close(_) => OperationKind::Close,
        FrontendMessage::Flush => OperationKind::Flush,
        FrontendMessage::Query(_) => OperationKind::Query,
        FrontendMessage::FunctionCall(_) => OperationKind::FunctionCall,
        FrontendMessage::CopyData(_) => OperationKind::CopyData,
        FrontendMessage::CopyDone => OperationKind::CopyDone,
        FrontendMessage::CopyFail(_) => OperationKind::CopyFail,
        FrontendMessage::Terminate => OperationKind::Terminate,
        FrontendMessage::PasswordResponse(_) => return None,
        FrontendMessage::Sync => unreachable!("Sync is classified before discard"),
    })
}

fn response_fits(kind: OperationKind, message: &BackendMessage) -> bool {
    use BackendMessage as B;
    use OperationKind as O;
    match kind {
        O::Query => matches!(
            message,
            B::RowDescription(_)
                | B::DataRow(_)
                | B::CommandComplete(_)
                | B::EmptyQueryResponse
                | B::CopyInResponse(_)
                | B::CopyOutResponse(_)
                | B::CopyBothResponse(_)
                | B::CopyData(_)
                | B::CopyDone
                | B::ErrorResponse(_)
                | B::ReadyForQuery(_)
        ),
        O::FunctionCall => matches!(
            message,
            B::FunctionCallResponse(_) | B::ErrorResponse(_) | B::ReadyForQuery(_)
        ),
        O::Parse => matches!(message, B::ParseComplete | B::ErrorResponse(_)),
        O::Bind => matches!(message, B::BindComplete | B::ErrorResponse(_)),
        O::Describe => matches!(
            message,
            B::ParameterDescription(_) | B::RowDescription(_) | B::NoData | B::ErrorResponse(_)
        ),
        O::Execute => matches!(
            message,
            B::RowDescription(_)
                | B::DataRow(_)
                | B::EmptyQueryResponse
                | B::CommandComplete(_)
                | B::PortalSuspended
                | B::CopyInResponse(_)
                | B::CopyOutResponse(_)
                | B::CopyBothResponse(_)
                | B::CopyData(_)
                | B::CopyDone
                | B::ErrorResponse(_)
        ),
        O::Close => matches!(message, B::CloseComplete | B::ErrorResponse(_)),
        O::Sync => matches!(message, B::ReadyForQuery(_)),
        O::CopyDone => matches!(
            message,
            B::CopyDone | B::CommandComplete(_) | B::ErrorResponse(_)
        ),
        O::CopyFail => matches!(message, B::ErrorResponse(_)),
        O::Flush | O::CopyData | O::Terminate => false,
    }
}

fn response_is_terminal(kind: OperationKind, message: &BackendMessage) -> bool {
    use BackendMessage as B;
    use OperationKind as O;
    match kind {
        O::Query | O::FunctionCall | O::Sync => matches!(message, B::ReadyForQuery(_)),
        O::Parse => matches!(message, B::ParseComplete | B::ErrorResponse(_)),
        O::Bind => matches!(message, B::BindComplete | B::ErrorResponse(_)),
        O::Describe => matches!(
            message,
            B::RowDescription(_) | B::NoData | B::ErrorResponse(_)
        ),
        O::Execute => matches!(
            message,
            B::CommandComplete(_) | B::PortalSuspended | B::ErrorResponse(_)
        ),
        O::Close => matches!(message, B::CloseComplete | B::ErrorResponse(_)),
        O::CopyDone => matches!(
            message,
            B::CopyDone | B::CommandComplete(_) | B::ErrorResponse(_)
        ),
        O::CopyFail => matches!(message, B::ErrorResponse(_)),
        O::Flush | O::CopyData | O::Terminate => true,
    }
}

fn is_extended_kind(kind: OperationKind) -> bool {
    !matches!(
        kind,
        OperationKind::Query | OperationKind::FunctionCall | OperationKind::Terminate
    )
}

fn copy_state(message: &BackendMessage) -> Option<RequestState> {
    match message {
        BackendMessage::CopyInResponse(_) => Some(RequestState::CopyIn),
        BackendMessage::CopyOutResponse(_) => Some(RequestState::CopyOut),
        BackendMessage::CopyBothResponse(_) => Some(RequestState::CopyBoth),
        _ => None,
    }
}

fn is_asynchronous(message: &BackendMessage) -> bool {
    Demux::is_asynchronous(message)
}
