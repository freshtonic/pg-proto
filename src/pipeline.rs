//! Bounded, payload-free orchestration for proxy request pipelines.
//!
//! The ledger in this module records protocol obligations, not wire messages.
//! Applications retain ownership of decoded messages until [`FrontendAction`] or
//! [`BackendAction`] tells them to forward, emit, retry, or discard the value.
//! Upstream transports may continue using [`Demux`]: drain its ordered async
//! events before passing each returned [`SessionItem`] to
//! [`Pipeline::accept_session_item`]. This retains the existing notice tagging,
//! parameter map, notification queue, cancellation key, and transaction evidence.

use std::{collections::VecDeque, sync::Arc};

use tokio::sync::Notify;

use crate::{
    codec::{BackendMessage, FrontendMessage},
    demux::{Demux, SessionItem},
    grammar::backend,
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
