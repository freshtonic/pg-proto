//! Contextual, per-connection middleware used by the builder facade.

use crate::codec::{BackendMessage, FrontendMessage};

/// Creates one isolated handler synchronously for a new connection.
pub trait MiddlewareFactory<Context> {
    /// Handler owned by that connection.
    type Handler;
    /// Creates the handler. Factories are deliberately infallible.
    fn create(&self, context: &Context) -> Self::Handler;
}

impl<Context, Handler, Factory> MiddlewareFactory<Context> for Factory
where
    Factory: Fn(&Context) -> Handler,
{
    type Handler = Handler;
    fn create(&self, context: &Context) -> Handler {
        self(context)
    }
}

/// Default factory and handler: messages pass through unchanged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityMiddleware;

impl<Context> MiddlewareFactory<Context> for IdentityMiddleware {
    type Handler = Self;
    fn create(&self, _context: &Context) -> Self {
        *self
    }
}

/// Two factories/handlers composed in builder declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareChain<First, Second>(pub First, pub Second);

impl<Context, First, Second> MiddlewareFactory<Context> for MiddlewareChain<First, Second>
where
    First: MiddlewareFactory<Context>,
    Second: MiddlewareFactory<Context>,
{
    type Handler = MiddlewareChain<First::Handler, Second::Handler>;
    fn create(&self, context: &Context) -> Self::Handler {
        MiddlewareChain(self.0.create(context), self.1.create(context))
    }
}

/// Middleware for a PostgreSQL client role. Implement only the directions used.
pub trait ClientMiddleware<State, Context> {
    /// Intercepts a client-originated pre-startup negotiation packet.
    fn pre_startup(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: crate::pre_startup::PreStartupMessage,
    ) -> crate::pre_startup::PreStartupMessage {
        message
    }
    /// Intercepts the owned startup message before it is sent.
    fn startup(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: crate::startup::StartupMessage,
    ) -> crate::startup::StartupMessage {
        message
    }
    /// Intercepts one message sent by the client.
    fn frontend(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: FrontendMessage,
    ) -> FrontendMessage {
        message
    }
    /// Intercepts one message received from the server.
    fn backend(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: BackendMessage,
    ) -> BackendMessage {
        message
    }
}

impl<State, Context> ClientMiddleware<State, Context> for IdentityMiddleware {}

impl<State, Context, First, Second> ClientMiddleware<State, Context>
    for MiddlewareChain<First, Second>
where
    First: ClientMiddleware<State, Context>,
    Second: ClientMiddleware<State, Context>,
{
    fn pre_startup(
        &mut self,
        context: &Context,
        state: &mut State,
        message: crate::pre_startup::PreStartupMessage,
    ) -> crate::pre_startup::PreStartupMessage {
        let message = self.0.pre_startup(context, state, message);
        self.1.pre_startup(context, state, message)
    }
    fn startup(
        &mut self,
        context: &Context,
        state: &mut State,
        message: crate::startup::StartupMessage,
    ) -> crate::startup::StartupMessage {
        let message = self.0.startup(context, state, message);
        self.1.startup(context, state, message)
    }
    fn frontend(
        &mut self,
        context: &Context,
        state: &mut State,
        message: FrontendMessage,
    ) -> FrontendMessage {
        let message = self.0.frontend(context, state, message);
        self.1.frontend(context, state, message)
    }
    fn backend(
        &mut self,
        context: &Context,
        state: &mut State,
        message: BackendMessage,
    ) -> BackendMessage {
        let message = self.0.backend(context, state, message);
        self.1.backend(context, state, message)
    }
}

/// Middleware for a PostgreSQL server role. Implement only the directions used.
pub trait ServerMiddleware<State, Context> {
    /// Intercepts one pre-startup packet before protocol dispatch.
    fn pre_startup(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: crate::pre_startup::PreStartupMessage,
    ) -> crate::pre_startup::PreStartupMessage {
        message
    }
    /// Intercepts the owned startup message before authentication.
    fn startup(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: crate::startup::StartupMessage,
    ) -> crate::startup::StartupMessage {
        message
    }
    /// Intercepts an out-of-band cancellation request before it is returned.
    fn cancellation(
        &mut self,
        _context: &Context,
        _state: &mut State,
        request: crate::CancellationRequest,
    ) -> crate::CancellationRequest {
        request
    }
    /// Intercepts one message received from the client.
    fn frontend(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: FrontendMessage,
    ) -> FrontendMessage {
        message
    }
    /// Intercepts one message sent by the server.
    fn backend(
        &mut self,
        _context: &Context,
        _state: &mut State,
        message: BackendMessage,
    ) -> BackendMessage {
        message
    }
}

impl<State, Context> ServerMiddleware<State, Context> for IdentityMiddleware {}

impl<State, Context, First, Second> ServerMiddleware<State, Context>
    for MiddlewareChain<First, Second>
where
    First: ServerMiddleware<State, Context>,
    Second: ServerMiddleware<State, Context>,
{
    fn pre_startup(
        &mut self,
        context: &Context,
        state: &mut State,
        message: crate::pre_startup::PreStartupMessage,
    ) -> crate::pre_startup::PreStartupMessage {
        let message = self.0.pre_startup(context, state, message);
        self.1.pre_startup(context, state, message)
    }
    fn startup(
        &mut self,
        context: &Context,
        state: &mut State,
        message: crate::startup::StartupMessage,
    ) -> crate::startup::StartupMessage {
        let message = self.0.startup(context, state, message);
        self.1.startup(context, state, message)
    }
    fn cancellation(
        &mut self,
        context: &Context,
        state: &mut State,
        request: crate::CancellationRequest,
    ) -> crate::CancellationRequest {
        let request = self.0.cancellation(context, state, request);
        self.1.cancellation(context, state, request)
    }
    fn frontend(
        &mut self,
        context: &Context,
        state: &mut State,
        message: FrontendMessage,
    ) -> FrontendMessage {
        let message = self.0.frontend(context, state, message);
        self.1.frontend(context, state, message)
    }
    fn backend(
        &mut self,
        context: &Context,
        state: &mut State,
        message: BackendMessage,
    ) -> BackendMessage {
        let message = self.0.backend(context, state, message);
        self.1.backend(context, state, message)
    }
}
