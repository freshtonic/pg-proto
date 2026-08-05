//! Stateful, composable interception of owned protocol messages.
//!
//! Middleware receives ownership of a decoded message and a mutable reference to
//! caller-defined state. Returning the input unchanged is a no-op; implementations
//! may instead mutate it or return another message of the same type. Protocol
//! session APIs remain responsible for checking that the result is legal in their
//! current state before advancing.

use std::convert::Infallible;

/// Intercepts an owned message with access to caller-defined state.
///
/// The message type determines the direction at compile time: middleware over
/// `FrontendMessage` cannot accidentally return a `BackendMessage`, and vice
/// versa.
pub trait MessageMiddleware<Message, State> {
    /// An error which prevents the message from continuing through the chain.
    type Error;

    /// Observes, mutates, or replaces one message.
    ///
    /// # Errors
    ///
    /// Returns a policy-defined error to stop message processing.
    fn intercept(&mut self, state: &mut State, message: Message) -> Result<Message, Self::Error>;
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
    F: FnMut(&mut State, Message) -> Result<Message, Error>,
{
    type Error = Error;

    fn intercept(&mut self, state: &mut State, message: Message) -> Result<Message, Self::Error> {
        self(state, message)
    }
}

/// Middleware which returns every message unchanged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Identity;

impl<Message, State> MessageMiddleware<Message, State> for Identity {
    type Error = Infallible;

    fn intercept(&mut self, _state: &mut State, message: Message) -> Result<Message, Self::Error> {
        Ok(message)
    }
}

/// Two middleware stages evaluated from `first` to `second`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Then<First, Second> {
    first: First,
    second: Second,
}

impl<Message, State, First, Second> MessageMiddleware<Message, State> for Then<First, Second>
where
    First: MessageMiddleware<Message, State>,
    Second: MessageMiddleware<Message, State>,
{
    type Error = ChainError<First::Error, Second::Error>;

    fn intercept(&mut self, state: &mut State, message: Message) -> Result<Message, Self::Error> {
        let message = self
            .first
            .intercept(state, message)
            .map_err(ChainError::First)?;
        self.second
            .intercept(state, message)
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

    /// Intercepts one owned message.
    ///
    /// # Errors
    ///
    /// Returns the middleware's policy-defined error.
    pub fn intercept<Message>(&mut self, message: Message) -> Result<Message, Handler::Error>
    where
        Handler: MessageMiddleware<Message, State>,
    {
        self.handler.intercept(&mut self.state, message)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChainError, Identity, MessageMiddlewareExt as _, Middleware};

    #[test]
    fn identity_is_a_no_op() {
        let mut middleware = Middleware::new((), Identity);
        assert_eq!(
            middleware.intercept(String::from("message")),
            Ok(String::from("message"))
        );
    }

    #[test]
    fn closure_can_replace_message_and_accumulate_state() {
        let mut middleware =
            Middleware::new(Vec::new(), |seen: &mut Vec<String>, message: String| {
                seen.push(message.clone());
                Ok::<_, &'static str>(message.to_uppercase())
            });

        assert_eq!(
            middleware.intercept(String::from("hello")),
            Ok(String::from("HELLO"))
        );
        assert_eq!(middleware.state(), &[String::from("hello")]);
    }

    #[test]
    fn chain_passes_replacement_to_next_stage_in_order() {
        let first = |order: &mut Vec<&'static str>, mut message: String| {
            order.push("first");
            message.push('1');
            Ok::<_, &'static str>(message)
        };
        let second = |order: &mut Vec<&'static str>, mut message: String| {
            order.push("second");
            message.push('2');
            Ok::<_, u8>(message)
        };
        let mut middleware = Middleware::new(Vec::new(), first.then(second));

        assert_eq!(
            middleware.intercept(String::from("m")),
            Ok(String::from("m12"))
        );
        assert_eq!(middleware.state(), &["first", "second"]);
    }

    #[test]
    fn chain_stops_after_first_error() {
        let first = |calls: &mut usize, _message: String| {
            *calls += 1;
            Err::<String, _>("rejected")
        };
        let second = |calls: &mut usize, message: String| {
            *calls += 1;
            Ok::<_, u8>(message)
        };
        let mut middleware = Middleware::new(0, first.then(second));

        assert_eq!(
            middleware.intercept(String::from("message")),
            Err(ChainError::First("rejected"))
        );
        assert_eq!(*middleware.state(), 1);
    }
}
