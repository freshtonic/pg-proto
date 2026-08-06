use std::convert::Infallible;

use pg_proto::{
    grammar::{backend, frontend},
    middleware::{ServerRole, TypedBackendMessage, TypedMiddleware},
};

fn require_server_ready_middleware<Handler>(_handler: Handler)
where
    Handler: TypedMiddleware<
            ServerRole,
            frontend::Ready,
            TypedBackendMessage<frontend::ReadyExternalMessage>,
            (),
        >,
{
}

fn illegal() {
    let handler = |_state: &mut (), message: backend::ReadyExternalMessage| {
        Ok::<_, Infallible>(message)
    };
    require_server_ready_middleware(handler);
}

fn main() {}
