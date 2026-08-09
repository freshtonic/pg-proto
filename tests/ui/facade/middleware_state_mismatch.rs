use pg_proto::{ClientConnectionContext, ClientMiddleware, FrontendMessage};

struct Handler;
struct ExpectedState;
struct WrongState;

impl ClientMiddleware<ExpectedState, ClientConnectionContext> for Handler {
    fn frontend(
        &mut self,
        _: &ClientConnectionContext,
        _: &mut ExpectedState,
        message: FrontendMessage,
    ) -> FrontendMessage {
        message
    }
}

fn require_wrong_state_middleware<M>()
where
    M: ClientMiddleware<WrongState, ClientConnectionContext>,
{
}

fn main() {
    require_wrong_state_middleware::<Handler>();
}
