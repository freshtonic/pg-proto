use pg_proto::{
    codec::FrontendMessage,
    grammar::backend::ReadyTerminateExternalTransitionMessage,
};

fn main() {
    let _unchecked: ReadyTerminateExternalTransitionMessage = FrontendMessage::Terminate.into();
}
