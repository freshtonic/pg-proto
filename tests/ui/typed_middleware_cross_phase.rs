use pg_proto::{
    codec::FrontendMessage,
    grammar::backend::{BuildingExternalMessage, ReadyExternalMessage},
};

fn replace_with_building_message(_message: ReadyExternalMessage) -> ReadyExternalMessage {
    let Ok(replacement) = BuildingExternalMessage::try_from(FrontendMessage::Sync) else {
        panic!("sync is legal while building");
    };
    replacement
}

fn main() {}
