use std::collections::BTreeMap;

use pg_proto::{Conn, startup::{ProtocolVersion, StartupMessage}};

fn main() {
    let (pending, _) = Conn::new(()).ssl_request();
    let message = StartupMessage {
        version: ProtocolVersion::V3_0,
        parameters: BTreeMap::new(),
    };
    let _ = pending.startup(&message);
}
