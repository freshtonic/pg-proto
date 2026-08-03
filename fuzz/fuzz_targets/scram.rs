#![no_main]

use libfuzzer_sys::fuzz_target;
use pg_proto::scram::{SCRAM_SHA_256, ScramServer, ServerChannelBinding};

fuzz_target!(|data: &[u8]| {
    let server = ScramServer::with_parameters(
        b"password",
        b"fixed fuzz salt".to_vec(),
        4096,
        ServerChannelBinding::None,
    )
    .unwrap();
    if let Ok((exchange, _)) = server.start(SCRAM_SHA_256, data) {
        let _ = exchange.finish(data);
    }
});
