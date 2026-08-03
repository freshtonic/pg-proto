#![no_main]

use libfuzzer_sys::fuzz_target;
use pg_proto::grammar::frontend::{Event, RuntimeFsm};

fuzz_target!(|data: &[u8]| {
    let mut fsm = RuntimeFsm::new();
    for byte in data {
        let event = match byte % 10 {
            0 => Event::Query,
            1 => Event::Parse,
            2 => Event::Bind,
            3 => Event::Execute,
            4 => Event::Sync,
            5 => Event::CopyIn,
            6 => Event::CopyOut,
            7 => Event::CopyBoth,
            8 => Event::Error,
            _ => Event::Ready,
        };
        let _ = fsm.step(event);
    }
});
