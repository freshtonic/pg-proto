//! Fuzzes generated runtime FSM transition sequences.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pg_proto::{Client, Intermediary, Server};

fuzz_target!(|data: &[u8]| {
    match data.first().map(|byte| byte % 3) {
        Some(0) => {
            let _ = Intermediary::builder().server(Server::builder()).build();
        }
        Some(1) => {
            let _ = Intermediary::builder().client(Client::builder()).build();
        }
        _ => {
            let _ = Intermediary::builder().build();
        }
    }
});
