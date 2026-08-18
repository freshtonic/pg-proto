//! Fuzzes decoding of arbitrary pre-startup protocol frames.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pg_proto::{DisabledServerTls, Server, ServerProtocolLimits, TrustServerAuthentication};
use tokio::io::{AsyncWriteExt as _, duplex};

fuzz_target!(|data: &[u8]| {
    let input = data.to_vec();
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async move {
        let (server_io, mut peer) = duplex(input.len().saturating_add(4096));
        tokio::spawn(async move {
            let _ = peer.write_all(&input).await;
            let _ = peer.shutdown().await;
        });
        let server = Server::builder()
            .tls(DisabledServerTls)
            .authentication(TrustServerAuthentication)
            .limits(ServerProtocolLimits::default().with_max_pre_startup_packet_len(4096))
            .build()
            .unwrap();
        let _ = server.accept(server_io, (), ()).await;
    });
});
