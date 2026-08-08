//! Lightweight throughput budget for representative facade construction.

use std::{convert::Infallible, hint::black_box, time::Instant};

use pg_proto::{
    Client, ClientTlsPolicy, DisabledServerTls, ProtocolLimits, Server, TrustClientAuthentication,
    TrustServerAuthentication,
};

const OPERATIONS: u32 = 200_000;
const MIN_OPERATIONS_PER_SECOND: f64 = 100_000.0;
const MAX_BENCH_BINARY_BYTES: u64 = 10 * 1024 * 1024;

fn main() {
    let builder_rate = builder_budget();
    let binary_bytes = std::fs::metadata(std::env::current_exe().unwrap())
        .unwrap()
        .len();

    println!("builder facade: {builder_rate:.0} operations/s");
    println!("representative monomorphised binary: {binary_bytes} bytes");

    assert!(builder_rate >= MIN_OPERATIONS_PER_SECOND);
    assert!(binary_bytes <= MAX_BENCH_BINARY_BYTES);
}

fn builder_budget() -> f64 {
    let started = Instant::now();
    for _ in 0..OPERATIONS {
        let client = Client::builder()
            .connector(|_| async { Ok::<_, Infallible>(()) })
            .tls(ClientTlsPolicy::Disabled)
            .authentication(TrustClientAuthentication)
            .protocol_limits(ProtocolLimits::default())
            .build()
            .unwrap();
        let server = Server::builder()
            .tls(DisabledServerTls)
            .authentication(TrustServerAuthentication)
            .build()
            .unwrap();
        black_box((client, server));
    }
    f64::from(OPERATIONS) / started.elapsed().as_secs_f64()
}
