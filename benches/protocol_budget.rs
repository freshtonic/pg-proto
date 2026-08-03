//! Lightweight throughput budget for representative codec operations.

use std::{hint::black_box, time::Instant};

use bytes::{Bytes, BytesMut};
use pg_proto::{
    codec::{Frontend, FrontendMessage, PgCodec},
    grammar::frontend::{Event, RuntimeFsm},
};
use tokio_util::codec::{Decoder, Encoder};

const OPERATIONS: u32 = 200_000;
const MIN_OPERATIONS_PER_SECOND: f64 = 100_000.0;
const MAX_BENCH_BINARY_BYTES: u64 = 10 * 1024 * 1024;

fn main() {
    let codec_rate = codec_budget();
    let fsm_rate = fsm_budget();
    let binary_bytes = std::fs::metadata(std::env::current_exe().unwrap())
        .unwrap()
        .len();

    println!("frontend codec: {codec_rate:.0} operations/s");
    println!("runtime FSM: {fsm_rate:.0} operations/s");
    println!("representative monomorphised binary: {binary_bytes} bytes");

    assert!(codec_rate >= MIN_OPERATIONS_PER_SECOND);
    assert!(fsm_rate >= MIN_OPERATIONS_PER_SECOND);
    assert!(binary_bytes <= MAX_BENCH_BINARY_BYTES);
}

fn codec_budget() -> f64 {
    let frame = FrontendMessage::Query(Bytes::from_static(b"select $1::int4"))
        .to_frame()
        .unwrap();
    let started = Instant::now();
    for _ in 0..OPERATIONS {
        let mut wire = BytesMut::new();
        PgCodec::<Frontend>::default()
            .encode(frame.clone(), &mut wire)
            .unwrap();
        let decoded = PgCodec::<Frontend>::default()
            .decode(&mut wire)
            .unwrap()
            .unwrap();
        black_box(decoded);
    }
    rate(started)
}

fn fsm_budget() -> f64 {
    let started = Instant::now();
    for _ in 0..OPERATIONS {
        let mut fsm = RuntimeFsm::new();
        fsm.step(Event::Query).unwrap();
        fsm.step(Event::Ready).unwrap();
        black_box(fsm.state());
    }
    rate(started)
}

fn rate(started: Instant) -> f64 {
    f64::from(OPERATIONS) / started.elapsed().as_secs_f64()
}
