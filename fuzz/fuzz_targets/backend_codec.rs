#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use pg_proto::codec::{Backend, PgCodec};
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut input = BytesMut::from(data);
    let _ = PgCodec::<Backend>::default().decode(&mut input);
});
