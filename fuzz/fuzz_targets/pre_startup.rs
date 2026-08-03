#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use pg_proto::pre_startup::decode_pre_startup;

fuzz_target!(|data: &[u8]| {
    let mut input = BytesMut::from(data);
    let _ = decode_pre_startup(&mut input);
});
