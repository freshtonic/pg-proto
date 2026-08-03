use bytes::Bytes;
use pg_proto::{Conn, codec::Execute, session::Building};

fn illegal<S, C>(building: Conn<S, Building, C>) {
    let execute = Execute {
        portal: Bytes::new(),
        max_rows: 0,
    };
    let _ = building.push_execute(&execute);
}

fn main() {}
