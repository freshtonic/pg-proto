use bytes::Bytes;
use pg_proto::{Conn, Pristine, auth::Ready, codec::Parse, session::Building};

fn require_pristine<S>(_: Conn<S, Building, Pristine>) {}

fn illegal<S>(ready: Conn<S, Ready, Pristine>) {
    let building = ready.begin_extended();
    let (building, _) = building
        .push_parse(&Parse {
            statement: Bytes::from_static(b"persistent"),
            query: Bytes::from_static(b"select 1"),
            parameter_types: vec![],
        })
        .unwrap();
    require_pristine(building);
}

fn main() {}
