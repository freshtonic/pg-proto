use bytes::Bytes;
use pg_proto::{Conn, auth::Ready, resources::with_connection_resources};

fn cross_connections(first: Conn<(), Ready>, second: Conn<(), Ready>) {
    with_connection_resources(first.begin_extended(), |first| {
        let (first, statement, _) = first
            .prepare(
                Bytes::new(),
                Bytes::from_static(b"statement"),
                Bytes::from_static(b"select 1"),
                vec![],
            )
            .unwrap();
        with_connection_resources(second.begin_extended(), |second| {
            let _ = second.bind(
                &statement,
                Bytes::new(),
                Bytes::from_static(b"portal"),
                vec![],
                vec![],
                vec![],
            );
        });
        first.into_connection().into_transport();
    });
}

fn main() {}
