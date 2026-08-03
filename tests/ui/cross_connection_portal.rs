use bytes::Bytes;
use pg_proto::resources::with_resources;

fn main() {
    with_resources(|mut first| {
        let (statement, _) = first
            .prepare(
                Bytes::from_static(b"client"),
                Bytes::from_static(b"upstream"),
                Bytes::from_static(b"select 1"),
                vec![],
            )
            .unwrap();
        with_resources(|mut second| {
            let _ = second.bind(
                &statement,
                Bytes::new(),
                Bytes::new(),
                vec![],
                vec![],
                vec![],
            );
        });
    });
}
