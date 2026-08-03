use pg_proto::{Conn, session::CopyIn};

fn illegal<S, C>(copy: Conn<S, CopyIn, C>) {
    let _ = copy.push_query(b"select 1");
}

fn main() {}
