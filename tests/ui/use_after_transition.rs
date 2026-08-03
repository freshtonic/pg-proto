use pg_proto::{Conn, auth::Ready};

fn illegal<S, C>(ready: Conn<S, Ready, C>) {
    let _building = ready.begin_extended();
    let _again = ready.begin_extended();
}

fn main() {}
