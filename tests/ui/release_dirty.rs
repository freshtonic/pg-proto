use pg_proto::{Conn, Dirty, auth::Ready};

fn illegal<S>(ready: Conn<S, Ready, Dirty>) {
    let _ = ready.release();
}

fn main() {}
