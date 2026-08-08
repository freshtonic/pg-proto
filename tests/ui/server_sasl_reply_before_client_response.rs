use bytes::Bytes;
use pg_proto::{Conn, server_auth::ServerSaslResponse};

fn reply_before_client_response(conn: Conn<(), ServerSaslResponse>) {
    let _ = conn.finish(Bytes::new());
}

fn main() {}
