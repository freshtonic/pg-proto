use std::convert::Infallible;

use pg_proto::{
    Conn, auth::Ready, codec::Backend, grammar::backend, middleware::Middleware,
    transport::Buffered,
};

async fn illegal<S: tokio::io::AsyncRead + Unpin>(mut conn: Conn<Buffered<S, Backend>, Ready>) {
    let handler = |_state: &mut (), message: backend::ReadyExternalMessage| {
        Ok::<_, Infallible>(message)
    };
    let mut middleware = Middleware::new((), handler);

    let _ = conn.receive_backend_typed(&mut middleware).await;
}

fn main() {}
