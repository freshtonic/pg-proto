use pg_proto::{
    ClientConnection, ClientConnectionContext, ClientMiddleware, ConnectionClean,
};
use tokio::io::{AsyncRead, AsyncWrite};

async fn connection_cannot_be_reused_while_query_owns_its_phase<T, S, E, H>(
    mut connection: ClientConnection<T, S, ConnectionClean, E, H>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
    H: ClientMiddleware<S, ClientConnectionContext<E>>,
{
    let query = connection.simple_query(b"select 1");
    let _ = connection.receive_wire().await;
    let _ = query.await;
}

fn main() {}
