use pg_proto::{
    ClientConnection, ClientConnectionContext, ClientMiddleware, ConnectionClean,
};
use tokio::io::{AsyncRead, AsyncWrite};

fn require_clean<T, S, E, H>(_: ClientConnection<T, S, ConnectionClean, E, H>) {}

async fn query_cannot_remain_clean<T, S, E, H>(
    connection: ClientConnection<T, S, ConnectionClean, E, H>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
    H: ClientMiddleware<S, ClientConnectionContext<E>>,
{
    let (connection, _) = connection.simple_query(b"select 1").await.unwrap();
    require_clean(connection);
}

fn main() {}
