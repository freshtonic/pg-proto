//! Minimal PostgreSQL-compatible server backed by an in-memory result set.

use bytes::Bytes;
use pg_proto::{
    BackendMessage, DataRow, FieldDescription, FrontendMessage, RowDescription, Server,
    ServerAccept, ServerConnection, ServerTlsPolicy, TransactionStatus, TrustServerAuthentication,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:55432".into());
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let (transport, peer) = listener.accept().await?;
    let ServerAccept::Session(connection) = server.accept(transport, peer, ()).await? else {
        return Err("mock server does not accept cancellation requests".into());
    };
    serve(connection).await
}

async fn serve(
    mut connection: ServerConnection<tokio::net::TcpStream, (), std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match connection.receive_wire().await? {
            FrontendMessage::Query(query) => {
                println!("mock query: {}", String::from_utf8_lossy(&query));
                connection
                    .send_wire(BackendMessage::RowDescription(RowDescription {
                        fields: vec![FieldDescription {
                            name: Bytes::from_static(b"answer"),
                            table_oid: 0,
                            column: 0,
                            type_oid: 23,
                            type_size: 4,
                            type_modifier: -1,
                            format: 0,
                        }],
                    }))
                    .await?;
                connection
                    .send_wire(BackendMessage::DataRow(DataRow {
                        columns: vec![Some(Bytes::from_static(b"42"))],
                    }))
                    .await?;
                connection
                    .send_wire(BackendMessage::CommandComplete(Bytes::from_static(
                        b"SELECT 1",
                    )))
                    .await?;
                connection
                    .send_wire(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
                    .await?;
            }
            FrontendMessage::Terminate => {
                let _parts = connection.teardown();
                return Ok(());
            }
            message => return Err(format!("unsupported mock request: {message:?}").into()),
        }
    }
}
