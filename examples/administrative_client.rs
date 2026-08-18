//! Administrative client whose type records whether session state has changed.

use pg_proto::{
    BackendMessage, Client, ClientConnection, ClientTlsPolicy, ConnectTarget, ConnectionChanged,
    StartupParameters, TrustClientAuthentication,
};

fn finish_changed<Transport, State, Evidence, Handler>(
    connection: ClientConnection<Transport, State, ConnectionChanged, Evidence, Handler>,
) {
    let _parts = connection.into_parts();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream: std::net::SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5432".into())
        .parse()?;
    let sql = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "SELECT version()".into());
    let client = Client::builder()
        .connector(move |_| tokio::net::TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()?;
    let connection = client
        .connect(
            ConnectTarget::new("administrative-upstream"),
            StartupParameters::new("postgres").database("postgres"),
            (),
        )
        .await?;
    let (connection, messages) = connection.simple_query(sql.as_bytes()).await?;
    for message in messages {
        match message {
            BackendMessage::DataRow(row) => println!("row: {:?}", row.columns),
            BackendMessage::CommandComplete(tag) => {
                println!("complete: {}", String::from_utf8_lossy(&tag));
            }
            _ => {}
        }
    }
    // The query consumes the clean connection and returns ConnectionChanged,
    // preventing code from accidentally treating it as unconditionally reusable.
    finish_changed(connection);
    Ok(())
}
