//! Connection-pool release policy driven by protocol and cleanliness evidence.

use pg_proto::{
    BackendMessage, Client, ClientConnection, ClientTlsPolicy, ConnectTarget, ConnectionChanged,
    ConnectionClean, StartupParameters, TransactionStatus, TrustClientAuthentication,
};

fn release_clean<Transport, State, Evidence, Handler>(
    connection: ClientConnection<Transport, State, ConnectionClean, Evidence, Handler>,
) {
    let _parts = connection.into_parts();
    println!("unused connection is clean and may return to the pool");
}

fn discard_changed<Transport, State, Evidence, Handler>(
    connection: ClientConnection<Transport, State, ConnectionChanged, Evidence, Handler>,
    transaction_status: TransactionStatus,
) {
    let _parts = connection.into_parts();
    println!(
        "connection is protocol-ready ({transaction_status:?}) but session state changed; discard or reset it before reuse"
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream: std::net::SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5432".into())
        .parse()?;
    let release_without_use = std::env::args().any(|argument| argument == "--release-unused");
    let client = Client::builder()
        .connector(move |_| tokio::net::TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()?;
    let connection = client
        .connect(
            ConnectTarget::new("pool-upstream"),
            StartupParameters::new("postgres"),
            (),
        )
        .await?;

    if release_without_use {
        release_clean(connection);
        return Ok(());
    }

    // Arbitrary SQL conservatively changes the compile-time cleanliness marker,
    // even when ReadyForQuery reports that no transaction remains open.
    let (connection, messages) = connection.simple_query(b"SELECT current_user").await?;
    let transaction_status = messages
        .iter()
        .rev()
        .find_map(|message| match message {
            BackendMessage::ReadyForQuery(status) => Some(*status),
            _ => None,
        })
        .ok_or("upstream did not report transaction status")?;
    discard_changed(connection, transaction_status);
    Ok(())
}
