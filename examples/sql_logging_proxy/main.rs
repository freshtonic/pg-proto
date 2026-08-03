#[path = "../proxy_support/mod.rs"]
mod proxy_support;

use std::{env, error::Error, net::SocketAddr, sync::Arc};

use proxy_support::Observation;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen = address(1, "127.0.0.1:6432")?;
    let upstream = proxy_support::ExampleUpstream::resolve(env::args().nth(2).as_deref()).await?;
    let upstream_address = upstream.address();
    let tls = proxy_support::ExampleTlsIdentity::generate()?;
    let listener = TcpListener::bind(listen).await?;
    println!("SQL logging proxy listening on {listen}; upstream is {upstream_address}");

    proxy_support::serve(
        listener,
        upstream_address,
        tls,
        Arc::new(|event| match event {
            Observation::Sql {
                connection,
                statement,
            } => println!("[{connection}] SQL: {statement}"),
            Observation::RowCount {
                connection,
                rows,
                command,
            } => println!("[{connection}] ROWS: {rows} ({command})"),
            Observation::Protocol { .. } => {}
        }),
    )
    .await?;
    Ok(())
}

fn address(argument: usize, default: &str) -> Result<SocketAddr, Box<dyn Error>> {
    Ok(env::args()
        .nth(argument)
        .as_deref()
        .unwrap_or(default)
        .parse()?)
}
