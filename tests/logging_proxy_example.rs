//! End-to-end coverage for the SQL-logging proxy example.

use std::{
    error::Error,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

#[path = "../examples/proxy_support/mod.rs"]
mod proxy_support;

use proxy_support::Observation;

#[tokio::test]
#[ignore = "requires local networking"]
async fn rejects_an_unavailable_explicit_upstream_before_listening() -> Result<(), Box<dyn Error>> {
    let unused = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = unused.local_addr()?;
    drop(unused);

    let Err(error) = proxy_support::ExampleUpstream::resolve(Some(&address.to_string())).await
    else {
        return Err("unexpectedly connected to an unused address".into());
    };
    assert!(error.to_string().contains("omit the upstream argument"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn logs_customer_order_sql_and_result_row_count() -> Result<(), Box<dyn Error>> {
    let postgres = proxy_support::ExampleUpstream::resolve(None).await?;
    let upstream = postgres.address();

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let proxy_address = listener.local_addr()?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observations);
    let tls = proxy_support::ExampleTlsIdentity::generate()?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(tls.certificate())?;
    let client_tls = tokio_postgres_rustls::MakeRustlsConnect::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy = tokio::spawn(proxy_support::serve(
        listener,
        upstream,
        tls,
        Arc::new(move |event| captured.lock().expect("observation lock").push(event)),
    ));

    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(proxy_address.port())
        .user("postgres")
        .dbname("postgres")
        .ssl_mode(tokio_postgres::config::SslMode::Require);
    let (client, connection) = config.connect(client_tls).await?;
    let connection = tokio::spawn(connection);

    let sql = "SELECT c.name, count(o.id)::bigint AS order_count \
               FROM customers AS c \
               LEFT JOIN orders AS o ON o.customer_id = c.id \
               GROUP BY c.id, c.name ORDER BY c.name";
    let rows = client.query(sql, &[]).await?;
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].get::<_, String>(0), "Ada Lovelace");
    assert_eq!(rows[0].get::<_, i64>(1), 2);
    assert_eq!(rows[1].get::<_, String>(0), "Edsger Dijkstra");
    assert_eq!(rows[1].get::<_, i64>(1), 0);
    assert_eq!(rows[2].get::<_, String>(0), "Grace Hopper");
    assert_eq!(rows[2].get::<_, i64>(1), 3);

    let captured = observations.lock().expect("observation lock");
    assert!(captured.iter().any(|event| matches!(
        event,
        Observation::Sql { statement, .. } if statement == sql
    )));
    assert!(captured.iter().any(|event| matches!(
        event,
        Observation::RowCount { rows: 3, command, .. } if command == "SELECT 3"
    )));
    assert!(captured.iter().any(|event| matches!(
        event,
        Observation::Protocol { direction: "client -> server", message, .. }
            if message.starts_with("Parse(") || message.starts_with("Query(")
    )));
    drop(captured);

    drop(client);
    connection.abort();
    proxy.abort();
    Ok(())
}
