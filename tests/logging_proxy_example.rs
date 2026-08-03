use std::{
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt as _, runners::AsyncRunner as _},
};
use tokio::net::TcpListener;

#[path = "../examples/proxy_support/mod.rs"]
mod proxy_support;

use proxy_support::Observation;

fn postgres_tag() -> String {
    let version = std::env::var("PG_PROTO_POSTGRES_VERSION").unwrap_or_else(|_| "18".to_owned());
    assert!(
        matches!(version.as_str(), "14" | "15" | "16" | "17" | "18"),
        "unsupported PostgreSQL test version"
    );
    format!("{version}-alpine")
}

#[tokio::test]
#[ignore = "requires a Docker-compatible container runtime"]
async fn logs_customer_order_sql_and_result_row_count() -> Result<(), Box<dyn Error>> {
    let postgres = Postgres::default()
        .with_init_sql(include_bytes!("../examples/sql_logging_proxy/customer_orders.sql").to_vec())
        .with_host_auth()
        .with_tag(postgres_tag())
        .start()
        .await?;
    let postgres_port = postgres.get_host_port_ipv4(5432).await?;
    let upstream = SocketAddr::from(([127, 0, 0, 1], postgres_port));

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let proxy_address = listener.local_addr()?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observations);
    let proxy = tokio::spawn(proxy_support::serve(
        listener,
        upstream,
        Arc::new(move |event| captured.lock().expect("observation lock").push(event)),
    ));

    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(proxy_address.port())
        .user("postgres")
        .dbname("postgres");
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
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
    drop(captured);

    drop(client);
    connection.abort();
    proxy.abort();
    Ok(())
}
