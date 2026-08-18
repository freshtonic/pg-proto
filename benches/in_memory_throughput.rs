//! In-memory end-to-end throughput benchmarks for the public proxy facade.

#![allow(clippy::too_many_lines)]

use std::{
    convert::Infallible,
    future::poll_fn,
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::future::join_all;
use pg_proto::{
    BackendMessage, BoundedPipeline, CancellationPolicy, Client, ClientTlsPolicy, ConnectTarget,
    DataRow, FieldDescription, ForwardedMessage, FrontendMessage, InitialServerContext,
    Intermediary, RowDescription, Server, ServerAccept, ServerTlsPolicy, StartupParameters,
    StartupRouteResolver, TransactionStatus, TrustClientAuthentication, TrustServerAuthentication,
};
use tokio::{io::DuplexStream, sync::mpsc, time::timeout};
use tokio_postgres::{AsyncMessage, NoTls, SimpleQueryMessage};

const SELECT_ROWS: u32 = 10_000;
const PIPELINED_INSERTS: u32 = 10_000;
const NOTIFICATIONS: u32 = 10_000;
const TIMEOUT: Duration = Duration::from_secs(30);
const BUFFER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Workload {
    Select,
    Insert,
    Notify,
}

struct Route;

impl StartupRouteResolver<()> for Route {
    type Error = Infallible;

    async fn resolve(
        &self,
        _startup: StartupParameters,
        _context: InitialServerContext<'_, ()>,
    ) -> Result<ConnectTarget, Self::Error> {
        Ok(ConnectTarget::new("in-memory-stub"))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let select = Box::pin(run(Workload::Select)).await?;
    println!(
        "SELECT: {SELECT_ROWS} rows in {:.3}s ({:.0} rows/s)",
        select.as_secs_f64(),
        f64::from(SELECT_ROWS) / select.as_secs_f64()
    );

    let inserts = Box::pin(run(Workload::Insert)).await?;
    println!(
        "pipelined INSERT: {PIPELINED_INSERTS} statements in {:.3}s ({:.0} statements/s)",
        inserts.as_secs_f64(),
        f64::from(PIPELINED_INSERTS) / inserts.as_secs_f64()
    );

    let notifications = Box::pin(run(Workload::Notify)).await?;
    println!(
        "LISTEN/NOTIFY: {NOTIFICATIONS} notifications in {:.3}s ({:.0} notifications/s)",
        notifications.as_secs_f64(),
        f64::from(NOTIFICATIONS) / notifications.as_secs_f64()
    );
    Ok(())
}

async fn run(workload: Workload) -> Result<Duration, Box<dyn std::error::Error>> {
    let rows = match workload {
        Workload::Select => pregenerated_rows(),
        Workload::Insert | Workload::Notify => Vec::new(),
    };
    let (adapter_io, intermediary_io) = tokio::io::duplex(BUFFER_BYTES);
    let (upstream_io, stub_io) = tokio::io::duplex(BUFFER_BYTES);
    let upstream = Arc::new(Mutex::new(Some(upstream_io)));

    let client = Client::builder()
        .connector(move |_| {
            let stream = upstream.lock().expect("upstream lock poisoned").take();
            async move { stream.ok_or_else(|| io::Error::other("upstream already connected")) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()?;
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()?;
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route)
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(
            usize::try_from(PIPELINED_INSERTS)? + 2,
        )?)
        .build()?;
    let stub = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()?;

    let mut config = tokio_postgres::Config::new();
    config.user("benchmark");
    let (accepted, upstream_accepted, adapter) = tokio::join!(
        intermediary.accept(intermediary_io, (), ()),
        stub.accept(stub_io, (), ()),
        config.connect_raw(adapter_io, NoTls),
    );
    let mut intermediary = accepted?.into_session();
    let ServerAccept::Session(mut stub) = upstream_accepted? else {
        return Err("stub received an unexpected cancellation request".into());
    };
    let (adapter, mut connection) = adapter?;
    let (notifications_tx, mut notifications_rx) = mpsc::unbounded_channel();
    let connection_driver = tokio::spawn(async move {
        while let Some(message) = poll_fn(|cx| connection.poll_message(cx))
            .await
            .transpose()?
        {
            if let AsyncMessage::Notification(notification) = message {
                let _ = notifications_tx.send(notification);
            }
        }
        Ok::<_, tokio_postgres::Error>(())
    });
    let insert_statements = (0..PIPELINED_INSERTS)
        .map(|index| {
            format!(
                "INSERT INTO customers (name, email) VALUES ('name-{index}', 'customer-{index}@example.com');"
            )
        })
        .collect::<Vec<_>>();
    let started = Instant::now();

    let workload_future = async move {
        let elapsed = match workload {
            Workload::Select => {
                let messages = adapter
                    .simple_query("SELECT id, name, email FROM customers;")
                    .await
                    .map_err(io::Error::other)?;
                let rows = messages
                    .iter()
                    .filter(|message| matches!(message, SimpleQueryMessage::Row(_)))
                    .count();
                if rows != usize::try_from(SELECT_ROWS).map_err(io::Error::other)? {
                    return Err(io::Error::other(format!(
                        "expected {SELECT_ROWS} rows, received {rows}"
                    )));
                }
                Some(started.elapsed())
            }
            Workload::Insert => {
                let mut statements = Vec::with_capacity(insert_statements.len() + 2);
                statements.push("BEGIN;".to_owned());
                statements.extend(insert_statements);
                statements.push("COMMIT;".to_owned());
                let pending = statements
                    .iter()
                    .map(|statement| adapter.simple_query(statement));
                for result in join_all(pending).await {
                    result.map_err(io::Error::other)?;
                }
                None
            }
            Workload::Notify => {
                adapter
                    .simple_query("LISTEN customer_events;")
                    .await
                    .map_err(io::Error::other)?;
                for received in 0..NOTIFICATIONS {
                    let notification = notifications_rx.recv().await.ok_or_else(|| {
                        io::Error::other(format!(
                            "notification stream ended after {received} messages"
                        ))
                    })?;
                    if notification.channel() != "customer_events" {
                        return Err(io::Error::other("unexpected notification channel"));
                    }
                }
                Some(started.elapsed())
            }
        };
        drop(adapter);
        Ok::<_, io::Error>(elapsed)
    };

    let proxy_future = async move {
        loop {
            if matches!(
                intermediary.forward_next().await?,
                ForwardedMessage::Frontend(FrontendMessage::Terminate)
            ) {
                break;
            }
        }
        let _ = intermediary.teardown();
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let stub_future = async move {
        let elapsed = serve_stub(&mut stub, workload, &rows, started).await?;
        let _ = stub.teardown();
        Ok::<_, Box<dyn std::error::Error>>(elapsed)
    };

    let (client_elapsed, proxy, server_elapsed) = timeout(TIMEOUT, async {
        tokio::join!(workload_future, proxy_future, stub_future)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "benchmark timed out"))?;
    proxy?;
    connection_driver.await??;
    client_elapsed?
        .or(server_elapsed?)
        .ok_or_else(|| io::Error::other("benchmark completion boundary was not observed").into())
}

async fn serve_stub(
    stub: &mut pg_proto::ServerConnection<DuplexStream, (), (), pg_proto::TrustIdentity>,
    workload: Workload,
    rows: &[BackendMessage],
    started: Instant,
) -> io::Result<Option<Duration>> {
    let mut completion = None;
    loop {
        match stub.receive_wire().await? {
            FrontendMessage::Query(query) => match workload {
                Workload::Select => send_rows(stub, query, rows).await?,
                Workload::Insert if query == Bytes::from_static(b"BEGIN;") => {
                    send_command(stub, b"BEGIN", TransactionStatus::InTransaction).await?;
                }
                Workload::Insert if query == Bytes::from_static(b"COMMIT;") => {
                    completion = Some(started.elapsed());
                    send_command(stub, b"COMMIT", TransactionStatus::Idle).await?;
                }
                Workload::Insert if query.starts_with(b"INSERT INTO customers ") => {
                    send_command(stub, b"INSERT 0 1", TransactionStatus::InTransaction).await?;
                }
                Workload::Insert => return Err(io::Error::other("unexpected transaction query")),
                Workload::Notify => {
                    send_command(stub, b"LISTEN", TransactionStatus::Idle).await?;
                    for index in 0..NOTIFICATIONS {
                        stub.send_wire(BackendMessage::NotificationResponse {
                            process_id: 1,
                            channel: Bytes::from_static(b"customer_events"),
                            payload: Bytes::from(index.to_string()),
                        })
                        .await?;
                    }
                }
            },
            FrontendMessage::Terminate => return Ok(completion),
            message => {
                return Err(io::Error::other(format!(
                    "stub received unexpected frontend message: {message:?}"
                )));
            }
        }
    }
}

async fn send_rows(
    stub: &mut pg_proto::ServerConnection<DuplexStream, (), (), pg_proto::TrustIdentity>,
    query: Bytes,
    rows: &[BackendMessage],
) -> io::Result<()> {
    if query != Bytes::from_static(b"SELECT id, name, email FROM customers;") {
        return Err(io::Error::other("unexpected SELECT query"));
    }
    stub.send_wire(BackendMessage::RowDescription(RowDescription {
        fields: vec![field("id", 20), field("name", 25), field("email", 25)],
    }))
    .await?;
    for row in rows {
        stub.send_wire(row.clone()).await?;
    }
    send_command(stub, b"SELECT 10000", TransactionStatus::Idle).await
}

fn pregenerated_rows() -> Vec<BackendMessage> {
    (0..SELECT_ROWS)
        .map(|index| {
            BackendMessage::DataRow(DataRow {
                columns: vec![
                    Some(Bytes::from(index.to_string())),
                    Some(Bytes::from(format!("customer-{index}"))),
                    Some(Bytes::from(format!("customer-{index}@example.com"))),
                ],
            })
        })
        .collect()
}

const fn field(name: &'static str, type_oid: u32) -> FieldDescription {
    FieldDescription {
        name: Bytes::from_static(name.as_bytes()),
        table_oid: 0,
        column: 0,
        type_oid,
        type_size: if type_oid == 20 { 8 } else { -1 },
        type_modifier: -1,
        format: 0,
    }
}

async fn send_command(
    stub: &mut pg_proto::ServerConnection<DuplexStream, (), (), pg_proto::TrustIdentity>,
    tag: &'static [u8],
    status: TransactionStatus,
) -> io::Result<()> {
    stub.send_wire(BackendMessage::CommandComplete(Bytes::from_static(tag)))
        .await?;
    stub.send_wire(BackendMessage::ReadyForQuery(status)).await
}
