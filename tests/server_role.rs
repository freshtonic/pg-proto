use bytes::Bytes;
use pg_proto::{
    Conn,
    codec::{BackendMessage, DataRow, FieldDescription, RowDescription, TransactionStatus},
    pre_startup::PreStartupOffer,
    server_session::{ServerReadyOffer, ServerReadyState},
    transport::Buffered,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::{NoTls, SimpleQueryMessage};

#[tokio::test]
async fn typed_server_role_serves_an_independent_client() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(serve_one_query(server_io));
    let mut config = tokio_postgres::Config::new();
    config.user("proxy_test");
    let (client, connection) = config.connect_raw(client_io, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let messages = client.simple_query("SELECT 42::int4").await.unwrap();
    let value = messages.iter().find_map(|message| match message {
        SimpleQueryMessage::Row(row) => row.get(0),
        SimpleQueryMessage::CommandComplete(_) | _ => None,
    });
    assert_eq!(value, Some("42"));

    drop(client);
    server.await.unwrap().unwrap();
    let _ = driver.await;
}

async fn serve_one_query<S>(stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pre_startup = Conn::new(Buffered::new_frontend(stream));
    let startup = loop {
        let message = pre_startup.receive_pre_startup_wire().await?;
        match pre_startup.offer_pre_startup(message) {
            PreStartupOffer::Ssl(decision) => {
                pre_startup = decision.decline_ssl();
                pre_startup.flush().await?;
            }
            PreStartupOffer::Startup { conn, message } => break (conn, message),
            offer => {
                abort_pre_startup_offer(offer);
                return Err(std::io::Error::other("unexpected pre-startup branch"));
            }
        }
    };
    assert_eq!(
        startup.1.parameters.get(b"user".as_slice()),
        Some(&Bytes::from_static(b"proxy_test"))
    );

    let (mut startup_ready, frame) = startup.0.begin_server_auth().authentication_ok()?;
    startup_ready.push_frame(frame)?;
    for (name, value) in [
        (b"server_version".as_slice(), b"18.0".as_slice()),
        (b"client_encoding".as_slice(), b"UTF8".as_slice()),
        (b"standard_conforming_strings".as_slice(), b"on".as_slice()),
    ] {
        let (next, frame) = startup_ready
            .parameter_status(Bytes::copy_from_slice(name), Bytes::copy_from_slice(value))?;
        startup_ready = next;
        startup_ready.push_frame(frame)?;
    }
    let (next, frame) = startup_ready.backend_key_data(42, Bytes::from_static(b"key!"))?;
    startup_ready = next;
    startup_ready.push_frame(frame)?;
    let (mut ready, frame) = startup_ready.ready()?;
    ready.push_frame(frame)?;
    ready.flush().await?;

    let message = ready.receive_frontend_wire().await?;
    let ServerReadyOffer::Query { mut conn, query } = ready
        .offer_frontend(message)
        .map_err(|_| std::io::Error::other("client did not send a simple query"))?
    else {
        return Err(std::io::Error::other("client did not send a simple query"));
    };
    assert_eq!(query, Bytes::from_static(b"SELECT 42::int4"));

    let (next, frame) = conn.send(&BackendMessage::RowDescription(RowDescription {
        fields: vec![FieldDescription {
            name: Bytes::from_static(b"int4"),
            table_oid: 0,
            column: 0,
            type_oid: 23,
            type_size: 4,
            type_modifier: -1,
            format: 0,
        }],
    }))?;
    conn = next;
    conn.push_frame(frame)?;
    let (next, frame) = conn.send(&BackendMessage::DataRow(DataRow {
        columns: vec![Some(Bytes::from_static(b"42"))],
    }))?;
    conn = next;
    conn.push_frame(frame)?;
    let (next, frame) = conn.send(&BackendMessage::CommandComplete(Bytes::from_static(
        b"SELECT 1",
    )))?;
    conn = next;
    conn.push_frame(frame)?;
    let (state, frame) = conn.ready(TransactionStatus::Idle)?;
    let ServerReadyState::Ready(mut ready) = state else {
        return Err(std::io::Error::other("idle response became dirty"));
    };
    ready.push_frame(frame)?;
    ready.flush().await?;
    let _transport = ready.into_transport();
    Ok(())
}

fn abort_pre_startup_offer(
    offer: PreStartupOffer<
        Buffered<impl AsyncRead + AsyncWrite + Unpin, pg_proto::codec::Frontend>,
    >,
) {
    match offer {
        PreStartupOffer::Gss(conn) => {
            let _transport = conn.into_transport();
        }
        PreStartupOffer::Cancel { conn, .. } => {
            let _transport = conn.into_transport();
        }
        PreStartupOffer::Ssl(conn) => {
            let _transport = conn.into_transport();
        }
        PreStartupOffer::Startup { conn, .. } => {
            let _transport = conn.into_transport();
        }
    }
}
