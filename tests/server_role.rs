//! Integration coverage for the typed client-facing server role.

use bytes::Bytes;
use pg_proto::{
    Conn,
    codec::{BackendMessage, DataRow, FieldDescription, RowDescription, TransactionStatus},
    credentials::{verify_cleartext, verify_md5_response},
    pre_startup::PreStartupOffer,
    scram::{SCRAM_SHA_256, ScramServer, ServerChannelBinding},
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

#[tokio::test]
async fn typed_server_scram_authenticates_an_independent_client() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(serve_scram_startup(server_io));
    let mut config = tokio_postgres::Config::new();
    config.user("proxy_test").password("secret");
    let (client, connection) = config.connect_raw(client_io, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);

    drop(client);
    server.await.unwrap().unwrap();
    let _ = driver.await;
}

#[derive(Clone, Copy)]
enum PasswordMethod {
    Cleartext,
    Md5([u8; 4]),
}

#[tokio::test]
async fn typed_server_cleartext_authenticates_an_independent_client() {
    independent_password_exchange(PasswordMethod::Cleartext).await;
}

#[tokio::test]
async fn typed_server_md5_authenticates_an_independent_client() {
    independent_password_exchange(PasswordMethod::Md5(*b"salt")).await;
}

async fn independent_password_exchange(method: PasswordMethod) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(serve_password_startup(server_io, method));
    let mut config = tokio_postgres::Config::new();
    config.user("proxy_test").password("secret");
    let (client, connection) = config.connect_raw(client_io, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);

    drop(client);
    server.await.unwrap().unwrap();
    let _ = driver.await;
}

async fn serve_password_startup<S>(stream: S, method: PasswordMethod) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pre_startup = Conn::new(Buffered::new_frontend(stream));
    let (startup, message) = loop {
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
    let pg_proto::server_auth::ServerProtocolOffer::Supported { conn, message, .. } =
        startup.validate_protocol(message, pg_proto::startup::ProtocolVersion::V3_2)
    else {
        return Err(std::io::Error::other("unsupported startup protocol"));
    };
    let username = message
        .parameters
        .get(b"user".as_slice())
        .ok_or_else(|| std::io::Error::other("startup omitted user"))?;
    let auth = conn.begin_server_auth();
    let (mut password_state, request) = match method {
        PasswordMethod::Cleartext => auth.request_cleartext()?,
        PasswordMethod::Md5(salt) => auth.request_md5(salt)?,
    };
    password_state.push_frame(request)?;
    password_state.flush().await?;
    let response = password_state.receive_frontend_wire().await?;
    let (auth, response) = password_state
        .receive_password(response)
        .map_err(|rejected| {
            let (conn, _) = *rejected;
            let _transport = conn.into_transport();
            std::io::Error::other("invalid password response")
        })?;
    let verified = match method {
        PasswordMethod::Cleartext => verify_cleartext(&response, b"secret"),
        PasswordMethod::Md5(salt) => verify_md5_response(&response, username, b"secret", salt),
    };
    if !verified {
        let _transport = auth.into_transport();
        return Err(std::io::Error::other("password verification failed"));
    }
    complete_server_startup(auth).await
}

async fn complete_server_startup<S>(
    auth: Conn<Buffered<S, pg_proto::codec::Frontend>, pg_proto::server_auth::ServerAuth>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut startup_ready, ok_frame) = auth.authentication_ok()?;
    startup_ready.push_frame(ok_frame)?;
    let (next, parameter) = startup_ready.parameter_status(
        Bytes::from_static(b"client_encoding"),
        Bytes::from_static(b"UTF8"),
    )?;
    startup_ready = next;
    startup_ready.push_frame(parameter)?;
    let (mut ready, ready_frame) = startup_ready.ready()?;
    ready.push_frame(ready_frame)?;
    ready.flush().await?;
    let _transport = ready.into_transport();
    Ok(())
}

async fn serve_scram_startup<S>(stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pre_startup = Conn::new(Buffered::new_frontend(stream));
    let (startup, message) = loop {
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
    let pg_proto::server_auth::ServerProtocolOffer::Supported { conn, .. } =
        startup.validate_protocol(message, pg_proto::startup::ProtocolVersion::V3_2)
    else {
        return Err(std::io::Error::other("unsupported startup protocol"));
    };

    let (mut initial, offer) = conn
        .begin_server_auth()
        .request_sasl(vec![Bytes::from_static(SCRAM_SHA_256)])?;
    initial.push_frame(offer)?;
    initial.flush().await?;
    let response = initial.receive_frontend_wire().await?;
    let (mut sasl, initial_response) = initial.receive_initial(response).map_err(|rejected| {
        let (conn, _) = *rejected;
        let _transport = conn.into_transport();
        std::io::Error::other("invalid SASL initial response")
    })?;
    let verifier = ScramServer::with_parameters(
        b"secret",
        b"independent client salt".to_vec(),
        pg_proto::scram::DEFAULT_ITERATIONS,
        ServerChannelBinding::None,
    )?;
    let client_first = initial_response
        .response
        .as_deref()
        .ok_or_else(|| std::io::Error::other("client omitted SCRAM initial data"))?;
    let (exchange, challenge) = verifier.start(&initial_response.mechanism, client_first)?;
    let (next, frame) = sasl.continue_with(challenge)?;
    sasl = next;
    sasl.push_frame(frame)?;
    sasl.flush().await?;

    let response = sasl.receive_frontend_wire().await?;
    let (sasl, client_final) = sasl.receive_response(response).map_err(|rejected| {
        let (conn, _) = *rejected;
        let _transport = conn.into_transport();
        std::io::Error::other("invalid SASL response")
    })?;
    let server_final = exchange.finish(&client_final)?;
    let (auth, final_frame) = sasl.finish(server_final)?;
    let (mut startup_ready, ok_frame) = auth.authentication_ok()?;
    startup_ready.push_frame(final_frame)?;
    startup_ready.push_frame(ok_frame)?;
    let (next, parameter) = startup_ready.parameter_status(
        Bytes::from_static(b"client_encoding"),
        Bytes::from_static(b"UTF8"),
    )?;
    startup_ready = next;
    startup_ready.push_frame(parameter)?;
    let (mut ready, ready_frame) = startup_ready.ready()?;
    ready.push_frame(ready_frame)?;
    ready.flush().await?;
    let _transport = ready.into_transport();
    Ok(())
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

    let pg_proto::server_auth::ServerProtocolOffer::Supported { conn, .. } = startup
        .0
        .validate_protocol(startup.1, pg_proto::startup::ProtocolVersion::V3_2)
    else {
        return Err(std::io::Error::other("unsupported startup protocol"));
    };
    let (mut startup_ready, frame) = conn.begin_server_auth().authentication_ok()?;
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
