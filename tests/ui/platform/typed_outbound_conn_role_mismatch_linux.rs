use pg_proto::{
    Conn,
    grammar::pre_startup,
    middleware::{Identity, Middleware, ServerRole},
    pre_startup::PreStartupMessage,
};

async fn wrong_sender_role() {
    let conn = Conn::new(());
    let mut middleware = Middleware::new((), Identity);
    let message = pre_startup::PreStartupInternalMessage::try_from(
        PreStartupMessage::SslRequest,
    )
    .unwrap();

    let _ = conn
        .intercept_outbound_typed::<ServerRole, PreStartupMessage, _, _>(
            &mut middleware,
            message,
        )
        .await;
}

fn main() {}
