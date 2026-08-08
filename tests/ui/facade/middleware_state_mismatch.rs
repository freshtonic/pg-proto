use pg_proto::{
    Client, ClientConnectionContext, ClientInitialContext, ClientMiddleware, ClientTlsPolicy,
    ConnectTarget, FrontendMessage, StartupParameters, TrustClientAuthentication,
};

struct Handler;
struct ExpectedState;
struct WrongState;

impl ClientMiddleware<ExpectedState, ClientConnectionContext> for Handler {
    fn frontend(
        &mut self,
        _: &ClientConnectionContext,
        _: &mut ExpectedState,
        message: FrontendMessage,
    ) -> FrontendMessage {
        message
    }
}

async fn mismatch() {
    let client = Client::builder()
        .connector(|_| async { Ok::<_, std::io::Error>(tokio::io::duplex(64).0) })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .middleware(|_: &ClientInitialContext| Handler)
        .build()
        .unwrap();
    let _ = client
        .connect(
            ConnectTarget::new("test"),
            StartupParameters::new("test"),
            WrongState,
        )
        .await;
}

fn main() {}
