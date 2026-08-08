//! Complete bounded-pipeline intermediary configuration.

use pg_proto::{
    BoundedPipeline, CancellationPolicy, Client, ClientTlsPolicy, ConnectTarget,
    InitialServerContext, Intermediary, Server, ServerTlsPolicy, StartupParameters,
    StartupRouteResolver, TrustClientAuthentication, TrustServerAuthentication,
};
use std::convert::Infallible;

struct Route;
impl<Peer> StartupRouteResolver<Peer> for Route {
    type Error = Infallible;
    fn resolve<'a>(
        &'a self,
        _: StartupParameters,
        _: InitialServerContext<'a, Peer>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ConnectTarget, Self::Error>> + 'a>>
    {
        Box::pin(async { Ok(ConnectTarget::new("postgres")) })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream: std::net::SocketAddr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:5432".into())
        .parse()?;
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let client = Client::builder()
        .connector(move |_| tokio::net::TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route)
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(1).expect("non-zero bound"))
        .build()
        .unwrap();
    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6432".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let (transport, peer) = listener.accept().await?;
    let mut session = Box::pin(intermediary.accept(transport, peer, ()))
        .await?
        .into_session();
    loop {
        if matches!(
            session.forward_frontend().await?,
            pg_proto::codec::FrontendMessage::Terminate
        ) {
            return Ok(());
        }
        match session.forward_frontend().await {
            Err(pg_proto::ForwardError::Frontend(pg_proto::FrontendProjectionError::Capacity(
                _,
            ))) => {
                println!("capacity reached: the second owned request is retained");
            }
            Ok(pg_proto::codec::FrontendMessage::Terminate) => return Ok(()),
            Ok(_) => unreachable!("capacity one must reject a second outstanding operation"),
            Err(error) => return Err(error.into()),
        }
        loop {
            if matches!(
                session.forward_backend().await?,
                pg_proto::codec::BackendMessage::ReadyForQuery(_)
            ) {
                break;
            }
        }
        session.forward_frontend().await?;
        println!("response progress freed capacity; retained request forwarded unchanged");
    }
}
