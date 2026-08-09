//! Smallest complete intermediary configuration.

use std::convert::Infallible;

use pg_proto::{
    CancellationPolicy, Client, ClientTlsPolicy, ConnectTarget, InitialServerContext, Intermediary,
    Server, ServerTlsPolicy, StartupParameters, StartupRouteResolver, TrustClientAuthentication,
    TrustServerAuthentication,
};

struct Route;

impl<Peer> StartupRouteResolver<Peer> for Route {
    type Error = Infallible;

    fn resolve<'a>(
        &'a self,
        _startup: StartupParameters,
        _context: InitialServerContext<'a, Peer>,
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
        // Demo-only posture: production deployments should configure TLS and
        // an application authentication implementation here.
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .expect("complete server configuration");
    let client = Client::builder()
        .connector(move |_target| tokio::net::TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .expect("complete client configuration");
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route)
        .cancellation(CancellationPolicy::Reject)
        .build()
        .expect("complete intermediary configuration");

    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6432".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let (transport, peer) = listener.accept().await?;
    let mut session = Box::pin(intermediary.accept(transport, peer, ()))
        .await?
        .into_session();
    while !matches!(
        session.forward_next().await?,
        pg_proto::ForwardedMessage::Frontend(pg_proto::FrontendMessage::Terminate)
    ) {}
    Ok(())
}
