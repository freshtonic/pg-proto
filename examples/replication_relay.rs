//! Replication relay which observes both COPY-BOTH half-closes.

use std::convert::Infallible;

use pg_proto::{
    BackendMessage, BoundedPipeline, CancellationPolicy, Client, ClientTlsPolicy, ConnectTarget,
    ForwardedMessage, FrontendMessage, InitialServerContext, Intermediary, Server, ServerTlsPolicy,
    StartupParameters, StartupRouteResolver, TrustClientAuthentication, TrustServerAuthentication,
};

struct Route;

impl<Peer: Sync> StartupRouteResolver<Peer> for Route {
    type Error = Infallible;

    async fn resolve(
        &self,
        _startup: StartupParameters,
        _context: InitialServerContext<'_, Peer>,
    ) -> Result<ConnectTarget, Self::Error> {
        Ok(ConnectTarget::new("replication-primary"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6432".into());
    let upstream: std::net::SocketAddr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:5432".into())
        .parse()?;
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()?;
    let client = Client::builder()
        .connector(move |_| tokio::net::TcpStream::connect(upstream))
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()?;
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route)
        .cancellation(CancellationPolicy::Reject)
        .pipeline(BoundedPipeline::new(4)?)
        .build()?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let (transport, peer) = listener.accept().await?;
    let mut session = Box::pin(intermediary.accept(transport, peer, ()))
        .await?
        .into_session();
    let mut standby_closed = false;
    let mut primary_closed = false;
    loop {
        match session.forward_next().await? {
            ForwardedMessage::Backend(BackendMessage::CopyBothResponse(_)) => {
                println!("replication entered typed COPY-BOTH mode");
            }
            ForwardedMessage::Frontend(FrontendMessage::CopyDone) => {
                standby_closed = true;
                println!("standby closed its COPY-BOTH half");
            }
            ForwardedMessage::Backend(BackendMessage::CopyDone) => {
                primary_closed = true;
                println!("primary closed its COPY-BOTH half");
            }
            ForwardedMessage::Frontend(FrontendMessage::Terminate) => break,
            _ => {}
        }
        if standby_closed && primary_closed {
            println!("both typed COPY-BOTH halves are closed");
        }
    }
    Ok(())
}
