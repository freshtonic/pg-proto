//! Wire-visible SQL and result-column rewriting at the intermediary boundary.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    BackendMessage, CancellationPolicy, Client, ClientConnectionContext, ClientTlsPolicy,
    ConnectTarget, FrontendMessage, InitialServerContext, Intermediary, IntermediaryMiddleware,
    Server, ServerConnectionContext, ServerTlsPolicy, StartupParameters, StartupRouteResolver,
    TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};

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

#[derive(Clone, Copy)]
struct Rewrite;
impl
    IntermediaryMiddleware<
        (),
        ServerConnectionContext<(), TrustIdentity>,
        ClientConnectionContext<()>,
    > for Rewrite
{
    fn frontend(
        &mut self,
        _: &ServerConnectionContext<(), TrustIdentity>,
        _: &ClientConnectionContext<()>,
        (): &mut (),
        message: FrontendMessage,
    ) -> FrontendMessage {
        match message {
            FrontendMessage::Query(_) => FrontendMessage::Query(Bytes::from_static(
                b"select amount from ledger where visible = true",
            )),
            FrontendMessage::Parse(mut parse) => {
                parse.query = Bytes::from_static(b"select amount from ledger where visible = true");
                FrontendMessage::Parse(parse)
            }
            other => other,
        }
    }
    fn backend(
        &mut self,
        _: &ServerConnectionContext<(), TrustIdentity>,
        _: &ClientConnectionContext<()>,
        (): &mut (),
        message: BackendMessage,
    ) -> BackendMessage {
        match message {
            BackendMessage::RowDescription(mut rows) if !rows.fields.is_empty() => {
                rows.fields[0].name = Bytes::from_static(b"visible_amount");
                BackendMessage::RowDescription(rows)
            }
            other => other,
        }
    }
}

#[tokio::main]
async fn main() {
    let upstream: std::net::SocketAddr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:5432".into())
        .parse()
        .unwrap();
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
        .middleware(
            |_: &ServerConnectionContext<(), TrustIdentity>, _: &ClientConnectionContext<()>| {
                Rewrite
            },
        )
        .build()
        .unwrap();
    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6432".into());
    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap();
    let (transport, _) = listener.accept().await.unwrap();
    let mut session = Box::pin(intermediary.accept(transport, (), ()))
        .await
        .unwrap()
        .into_session();
    loop {
        let forwarded = session.forward_next().await.unwrap();
        println!("forwarded rewritten message: {forwarded:?}");
        if matches!(
            forwarded,
            pg_proto::ForwardedMessage::Frontend(FrontendMessage::Terminate)
        ) {
            break;
        }
    }
}
