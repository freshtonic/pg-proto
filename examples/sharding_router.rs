//! Shard router which namespaces prepared statements and portals per route.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    CancellationPolicy, Client, ClientConnectionContext, ClientTlsPolicy, Close, ConnectTarget,
    Describe, Execute, FrontendMessage, InitialServerContext, Intermediary, IntermediaryMiddleware,
    Parse, Server, ServerConnectionContext, ServerTlsPolicy, StartupParameters,
    StartupRouteResolver, TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};

struct ShardRoute;

impl<Peer: Sync> StartupRouteResolver<Peer> for ShardRoute {
    type Error = Infallible;

    async fn resolve(
        &self,
        startup: StartupParameters,
        _context: InitialServerContext<'_, Peer>,
    ) -> Result<ConnectTarget, Self::Error> {
        let shard = startup
            .database_name()
            .map(|database| database.bytes().fold(0_u8, u8::wrapping_add) % 4)
            .unwrap_or_default();
        Ok(ConnectTarget::new(format!("shard-{shard}")))
    }
}

#[derive(Default)]
struct ShardState {
    namespace: Bytes,
}

struct NamespaceResources;

impl
    IntermediaryMiddleware<
        ShardState,
        ServerConnectionContext<std::net::SocketAddr, TrustIdentity>,
        ClientConnectionContext<()>,
    > for NamespaceResources
{
    type Error = Infallible;

    async fn frontend(
        &mut self,
        _server: &ServerConnectionContext<std::net::SocketAddr, TrustIdentity>,
        _client: &ClientConnectionContext<()>,
        state: &mut ShardState,
        message: FrontendMessage,
    ) -> Result<pg_proto::FrontendMiddlewareOutput, Self::Error> {
        let rewritten = match message {
            FrontendMessage::Parse(Parse {
                statement,
                query,
                parameter_types,
            }) => FrontendMessage::Parse(Parse {
                statement: qualify(&state.namespace, &statement, b"statement"),
                query,
                parameter_types,
            }),
            FrontendMessage::Bind(mut bind) => {
                bind.statement = qualify(&state.namespace, &bind.statement, b"statement");
                bind.portal = qualify(&state.namespace, &bind.portal, b"portal");
                FrontendMessage::Bind(bind)
            }
            FrontendMessage::Describe(Describe { target, name }) => {
                let kind = match target {
                    pg_proto::DescribeTarget::Statement => b"statement".as_slice(),
                    pg_proto::DescribeTarget::Portal => b"portal".as_slice(),
                };
                FrontendMessage::Describe(Describe {
                    target,
                    name: qualify(&state.namespace, &name, kind),
                })
            }
            FrontendMessage::Execute(Execute { portal, max_rows }) => {
                FrontendMessage::Execute(Execute {
                    portal: qualify(&state.namespace, &portal, b"portal"),
                    max_rows,
                })
            }
            FrontendMessage::Close(Close { target, name }) => {
                let kind = match target {
                    pg_proto::DescribeTarget::Statement => b"statement".as_slice(),
                    pg_proto::DescribeTarget::Portal => b"portal".as_slice(),
                };
                FrontendMessage::Close(Close {
                    target,
                    name: qualify(&state.namespace, &name, kind),
                })
            }
            other => other,
        };
        Ok(pg_proto::FrontendMiddlewareOutput::Forward(rewritten))
    }
}

fn qualify(namespace: &[u8], client_name: &[u8], kind: &[u8]) -> Bytes {
    let client_name = if client_name.is_empty() {
        b"unnamed".as_slice()
    } else {
        client_name
    };
    Bytes::from([namespace, b"::", kind, b"::", client_name].concat())
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
        .startup_resolver(ShardRoute)
        .cancellation(CancellationPolicy::Reject)
        .middleware(
            |_: &ServerConnectionContext<std::net::SocketAddr, TrustIdentity>,
             target: &ClientConnectionContext<()>| {
                println!("routing through {}", target.target().name());
                NamespaceResources
            },
        )
        .build()?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let (transport, peer) = listener.accept().await?;
    let namespace = Bytes::from(format!("client-{peer}"));
    let mut session = Box::pin(intermediary.accept(transport, peer, ShardState { namespace }))
        .await?
        .into_session();
    while !matches!(
        session.forward_next().await?,
        pg_proto::ForwardedMessage::Frontend(FrontendMessage::Terminate)
    ) {}
    Ok(())
}
