//! Compile-time coverage for multithreaded intermediary task ownership.

use std::convert::Infallible;

use pg_proto::{
    CancellationPolicy, Client, ClientConnectionContext, ClientTlsConfig, ClientTlsPolicy,
    ClientTlsProvider, ConnectTarget, FrontendMessage, FrontendMiddlewareOutput,
    InitialServerContext, Intermediary, IntermediaryAccept, IntermediaryMiddleware, Server,
    ServerConnectionContext, ServerTlsPolicy, SslMode, StartupParameters, StartupRouteResolver,
    TrustClientAuthentication, TrustIdentity, TrustServerAuthentication,
};

struct Route;

struct Tls;

struct Boundary;

fn boundary_factory(
    _: &ServerConnectionContext<(), TrustIdentity>,
    _: &ClientConnectionContext<()>,
) -> Boundary {
    Boundary
}

impl
    IntermediaryMiddleware<
        (),
        ServerConnectionContext<(), TrustIdentity>,
        ClientConnectionContext<()>,
    > for Boundary
{
    type Error = Infallible;

    async fn frontend(
        &mut self,
        _: &ServerConnectionContext<(), TrustIdentity>,
        _: &ClientConnectionContext<()>,
        (): &mut (),
        message: FrontendMessage,
    ) -> Result<FrontendMiddlewareOutput, Self::Error> {
        tokio::task::yield_now().await;
        Ok(FrontendMiddlewareOutput::Forward(message))
    }
}

impl ClientTlsProvider for Tls {
    type Error = Infallible;

    async fn resolve(&self, _: &ConnectTarget) -> Result<ClientTlsConfig, Self::Error> {
        Ok(ClientTlsConfig::new(
            "postgres".try_into().unwrap(),
            rustls::RootCertStore::empty(),
        ))
    }
}

impl StartupRouteResolver<()> for Route {
    type Error = Infallible;

    async fn resolve(
        &self,
        _: StartupParameters,
        _: InitialServerContext<'_, ()>,
    ) -> Result<ConnectTarget, Self::Error> {
        Ok(ConnectTarget::new("postgres"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intermediary_session_can_run_in_a_spawned_task() {
    let (downstream, _client_peer) = tokio::io::duplex(256);
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .unwrap();
    let client = Client::builder()
        .connector(|_| async { Ok::<_, Infallible>(tokio::io::duplex(256).0) })
        .tls(ClientTlsPolicy::libpq(SslMode::Prefer, Tls))
        .authentication(TrustClientAuthentication)
        .build()
        .unwrap();
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(Route)
        .cancellation(CancellationPolicy::Reject)
        .middleware(boundary_factory)
        .build()
        .unwrap();

    let task = tokio::spawn(async move {
        if let Ok(IntermediaryAccept::Session(mut session)) =
            Box::pin(intermediary.accept(downstream, (), ())).await
        {
            let _ = session.forward_next().await;
        }
    });

    task.abort();
    let _ = task.await;
}
