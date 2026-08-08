#![no_main]

use libfuzzer_sys::fuzz_target;
use pg_proto::{
    DisabledServerTls, Server, ServerAuthentication, ServerAuthenticationAction,
    ServerAuthenticationFuture, ServerAuthenticationProvider, ServerAuthenticationRequest,
    ServerAuthenticationResponse,
};
use tokio::io::{AsyncWriteExt as _, duplex};

#[derive(Clone, Copy)]
struct SaslPolicy;

impl ServerAuthenticationProvider for SaslPolicy {
    type Authentication = Self;
    fn create(&self) -> Self { *self }
}

impl ServerAuthentication<()> for SaslPolicy {
    type Identity = ();
    type Error = std::convert::Infallible;

    fn start<'a>(&'a mut self, _: ServerAuthenticationRequest<'a, ()>)
        -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<()>, Self::Error>
    {
        Box::pin(async {
            Ok(ServerAuthenticationAction::Sasl {
                mechanisms: vec![bytes::Bytes::from_static(b"SCRAM-SHA-256")],
            })
        })
    }

    fn respond<'a>(
        &'a mut self,
        _: ServerAuthenticationRequest<'a, ()>,
        response: ServerAuthenticationResponse,
    ) -> ServerAuthenticationFuture<'a, ServerAuthenticationAction<()>, Self::Error> {
        Box::pin(async move {
            Ok(match response {
                ServerAuthenticationResponse::SaslInitial { .. } =>
                    ServerAuthenticationAction::SaslContinue(bytes::Bytes::from_static(b"r=fuzz")),
                ServerAuthenticationResponse::Sasl(_) => ServerAuthenticationAction::Accept(()),
                _ => ServerAuthenticationAction::Accept(()),
            })
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = vec![0, 0, 0, 13, 0, 3, 0, 0, b'u', 0, b'f', 0, 0];
    input.extend_from_slice(data);
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async move {
        let (server_io, mut peer) = duplex(input.len().saturating_add(4096));
        tokio::spawn(async move {
            let _ = peer.write_all(&input).await;
            let _ = peer.shutdown().await;
        });
        let server = Server::builder()
            .tls(DisabledServerTls)
            .authentication(SaslPolicy)
            .build()
            .unwrap();
        let _ = server.accept(server_io, (), ()).await;
    });
});
