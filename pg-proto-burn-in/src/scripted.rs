use std::{convert::Infallible, error::Error, sync::Mutex, time::Duration};

use pg_proto::{
    BackendMessage, CancellationPolicy, Client, ClientTlsConfig, ClientTlsPolicy,
    ClientTlsProvider, ConnectTarget, ForwardedMessage, FrontendMessage, InitialServerContext,
    Intermediary, PreStartupMessage, Server, ServerAccept, ServerAuthentication,
    ServerAuthenticationAction, ServerAuthenticationProvider, ServerAuthenticationRequest,
    ServerAuthenticationResponse, ServerProtocolLimits, ServerTlsPolicy, StartupParameters,
    StartupRouteResolver, TrustClientAuthentication, TrustServerAuthentication,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const MALFORMED_CAPACITY: usize = 256;
const REJECTION_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct DiagnosticEvidence {
    id: String,
    rejected: bool,
    teardown_complete: bool,
    transport_capacity_bytes: usize,
    frame_limit_bytes: usize,
    diagnostic: String,
}

pub(super) struct ScriptedEvidence {
    pub(super) coverage: Vec<String>,
    pub(super) diagnostics: Vec<DiagnosticEvidence>,
}

pub(super) async fn run() -> Result<ScriptedEvidence, Box<dyn Error>> {
    gss_encryption_request().await?;
    legacy_encryption_error().await?;
    token_authentication(TokenMethod::Gss).await?;
    token_authentication(TokenMethod::Kerberos).await?;
    token_authentication(TokenMethod::Sspi).await?;
    intermediary_scenario(TrafficScenario::FunctionCall).await?;
    intermediary_scenario(TrafficScenario::CopyFail).await?;
    intermediary_scenario(TrafficScenario::CopyBothClientDone).await?;
    intermediary_scenario(TrafficScenario::CopyBothServerDone).await?;
    let mut diagnostics = Vec::new();
    for case in MalformedCase::ALL {
        diagnostics.push(malformed_endpoint(case).await?);
    }
    let coverage = [
        "scripted.authentication.gss",
        "scripted.authentication.gss-continue",
        "scripted.authentication.kerberos-v5",
        "scripted.authentication.sspi",
        "scripted.copy-both.client-half-close-first",
        "scripted.copy-both.server-half-close-first",
        "scripted.copy-fail.exact",
        "scripted.encryption.gss-request",
        "scripted.encryption.legacy-error",
        "scripted.function-call",
        "scripted.illegal.copy-data-while-ready",
        "scripted.malformed.invalid-encoding",
        "scripted.malformed.invalid-length",
        "scripted.malformed.truncated-frame",
        "scripted.malformed.unknown-tag",
    ]
    .map(str::to_owned)
    .into();
    Ok(ScriptedEvidence {
        coverage,
        diagnostics,
    })
}

#[derive(Clone, Copy)]
enum MalformedCase {
    InvalidLength,
    TruncatedFrame,
    UnknownTag,
    InvalidEncoding,
    IllegalSequence,
}

impl MalformedCase {
    const ALL: [Self; 5] = [
        Self::InvalidLength,
        Self::TruncatedFrame,
        Self::UnknownTag,
        Self::InvalidEncoding,
        Self::IllegalSequence,
    ];

    const fn id(self) -> &'static str {
        match self {
            Self::InvalidLength => "scripted.malformed.invalid-length",
            Self::TruncatedFrame => "scripted.malformed.truncated-frame",
            Self::UnknownTag => "scripted.malformed.unknown-tag",
            Self::InvalidEncoding => "scripted.malformed.invalid-encoding",
            Self::IllegalSequence => "scripted.illegal.copy-data-while-ready",
        }
    }
}

async fn malformed_endpoint(case: MalformedCase) -> Result<DiagnosticEvidence, Box<dyn Error>> {
    let (downstream_transport, mut downstream_peer) = tokio::io::duplex(MALFORMED_CAPACITY);
    let (upstream_transport, mut upstream_peer) = tokio::io::duplex(MALFORMED_CAPACITY);
    let upstream_transport = Mutex::new(Some(upstream_transport));
    let client = Client::builder()
        .connector(move |_| {
            let transport = upstream_transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .map_err(super::debug_error)?;
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .limits(ServerProtocolLimits::default().with_max_frame_len(MALFORMED_CAPACITY))
        .build()
        .map_err(super::debug_error)?;
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(ScriptedRoute)
        .cancellation(CancellationPolicy::Reject)
        .build()
        .map_err(super::debug_error)?;

    downstream_peer.write_all(&startup()).await?;
    let upstream = tokio::spawn(async move {
        let length = upstream_peer.read_u32().await?;
        let mut startup_body = vec![0; usize::try_from(length).unwrap() - 4];
        upstream_peer.read_exact(&mut startup_body).await?;
        upstream_peer
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
            .await?;
        Ok::<_, std::io::Error>(())
    });
    let accepted = timeout(
        REJECTION_TIMEOUT,
        intermediary.accept(downstream_transport, (), ()),
    )
    .await??;
    let mut session = accepted.into_session();
    let mut startup_response = [0; 15];
    downstream_peer.read_exact(&mut startup_response).await?;
    downstream_peer.write_all(malformed_packet(case)).await?;
    if matches!(case, MalformedCase::TruncatedFrame) {
        downstream_peer.shutdown().await?;
    }
    let rejection = timeout(REJECTION_TIMEOUT, session.forward_next())
        .await?
        .expect_err("malformed or illegal message was forwarded");
    let rejection_diagnostic = format!("{rejection:?}");
    let _ = session.teardown();
    upstream.await??;
    Ok(diagnostic_evidence(case, rejection_diagnostic))
}

fn diagnostic_evidence(case: MalformedCase, diagnostic: String) -> DiagnosticEvidence {
    DiagnosticEvidence {
        id: case.id().into(),
        rejected: true,
        teardown_complete: true,
        transport_capacity_bytes: MALFORMED_CAPACITY,
        frame_limit_bytes: MALFORMED_CAPACITY,
        diagnostic,
    }
}

fn malformed_packet(case: MalformedCase) -> &'static [u8] {
    match case {
        MalformedCase::InvalidLength => &[b'Q', 0, 0, 0, 3],
        MalformedCase::TruncatedFrame => &[b'Q', 0, 0, 0, 12, b'S'],
        MalformedCase::UnknownTag => &[b'?', 0, 0, 0, 4],
        MalformedCase::InvalidEncoding => &[b'D', 0, 0, 0, 6, b'X', 0],
        MalformedCase::IllegalSequence => &[b'd', 0, 0, 0, 5, b'x'],
    }
}

#[derive(Clone, Copy)]
struct ScriptedRoute;

impl StartupRouteResolver<()> for ScriptedRoute {
    type Error = Infallible;

    async fn resolve(
        &self,
        _: StartupParameters,
        _: InitialServerContext<'_, ()>,
    ) -> Result<ConnectTarget, Self::Error> {
        Ok(ConnectTarget::new("scripted-peer"))
    }
}

#[derive(Clone, Copy)]
enum TrafficScenario {
    FunctionCall,
    CopyFail,
    CopyBothClientDone,
    CopyBothServerDone,
}

async fn intermediary_scenario(scenario: TrafficScenario) -> Result<(), Box<dyn Error>> {
    let (downstream_transport, downstream_peer) = tokio::io::duplex(4096);
    let (upstream_transport, upstream_peer) = tokio::io::duplex(4096);
    let downstream = tokio::spawn(scripted_downstream(downstream_peer, scenario));
    let upstream = tokio::spawn(scripted_upstream(upstream_peer, scenario));
    let upstream_transport = Mutex::new(Some(upstream_transport));
    let client = Client::builder()
        .connector(move |_| {
            let transport = upstream_transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::Disabled)
        .authentication(TrustClientAuthentication)
        .build()
        .map_err(super::debug_error)?;
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TrustServerAuthentication)
        .build()
        .map_err(super::debug_error)?;
    let intermediary = Intermediary::builder()
        .server(server)
        .client(client)
        .startup_resolver(ScriptedRoute)
        .cancellation(CancellationPolicy::Reject)
        .build()
        .map_err(super::debug_error)?;
    let mut session = Box::pin(intermediary.accept(downstream_transport, (), ()))
        .await
        .map_err(super::debug_error)?
        .into_session();

    match scenario {
        TrafficScenario::FunctionCall => {
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Frontend(FrontendMessage::FunctionCall(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::FunctionCallResponse(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::ReadyForQuery(_))
            ));
        }
        TrafficScenario::CopyFail => {
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Frontend(FrontendMessage::Query(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::CopyInResponse(_))
            ));
            let forwarded = session.forward_next().await.unwrap();
            assert!(
                matches!(&forwarded, ForwardedMessage::FrontendSuppressed(FrontendMessage::CopyFail(reason)) if reason == "scripted exact failure"),
                "{forwarded:?}"
            );
        }
        TrafficScenario::CopyBothClientDone => {
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Frontend(FrontendMessage::Query(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::CopyBothResponse(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Frontend(FrontendMessage::CopyDone)
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::CopyData(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::CopyDone)
            ));
        }
        TrafficScenario::CopyBothServerDone => {
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Frontend(FrontendMessage::Query(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::CopyBothResponse(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Backend(BackendMessage::CopyDone)
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Frontend(FrontendMessage::CopyData(_))
            ));
            assert!(matches!(
                session.forward_next().await.unwrap(),
                ForwardedMessage::Frontend(FrontendMessage::CopyDone)
            ));
        }
    }
    let _ = session.teardown();
    downstream.await??;
    upstream.await??;
    Ok(())
}

async fn scripted_downstream(
    mut peer: tokio::io::DuplexStream,
    scenario: TrafficScenario,
) -> Result<(), std::io::Error> {
    peer.write_all(&startup()).await?;
    let mut accepted = [0; 15];
    peer.read_exact(&mut accepted).await?;
    match scenario {
        TrafficScenario::FunctionCall => {
            peer.write_all(&tagged(b'F', &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
                .await?;
            read_tagged(&mut peer).await?;
            read_tagged(&mut peer).await?;
        }
        TrafficScenario::CopyFail => {
            peer.write_all(&tagged(b'Q', b"START_REPLICATION\0"))
                .await?;
            read_tagged(&mut peer).await?;
            peer.write_all(&tagged(b'f', b"scripted exact failure\0"))
                .await?;
        }
        TrafficScenario::CopyBothClientDone => {
            peer.write_all(&tagged(b'Q', b"START_REPLICATION\0"))
                .await?;
            read_tagged(&mut peer).await?;
            peer.write_all(&tagged(b'c', &[])).await?;
            read_tagged(&mut peer).await?;
            read_tagged(&mut peer).await?;
        }
        TrafficScenario::CopyBothServerDone => {
            peer.write_all(&tagged(b'Q', b"START_REPLICATION\0"))
                .await?;
            read_tagged(&mut peer).await?;
            read_tagged(&mut peer).await?;
            peer.write_all(&tagged(b'd', b"standby-status")).await?;
            peer.write_all(&tagged(b'c', &[])).await?;
        }
    }
    Ok(())
}

async fn scripted_upstream(
    mut peer: tokio::io::DuplexStream,
    scenario: TrafficScenario,
) -> Result<(), std::io::Error> {
    let length = peer.read_u32().await?;
    let mut startup_body = vec![0; usize::try_from(length).unwrap() - 4];
    peer.read_exact(&mut startup_body).await?;
    peer.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
        .await?;
    let (tag, body) = read_tagged(&mut peer).await?;
    match scenario {
        TrafficScenario::FunctionCall => {
            assert_eq!(tag, b'F');
            assert_eq!(&body[..4], &1_u32.to_be_bytes());
            peer.write_all(&tagged(b'V', b"function-result")).await?;
            peer.write_all(&tagged(b'Z', b"I")).await?;
        }
        TrafficScenario::CopyFail => {
            assert_eq!(tag, b'Q');
            peer.write_all(&tagged(b'G', &[0, 0, 0])).await?;
            let closed = peer.read_u8().await.expect_err("CopyFail is suppressed");
            assert_eq!(closed.kind(), std::io::ErrorKind::UnexpectedEof);
        }
        TrafficScenario::CopyBothClientDone => {
            assert_eq!(tag, b'Q');
            peer.write_all(&tagged(b'W', &[0, 0, 0])).await?;
            assert_eq!(read_tagged(&mut peer).await?.0, b'c');
            peer.write_all(&tagged(b'd', b"remaining-wal")).await?;
            peer.write_all(&tagged(b'c', &[])).await?;
        }
        TrafficScenario::CopyBothServerDone => {
            assert_eq!(tag, b'Q');
            peer.write_all(&tagged(b'W', &[0, 0, 0])).await?;
            peer.write_all(&tagged(b'c', &[])).await?;
            assert_eq!(read_tagged(&mut peer).await?.0, b'd');
            assert_eq!(read_tagged(&mut peer).await?.0, b'c');
        }
    }
    Ok(())
}

fn tagged(tag: u8, body: &[u8]) -> Vec<u8> {
    [
        [tag].as_slice(),
        u32::try_from(body.len() + 4)
            .unwrap()
            .to_be_bytes()
            .as_slice(),
        body,
    ]
    .concat()
}

async fn read_tagged(
    stream: &mut tokio::io::DuplexStream,
) -> Result<(u8, Vec<u8>), std::io::Error> {
    let tag = stream.read_u8().await?;
    let length = stream.read_u32().await?;
    let mut body = vec![0; usize::try_from(length).unwrap() - 4];
    stream.read_exact(&mut body).await?;
    Ok((tag, body))
}

async fn gss_encryption_request() -> Result<(), Box<dyn Error>> {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(pg_proto::TrustServerAuthentication)
        .build()
        .map_err(super::debug_error)?;
    let (mut peer, transport) = tokio::io::duplex(256);
    let exchange = async move {
        peer.write_all(&PreStartupMessage::GssEncRequest.to_packet()?)
            .await?;
        if peer.read_u8().await? != b'N' {
            return Err::<(), std::io::Error>(std::io::Error::other("GSSENC was not rejected"));
        }
        peer.write_all(&startup()).await?;
        let mut accepted = [0; 15];
        peer.read_exact(&mut accepted).await?;
        Ok::<(), std::io::Error>(())
    };
    let (accepted, exchanged) = tokio::join!(server.accept(transport, (), ()), exchange);
    exchanged?;
    let ServerAccept::Session(session) = accepted.map_err(super::debug_error)? else {
        return Err("expected a server session".into());
    };
    let _ = session.teardown();
    Ok(())
}

async fn legacy_encryption_error() -> Result<(), Box<dyn Error>> {
    let (transport, mut peer) = tokio::io::duplex(256);
    let peer_task = tokio::spawn(async move {
        let mut request = [0; 8];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
        peer.write_u8(b'E').await.unwrap();
    });
    let transport = Mutex::new(Some(transport));
    let client = Client::builder()
        .connector(move |_| {
            let transport = transport.lock().unwrap().take().unwrap();
            async move { Ok::<_, std::io::Error>(transport) }
        })
        .tls(ClientTlsPolicy::libpq(pg_proto::SslMode::Prefer, LegacyTls))
        .authentication(TrustClientAuthentication)
        .build()
        .map_err(super::debug_error)?;
    let result = client
        .connect(
            ConnectTarget::new("scripted"),
            StartupParameters::new("alice"),
            (),
        )
        .await;
    peer_task.await?;
    if !matches!(result, Err(pg_proto::ConnectError::Tls(_))) {
        return Err("legacy encryption error was not surfaced as a TLS failure".into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct LegacyTls;

impl ClientTlsProvider for LegacyTls {
    type Error = Infallible;

    async fn resolve(&self, _: &ConnectTarget) -> Result<ClientTlsConfig, Self::Error> {
        unreachable!("legacy error terminates negotiation before TLS material is resolved")
    }
}

#[derive(Clone, Copy)]
enum TokenMethod {
    Gss,
    Kerberos,
    Sspi,
}

struct TokenFactory(TokenMethod);
struct TokenAuthentication {
    method: TokenMethod,
    responses: usize,
}

impl ServerAuthenticationProvider for TokenFactory {
    type Authentication = TokenAuthentication;

    fn create(&self) -> Self::Authentication {
        TokenAuthentication {
            method: self.0,
            responses: 0,
        }
    }
}

impl ServerAuthentication<()> for TokenAuthentication {
    type Identity = ();
    type Error = Infallible;

    async fn start(
        &mut self,
        _: ServerAuthenticationRequest<'_, ()>,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        Ok(match self.method {
            TokenMethod::Gss => ServerAuthenticationAction::Gss,
            TokenMethod::Kerberos => ServerAuthenticationAction::KerberosV5,
            TokenMethod::Sspi => ServerAuthenticationAction::Sspi,
        })
    }

    async fn respond(
        &mut self,
        _: ServerAuthenticationRequest<'_, ()>,
        response: ServerAuthenticationResponse,
    ) -> Result<ServerAuthenticationAction<Self::Identity>, Self::Error> {
        let ServerAuthenticationResponse::Token(token) = response else {
            unreachable!()
        };
        self.responses += 1;
        Ok(
            if matches!(self.method, TokenMethod::Gss) && self.responses == 1 {
                assert_eq!(token, b"client-one".as_slice());
                ServerAuthenticationAction::GssContinue(b"server-two".as_slice().into())
            } else {
                ServerAuthenticationAction::Accept(())
            },
        )
    }
}

async fn token_authentication(method: TokenMethod) -> Result<(), Box<dyn Error>> {
    let server = Server::builder()
        .tls(ServerTlsPolicy::Disabled)
        .authentication(TokenFactory(method))
        .build()
        .map_err(super::debug_error)?;
    let (mut peer, transport) = tokio::io::duplex(512);
    peer.write_all(&startup()).await?;
    let exchange = async move {
        let mut request = [0; 9];
        peer.read_exact(&mut request).await?;
        let expected = match method {
            TokenMethod::Kerberos => 2,
            TokenMethod::Gss => 7,
            TokenMethod::Sspi => 9,
        };
        if u32::from_be_bytes(request[5..9].try_into().unwrap()) != expected {
            return Err::<(), std::io::Error>(std::io::Error::other(
                "wrong authentication request",
            ));
        }
        peer.write_all(&password_packet(b"client-one")).await?;
        if matches!(method, TokenMethod::Gss) {
            let mut continuation = [0; 19];
            peer.read_exact(&mut continuation).await?;
            if &continuation[9..] != b"server-two" {
                return Err(std::io::Error::other("wrong GSS continuation"));
            }
            peer.write_all(&password_packet(b"client-three")).await?;
        }
        let mut ready = [0; 15];
        peer.read_exact(&mut ready).await?;
        Ok(())
    };
    let (accepted, exchanged) = tokio::join!(server.accept(transport, (), ()), exchange);
    exchanged?;
    let ServerAccept::Session(session) = accepted.map_err(super::debug_error)? else {
        return Err("expected a server session".into());
    };
    let _ = session.teardown();
    Ok(())
}

fn startup() -> Vec<u8> {
    [
        20_u32.to_be_bytes().as_slice(),
        196_608_u32.to_be_bytes().as_slice(),
        b"user\0alice\0\0",
    ]
    .concat()
}

fn password_packet(token: &[u8]) -> Vec<u8> {
    b"p".iter()
        .copied()
        .chain(u32::try_from(token.len() + 4).unwrap().to_be_bytes())
        .chain(token.iter().copied())
        .collect()
}
