#![doc = include_str!("../README.md")]
#![allow(
    clippy::doc_markdown,
    clippy::enum_variant_names,
    clippy::redundant_pub_crate
)]
#![deny(private_bounds, private_interfaces, unreachable_pub)]

#[allow(dead_code)]
mod auth;
mod backend_hold;
#[allow(dead_code)]
mod cancel;
#[allow(dead_code)]
mod cleanliness;
mod client_component;
#[allow(dead_code)]
mod codec;
#[allow(dead_code)]
mod credentials;
#[allow(dead_code)]
mod demux;
#[allow(dead_code)]
mod erased;
#[allow(dead_code)]
pub mod grammar;
#[allow(dead_code)]
mod integrations;
#[allow(dead_code)]
mod intermediary;
mod intermediary_component;
#[allow(dead_code)]
mod middleware;
#[allow(dead_code)]
mod net;
#[allow(dead_code)]
mod pipeline;
#[allow(dead_code)]
mod pre_startup;
#[allow(dead_code)]
mod replication;
#[allow(dead_code)]
mod resources;
mod runtime_middleware;
#[allow(dead_code)]
mod scram;
#[allow(dead_code)]
mod server_auth;
mod server_component;
#[allow(dead_code)]
mod server_session;
#[allow(dead_code)]
mod session;
#[allow(dead_code)]
mod startup;
#[allow(dead_code)]
mod tls;
#[allow(dead_code)]
mod transport;

pub use client_component::{
    BuildError, CancelError, Client, ClientAuthentication, ClientAuthenticationChallenge,
    ClientAuthenticationError, ClientAuthenticationResponse, ClientAuthenticationSession,
    ClientBuilder, ClientConnection, ClientConnectionContext, ClientInitialContext,
    ClientTlsConfig, ClientTlsConfiguration, ClientTlsError, ClientTlsPolicy, ClientTlsProvider,
    ClientTlsStatus, ClientTransport, ConnectError, ConnectTarget, ConnectionChanged,
    ConnectionClean, IdentityHandler, ProtocolLimitError, ProtocolLimits, QueryError,
    ReloadableClientTls, StartupParameterError, StartupParameters, StaticClientCredentialSession,
    StaticClientCredentials, StaticCredentialError, TrustClientAuthentication,
};
pub use codec::{
    Authentication, BackendMessage, Bind, Close, CopyResponse, DataRow, Describe, DescribeTarget,
    DiagnosticField, DiagnosticResponse, Execute, FieldDescription, FrontendMessage, FunctionCall,
    NegotiateProtocolVersion, Parse, RowDescription, TransactionStatus,
};
pub use demux::CancelKey;
pub use intermediary_component::{
    AllowAuthenticatedRoute, AttributedBackendMessages, AuthenticatedRouteContext,
    AuthenticatedRoutePolicy, BackendBatchForwarding, BackendBatchOutput,
    BackendBatchProjectionError, BackendFlushReason, BackendForwarding, BackendHoldConfigError,
    BackendHoldLimits, BackendMiddlewareOutput, CancellationPolicy, CancellationRoute,
    EstablishmentFailurePolicy, ForwardError, ForwardedMessage, FrontendForwarding,
    FrontendMiddlewareOutput, HeldBackendMessages, IdentityIntermediaryMiddleware,
    InMemoryCancellationRegistry, InMemoryCancellationRegistryError, InitialServerContext,
    Intermediary, IntermediaryAccept, IntermediaryAcceptError, IntermediaryBuildError,
    IntermediaryBuilder, IntermediaryCancellationRegistry, IntermediaryConnection,
    IntermediaryContexts, IntermediaryMiddleware, IntermediaryMiddlewareFactory,
    RejectCancellation, StartupResolutionError, StartupRouteResolver,
};
pub use pipeline::{
    BackendProjectionError, BoundedPipeline, FrontendProjectionError, NoPipeline, OperationId,
    PipelineConfigError, PipelinePolicy,
};
pub use pre_startup::{CertificateVerification, PreStartupMessage, SslMode, SslStrategy};
pub use runtime_middleware::{
    ClientMiddleware, IdentityMiddleware, MiddlewareChain, MiddlewareFactory, ServerMiddleware,
};
pub use server_component::{
    AcceptError, AcceptedServerTransport, BuildServerError, CancellationRequest, DisabledServerTls,
    IdentityServerHandler, NegotiatedServerTls, NoServerIdentity, NoServerIdentityProvider,
    OptionalServerTls, RequiredServerTls, Server, ServerAccept, ServerAcceptFuture,
    ServerAuthentication, ServerAuthenticationAction, ServerAuthenticationProvider,
    ServerAuthenticationRequest, ServerAuthenticationResponse, ServerBuilder, ServerCancellation,
    ServerConnection, ServerConnectionContext, ServerIdentity, ServerIdentityProvider,
    ServerProtocolLimits, ServerTlsConfiguration, ServerTlsPolicy,
    StaticMd5ServerCredentialSession, StaticMd5ServerCredentials, TrustIdentity,
    TrustServerAuthentication,
};
pub use startup::{ProtocolVersion, StartupMessage};

#[cfg(test)]
extern crate self as pg_proto;

#[cfg(test)]
mod internal_tests;

use std::marker::PhantomData;

/// A connection whose legal operations are selected by `Phase` and `Cleanliness`.
#[must_use = "dropping a connection abandons the PostgreSQL session"]
#[derive(Debug)]
pub(crate) struct Conn<Transport, Phase, Cleanliness = Pristine> {
    transport: Option<Transport>,
    _state: PhantomData<(Phase, Cleanliness)>,
}

impl<Transport, Phase, Cleanliness> Conn<Transport, Phase, Cleanliness> {
    pub(crate) fn transition<NextPhase, NextCleanliness>(
        mut self,
    ) -> Conn<Transport, NextPhase, NextCleanliness> {
        Conn {
            transport: self.transport.take(),
            _state: PhantomData,
        }
    }

    /// Returns the underlying transport when deliberately leaving the typed API.
    ///
    /// # Panics
    ///
    /// Panics only if an internal transition has already moved the transport.
    pub(crate) fn into_transport(mut self) -> Transport {
        self.transport
            .take()
            .expect("live connection has a transport")
    }

    /// Changes transport representation without changing either state index.
    ///
    /// # Panics
    ///
    /// Panics only if an internal transition has already moved the transport.
    pub(crate) fn map_transport<Next>(
        mut self,
        map: impl FnOnce(Transport) -> Next,
    ) -> Conn<Next, Phase, Cleanliness> {
        Conn {
            transport: Some(map(self
                .transport
                .take()
                .expect("live connection has a transport"))),
            _state: PhantomData,
        }
    }

    pub(crate) const fn transport(&self) -> &Transport {
        match &self.transport {
            Some(transport) => transport,
            None => panic!("connection transport has already moved"),
        }
    }

    pub(crate) const fn transport_mut(&mut self) -> &mut Transport {
        match &mut self.transport {
            Some(transport) => transport,
            None => panic!("connection transport has already moved"),
        }
    }
}

impl<Transport> Conn<Transport, pre_startup::PreStartup, Pristine> {
    /// Starts a new connection before any startup packet has been sent.
    pub(crate) const fn new(transport: Transport) -> Self {
        Self {
            transport: Some(transport),
            _state: PhantomData,
        }
    }
}

#[cfg(debug_assertions)]
impl<Transport, Phase, Cleanliness> Drop for Conn<Transport, Phase, Cleanliness> {
    fn drop(&mut self) {
        assert!(
            self.transport.is_none() || std::thread::panicking(),
            "live PostgreSQL connection dropped before a terminal transition; call into_transport() to abort deliberately"
        );
    }
}

/// The connection has no known session-local changes.
#[derive(Debug)]
pub(crate) enum Pristine {}

/// The connection has state which prevents unconditional pool release.
#[derive(Debug)]
pub(crate) enum Dirty {}
