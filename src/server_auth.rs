//! Server-role authentication typestates for proxy-side client termination.

use std::io;

use bytes::{Buf, Bytes};

use crate::{
    Conn,
    auth::Ready,
    codec::{
        Authentication, BackendMessage, DiagnosticResponse, Frame, FrontendMessage,
        NegotiateProtocolVersion, TransactionStatus,
    },
    grammar::server_authentication as auth_grammar,
    pre_startup::{Startup, Terminated},
    startup::{ProtocolVersion, StartupMessage},
};

#[derive(Debug)]
/// The proxy is selecting how to authenticate its client.
pub enum ServerAuth {}

#[derive(Debug)]
/// The client's startup protocol version is supported.
pub enum ServerStartupValidated {}

#[derive(Debug)]
/// The client's startup protocol version must be rejected.
pub enum ServerStartupRejected {}

#[derive(Debug)]
/// A password response is expected from the client.
pub enum ServerPassword {}

#[derive(Debug)]
/// A SASL initial response is expected from the client.
pub enum ServerSaslInitial {}

#[derive(Debug)]
/// A recursive SASL response exchange is in progress.
pub enum ServerSasl {}

#[derive(Debug)]
/// A GSS, SSPI, or Kerberos response token is expected.
pub enum ServerAuthResponse {}

#[derive(Debug)]
/// Authentication succeeded and startup metadata may be sent before readiness.
pub enum ServerStartupReady {}

/// Result of validating a client's requested protocol version.
#[derive(Debug)]
pub enum ServerProtocolOffer<S, C> {
    /// The major version is supported, with optional minor-version negotiation.
    Supported {
        /// Connection authorised to begin authentication.
        conn: Conn<S, ServerStartupValidated, C>,
        /// Inspected startup message.
        message: StartupMessage,
        /// Highest supported version to advertise when the requested minor is newer.
        negotiate_to: Option<ProtocolVersion>,
    },
    /// The major protocol version is unsupported.
    Rejected {
        /// Connection authorised only to send an error and terminate.
        conn: Conn<S, ServerStartupRejected, C>,
        /// Rejected startup message.
        message: StartupMessage,
    },
}

/// A decoded SASL initial response selected by the client.
#[derive(Clone, Eq, PartialEq)]
pub struct SaslInitialResponse {
    /// SASL mechanism selected by the client.
    pub mechanism: Bytes,
    /// Optional mechanism-specific initial response.
    pub response: Option<Bytes>,
}

impl std::fmt::Debug for SaslInitialResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SaslInitialResponse")
            .field("mechanism", &self.mechanism)
            .field("response", &self.response.as_ref().map(Bytes::len))
            .finish()
    }
}

/// A rejected frontend message paired with the unchanged authentication state.
pub type ServerProjection<T, S, Phase, C> = Result<T, Box<(Conn<S, Phase, C>, FrontendMessage)>>;

/// Projection of a valid password body or the unchanged server-password state.
pub type PasswordProjection<S, C> =
    ServerProjection<(Conn<S, ServerAuth, C>, Bytes), S, ServerPassword, C>;

/// Projection of a valid SASL initial response or the unchanged initial state.
pub type SaslInitialProjection<S, C> =
    ServerProjection<(Conn<S, ServerSasl, C>, SaslInitialResponse), S, ServerSaslInitial, C>;

impl<S, C> Conn<S, Startup, C> {
    /// Validates the startup protocol before authentication can begin.
    pub fn validate_protocol(
        self,
        message: StartupMessage,
        newest: ProtocolVersion,
    ) -> ServerProtocolOffer<S, C> {
        if message.version.major == newest.major {
            let negotiate_to = (message.version.minor > newest.minor).then_some(newest);
            ServerProtocolOffer::Supported {
                conn: self.transition(),
                message,
                negotiate_to,
            }
        } else {
            ServerProtocolOffer::Rejected {
                conn: self.transition(),
                message,
            }
        }
    }
}

impl<S, C> Conn<S, ServerStartupValidated, C> {
    /// Begins proxy-side authentication of a protocol-compatible client.
    pub fn begin_server_auth(self) -> Conn<S, ServerAuth, C> {
        self.transition()
    }
}

impl<S, C> Conn<S, ServerStartupRejected, C> {
    /// Rejects an unsupported major protocol version and terminates the session.
    ///
    /// # Errors
    ///
    /// Returns an error if a diagnostic field is invalid.
    pub fn error(
        self,
        response: DiagnosticResponse,
    ) -> io::Result<(Conn<S, Terminated, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::ErrorResponse(response).to_frame()?,
        ))
    }
}

impl<S, C> Conn<S, ServerAuth, C> {
    /// Requests a cleartext password from the client.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed authentication message cannot be encoded.
    pub fn request_cleartext(self) -> io::Result<(Conn<S, ServerPassword, C>, Frame)> {
        Ok((
            self.transition(),
            authentication_frame(Authentication::CleartextPassword)?,
        ))
    }

    /// Requests a `PostgreSQL` MD5 password response from the client.
    ///
    /// # Errors
    ///
    /// Returns an error only if the authentication message cannot be encoded.
    pub fn request_md5(self, salt: [u8; 4]) -> io::Result<(Conn<S, ServerPassword, C>, Frame)> {
        Ok((
            self.transition(),
            authentication_frame(Authentication::Md5Password { salt })?,
        ))
    }

    /// Offers one or more SASL mechanisms to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if a mechanism contains a NUL byte.
    pub fn request_sasl(
        self,
        mechanisms: Vec<Bytes>,
    ) -> io::Result<(Conn<S, ServerSaslInitial, C>, Frame)> {
        Ok((
            self.transition(),
            authentication_frame(Authentication::Sasl { mechanisms })?,
        ))
    }

    /// Requests Kerberos V5 authentication.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed authentication message cannot be encoded.
    pub fn request_kerberos_v5(self) -> io::Result<(Conn<S, ServerAuthResponse, C>, Frame)> {
        Ok((
            self.transition(),
            authentication_frame(Authentication::KerberosV5)?,
        ))
    }

    /// Requests GSSAPI authentication.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed authentication message cannot be encoded.
    pub fn request_gss(self) -> io::Result<(Conn<S, ServerAuthResponse, C>, Frame)> {
        Ok((
            self.transition(),
            authentication_frame(Authentication::Gss)?,
        ))
    }

    /// Requests SSPI authentication.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed authentication message cannot be encoded.
    pub fn request_sspi(self) -> io::Result<(Conn<S, ServerAuthResponse, C>, Frame)> {
        Ok((
            self.transition(),
            authentication_frame(Authentication::Sspi)?,
        ))
    }

    /// Confirms authentication and enters the startup-completion phase.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed authentication message cannot be encoded.
    pub fn authentication_ok(self) -> io::Result<(Conn<S, ServerStartupReady, C>, Frame)> {
        Ok((self.transition(), authentication_frame(Authentication::Ok)?))
    }
}

impl<S, C> Conn<S, ServerPassword, C> {
    /// Projects the inspected password response and returns to policy evaluation.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not a valid password response.
    pub fn receive_password(self, message: FrontendMessage) -> PasswordProjection<S, C> {
        match (
            auth_grammar::project_external(auth_grammar::RuntimeState::PasswordResponse, &message),
            message,
        ) {
            (Some(auth_grammar::Event::Response), FrontendMessage::PasswordResponse(body)) => {
                match password_body(body) {
                    Ok(password) => Ok((self.transition(), password)),
                    Err(body) => Err(Box::new((self, FrontendMessage::PasswordResponse(body)))),
                }
            }
            (_, other) => Err(Box::new((self, other))),
        }
    }
}

impl<S, C> Conn<S, ServerSaslInitial, C> {
    /// Projects the client's selected SASL mechanism and initial response.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if the SASL initial response is malformed.
    pub fn receive_initial(self, message: FrontendMessage) -> SaslInitialProjection<S, C> {
        match (
            auth_grammar::project_external(auth_grammar::RuntimeState::SaslInitial, &message),
            message,
        ) {
            (Some(auth_grammar::Event::Initial), FrontendMessage::PasswordResponse(body)) => {
                match sasl_initial(body) {
                    Ok(initial) => Ok((self.transition(), initial)),
                    Err(body) => Err(Box::new((self, FrontendMessage::PasswordResponse(body)))),
                }
            }
            (_, other) => Err(Box::new((self, other))),
        }
    }
}

impl<S, C> Conn<S, ServerSasl, C> {
    /// Projects one client SASL response and remains in the recursive exchange.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not a SASL response.
    pub fn receive_response(
        self,
        message: FrontendMessage,
    ) -> ServerProjection<(Self, Bytes), S, ServerSasl, C> {
        match (
            auth_grammar::project_external(auth_grammar::RuntimeState::SaslResponse, &message),
            message,
        ) {
            (Some(auth_grammar::Event::Response), FrontendMessage::PasswordResponse(response)) => {
                Ok((self, response))
            }
            (_, other) => Err(Box::new((self, other))),
        }
    }

    /// Sends a SASL challenge and remains in the recursive exchange.
    ///
    /// # Errors
    ///
    /// Returns an error only if the authentication message cannot be encoded.
    pub fn continue_with(self, challenge: Bytes) -> io::Result<(Self, Frame)> {
        Ok((
            self,
            authentication_frame(Authentication::SaslContinue(challenge))?,
        ))
    }

    /// Sends verified server-final data and returns to authentication completion.
    ///
    /// # Errors
    ///
    /// Returns an error only if the authentication message cannot be encoded.
    pub fn finish(self, server_final: Bytes) -> io::Result<(Conn<S, ServerAuth, C>, Frame)> {
        Ok((
            self.transition(),
            authentication_frame(Authentication::SaslFinal(server_final))?,
        ))
    }
}

impl<S, C> Conn<S, ServerAuthResponse, C> {
    /// Projects one GSS, SSPI, or Kerberos response token.
    ///
    /// # Errors
    ///
    /// Returns the unchanged state and message if it is not an authentication token.
    pub fn receive_response(
        self,
        message: FrontendMessage,
    ) -> ServerProjection<(Self, Bytes), S, ServerAuthResponse, C> {
        match (
            auth_grammar::project_external(auth_grammar::RuntimeState::TokenResponse, &message),
            message,
        ) {
            (Some(auth_grammar::Event::Response), FrontendMessage::PasswordResponse(response)) => {
                Ok((self, response))
            }
            (_, other) => Err(Box::new((self, other))),
        }
    }

    /// Sends a GSS continuation token and remains in the authentication exchange.
    ///
    /// # Errors
    ///
    /// Returns an error only if the authentication message cannot be encoded.
    pub fn continue_gss(self, token: Bytes) -> io::Result<(Self, Frame)> {
        Ok((
            self,
            authentication_frame(Authentication::GssContinue(token))?,
        ))
    }

    /// Returns to policy evaluation after the mechanism verifies its response.
    pub fn verified(self) -> Conn<S, ServerAuth, C> {
        self.transition()
    }
}

impl<S, C> Conn<S, ServerStartupReady, C> {
    /// Emits a startup parameter while remaining before `ReadyForQuery`.
    ///
    /// # Errors
    ///
    /// Returns an error if either value contains a NUL byte.
    pub fn parameter_status(self, name: Bytes, value: Bytes) -> io::Result<(Self, Frame)> {
        Ok((
            self,
            BackendMessage::ParameterStatus { name, value }.to_frame()?,
        ))
    }

    /// Emits the proxy-minted cancellation key exposed to this client.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is outside the protocol's 4–256 byte range.
    pub fn backend_key_data(self, process_id: u32, secret_key: Bytes) -> io::Result<(Self, Frame)> {
        if !(4..=256).contains(&secret_key.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cancellation key length is outside 4..=256",
            ));
        }
        Ok((
            self,
            BackendMessage::BackendKeyData {
                process_id,
                secret_key,
            }
            .to_frame()?,
        ))
    }

    /// Responds to unsupported protocol 3.1/3.2 startup options.
    ///
    /// # Errors
    ///
    /// Returns an error if an option name contains a NUL byte or counts overflow.
    pub fn negotiate_protocol(
        self,
        newest: ProtocolVersion,
        unsupported_options: Vec<Bytes>,
    ) -> io::Result<(Self, Frame)> {
        Ok((
            self,
            BackendMessage::NegotiateProtocolVersion(NegotiateProtocolVersion {
                newest,
                unsupported_options,
            })
            .to_frame()?,
        ))
    }

    /// Completes startup with an idle `ReadyForQuery`.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed message cannot be encoded.
    pub fn ready(self) -> io::Result<(Conn<S, Ready, C>, Frame)> {
        Ok((
            self.transition(),
            BackendMessage::ReadyForQuery(TransactionStatus::Idle).to_frame()?,
        ))
    }
}

fn authentication_frame(authentication: Authentication) -> io::Result<Frame> {
    BackendMessage::Authentication(authentication).to_frame()
}

fn password_body(body: Bytes) -> Result<Bytes, Bytes> {
    if body.last() == Some(&0) && !body[..body.len() - 1].contains(&0) {
        Ok(body.slice(..body.len() - 1))
    } else {
        Err(body)
    }
}

fn sasl_initial(mut body: Bytes) -> Result<SaslInitialResponse, Bytes> {
    let original = body.clone();
    let Some(nul) = body.iter().position(|byte| *byte == 0) else {
        return Err(original);
    };
    let mechanism = body.split_to(nul);
    body.advance(1);
    if body.len() < 4 {
        return Err(original);
    }
    let length = body.get_i32();
    if length == -1 && body.is_empty() {
        return Ok(SaslInitialResponse {
            mechanism,
            response: None,
        });
    }
    let Ok(length) = usize::try_from(length) else {
        return Err(original);
    };
    if body.len() != length {
        return Err(original);
    }
    Ok(SaslInitialResponse {
        mechanism,
        response: Some(body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Pristine,
        grammar::server_authentication,
        middleware::{Identity, Middleware, ServerRole, TypedBackendMessage},
        scram::{SCRAM_SHA_256, ScramServer, ServerChannelBinding},
    };
    use bytes::{BufMut as _, BytesMut};
    use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
    use std::collections::BTreeMap;

    fn validated_startup() -> Conn<(), ServerStartupValidated, Pristine> {
        let startup: Conn<(), Startup, Pristine> = Conn::new(()).transition();
        let message = StartupMessage {
            version: ProtocolVersion::V3_2,
            parameters: BTreeMap::new(),
        };
        let ServerProtocolOffer::Supported { conn, .. } =
            startup.validate_protocol(message, ProtocolVersion::V3_2)
        else {
            panic!("supported protocol was rejected")
        };
        conn
    }

    #[test]
    fn cleartext_response_returns_to_independent_policy_choice() {
        let (password, request) = validated_startup()
            .begin_server_auth()
            .request_cleartext()
            .unwrap();
        assert_eq!(
            request,
            authentication_frame(Authentication::CleartextPassword).unwrap()
        );

        let (auth, response) = password
            .receive_password(FrontendMessage::PasswordResponse(Bytes::from_static(
                b"secret\0",
            )))
            .unwrap();
        assert_eq!(response, Bytes::from_static(b"secret"));
        let (ready, ok) = auth.authentication_ok().unwrap();
        assert_eq!(ok, authentication_frame(Authentication::Ok).unwrap());
        ready.into_transport();
    }

    #[tokio::test]
    async fn server_outbound_middleware_includes_asynchronous_messages() {
        let conn = validated_startup().begin_server_auth();
        let message = TypedBackendMessage::<server_authentication::AuthInternalMessage>::try_from(
            BackendMessage::NoticeResponse(DiagnosticResponse { fields: vec![] }),
        )
        .expect("NoticeResponse is legal without advancing authentication");
        let mut middleware = Middleware::new((), Identity);

        let output = conn
            .intercept_outbound_typed::<ServerRole, BackendMessage, _, _>(&mut middleware, message)
            .await
            .expect("asynchronous server traffic remains phase legal");

        assert!(matches!(output, TypedBackendMessage::Asynchronous(_)));
        conn.into_transport();
    }

    #[test]
    fn sasl_is_a_recursive_server_sub_session() {
        let (initial, _) = validated_startup()
            .begin_server_auth()
            .request_sasl(vec![Bytes::from_static(b"SCRAM-SHA-256")])
            .unwrap();
        let body = Bytes::from_static(b"SCRAM-SHA-256\0\0\0\0\x03one");
        let (sasl, initial) = initial
            .receive_initial(FrontendMessage::PasswordResponse(body))
            .unwrap();
        assert_eq!(initial.response, Some(Bytes::from_static(b"one")));
        let (sasl, _) = sasl
            .continue_with(Bytes::from_static(b"challenge"))
            .unwrap();
        let (sasl, response) = sasl
            .receive_response(FrontendMessage::PasswordResponse(Bytes::from_static(
                b"two",
            )))
            .unwrap();
        assert_eq!(response, Bytes::from_static(b"two"));
        let (auth, _) = sasl.finish(Bytes::from_static(b"verified")).unwrap();
        auth.into_transport();
    }

    #[test]
    fn startup_completion_mints_keys_and_requires_ready() {
        let (startup_ready, _) = validated_startup()
            .begin_server_auth()
            .authentication_ok()
            .unwrap();
        let (startup_ready, parameter) = startup_ready
            .parameter_status(
                Bytes::from_static(b"server_version"),
                Bytes::from_static(b"18"),
            )
            .unwrap();
        assert_eq!(parameter.tag, b'S');
        let (startup_ready, key) = startup_ready
            .backend_key_data(42, Bytes::from_static(b"secret-key"))
            .unwrap();
        assert_eq!(key.tag, b'K');
        let (ready, frame) = startup_ready.ready().unwrap();
        assert_eq!(frame.body, Bytes::from_static(b"I"));
        ready.into_transport();
    }

    #[test]
    fn protocol_validation_negotiates_minor_and_rejects_major() {
        let startup: Conn<(), Startup> = Conn::new(()).transition();
        let message = StartupMessage {
            version: ProtocolVersion { major: 3, minor: 9 },
            parameters: BTreeMap::new(),
        };
        let ServerProtocolOffer::Supported {
            conn, negotiate_to, ..
        } = startup.validate_protocol(message, ProtocolVersion::V3_2)
        else {
            panic!("compatible major was rejected")
        };
        assert_eq!(negotiate_to, Some(ProtocolVersion::V3_2));
        conn.into_transport();

        let startup: Conn<(), Startup> = Conn::new(()).transition();
        let message = StartupMessage {
            version: ProtocolVersion { major: 4, minor: 0 },
            parameters: BTreeMap::new(),
        };
        let ServerProtocolOffer::Rejected { conn, .. } =
            startup.validate_protocol(message, ProtocolVersion::V3_2)
        else {
            panic!("unsupported major was accepted")
        };
        conn.into_transport();
    }

    #[test]
    fn scram_server_engine_completes_the_typed_authentication_session() {
        use crate::grammar::server_authentication::{Event, RuntimeFsm, RuntimeState};

        let mut generated = RuntimeFsm::new();
        generated.step(Event::Begin).unwrap();
        let (initial_state, offer_frame) = validated_startup()
            .begin_server_auth()
            .request_sasl(vec![Bytes::from_static(SCRAM_SHA_256)])
            .unwrap();
        generated.step(Event::Sasl).unwrap();
        assert_eq!(offer_frame.tag, b'R');

        let mut client = ScramSha256::new(b"secret", ChannelBinding::unsupported());
        let mut initial_body = BytesMut::new();
        initial_body.extend_from_slice(SCRAM_SHA_256);
        initial_body.put_u8(0);
        initial_body.put_i32(i32::try_from(client.message().len()).unwrap());
        initial_body.extend_from_slice(client.message());
        let (sasl, initial) = initial_state
            .receive_initial(FrontendMessage::PasswordResponse(initial_body.freeze()))
            .unwrap();
        generated.step(Event::Initial).unwrap();

        let verifier = ScramServer::with_parameters(
            b"secret",
            b"fixed test salt".to_vec(),
            crate::scram::DEFAULT_ITERATIONS,
            ServerChannelBinding::None,
        )
        .unwrap();
        let (exchange, challenge) = verifier
            .start(&initial.mechanism, initial.response.as_deref().unwrap())
            .unwrap();
        let (sasl, challenge_frame) = sasl.continue_with(challenge.clone()).unwrap();
        generated.step(Event::Continue).unwrap();
        assert_eq!(challenge_frame.tag, b'R');
        client.update(&challenge).unwrap();

        let (sasl, response) = sasl
            .receive_response(FrontendMessage::PasswordResponse(Bytes::copy_from_slice(
                client.message(),
            )))
            .unwrap();
        generated.step(Event::Response).unwrap();
        let server_final = exchange.finish(&response).unwrap();
        client.finish(&server_final).unwrap();
        let (auth, final_frame) = sasl.finish(server_final).unwrap();
        generated.step(Event::Final).unwrap();
        assert_eq!(final_frame.tag, b'R');
        let (startup_ready, ok) = auth.authentication_ok().unwrap();
        generated.step(Event::Ok).unwrap();
        assert_eq!(ok.tag, b'R');
        assert_eq!(generated.state(), RuntimeState::StartupReady);
        startup_ready.into_transport();
    }
}
