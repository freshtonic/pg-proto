//! Authentication typestates, including the recursive SASL sub-session.

use bytes::{BufMut, Bytes, BytesMut};

use crate::demux::SessionItem;
use crate::{
    Conn, Pristine, codec,
    grammar::authentication as auth_grammar,
    pre_startup::{Startup, Terminated},
};

#[derive(Debug)]
/// The backend's initial authentication choice.
pub enum Auth {}

#[derive(Debug)]
/// A cleartext or MD5 password response is required.
pub enum PasswordResponse {}

#[derive(Debug)]
/// A SASL mechanism and optional initial response must be selected.
pub enum SaslInitial {}

#[derive(Debug)]
/// The backend must provide the next SASL continuation or final message.
pub enum Sasl {}

#[derive(Debug)]
/// A client response to a SASL challenge is required.
pub enum SaslChallenge {}

#[derive(Debug)]
/// The received SASL final message must be verified by authentication policy.
pub enum SaslFinal {}

#[derive(Debug)]
/// A client token for GSS, SSPI, or Kerberos authentication is required.
pub enum TokenResponse {}

#[derive(Debug)]
/// The backend must continue or complete token-based authentication.
pub enum TokenChallenge {}

#[derive(Debug)]
/// The selected mechanism has completed and `AuthenticationOk` is required.
pub enum AwaitingAuthOk {}

#[derive(Debug)]
/// Authentication and startup have completed and commands may be issued.
pub enum Ready {}

#[derive(Debug)]
/// Authentication succeeded and startup messages are being consumed until ready.
pub enum AwaitingStartupReady {}

/// TLS transports expose the RFC 5929 `tls-server-end-point` binding.
pub trait TlsServerEndPoint {
    /// Returns the RFC 5929 channel-binding bytes derived from the peer certificate.
    fn tls_server_end_point(&self) -> &[u8];
}

impl<S: TlsServerEndPoint, Phase, Cleanliness> Conn<S, Phase, Cleanliness> {
    /// Returns the peer-certificate binding for custom authentication policy.
    #[must_use]
    pub fn tls_server_end_point(&self) -> &[u8] {
        self.transport().tls_server_end_point()
    }
}

/// External choice offered by the backend during authentication.
#[derive(Debug)]
pub enum AuthOffer<S> {
    /// Authentication completed without a credential exchange.
    Ok(Conn<S, AwaitingStartupReady>),
    /// The backend requested a cleartext password.
    Cleartext(Conn<S, PasswordResponse>),
    /// The backend requested a `PostgreSQL` MD5 password response.
    Md5 {
        /// Connection waiting for the password response.
        conn: Conn<S, PasswordResponse>,
        /// Four-byte salt supplied by the backend.
        salt: [u8; 4],
    },
    /// The backend offered a SASL mechanism negotiation.
    Sasl {
        /// Connection waiting for mechanism selection.
        conn: Conn<S, SaslInitial>,
        /// Mechanism names offered in backend preference order.
        mechanisms: Vec<Bytes>,
    },
    /// The backend requested GSSAPI authentication.
    Gss(Conn<S, TokenResponse>),
    /// The backend requested SSPI authentication.
    Sspi(Conn<S, TokenResponse>),
    /// The backend requested Kerberos V5 authentication.
    KerberosV5(Conn<S, TokenResponse>),
}

/// A startup message that advances or terminates authentication.
#[derive(Debug)]
pub enum AuthEvent<S> {
    /// An authentication request or successful completion.
    Authentication(AuthOffer<S>),
    /// A protocol-version negotiation message that leaves authentication active.
    Negotiate {
        /// Connection remaining in the authentication phase.
        conn: Conn<S, Auth>,
        /// Version and unsupported-option information supplied by the backend.
        message: codec::NegotiateProtocolVersion,
    },
    /// Authentication failed and the connection is terminated.
    Error {
        /// Terminated connection.
        conn: Conn<S, Terminated>,
        /// Backend diagnostic describing the failure.
        error: codec::DiagnosticResponse,
    },
}

/// An external choice received during a SASL exchange.
#[derive(Debug)]
pub enum SaslEvent<S> {
    /// The backend supplied another challenge.
    Continue {
        /// Connection waiting for the corresponding client response.
        conn: Conn<S, SaslChallenge>,
        /// Opaque mechanism-specific challenge bytes.
        challenge: Bytes,
    },
    /// The backend supplied its final verifier.
    Final {
        /// Connection waiting for verification by authentication policy.
        conn: Conn<S, SaslFinal>,
        /// Opaque mechanism-specific server-final bytes.
        server_final: Bytes,
    },
    /// The backend aborted authentication.
    Error {
        /// Terminated connection.
        conn: Conn<S, Terminated>,
        /// Backend diagnostic describing the failure.
        error: codec::DiagnosticResponse,
    },
}

/// Completion or failure after a credential mechanism finishes.
#[derive(Debug)]
pub enum AuthCompletion<S> {
    /// The backend confirmed authentication.
    Ok(Conn<S, AwaitingStartupReady>),
    /// The backend rejected authentication.
    Error {
        /// Terminated connection.
        conn: Conn<S, Terminated>,
        /// Backend diagnostic describing the failure.
        error: codec::DiagnosticResponse,
    },
}

/// An external choice during GSS, SSPI, or Kerberos token exchange.
#[derive(Debug)]
pub enum TokenAuthEvent<S> {
    /// The backend supplied another token.
    Continue {
        /// Connection waiting for the next client token.
        conn: Conn<S, TokenResponse>,
        /// Opaque mechanism-specific backend token.
        token: Bytes,
    },
    /// The backend confirmed authentication.
    Ok(Conn<S, AwaitingStartupReady>),
    /// The backend rejected authentication.
    Error {
        /// Terminated connection.
        conn: Conn<S, Terminated>,
        /// Backend diagnostic describing the failure.
        error: codec::DiagnosticResponse,
    },
}

impl<S> Conn<S, Startup, Pristine> {
    /// Enters backend-driven authentication after sending the startup message.
    pub fn authentication(self) -> Conn<S, Auth> {
        self.transition()
    }
}

impl<S> Conn<S, Auth, Pristine> {
    /// Projects either protocol negotiation or an authentication request.
    ///
    /// # Errors
    ///
    /// Returns an authentication parsing error, or the unchanged connection and
    /// message when the backend message is unrelated to startup authentication.
    ///
    /// # Panics
    ///
    /// Panics only if the exhaustive continuation guard above the internal
    /// projection becomes inconsistent with [`Self::offer`].
    pub fn offer_backend(
        self,
        message: codec::BackendMessage,
    ) -> Result<AuthEvent<S>, (Self, codec::BackendMessage, Option<std::io::Error>)> {
        match message {
            codec::BackendMessage::Authentication(
                authentication @ (codec::Authentication::GssContinue(_)
                | codec::Authentication::SaslContinue(_)
                | codec::Authentication::SaslFinal(_)),
            ) => Err((
                self,
                codec::BackendMessage::Authentication(authentication),
                Some(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "authentication continuation before mechanism selection",
                )),
            )),
            codec::BackendMessage::Authentication(authentication) => Ok(AuthEvent::Authentication(
                self.offer(authentication)
                    .expect("non-continuation authentication is valid in Auth"),
            )),
            codec::BackendMessage::NegotiateProtocolVersion(message) => Ok(AuthEvent::Negotiate {
                conn: self,
                message,
            }),
            codec::BackendMessage::ErrorResponse(error) => Ok(AuthEvent::Error {
                conn: self.transition(),
                error,
            }),
            message => Err((self, message, None)),
        }
    }

    /// Applies one backend authentication request to the session state.
    ///
    /// # Errors
    ///
    /// SASL continuation/final messages are rejected before SASL is selected.
    pub fn offer(self, authentication: codec::Authentication) -> std::io::Result<AuthOffer<S>> {
        match (
            project_authentication(auth_grammar::RuntimeState::Auth, &authentication),
            authentication,
        ) {
            (Some(auth_grammar::Event::Ok), codec::Authentication::Ok) => {
                Ok(AuthOffer::Ok(self.transition()))
            }
            (Some(auth_grammar::Event::Cleartext), codec::Authentication::CleartextPassword) => {
                Ok(AuthOffer::Cleartext(self.transition()))
            }
            (Some(auth_grammar::Event::Md5), codec::Authentication::Md5Password { salt }) => {
                Ok(AuthOffer::Md5 {
                    conn: self.transition(),
                    salt,
                })
            }
            (Some(auth_grammar::Event::Sasl), codec::Authentication::Sasl { mechanisms }) => {
                Ok(AuthOffer::Sasl {
                    conn: self.transition(),
                    mechanisms,
                })
            }
            (Some(auth_grammar::Event::Gss), codec::Authentication::Gss) => {
                Ok(AuthOffer::Gss(self.transition()))
            }
            (Some(auth_grammar::Event::Sspi), codec::Authentication::Sspi) => {
                Ok(AuthOffer::Sspi(self.transition()))
            }
            (Some(auth_grammar::Event::KerberosV5), codec::Authentication::KerberosV5) => {
                Ok(AuthOffer::KerberosV5(self.transition()))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "authentication continuation before mechanism selection",
            )),
        }
    }
}

impl<S> Conn<S, TokenResponse, Pristine> {
    /// Sends a GSS, SSPI, or Kerberos token and waits for continuation or success.
    pub fn respond(self, token: Bytes) -> (Conn<S, TokenChallenge>, codec::Frame) {
        (
            self.transition(),
            codec::Frame {
                tag: b'p',
                body: token,
            },
        )
    }
}

impl<S> Conn<S, TokenChallenge, Pristine> {
    /// Projects recursive GSS continuation, successful authentication, or failure.
    ///
    /// # Errors
    ///
    /// Returns the live connection and message for an illegal response.
    pub fn offer(
        self,
        message: codec::BackendMessage,
    ) -> Result<TokenAuthEvent<S>, (Self, codec::BackendMessage)> {
        match (
            auth_grammar::project_external(auth_grammar::RuntimeState::TokenChallenge, &message),
            message,
        ) {
            (
                Some(auth_grammar::Event::Continue),
                codec::BackendMessage::Authentication(codec::Authentication::GssContinue(token)),
            ) => Ok(TokenAuthEvent::Continue {
                conn: self.transition(),
                token,
            }),
            (
                Some(auth_grammar::Event::Ok),
                codec::BackendMessage::Authentication(codec::Authentication::Ok),
            ) => Ok(TokenAuthEvent::Ok(self.transition())),
            (Some(auth_grammar::Event::Error), codec::BackendMessage::ErrorResponse(error)) => {
                Ok(TokenAuthEvent::Error {
                    conn: self.transition(),
                    error,
                })
            }
            (_, message) => Err((self, message)),
        }
    }
}

impl<S> Conn<S, PasswordResponse, Pristine> {
    /// Sends a cleartext or precomputed MD5 password response.
    ///
    /// # Errors
    ///
    /// Returns an error if the response contains a NUL byte or is too large.
    pub fn password(
        self,
        password: &[u8],
    ) -> std::io::Result<(Conn<S, AwaitingAuthOk>, codec::Frame)> {
        if password.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "password response contains a NUL byte",
            ));
        }
        let mut body = BytesMut::with_capacity(password.len() + 1);
        body.extend_from_slice(password);
        body.put_u8(0);
        Ok((
            self.transition(),
            codec::Frame {
                tag: b'p',
                body: body.freeze(),
            },
        ))
    }
}

impl<S> Conn<S, SaslInitial, Pristine> {
    /// Selects SCRAM without channel binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial response is too large.
    pub fn scram_sha_256(self, initial: &[u8]) -> std::io::Result<(Conn<S, Sasl>, codec::Frame)> {
        sasl_initial(self, b"SCRAM-SHA-256", initial)
    }
}

impl<S: TlsServerEndPoint> Conn<S, SaslInitial, Pristine> {
    /// Selects SCRAM-PLUS. This method is unavailable on transports which cannot
    /// provide the peer-certificate channel binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial response is too large.
    pub fn scram_sha_256_plus(
        self,
        initial: &[u8],
    ) -> std::io::Result<(Conn<S, Sasl>, codec::Frame)> {
        sasl_initial(self, b"SCRAM-SHA-256-PLUS", initial)
    }
}

impl<S> Conn<S, Sasl, Pristine> {
    /// Projects the next server challenge or final verifier.
    ///
    /// # Errors
    ///
    /// Returns the live connection and authentication message for an illegal branch.
    pub fn offer(
        self,
        authentication: codec::Authentication,
    ) -> Result<SaslEvent<S>, (Self, codec::Authentication)> {
        match (
            project_authentication(auth_grammar::RuntimeState::Sasl, &authentication),
            authentication,
        ) {
            (
                Some(auth_grammar::Event::Continue),
                codec::Authentication::SaslContinue(challenge),
            ) => Ok(SaslEvent::Continue {
                conn: self.transition(),
                challenge,
            }),
            (Some(auth_grammar::Event::Final), codec::Authentication::SaslFinal(server_final)) => {
                Ok(SaslEvent::Final {
                    conn: self.transition(),
                    server_final,
                })
            }
            (_, authentication) => Err((self, authentication)),
        }
    }

    /// Projects an authentication error which terminates an active SASL exchange.
    ///
    /// # Errors
    ///
    /// Returns the live connection and message for an illegal response.
    pub fn offer_backend(
        self,
        message: codec::BackendMessage,
    ) -> Result<SaslEvent<S>, (Self, codec::BackendMessage)> {
        match message {
            codec::BackendMessage::Authentication(authentication) => self
                .offer(authentication)
                .map_err(|(conn, authentication)| {
                    (conn, codec::BackendMessage::Authentication(authentication))
                }),
            codec::BackendMessage::ErrorResponse(error) => Ok(SaslEvent::Error {
                conn: self.transition(),
                error,
            }),
            message => Err((self, message)),
        }
    }
}

impl<S> Conn<S, SaslChallenge, Pristine> {
    /// Sends the response to one received challenge and re-enters the SASL loop.
    pub fn respond(self, response: Bytes) -> (Conn<S, Sasl>, codec::Frame) {
        (
            self.transition(),
            codec::Frame {
                tag: b'p',
                body: response,
            },
        )
    }
}

impl<S> Conn<S, SaslFinal, Pristine> {
    /// Records that custom SCRAM logic verified the received server-final value.
    pub fn verified(self) -> Conn<S, AwaitingAuthOk> {
        self.transition()
    }
}

impl<S> Conn<S, AwaitingAuthOk, Pristine> {
    /// Requires backend evidence that authentication succeeded or failed.
    ///
    /// # Errors
    ///
    /// Returns the live connection and message for an illegal response.
    pub fn offer(
        self,
        message: codec::BackendMessage,
    ) -> Result<AuthCompletion<S>, (Self, codec::BackendMessage)> {
        match (
            auth_grammar::project_external(auth_grammar::RuntimeState::AwaitingAuthOk, &message),
            message,
        ) {
            (
                Some(auth_grammar::Event::Ok),
                codec::BackendMessage::Authentication(codec::Authentication::Ok),
            ) => Ok(AuthCompletion::Ok(self.transition())),
            (Some(auth_grammar::Event::Error), codec::BackendMessage::ErrorResponse(error)) => {
                Ok(AuthCompletion::Error {
                    conn: self.transition(),
                    error,
                })
            }
            (_, message) => Err((self, message)),
        }
    }
}

fn project_authentication(
    state: auth_grammar::RuntimeState,
    authentication: &codec::Authentication,
) -> Option<auth_grammar::Event> {
    auth_grammar::project_external(
        state,
        &codec::BackendMessage::Authentication(authentication.clone()),
    )
}

impl<S> Conn<S, AwaitingStartupReady, Pristine> {
    /// Completes startup only when presented with a projected `ReadyForQuery`.
    ///
    /// # Errors
    ///
    /// Returns the unchanged connection and item when it is not `ReadyForQuery`.
    pub fn offer_ready(self, item: SessionItem) -> Result<Conn<S, Ready>, (Self, SessionItem)> {
        if matches!(
            item,
            SessionItem::ReadyForQuery {
                status: codec::TransactionStatus::Idle,
                parameters_changed: false,
            }
        ) {
            Ok(self.transition())
        } else {
            Err((self, item))
        }
    }
}

fn sasl_initial<S>(
    conn: Conn<S, SaslInitial>,
    mechanism: &[u8],
    initial: &[u8],
) -> std::io::Result<(Conn<S, Sasl>, codec::Frame)> {
    let length = i32::try_from(initial.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "SASL response too large")
    })?;
    let mut body = BytesMut::with_capacity(mechanism.len() + initial.len() + 5);
    body.extend_from_slice(mechanism);
    body.put_u8(0);
    body.put_i32(length);
    body.extend_from_slice(initial);
    Ok((
        conn.transition(),
        codec::Frame {
            tag: b'p',
            body: body.freeze(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Tls(Vec<u8>);

    impl TlsServerEndPoint for Tls {
        fn tls_server_end_point(&self) -> &[u8] {
            &self.0
        }
    }

    #[test]
    fn sasl_continue_alternates_challenge_and_response() {
        let sasl: Conn<Tls, Sasl> = Conn::new(Tls(vec![1])).transition();
        let SaslEvent::Continue { conn, challenge } = sasl
            .offer(codec::Authentication::SaslContinue(Bytes::from_static(
                b"challenge",
            )))
            .unwrap()
        else {
            panic!("challenge projected to the wrong branch")
        };
        assert_eq!(challenge, Bytes::from_static(b"challenge"));
        let (sasl, response) = conn.respond(Bytes::from_static(b"response"));
        assert_eq!(response.body, Bytes::from_static(b"response"));

        let SaslEvent::Final { conn, server_final } = sasl
            .offer(codec::Authentication::SaslFinal(Bytes::from_static(
                b"verified",
            )))
            .unwrap()
        else {
            panic!("server final projected to the wrong branch")
        };
        assert_eq!(server_final, Bytes::from_static(b"verified"));
        conn.verified().into_transport();
    }

    #[test]
    fn gss_continuation_is_a_recursive_token_exchange() {
        let auth: Conn<(), Auth> = Conn::new(()).transition();
        let AuthOffer::Gss(response) = auth.offer(codec::Authentication::Gss).unwrap() else {
            panic!("GSS request projected to the wrong branch")
        };
        let (waiting, frame) = response.respond(Bytes::from_static(b"client-token-1"));
        assert_eq!(frame.body, Bytes::from_static(b"client-token-1"));

        let TokenAuthEvent::Continue { conn, token } = waiting
            .offer(codec::BackendMessage::Authentication(
                codec::Authentication::GssContinue(Bytes::from_static(b"server-token")),
            ))
            .unwrap()
        else {
            panic!("GSS continuation projected to the wrong branch")
        };
        assert_eq!(token, Bytes::from_static(b"server-token"));
        let (waiting, _) = conn.respond(Bytes::from_static(b"client-token-2"));
        let TokenAuthEvent::Ok(awaiting_ready) = waiting
            .offer(codec::BackendMessage::Authentication(
                codec::Authentication::Ok,
            ))
            .unwrap()
        else {
            panic!("authentication success projected to the wrong branch")
        };
        awaiting_ready.into_transport();
    }

    #[test]
    fn scram_plus_exposes_binding_to_custom_authentication_logic() {
        let conn: Conn<Tls, SaslInitial> = Conn::new(Tls(vec![1, 2, 3])).transition();
        assert_eq!(conn.tls_server_end_point(), [1, 2, 3]);

        let (sasl, frame) = conn.scram_sha_256_plus(b"client-first").unwrap();
        assert_eq!(frame.tag, b'p');
        assert_eq!(
            frame.body,
            Bytes::from_static(b"SCRAM-SHA-256-PLUS\0\0\0\0\x0cclient-first")
        );
        let _transport = sasl.into_transport();
    }

    #[test]
    fn protocol_negotiation_is_an_auth_self_loop() {
        let auth: Conn<(), Auth> = Conn::new(()).transition();
        let negotiation = codec::NegotiateProtocolVersion {
            newest: crate::startup::ProtocolVersion::V3_2,
            unsupported_options: vec![Bytes::from_static(b"_pq_.feature")],
        };
        let AuthEvent::Negotiate { conn, message } = auth
            .offer_backend(codec::BackendMessage::NegotiateProtocolVersion(
                negotiation.clone(),
            ))
            .unwrap()
        else {
            panic!("negotiation projected to the wrong branch")
        };
        assert_eq!(message, negotiation);
        let AuthEvent::Authentication(AuthOffer::Ok(ready)) = conn
            .offer_backend(codec::BackendMessage::Authentication(
                codec::Authentication::Ok,
            ))
            .unwrap()
        else {
            panic!("authentication projected to the wrong branch")
        };
        ready.into_transport();
    }

    #[test]
    fn authentication_completion_requires_backend_evidence() {
        let awaiting: Conn<(), AwaitingAuthOk> = Conn::new(()).transition();
        let AuthCompletion::Ok(startup) = awaiting
            .offer(codec::BackendMessage::Authentication(
                codec::Authentication::Ok,
            ))
            .unwrap()
        else {
            panic!("AuthenticationOk projected to the wrong branch")
        };
        startup.into_transport();

        let awaiting: Conn<(), AwaitingAuthOk> = Conn::new(()).transition();
        let error = codec::DiagnosticResponse {
            fields: vec![codec::DiagnosticField {
                code: b'M',
                value: Bytes::from_static(b"password authentication failed"),
            }],
        };
        let AuthCompletion::Error {
            conn,
            error: projected,
        } = awaiting
            .offer(codec::BackendMessage::ErrorResponse(error.clone()))
            .unwrap()
        else {
            panic!("authentication error projected to the wrong branch")
        };
        assert_eq!(projected, error);
        conn.into_transport();
    }
}
