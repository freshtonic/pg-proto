//! Server-role authentication typestates for proxy-side client termination.

use std::io;

use bytes::{Buf, Bytes};

use crate::{
    Conn,
    auth::Ready,
    codec::{
        Authentication, BackendMessage, Frame, FrontendMessage, NegotiateProtocolVersion,
        TransactionStatus,
    },
    pre_startup::Startup,
    startup::ProtocolVersion,
};

#[derive(Debug)]
pub enum ServerAuth {}

#[derive(Debug)]
pub enum ServerPassword {}

#[derive(Debug)]
pub enum ServerSaslInitial {}

#[derive(Debug)]
pub enum ServerSasl {}

#[derive(Debug)]
pub enum ServerAuthResponse {}

#[derive(Debug)]
pub enum ServerStartupReady {}

/// A decoded SASL initial response selected by the client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaslInitialResponse {
    pub mechanism: Bytes,
    pub response: Option<Bytes>,
}

/// A rejected frontend message paired with the unchanged authentication state.
pub type ServerProjection<T, S, Phase, C> = Result<T, Box<(Conn<S, Phase, C>, FrontendMessage)>>;

pub type PasswordProjection<S, C> =
    ServerProjection<(Conn<S, ServerAuth, C>, Bytes), S, ServerPassword, C>;

pub type SaslInitialProjection<S, C> =
    ServerProjection<(Conn<S, ServerSasl, C>, SaslInitialResponse), S, ServerSaslInitial, C>;

impl<S, C> Conn<S, Startup, C> {
    /// Begins proxy-side authentication of the connected client.
    pub fn begin_server_auth(self) -> Conn<S, ServerAuth, C> {
        self.transition()
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
        match message {
            FrontendMessage::PasswordResponse(body) => match password_body(body) {
                Ok(password) => Ok((self.transition(), password)),
                Err(body) => Err(Box::new((self, FrontendMessage::PasswordResponse(body)))),
            },
            other => Err(Box::new((self, other))),
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
        match message {
            FrontendMessage::PasswordResponse(body) => match sasl_initial(body) {
                Ok(initial) => Ok((self.transition(), initial)),
                Err(body) => Err(Box::new((self, FrontendMessage::PasswordResponse(body)))),
            },
            other => Err(Box::new((self, other))),
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
        match message {
            FrontendMessage::PasswordResponse(response) => Ok((self, response)),
            other => Err(Box::new((self, other))),
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
        match message {
            FrontendMessage::PasswordResponse(response) => Ok((self, response)),
            other => Err(Box::new((self, other))),
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
    use crate::Pristine;

    #[test]
    fn cleartext_response_returns_to_independent_policy_choice() {
        let startup: Conn<(), Startup, Pristine> = Conn::new(()).transition();
        let (password, request) = startup.begin_server_auth().request_cleartext().unwrap();
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

    #[test]
    fn sasl_is_a_recursive_server_sub_session() {
        let startup: Conn<(), Startup, Pristine> = Conn::new(()).transition();
        let (initial, _) = startup
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
        let startup: Conn<(), Startup, Pristine> = Conn::new(()).transition();
        let (startup_ready, _) = startup.begin_server_auth().authentication_ok().unwrap();
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
}
