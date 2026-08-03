//! Authentication typestates, including the recursive SASL sub-session.

use bytes::{BufMut, Bytes, BytesMut};

use crate::demux::SessionItem;
use crate::{Conn, Pristine, codec, pre_startup::Startup};

#[derive(Debug)]
pub enum Auth {}

#[derive(Debug)]
pub enum PasswordResponse {}

#[derive(Debug)]
pub enum SaslInitial {}

#[derive(Debug)]
pub enum Sasl {}

#[derive(Debug)]
pub enum SaslFinal {}

#[derive(Debug)]
pub enum AwaitingAuthOk {}

#[derive(Debug)]
pub enum Ready {}

#[derive(Debug)]
pub enum AwaitingStartupReady {}

/// TLS transports expose the RFC 5929 `tls-server-end-point` binding.
pub trait TlsServerEndPoint {
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
    Ok(Conn<S, AwaitingStartupReady>),
    Cleartext(Conn<S, PasswordResponse>),
    Md5 {
        conn: Conn<S, PasswordResponse>,
        salt: [u8; 4],
    },
    Sasl {
        conn: Conn<S, SaslInitial>,
        mechanisms: Vec<Bytes>,
    },
    Gss(Conn<S, Auth>),
    Sspi(Conn<S, Auth>),
    KerberosV5(Conn<S, Auth>),
}

impl<S> Conn<S, Startup, Pristine> {
    pub fn authentication(self) -> Conn<S, Auth> {
        self.transition()
    }
}

impl<S> Conn<S, Auth, Pristine> {
    /// Applies one backend authentication request to the session state.
    ///
    /// # Errors
    ///
    /// SASL continuation/final messages are rejected before SASL is selected.
    pub fn offer(self, authentication: codec::Authentication) -> std::io::Result<AuthOffer<S>> {
        match authentication {
            codec::Authentication::Ok => Ok(AuthOffer::Ok(self.transition())),
            codec::Authentication::CleartextPassword => Ok(AuthOffer::Cleartext(self.transition())),
            codec::Authentication::Md5Password { salt } => Ok(AuthOffer::Md5 {
                conn: self.transition(),
                salt,
            }),
            codec::Authentication::Sasl { mechanisms } => Ok(AuthOffer::Sasl {
                conn: self.transition(),
                mechanisms,
            }),
            codec::Authentication::Gss => Ok(AuthOffer::Gss(self)),
            codec::Authentication::Sspi => Ok(AuthOffer::Sspi(self)),
            codec::Authentication::KerberosV5 => Ok(AuthOffer::KerberosV5(self)),
            codec::Authentication::GssContinue(_)
            | codec::Authentication::SaslContinue(_)
            | codec::Authentication::SaslFinal(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "authentication continuation before mechanism selection",
            )),
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
    /// Sends one response and remains in the recursive SASL sub-session.
    pub fn continue_with(self, response: Bytes) -> (Self, codec::Frame) {
        (
            self,
            codec::Frame {
                tag: b'p',
                body: response,
            },
        )
    }

    /// Accepts the server-final data after the SCRAM implementation verifies it.
    pub fn server_final(self, _verified_server_final: Bytes) -> Conn<S, AwaitingAuthOk> {
        self.transition()
    }
}

impl<S> Conn<S, AwaitingAuthOk, Pristine> {
    pub fn authentication_ok(self) -> Conn<S, AwaitingStartupReady> {
        self.transition()
    }
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

    struct Tls(Vec<u8>);

    impl TlsServerEndPoint for Tls {
        fn tls_server_end_point(&self) -> &[u8] {
            &self.0
        }
    }

    #[test]
    fn sasl_continue_is_a_self_loop() {
        let conn: Conn<Tls, Sasl> = Conn::new(Tls(vec![1])).transition();
        let (conn, first) = conn.continue_with(Bytes::from_static(b"one"));
        let (conn, second) = conn.continue_with(Bytes::from_static(b"two"));
        assert_eq!(first.body, Bytes::from_static(b"one"));
        assert_eq!(second.body, Bytes::from_static(b"two"));
        let _transport = conn.into_transport();
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
}
