//! `PostgreSQL`'s untagged pre-startup protocol.
//!
//! These packets precede normal message framing. Encryption acceptance is a raw
//! byte, and a successful negotiation changes the connection's transport type.

use crate::{Conn, Pristine, startup::StartupMessage};
use bytes::BufMut as _;

const SSL_REQUEST_CODE: u32 = 80_877_103;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;

#[derive(Debug)]
pub enum PreStartup {}

#[derive(Debug)]
pub enum Startup {}

#[derive(Debug)]
pub enum AwaitingSslReply {}

#[derive(Debug)]
pub enum AwaitingGssReply {}

#[derive(Debug)]
pub enum TlsHandshake {}

#[derive(Debug)]
pub enum GssHandshake {}

#[derive(Debug)]
pub enum Terminated {}

/// The server's single-byte answer to an SSL request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionReply {
    Accepted,
    Rejected,
    LegacyError,
}

impl TryFrom<u8> for EncryptionReply {
    type Error = InvalidEncryptionReply;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            b'S' => Ok(Self::Accepted),
            b'N' => Ok(Self::Rejected),
            b'E' => Ok(Self::LegacyError),
            byte => Err(InvalidEncryptionReply(byte)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidEncryptionReply(pub u8);

/// libpq-compatible TLS negotiation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SslMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateVerification {
    None,
    CertificateAuthority,
    CertificateAuthorityAndHost,
}

/// Actions needed to apply an [`SslMode`] across connection attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SslStrategy {
    pub request_on_first_connection: bool,
    pub retry_with_ssl_after_plaintext_failure: bool,
    pub allow_server_rejection: bool,
    pub verification: CertificateVerification,
}

impl SslMode {
    #[must_use]
    pub const fn strategy(self) -> SslStrategy {
        match self {
            Self::Disable => SslStrategy {
                request_on_first_connection: false,
                retry_with_ssl_after_plaintext_failure: false,
                allow_server_rejection: true,
                verification: CertificateVerification::None,
            },
            Self::Allow => SslStrategy {
                request_on_first_connection: false,
                retry_with_ssl_after_plaintext_failure: true,
                allow_server_rejection: true,
                verification: CertificateVerification::None,
            },
            Self::Prefer => SslStrategy {
                request_on_first_connection: true,
                retry_with_ssl_after_plaintext_failure: false,
                allow_server_rejection: true,
                verification: CertificateVerification::None,
            },
            Self::Require => SslStrategy {
                request_on_first_connection: true,
                retry_with_ssl_after_plaintext_failure: false,
                allow_server_rejection: false,
                verification: CertificateVerification::None,
            },
            Self::VerifyCa => SslStrategy {
                request_on_first_connection: true,
                retry_with_ssl_after_plaintext_failure: false,
                allow_server_rejection: false,
                verification: CertificateVerification::CertificateAuthority,
            },
            Self::VerifyFull => SslStrategy {
                request_on_first_connection: true,
                retry_with_ssl_after_plaintext_failure: false,
                allow_server_rejection: false,
                verification: CertificateVerification::CertificateAuthorityAndHost,
            },
        }
    }
}

/// A reply whose branches deliberately have different typestates.
#[derive(Debug)]
pub enum Negotiation<S, Handshake> {
    Accepted(Conn<S, Handshake>),
    Rejected(Conn<S, PreStartup>),
    LegacyError(Conn<S, Terminated>),
}

impl<S> Conn<S, PreStartup, Pristine> {
    pub fn ssl_request(self) -> (Conn<S, AwaitingSslReply>, [u8; 8]) {
        (self.transition(), request_packet(SSL_REQUEST_CODE))
    }

    pub fn gssenc_request(self) -> (Conn<S, AwaitingGssReply>, [u8; 8]) {
        (self.transition(), request_packet(GSSENC_REQUEST_CODE))
    }

    /// Encodes and enters the startup phase.
    ///
    /// # Errors
    ///
    /// Returns an error when the startup parameters cannot be encoded.
    pub fn startup(
        self,
        message: &StartupMessage,
    ) -> std::io::Result<(Conn<S, Startup>, bytes::Bytes)> {
        Ok((self.transition(), message.encode()?))
    }

    /// Encodes a version 3.0 or 3.2 out-of-band cancellation request.
    ///
    /// # Errors
    ///
    /// Returns an error unless the cancellation key is between 4 and 256 bytes.
    pub fn cancel_request(
        self,
        process_id: u32,
        secret_key: &[u8],
    ) -> std::io::Result<(Conn<S, Terminated>, bytes::Bytes)> {
        if !(4..=256).contains(&secret_key.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cancellation key length is outside 4..=256",
            ));
        }
        let key_length = u32::try_from(secret_key.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cancellation key too large",
            )
        })?;
        let length = 12 + key_length;
        let mut packet = bytes::BytesMut::with_capacity(12 + secret_key.len());
        packet.put_u32(length);
        packet.put_u32(CANCEL_REQUEST_CODE);
        packet.put_u32(process_id);
        packet.extend_from_slice(secret_key);
        Ok((self.transition(), packet.freeze()))
    }
}

impl<S> Conn<S, AwaitingSslReply, Pristine> {
    /// Resolves the raw SSL response byte.
    ///
    /// A pending negotiation cannot send a startup message:
    ///
    /// ```compile_fail
    /// use pg_proto::Conn;
    /// let (pending, _) = Conn::new(()).ssl_request();
    /// let _ = pending.startup();
    /// ```
    pub fn receive_reply(self, reply: EncryptionReply) -> Negotiation<S, TlsHandshake> {
        match reply {
            EncryptionReply::Accepted => Negotiation::Accepted(self.transition()),
            EncryptionReply::Rejected => Negotiation::Rejected(self.transition()),
            EncryptionReply::LegacyError => Negotiation::LegacyError(self.transition()),
        }
    }
}

impl<S> Conn<S, AwaitingGssReply, Pristine> {
    pub fn receive_reply(self, reply: EncryptionReply) -> Negotiation<S, GssHandshake> {
        match reply {
            EncryptionReply::Accepted => Negotiation::Accepted(self.transition()),
            EncryptionReply::Rejected => Negotiation::Rejected(self.transition()),
            EncryptionReply::LegacyError => Negotiation::LegacyError(self.transition()),
        }
    }
}

impl<S> Conn<S, TlsHandshake, Pristine> {
    /// Records a completed in-place TLS upgrade, changing the transport type.
    pub fn finish_tls<Tls>(self, upgrade: impl FnOnce(S) -> Tls) -> Conn<Tls, PreStartup> {
        Conn::new(upgrade(self.into_transport()))
    }
}

impl<S> Conn<S, GssHandshake, Pristine> {
    /// Records a completed in-place GSS encryption upgrade.
    pub fn finish_gss<Gss>(self, upgrade: impl FnOnce(S) -> Gss) -> Conn<Gss, PreStartup> {
        Conn::new(upgrade(self.into_transport()))
    }
}

const fn request_packet(code: u32) -> [u8; 8] {
    let length = 8_u32.to_be_bytes();
    let code = code.to_be_bytes();
    [
        length[0], length[1], length[2], length[3], code[0], code[1], code[2], code[3],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_special_requests_in_network_byte_order() {
        let (_, ssl) = Conn::new(()).ssl_request();
        assert_eq!(ssl, [0, 0, 0, 8, 4, 210, 22, 47]);

        let (_, cancel) = Conn::new(())
            .cancel_request(0x0102_0304, &[5, 6, 7, 8])
            .expect("valid protocol 3.0 cancellation key");
        assert_eq!(
            &cancel[..],
            [0, 0, 0, 16, 4, 210, 22, 46, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn tls_upgrade_changes_the_transport_type() {
        struct Tcp;
        struct Tls;

        let (pending, _) = Conn::new(Tcp).ssl_request();
        let Negotiation::Accepted(handshake) = pending.receive_reply(EncryptionReply::Accepted)
        else {
            panic!("unexpected negotiation branch")
        };
        let upgraded: Conn<Tls, PreStartup> = handshake.finish_tls(|Tcp| Tls);
        let message = StartupMessage {
            version: crate::startup::ProtocolVersion::V3_0,
            parameters: std::collections::BTreeMap::new(),
        };
        let (_startup, _) = upgraded.startup(&message).expect("valid startup message");
    }

    #[test]
    fn sslmode_allow_starts_plaintext_then_reconnects_with_tls() {
        assert_eq!(
            SslMode::Allow.strategy(),
            SslStrategy {
                request_on_first_connection: false,
                retry_with_ssl_after_plaintext_failure: true,
                allow_server_rejection: true,
                verification: CertificateVerification::None,
            }
        );
    }

    #[test]
    fn verify_full_requires_tls_ca_and_hostname() {
        assert_eq!(
            SslMode::VerifyFull.strategy(),
            SslStrategy {
                request_on_first_connection: true,
                retry_with_ssl_after_plaintext_failure: false,
                allow_server_rejection: false,
                verification: CertificateVerification::CertificateAuthorityAndHost,
            }
        );
    }
}
