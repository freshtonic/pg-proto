//! `PostgreSQL`'s untagged pre-startup protocol.
//!
//! These packets precede normal message framing. Encryption acceptance is a raw
//! byte, and a successful negotiation changes the connection's transport type.

use crate::{Conn, Pristine, startup::StartupMessage};
use bytes::{BufMut as _, Bytes, BytesMut};

const SSL_REQUEST_CODE: u32 = 80_877_103;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;

/// `PostgreSQL`'s maximum accepted untagged startup packet size.
pub(crate) const DEFAULT_MAX_PRE_STARTUP_PACKET_LEN: usize = 10_000;

/// Connection awaits the client's first untagged startup-family packet.
#[derive(Debug)]
pub(crate) enum PreStartup {}

/// A decoded `StartupMessage` is ready for protocol validation.
#[derive(Debug)]
pub(crate) enum Startup {}

/// Client role awaits the server's raw SSL decision byte.
#[derive(Debug)]
pub(crate) enum AwaitingSslReply {}

/// Client role awaits the server's raw GSS encryption decision byte.
#[derive(Debug)]
pub(crate) enum AwaitingGssReply {}

/// SSL was accepted and the transport must complete a TLS handshake.
#[derive(Debug)]
pub(crate) enum TlsHandshake {}

/// GSS encryption was accepted and the transport must complete its handshake.
#[derive(Debug)]
pub(crate) enum GssHandshake {}

/// Pre-startup processing terminated without entering a normal session.
#[derive(Debug)]
pub(crate) enum Terminated {}

/// Server role must accept or reject a client's `SSLRequest`.
#[derive(Debug)]
pub(crate) enum ServerSslDecision {}

/// Server role must accept or reject a client's `GSSENCRequest`.
#[derive(Debug)]
pub(crate) enum ServerGssDecision {}

/// Server-role projection of the client's first-packet external choice.
#[derive(Debug)]
pub(crate) enum PreStartupOffer<S, C = Pristine> {
    /// Client requested TLS negotiation.
    Ssl(Conn<S, ServerSslDecision, C>),
    /// Client requested GSS encryption negotiation.
    Gss(Conn<S, ServerGssDecision, C>),
    /// Client sent an out-of-band cancellation request.
    Cancel {
        /// Terminal connection carrying the received transport.
        conn: Conn<S, Terminated, C>,
        /// Target backend process ID.
        process_id: u32,
        /// Target backend secret key.
        secret_key: Bytes,
    },
    /// Client supplied normal startup parameters.
    Startup {
        /// Connection ready for protocol validation and authentication.
        conn: Conn<S, Startup, C>,
        /// Decoded startup version and parameters.
        message: StartupMessage,
    },
}

/// The server's single-byte answer to an SSL request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncryptionReply {
    /// Server sent `S` and requires an in-place encryption handshake.
    Accepted,
    /// Server sent `N` and declined encryption.
    Rejected,
    /// Historical server sent `E` and terminated the connection.
    LegacyError,
}

impl EncryptionReply {
    /// Returns `PostgreSQL`'s raw one-byte wire representation.
    #[must_use]
    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::Accepted => b'S',
            Self::Rejected => b'N',
            Self::LegacyError => b'E',
        }
    }
}

/// The external choice occupying a new connection's untagged first packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreStartupMessage {
    /// Raw SSL negotiation request code 80877103.
    SslRequest,
    /// Raw GSS encryption request code 80877104.
    GssEncRequest,
    /// Out-of-band cancellation packet.
    CancelRequest {
        /// Target backend process ID.
        process_id: u32,
        /// Target backend secret key.
        secret_key: Bytes,
    },
    /// Normal protocol startup packet.
    Startup(StartupMessage),
}

impl PreStartupMessage {
    /// Reconstructs the complete raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid cancellation key or startup message.
    pub fn to_packet(&self) -> std::io::Result<Bytes> {
        match self {
            Self::SslRequest => Ok(Bytes::copy_from_slice(&request_packet(SSL_REQUEST_CODE))),
            Self::GssEncRequest => Ok(Bytes::copy_from_slice(&request_packet(GSSENC_REQUEST_CODE))),
            Self::CancelRequest {
                process_id,
                secret_key,
            } => cancel_packet(*process_id, secret_key),
            Self::Startup(message) => message.encode(),
        }
    }
}

/// Incrementally decodes one raw pre-startup packet without consuming partial input.
///
/// # Errors
///
/// Returns an error for invalid lengths, special-request shapes, or startup data.
pub(crate) fn decode_pre_startup(
    input: &mut BytesMut,
) -> std::io::Result<Option<PreStartupMessage>> {
    decode_pre_startup_with_limit(input, DEFAULT_MAX_PRE_STARTUP_PACKET_LEN)
}

/// Incrementally decodes one raw pre-startup packet with an allocation bound.
///
/// The declared length is checked before reserving space for the remainder of
/// a partial packet.
///
/// # Errors
///
/// Returns an error for an invalid limit, an oversized packet, invalid lengths,
/// special-request shapes, or startup data.
pub(crate) fn decode_pre_startup_with_limit(
    input: &mut BytesMut,
    max_packet_len: usize,
) -> std::io::Result<Option<PreStartupMessage>> {
    if !(8..=i32::MAX as usize).contains(&max_packet_len) {
        return Err(invalid(
            "pre-startup packet limit must be between 8 and i32::MAX bytes",
        ));
    }
    if input.len() < 4 {
        input.reserve(4 - input.len());
        return Ok(None);
    }
    let length = usize::try_from(u32::from_be_bytes([input[0], input[1], input[2], input[3]]))
        .map_err(|_| invalid("pre-startup packet length overflow"))?;
    if length < 8 {
        return Err(invalid("pre-startup packet is shorter than 8 bytes"));
    }
    if length > i32::MAX as usize {
        return Err(invalid("pre-startup packet length exceeds i32::MAX"));
    }
    if length > max_packet_len {
        return Err(invalid("pre-startup packet exceeds configured limit"));
    }
    if input.len() < length {
        input.reserve(length - input.len());
        return Ok(None);
    }
    let packet = input.split_to(length).freeze();
    let code = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    match code {
        SSL_REQUEST_CODE if length == 8 => Ok(Some(PreStartupMessage::SslRequest)),
        GSSENC_REQUEST_CODE if length == 8 => Ok(Some(PreStartupMessage::GssEncRequest)),
        CANCEL_REQUEST_CODE => {
            if !(16..=268).contains(&length) {
                return Err(invalid("invalid CancelRequest length"));
            }
            let process_id = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
            let secret_key = packet.slice(12..);
            Ok(Some(PreStartupMessage::CancelRequest {
                process_id,
                secret_key,
            }))
        }
        _ => StartupMessage::decode(packet)
            .map(PreStartupMessage::Startup)
            .map(Some),
    }
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

/// A raw encryption decision byte other than `S`, `N`, or legacy `E`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidEncryptionReply(
    /// Invalid byte received from the server.
    pub u8,
);

/// libpq-compatible TLS negotiation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SslMode {
    /// Never request TLS.
    Disable,
    /// Try plaintext first and retry with TLS if plaintext fails.
    Allow,
    /// Request TLS first but permit plaintext fallback.
    Prefer,
    /// Require encryption without certificate verification.
    Require,
    /// Require TLS and validate the certificate chain.
    VerifyCa,
    /// Require TLS and validate both chain and server hostname.
    VerifyFull,
}

/// Peer-certificate checks required by an SSL mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateVerification {
    /// Do not authenticate the peer certificate.
    None,
    /// Validate the certificate chain against configured roots.
    CertificateAuthority,
    /// Validate the certificate chain and requested hostname.
    CertificateAuthorityAndHost,
}

/// Actions needed to apply an [`SslMode`] across connection attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SslStrategy {
    /// Whether the first connection should send `SSLRequest`.
    pub request_on_first_connection: bool,
    /// Whether plaintext failure should open a new TLS-first connection.
    pub retry_with_ssl_after_plaintext_failure: bool,
    /// Whether an `N` response permits continuation in plaintext.
    pub allow_server_rejection: bool,
    /// Certificate verification required after TLS acceptance.
    pub verification: CertificateVerification,
}

impl SslMode {
    /// Converts libpq-compatible mode semantics into connection actions.
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
pub(crate) enum Negotiation<S, Handshake, C = Pristine> {
    /// Encryption accepted; complete the transport handshake next.
    Accepted(Conn<S, Handshake, C>),
    /// Encryption rejected; plaintext pre-startup choice resumes.
    Rejected(Conn<S, PreStartup, C>),
    /// Historical `E` response terminated negotiation.
    LegacyError(Conn<S, Terminated, C>),
}

/// SSL negotiation after applying plaintext-fallback policy.
#[derive(Debug)]
pub(crate) enum SslModeNegotiation<S, C = Pristine> {
    /// TLS was accepted and must be handshaken.
    Accepted(Conn<S, TlsHandshake, C>),
    /// Mode permits continuation in plaintext.
    Plaintext(Conn<S, PreStartup, C>),
    /// Server rejected TLS required by the configured mode.
    RequiredRejected {
        /// Terminal connection retaining the transport.
        conn: Conn<S, Terminated, C>,
        /// Mode whose requirement could not be met.
        mode: SslMode,
    },
    /// Historical server error terminated negotiation.
    LegacyError(Conn<S, Terminated, C>),
}

impl<S> Conn<S, PreStartup, Pristine> {
    /// Encodes `SSLRequest` and enters the raw-reply phase.
    pub(crate) fn ssl_request(self) -> (Conn<S, AwaitingSslReply>, [u8; 8]) {
        (self.transition(), ssl_request_packet())
    }

    /// Encodes `GSSENCRequest` and enters the raw-reply phase.
    pub(crate) fn gssenc_request(self) -> (Conn<S, AwaitingGssReply>, [u8; 8]) {
        (self.transition(), gssenc_request_packet())
    }

    /// Encodes and enters the startup phase.
    ///
    /// # Errors
    ///
    /// Returns an error when the startup parameters cannot be encoded.
    pub(crate) fn startup(
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
    pub(crate) fn cancel_request(
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
        Ok((self.transition(), cancel_packet(process_id, secret_key)?))
    }
}

impl<S, C> Conn<S, PreStartup, C> {
    /// Projects an inspected client pre-startup packet into the server role.
    pub(crate) fn offer_pre_startup(self, message: PreStartupMessage) -> PreStartupOffer<S, C> {
        match message {
            PreStartupMessage::SslRequest => PreStartupOffer::Ssl(self.transition()),
            PreStartupMessage::GssEncRequest => PreStartupOffer::Gss(self.transition()),
            PreStartupMessage::CancelRequest {
                process_id,
                secret_key,
            } => PreStartupOffer::Cancel {
                conn: self.transition(),
                process_id,
                secret_key,
            },
            PreStartupMessage::Startup(message) => PreStartupOffer::Startup {
                conn: self.transition(),
                message,
            },
        }
    }
}

impl<S, C> Conn<S, ServerSslDecision, C> {
    /// Rejects SSL and returns to the pre-startup choice on the same transport.
    pub(crate) fn reject_ssl(self) -> (Conn<S, PreStartup, C>, u8) {
        (self.transition(), EncryptionReply::Rejected.as_byte())
    }

    /// Accepts SSL and requires the transport handshake before startup is legal.
    pub(crate) fn accept_ssl(self) -> (Conn<S, TlsHandshake, C>, u8) {
        (self.transition(), EncryptionReply::Accepted.as_byte())
    }

    /// Emits the historical raw `E` response and terminates negotiation.
    pub(crate) fn legacy_ssl_error(self) -> (Conn<S, Terminated, C>, u8) {
        (self.transition(), EncryptionReply::LegacyError.as_byte())
    }
}

impl<S, C> Conn<S, ServerGssDecision, C> {
    /// Sends `N` and returns to plaintext pre-startup choice.
    pub(crate) fn reject_gss(self) -> (Conn<S, PreStartup, C>, u8) {
        (self.transition(), EncryptionReply::Rejected.as_byte())
    }

    /// Sends `S` and requires a server-side GSS transport handshake.
    pub(crate) fn accept_gss(self) -> (Conn<S, GssHandshake, C>, u8) {
        (self.transition(), EncryptionReply::Accepted.as_byte())
    }

    /// Emits the historical raw `E` response and terminates negotiation.
    pub(crate) fn legacy_gss_error(self) -> (Conn<S, Terminated, C>, u8) {
        (self.transition(), EncryptionReply::LegacyError.as_byte())
    }
}

impl<S, C> Conn<S, AwaitingSslReply, C> {
    /// Resolves the raw SSL response byte.
    ///
    /// A pending negotiation cannot send a startup message:
    ///
    /// ```rust,compile_fail
    /// use pg_proto::Conn;
    /// let (pending, _) = Conn::new(()).ssl_request();
    /// let _ = pending.startup();
    /// ```
    pub(crate) fn receive_reply(self, reply: EncryptionReply) -> Negotiation<S, TlsHandshake, C> {
        match reply {
            EncryptionReply::Accepted => Negotiation::Accepted(self.transition()),
            EncryptionReply::Rejected => Negotiation::Rejected(self.transition()),
            EncryptionReply::LegacyError => Negotiation::LegacyError(self.transition()),
        }
    }

    /// Resolves the SSL response while enforcing an [`SslMode`]'s fallback rule.
    pub(crate) fn apply_ssl_reply(
        self,
        reply: EncryptionReply,
        mode: SslMode,
    ) -> SslModeNegotiation<S, C> {
        match reply {
            EncryptionReply::Accepted => SslModeNegotiation::Accepted(self.transition()),
            EncryptionReply::Rejected if mode.strategy().allow_server_rejection => {
                SslModeNegotiation::Plaintext(self.transition())
            }
            EncryptionReply::Rejected => SslModeNegotiation::RequiredRejected {
                conn: self.transition(),
                mode,
            },
            EncryptionReply::LegacyError => SslModeNegotiation::LegacyError(self.transition()),
        }
    }
}

impl<S, C> Conn<S, AwaitingGssReply, C> {
    /// Applies the server's GSS encryption decision byte.
    pub(crate) fn receive_reply(self, reply: EncryptionReply) -> Negotiation<S, GssHandshake, C> {
        match reply {
            EncryptionReply::Accepted => Negotiation::Accepted(self.transition()),
            EncryptionReply::Rejected => Negotiation::Rejected(self.transition()),
            EncryptionReply::LegacyError => Negotiation::LegacyError(self.transition()),
        }
    }
}

impl<S, C> Conn<S, TlsHandshake, C> {
    /// Records a completed in-place TLS upgrade, changing the transport type.
    pub(crate) fn finish_tls<Tls>(
        self,
        upgrade: impl FnOnce(S) -> Tls,
    ) -> Conn<Tls, PreStartup, C> {
        self.map_transport(upgrade).transition()
    }
}

impl<S, C> Conn<S, TlsHandshake, C> {
    /// Records a server-side TLS upgrade while preserving cleanliness.
    pub(crate) fn finish_server_tls<Tls>(
        self,
        upgrade: impl FnOnce(S) -> Tls,
    ) -> Conn<Tls, PreStartup, C> {
        self.map_transport(upgrade).transition()
    }
}

impl<S> Conn<S, GssHandshake, Pristine> {
    /// Records a completed in-place GSS encryption upgrade.
    pub(crate) fn finish_gss<Gss>(self, upgrade: impl FnOnce(S) -> Gss) -> Conn<Gss, PreStartup> {
        Conn::new(upgrade(self.into_transport()))
    }
}

impl<S, C> Conn<S, GssHandshake, C> {
    /// Completes a server-side GSS upgrade and returns to encrypted pre-startup.
    pub(crate) fn finish_server_gss<Gss>(
        self,
        upgrade: impl FnOnce(S) -> Gss,
    ) -> Conn<Gss, PreStartup, C> {
        self.map_transport(upgrade).transition()
    }
}

pub(crate) const fn ssl_request_packet() -> [u8; 8] {
    request_packet(SSL_REQUEST_CODE)
}

pub(crate) const fn gssenc_request_packet() -> [u8; 8] {
    request_packet(GSSENC_REQUEST_CODE)
}

const fn request_packet(code: u32) -> [u8; 8] {
    let length = 8_u32.to_be_bytes();
    let code = code.to_be_bytes();
    [
        length[0], length[1], length[2], length[3], code[0], code[1], code[2], code[3],
    ]
}

fn cancel_packet(process_id: u32, secret_key: &[u8]) -> std::io::Result<Bytes> {
    if !(4..=256).contains(&secret_key.len()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cancellation key length is outside 4..=256",
        ));
    }
    let key_length =
        u32::try_from(secret_key.len()).map_err(|_| invalid("cancellation key length overflow"))?;
    let length = 12 + key_length;
    let mut packet = BytesMut::with_capacity(12 + secret_key.len());
    packet.put_u32(length);
    packet.put_u32(CANCEL_REQUEST_CODE);
    packet.put_u32(process_id);
    packet.extend_from_slice(secret_key);
    Ok(packet.freeze())
}

fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
/// Tests for typed pre-startup negotiation and upgrades.
mod tests {
    use super::*;

    #[test]
    fn encodes_special_requests_in_network_byte_order() {
        let (pending, ssl) = Conn::new(()).ssl_request();
        assert_eq!(ssl, [0, 0, 0, 8, 4, 210, 22, 47]);
        pending.into_transport();

        let (terminated, cancel) = Conn::new(())
            .cancel_request(0x0102_0304, &[5, 6, 7, 8])
            .expect("valid protocol 3.0 cancellation key");
        assert_eq!(
            &cancel[..],
            [0, 0, 0, 16, 4, 210, 22, 46, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        terminated.into_transport();
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
        let (startup, _) = upgraded.startup(&message).expect("valid startup message");
        let _transport = startup.into_transport();
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

    #[test]
    fn sslmode_rejection_is_plaintext_only_when_policy_allows_it() {
        let (pending, _) = Conn::new(()).ssl_request();
        let SslModeNegotiation::Plaintext(plaintext) =
            pending.apply_ssl_reply(EncryptionReply::Rejected, SslMode::Prefer)
        else {
            panic!("prefer should permit a plaintext fallback")
        };
        plaintext.into_transport();

        let (pending, _) = Conn::new(()).ssl_request();
        let SslModeNegotiation::RequiredRejected { conn, mode } =
            pending.apply_ssl_reply(EncryptionReply::Rejected, SslMode::VerifyFull)
        else {
            panic!("verify-full must reject a server without TLS")
        };
        assert_eq!(mode, SslMode::VerifyFull);
        conn.into_transport();
    }

    #[test]
    fn encryption_negotiation_and_upgrade_preserve_cleanliness() {
        fn require_dirty<S>(conn: Conn<S, PreStartup, crate::Dirty>) {
            conn.into_transport();
        }

        let pending: Conn<(), AwaitingSslReply, crate::Dirty> = Conn::new(()).transition();
        let Negotiation::Accepted(handshake) = pending.receive_reply(EncryptionReply::Accepted)
        else {
            panic!("expected the TLS handshake branch")
        };
        let upgraded = handshake.finish_tls(|()| 42_u8);

        require_dirty(upgraded);
    }

    #[test]
    fn incrementally_decodes_each_pre_startup_branch() {
        let messages = [
            PreStartupMessage::SslRequest,
            PreStartupMessage::GssEncRequest,
            PreStartupMessage::CancelRequest {
                process_id: 42,
                secret_key: Bytes::from_static(&[7; 32]),
            },
            PreStartupMessage::Startup(StartupMessage {
                version: crate::startup::ProtocolVersion::V3_2,
                parameters: std::collections::BTreeMap::from([(
                    Bytes::from_static(b"user"),
                    Bytes::from_static(b"postgres"),
                )]),
            }),
        ];

        for message in messages {
            let packet = message.to_packet().expect("encodable pre-startup message");
            let mut input = BytesMut::from(&packet[..3]);
            assert_eq!(
                decode_pre_startup(&mut input).expect("partial input is valid"),
                None
            );
            input.extend_from_slice(&packet[3..]);
            assert_eq!(
                decode_pre_startup(&mut input).expect("complete packet is valid"),
                Some(message)
            );
            assert!(input.is_empty());
        }
    }

    #[test]
    fn rejects_oversized_pre_startup_before_reserving_body() {
        let mut input = BytesMut::from(&10_001_u32.to_be_bytes()[..]);
        let capacity = input.capacity();

        let error = decode_pre_startup(&mut input).expect_err("packet exceeds the default limit");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(input.len(), 4);
        assert_eq!(input.capacity(), capacity);
    }

    #[test]
    fn validates_custom_pre_startup_limit() {
        let packet = PreStartupMessage::SslRequest
            .to_packet()
            .expect("SSL request is encodable");

        assert!(decode_pre_startup_with_limit(&mut BytesMut::from(&packet[..]), 7).is_err());
        assert!(
            decode_pre_startup_with_limit(&mut BytesMut::from(&packet[..]), i32::MAX as usize + 1)
                .is_err()
        );
    }
}
