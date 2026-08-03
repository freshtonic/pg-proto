//! `PostgreSQL`'s untagged pre-startup protocol.
//!
//! These packets precede normal message framing. Encryption acceptance is a raw
//! byte, and a successful negotiation changes the connection's transport type.

use crate::{Conn, Pristine};

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

    pub fn startup(self) -> Conn<S, Startup> {
        self.transition()
    }

    pub fn cancel_request(
        self,
        process_id: u32,
        secret_key: u32,
    ) -> (Conn<S, Terminated>, [u8; 16]) {
        let mut packet = [0; 16];
        packet[..4].copy_from_slice(&16_u32.to_be_bytes());
        packet[4..8].copy_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
        packet[8..12].copy_from_slice(&process_id.to_be_bytes());
        packet[12..].copy_from_slice(&secret_key.to_be_bytes());
        (self.transition(), packet)
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

        let (_, cancel) = Conn::new(()).cancel_request(0x0102_0304, 0x0506_0708);
        assert_eq!(
            cancel,
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
        let _startup: Conn<Tls, Startup> = upgraded.startup();
    }
}
