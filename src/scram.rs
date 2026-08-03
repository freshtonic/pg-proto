//! Server-side SCRAM-SHA-256 and SCRAM-SHA-256-PLUS verification.

use std::{io, str};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hmac::{Hmac, KeyInit as _, Mac as _};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

pub const SCRAM_SHA_256: &[u8] = b"SCRAM-SHA-256";
pub const SCRAM_SHA_256_PLUS: &[u8] = b"SCRAM-SHA-256-PLUS";
pub const DEFAULT_ITERATIONS: u32 = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerChannelBinding {
    None,
    TlsServerEndPoint(Vec<u8>),
}

/// Reusable server policy holding the credential and channel-binding context.
pub struct ScramServer {
    password: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
    channel_binding: ServerChannelBinding,
}

/// One nonce-bound SCRAM exchange awaiting the client-final message.
pub struct ScramExchange {
    salted_password: [u8; 32],
    client_first_bare: String,
    server_first: String,
    combined_nonce: String,
    expected_channel_binding: Vec<u8>,
}

impl ScramServer {
    /// Creates a server policy with a random 16-byte salt.
    #[must_use]
    pub fn new(password: &[u8], channel_binding: ServerChannelBinding) -> Self {
        let mut salt = vec![0; 16];
        rand::rng().fill(&mut salt[..]);
        Self {
            password: normalize(password),
            salt,
            iterations: DEFAULT_ITERATIONS,
            channel_binding,
        }
    }

    /// Creates a deterministic policy, primarily for persisted verifiers and tests.
    ///
    /// # Errors
    ///
    /// Rejects an iteration count below RFC 7677's recommended minimum.
    pub fn with_parameters(
        password: &[u8],
        salt: Vec<u8>,
        iterations: u32,
        channel_binding: ServerChannelBinding,
    ) -> io::Result<Self> {
        if iterations < DEFAULT_ITERATIONS {
            return Err(invalid("SCRAM iteration count is below 4096"));
        }
        Ok(Self {
            password: normalize(password),
            salt,
            iterations,
            channel_binding,
        })
    }

    /// Accepts a SASL initial response and creates the server-first challenge.
    ///
    /// # Errors
    ///
    /// Rejects unsupported mechanisms, malformed attributes, invalid nonces,
    /// and channel-binding downgrade attempts.
    pub fn start(
        &self,
        mechanism: &[u8],
        client_first: &[u8],
    ) -> io::Result<(ScramExchange, Bytes)> {
        let client_first = str::from_utf8(client_first)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let (gs2_header, client_first_bare) = split_gs2(client_first)?;
        let plus = match mechanism {
            SCRAM_SHA_256 => false,
            SCRAM_SHA_256_PLUS => true,
            _ => return Err(invalid("unsupported SCRAM mechanism")),
        };
        let expected_channel_binding = self.expected_binding(plus, gs2_header)?;
        let attributes = attributes(client_first_bare)?;
        reject_mandatory_extension(&attributes)?;
        let client_nonce = required(&attributes, b'r')?;
        validate_nonce(client_nonce)?;
        let _username = required(&attributes, b'n')?;

        let server_nonce = random_nonce();
        let combined_nonce = format!("{client_nonce}{server_nonce}");
        let server_first = format!(
            "r={combined_nonce},s={},i={}",
            STANDARD.encode(&self.salt),
            self.iterations
        );
        let exchange = ScramExchange {
            salted_password: hi(&self.password, &self.salt, self.iterations),
            client_first_bare: client_first_bare.to_owned(),
            server_first: server_first.clone(),
            combined_nonce,
            expected_channel_binding,
        };
        Ok((exchange, Bytes::from(server_first)))
    }

    fn expected_binding(&self, plus: bool, gs2_header: &str) -> io::Result<Vec<u8>> {
        match (plus, &self.channel_binding) {
            (true, ServerChannelBinding::TlsServerEndPoint(binding))
                if gs2_header == "p=tls-server-end-point,," =>
            {
                let mut expected = gs2_header.as_bytes().to_vec();
                expected.extend_from_slice(binding);
                Ok(expected)
            }
            (true, _) => Err(invalid(
                "SCRAM-PLUS channel binding is unavailable or invalid",
            )),
            (false, ServerChannelBinding::TlsServerEndPoint(_)) if gs2_header == "y,," => {
                Err(invalid("SCRAM channel-binding downgrade detected"))
            }
            (false, _) if matches!(gs2_header, "n,," | "y,,") => Ok(gs2_header.as_bytes().to_vec()),
            (false, _) => Err(invalid("channel binding used with SCRAM-SHA-256")),
        }
    }
}

impl ScramExchange {
    /// Verifies the client proof and returns the server-final verifier.
    ///
    /// # Errors
    ///
    /// Rejects malformed attributes, nonce or channel-binding mismatches, and
    /// invalid client proofs.
    pub fn finish(self, client_final: &[u8]) -> io::Result<Bytes> {
        let client_final = str::from_utf8(client_final)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let proof_marker = client_final
            .rfind(",p=")
            .ok_or_else(|| invalid("SCRAM client-final has no proof"))?;
        let without_proof = &client_final[..proof_marker];
        let attributes = attributes(client_final)?;
        reject_mandatory_extension(&attributes)?;
        if required(&attributes, b'r')? != self.combined_nonce {
            return Err(invalid("SCRAM nonce mismatch"));
        }
        let channel_binding = STANDARD
            .decode(required(&attributes, b'c')?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if !bool::from(channel_binding.ct_eq(&self.expected_channel_binding)) {
            return Err(invalid("SCRAM channel binding mismatch"));
        }
        let encoded_proof = required(&attributes, b'p')?;
        if proof_marker + 3 + encoded_proof.len() != client_final.len() {
            return Err(invalid("SCRAM proof is not the final attribute"));
        }
        let proof = STANDARD
            .decode(encoded_proof)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if proof.len() != 32 {
            return Err(invalid("SCRAM proof is not 32 bytes"));
        }

        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, without_proof
        );
        let client_key = hmac(&self.salted_password, b"Client Key");
        let stored_key = Sha256::digest(client_key);
        let client_signature = hmac(&stored_key, auth_message.as_bytes());
        let mut recovered_key = [0; 32];
        for ((recovered, proof), signature) in
            recovered_key.iter_mut().zip(proof).zip(client_signature)
        {
            *recovered = proof ^ signature;
        }
        let recovered_stored_key = Sha256::digest(recovered_key);
        if !bool::from(recovered_stored_key.ct_eq(&stored_key)) {
            return Err(invalid("invalid SCRAM client proof"));
        }

        let server_key = hmac(&self.salted_password, b"Server Key");
        let server_signature = hmac(&server_key, auth_message.as_bytes());
        Ok(Bytes::from(format!(
            "v={}",
            STANDARD.encode(server_signature)
        )))
    }
}

fn split_gs2(message: &str) -> io::Result<(&str, &str)> {
    let first = message
        .find(',')
        .ok_or_else(|| invalid("malformed SCRAM GS2 header"))?;
    let second = message[first + 1..]
        .find(',')
        .map(|position| first + 1 + position)
        .ok_or_else(|| invalid("malformed SCRAM GS2 header"))?;
    Ok((&message[..=second], &message[second + 1..]))
}

fn attributes(message: &str) -> io::Result<Vec<(u8, &str)>> {
    let mut output = Vec::new();
    for attribute in message.split(',') {
        let bytes = attribute.as_bytes();
        if bytes.len() < 2 || bytes[1] != b'=' || !bytes[0].is_ascii_alphabetic() {
            return Err(invalid("malformed SCRAM attribute"));
        }
        if output.iter().any(|(name, _)| *name == bytes[0]) {
            return Err(invalid("duplicate SCRAM attribute"));
        }
        output.push((bytes[0], &attribute[2..]));
    }
    Ok(output)
}

fn required<'a>(attributes: &[(u8, &'a str)], name: u8) -> io::Result<&'a str> {
    attributes
        .iter()
        .find_map(|(candidate, value)| (*candidate == name).then_some(*value))
        .ok_or_else(|| invalid("required SCRAM attribute is missing"))
}

fn reject_mandatory_extension(attributes: &[(u8, &str)]) -> io::Result<()> {
    if attributes.iter().any(|(name, _)| *name == b'm') {
        Err(invalid("unsupported mandatory SCRAM extension"))
    } else {
        Ok(())
    }
}

fn validate_nonce(nonce: &str) -> io::Result<()> {
    if !nonce.is_empty()
        && nonce
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x2b | 0x2d..=0x7e))
    {
        Ok(())
    } else {
        Err(invalid("invalid SCRAM nonce"))
    }
}

fn random_nonce() -> String {
    let mut rng = rand::rng();
    (0..24)
        .map(|_| {
            let mut byte = rng.random_range(0x21_u8..0x7f);
            if byte == b',' {
                byte = b'~';
            }
            char::from(byte)
        })
        .collect()
}

fn normalize(password: &[u8]) -> Vec<u8> {
    let Ok(password) = str::from_utf8(password) else {
        return password.to_vec();
    };
    stringprep::saslprep(password).map_or_else(
        |_| password.as_bytes().to_vec(),
        |normalised| normalised.into_owned().into_bytes(),
    )
}

fn hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(salt.len() + 4);
    input.extend_from_slice(salt);
    input.extend_from_slice(&[0, 0, 0, 1]);
    let mut previous = hmac(password, &input);
    let mut output = previous;
    for _ in 1..iterations {
        previous = hmac(password, &previous);
        for (output, previous) in output.iter_mut().zip(previous) {
            *output ^= previous;
        }
    }
    output
}

fn hmac(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts every key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};

    use super::*;

    fn exchange(binding: ServerChannelBinding, client_binding: ChannelBinding, mechanism: &[u8]) {
        let server = ScramServer::with_parameters(
            b"pencil",
            b"fixed test salt".to_vec(),
            DEFAULT_ITERATIONS,
            binding,
        )
        .unwrap();
        let mut client = ScramSha256::new(b"pencil", client_binding);
        let (exchange, server_first) = server.start(mechanism, client.message()).unwrap();
        client.update(&server_first).unwrap();
        let server_final = exchange.finish(client.message()).unwrap();
        client.finish(&server_final).unwrap();
    }

    #[test]
    fn verifies_scram_sha_256() {
        exchange(
            ServerChannelBinding::None,
            ChannelBinding::unsupported(),
            SCRAM_SHA_256,
        );
    }

    #[test]
    fn verifies_scram_sha_256_plus() {
        let binding = b"certificate digest".to_vec();
        exchange(
            ServerChannelBinding::TlsServerEndPoint(binding.clone()),
            ChannelBinding::tls_server_end_point(binding),
            SCRAM_SHA_256_PLUS,
        );
    }

    #[test]
    fn rejects_wrong_password_and_channel_binding() {
        let server = ScramServer::with_parameters(
            b"correct",
            b"fixed test salt".to_vec(),
            DEFAULT_ITERATIONS,
            ServerChannelBinding::None,
        )
        .unwrap();
        let mut client = ScramSha256::new(b"wrong", ChannelBinding::unsupported());
        let (exchange, server_first) = server.start(SCRAM_SHA_256, client.message()).unwrap();
        client.update(&server_first).unwrap();
        assert!(exchange.finish(client.message()).is_err());

        let server = ScramServer::with_parameters(
            b"correct",
            b"fixed test salt".to_vec(),
            DEFAULT_ITERATIONS,
            ServerChannelBinding::TlsServerEndPoint(b"expected".to_vec()),
        )
        .unwrap();
        let client = ScramSha256::new(
            b"correct",
            ChannelBinding::tls_server_end_point(b"different".to_vec()),
        );
        let (exchange, server_first) = server.start(SCRAM_SHA_256_PLUS, client.message()).unwrap();
        let mut client = client;
        client.update(&server_first).unwrap();
        assert!(exchange.finish(client.message()).is_err());
    }
}
