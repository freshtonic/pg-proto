//! Untagged startup messages and protocol-version negotiation.

use std::{collections::BTreeMap, io};

use bytes::{BufMut, Bytes, BytesMut};

/// A frontend startup message, retained as bytes for lossless proxy forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupMessage {
    pub version: ProtocolVersion,
    pub parameters: BTreeMap<Bytes, Bytes>,
}

impl StartupMessage {
    /// Encodes the untagged startup packet.
    ///
    /// # Errors
    ///
    /// Returns an error for embedded NUL bytes or a packet larger than `i32::MAX`.
    pub fn encode(&self) -> io::Result<Bytes> {
        let mut output = BytesMut::new();
        output.extend_from_slice(&[0; 4]);
        output.put_u16(self.version.major);
        output.put_u16(self.version.minor);
        for (name, value) in &self.parameters {
            put_cstr(name, &mut output)?;
            put_cstr(value, &mut output)?;
        }
        output.put_u8(0);
        let length = i32::try_from(output.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "startup packet too large"))?;
        output[..4].copy_from_slice(&length.to_be_bytes());
        Ok(output.freeze())
    }
}

/// `PostgreSQL` protocol version, including supported 3.x minor versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const V3_0: Self = Self { major: 3, minor: 0 };
    pub const V3_1: Self = Self { major: 3, minor: 1 };
    pub const V3_2: Self = Self { major: 3, minor: 2 };
}

fn put_cstr(value: &[u8], output: &mut BytesMut) -> io::Result<()> {
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "startup parameter contains a NUL byte",
        ));
    }
    output.extend_from_slice(value);
    output.put_u8(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_packet_has_raw_length_and_version() {
        let message = StartupMessage {
            version: ProtocolVersion::V3_2,
            parameters: BTreeMap::from([
                (Bytes::from_static(b"database"), Bytes::from_static(b"db")),
                (Bytes::from_static(b"user"), Bytes::from_static(b"alice")),
            ]),
        };
        let encoded = message.encode().expect("valid startup message");
        assert_eq!(u32::from_be_bytes(encoded[..4].try_into().unwrap()), 32);
        assert_eq!(&encoded[4..8], &[0, 3, 0, 2]);
        assert_eq!(encoded.last(), Some(&0));
    }
}
