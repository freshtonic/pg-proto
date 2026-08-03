//! Typed payloads carried inside walsender `CopyData` messages.

use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendReplication {
    XLogData {
        wal_start: u64,
        wal_end: u64,
        server_time: i64,
        data: Bytes,
    },
    PrimaryKeepalive {
        wal_end: u64,
        server_time: i64,
        reply_requested: bool,
    },
    Unknown {
        tag: u8,
        body: Bytes,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrontendReplication {
    StandbyStatus {
        written: u64,
        flushed: u64,
        applied: u64,
        client_time: i64,
        reply_requested: bool,
    },
    HotStandbyFeedback {
        client_time: i64,
        xmin: u32,
        xmin_epoch: u32,
        catalog_xmin: u32,
        catalog_xmin_epoch: u32,
    },
    Unknown {
        tag: u8,
        body: Bytes,
    },
}

impl BackendReplication {
    /// Decodes a backend walsender payload while preserving extension messages.
    ///
    /// # Errors
    ///
    /// Returns an error for a truncated known message or an invalid Boolean byte.
    pub fn decode(mut payload: Bytes) -> io::Result<Self> {
        let tag = take_tag(&mut payload)?;
        match tag {
            b'w' => {
                require(&payload, 24, "truncated XLogData")?;
                Ok(Self::XLogData {
                    wal_start: payload.get_u64(),
                    wal_end: payload.get_u64(),
                    server_time: payload.get_i64(),
                    data: payload,
                })
            }
            b'k' => {
                require_exact(&payload, 17, "invalid primary keepalive length")?;
                let wal_end = payload.get_u64();
                let server_time = payload.get_i64();
                let reply_requested = take_bool(payload.get_u8())?;
                Ok(Self::PrimaryKeepalive {
                    wal_end,
                    server_time,
                    reply_requested,
                })
            }
            tag => Ok(Self::Unknown { tag, body: payload }),
        }
    }

    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut output = BytesMut::new();
        match self {
            Self::XLogData {
                wal_start,
                wal_end,
                server_time,
                data,
            } => {
                output.put_u8(b'w');
                output.put_u64(*wal_start);
                output.put_u64(*wal_end);
                output.put_i64(*server_time);
                output.extend_from_slice(data);
            }
            Self::PrimaryKeepalive {
                wal_end,
                server_time,
                reply_requested,
            } => {
                output.put_u8(b'k');
                output.put_u64(*wal_end);
                output.put_i64(*server_time);
                output.put_u8(u8::from(*reply_requested));
            }
            Self::Unknown { tag, body } => {
                output.put_u8(*tag);
                output.extend_from_slice(body);
            }
        }
        output.freeze()
    }
}

impl FrontendReplication {
    /// Decodes a standby payload while preserving extension messages.
    ///
    /// # Errors
    ///
    /// Returns an error for a truncated known message or an invalid Boolean byte.
    pub fn decode(mut payload: Bytes) -> io::Result<Self> {
        let tag = take_tag(&mut payload)?;
        match tag {
            b'r' => {
                require_exact(&payload, 33, "invalid standby status length")?;
                let written = payload.get_u64();
                let flushed = payload.get_u64();
                let applied = payload.get_u64();
                let client_time = payload.get_i64();
                let reply_requested = take_bool(payload.get_u8())?;
                Ok(Self::StandbyStatus {
                    written,
                    flushed,
                    applied,
                    client_time,
                    reply_requested,
                })
            }
            b'h' => {
                require_exact(&payload, 24, "invalid hot standby feedback length")?;
                Ok(Self::HotStandbyFeedback {
                    client_time: payload.get_i64(),
                    xmin: payload.get_u32(),
                    xmin_epoch: payload.get_u32(),
                    catalog_xmin: payload.get_u32(),
                    catalog_xmin_epoch: payload.get_u32(),
                })
            }
            tag => Ok(Self::Unknown { tag, body: payload }),
        }
    }

    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut output = BytesMut::new();
        match self {
            Self::StandbyStatus {
                written,
                flushed,
                applied,
                client_time,
                reply_requested,
            } => {
                output.put_u8(b'r');
                output.put_u64(*written);
                output.put_u64(*flushed);
                output.put_u64(*applied);
                output.put_i64(*client_time);
                output.put_u8(u8::from(*reply_requested));
            }
            Self::HotStandbyFeedback {
                client_time,
                xmin,
                xmin_epoch,
                catalog_xmin,
                catalog_xmin_epoch,
            } => {
                output.put_u8(b'h');
                output.put_i64(*client_time);
                output.put_u32(*xmin);
                output.put_u32(*xmin_epoch);
                output.put_u32(*catalog_xmin);
                output.put_u32(*catalog_xmin_epoch);
            }
            Self::Unknown { tag, body } => {
                output.put_u8(*tag);
                output.extend_from_slice(body);
            }
        }
        output.freeze()
    }
}

fn take_tag(payload: &mut Bytes) -> io::Result<u8> {
    if payload.is_empty() {
        Err(invalid("empty replication payload"))
    } else {
        Ok(payload.get_u8())
    }
}

fn take_bool(value: u8) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("invalid replication Boolean")),
    }
}

fn require(payload: &Bytes, minimum: usize, message: &'static str) -> io::Result<()> {
    if payload.len() < minimum {
        Err(invalid(message))
    } else {
        Ok(())
    }
}

fn require_exact(payload: &Bytes, length: usize, message: &'static str) -> io::Result<()> {
    if payload.len() == length {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_replication_messages_round_trip() {
        let backend = [
            BackendReplication::XLogData {
                wal_start: 10,
                wal_end: 20,
                server_time: -30,
                data: Bytes::from_static(b"wal"),
            },
            BackendReplication::PrimaryKeepalive {
                wal_end: 40,
                server_time: 50,
                reply_requested: true,
            },
            BackendReplication::Unknown {
                tag: b'z',
                body: Bytes::from_static(b"extension"),
            },
        ];
        for message in backend {
            assert_eq!(
                BackendReplication::decode(message.encode()).unwrap(),
                message
            );
        }

        let frontend = [
            FrontendReplication::StandbyStatus {
                written: 10,
                flushed: 20,
                applied: 30,
                client_time: 40,
                reply_requested: false,
            },
            FrontendReplication::HotStandbyFeedback {
                client_time: 50,
                xmin: 60,
                xmin_epoch: 70,
                catalog_xmin: 80,
                catalog_xmin_epoch: 90,
            },
            FrontendReplication::Unknown {
                tag: b'z',
                body: Bytes::from_static(b"extension"),
            },
        ];
        for message in frontend {
            assert_eq!(
                FrontendReplication::decode(message.encode()).unwrap(),
                message
            );
        }
    }

    #[test]
    fn known_messages_reject_invalid_shapes() {
        assert!(BackendReplication::decode(Bytes::from_static(b"kshort")).is_err());
        let mut invalid_bool = BytesMut::new();
        invalid_bool.put_u8(b'k');
        invalid_bool.extend_from_slice(&[0; 16]);
        invalid_bool.put_u8(2);
        assert!(BackendReplication::decode(invalid_bool.freeze()).is_err());
    }
}
