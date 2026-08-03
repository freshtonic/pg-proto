//! Direction-parameterised framing and lossless message decoding.

use std::{io, marker::PhantomData};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::startup::ProtocolVersion;

/// Messages sent by a `PostgreSQL` frontend.
#[derive(Debug)]
pub enum Frontend {}

/// Messages sent by a `PostgreSQL` backend.
#[derive(Debug)]
pub enum Backend {}

/// A validated `PostgreSQL` tagged frame, including its tag but not its length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub tag: u8,
    pub body: Bytes,
}

/// Decoder direction. The same byte tag has different meanings in each direction.
pub trait Direction {
    type Message;

    /// # Errors
    ///
    /// Returns an error when the tag is unknown or its body is malformed.
    fn decode(frame: Frame) -> io::Result<Self::Message>;
}

/// A `PostgreSQL` codec which cannot confuse frontend and backend tag alphabets.
#[derive(Debug)]
pub struct PgCodec<D> {
    _direction: PhantomData<fn() -> D>,
}

impl<D> Default for PgCodec<D> {
    fn default() -> Self {
        Self {
            _direction: PhantomData,
        }
    }
}

impl<D: Direction> Decoder for PgCodec<D> {
    type Item = D::Message;
    type Error = io::Error;

    fn decode(&mut self, source: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        let Some(frame) = decode_frame(source)? else {
            return Ok(None);
        };
        let tag = frame.tag;
        D::decode(frame).map(Some).map_err(|error| {
            io::Error::new(error.kind(), format!("message tag 0x{tag:02x}: {error}"))
        })
    }
}

impl<D> Encoder<Frame> for PgCodec<D> {
    type Error = io::Error;

    fn encode(&mut self, item: Frame, destination: &mut BytesMut) -> io::Result<()> {
        let length = item
            .body
            .len()
            .checked_add(4)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
        destination.reserve(item.body.len() + 5);
        destination.put_u8(item.tag);
        destination.put_u32(length);
        destination.extend_from_slice(&item.body);
        Ok(())
    }
}

fn decode_frame(source: &mut BytesMut) -> io::Result<Option<Frame>> {
    if source.len() < 5 {
        source.reserve(5 - source.len());
        return Ok(None);
    }

    let length = u32::from_be_bytes(source[1..5].try_into().expect("four-byte slice"));
    if length < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message length is smaller than its length field",
        ));
    }
    let frame_length = usize::try_from(length)
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message length overflow"))?;
    if source.len() < frame_length {
        source.reserve(frame_length - source.len());
        return Ok(None);
    }

    let tag = source[0];
    let mut bytes = source.split_to(frame_length).freeze();
    bytes.advance(5);
    Ok(Some(Frame { tag, body: bytes }))
}

/// Frontend messages whose contents a rewriting proxy must retain structurally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrontendMessage {
    Parse(Parse),
    Bind(Bind),
    Describe(Describe),
    /// A recognised message not yet lifted into a more specific representation.
    Recognised(Frame),
}

impl FrontendMessage {
    /// Reconstructs a frontend frame after inspection or modification.
    ///
    /// # Errors
    ///
    /// Returns an error when a structured message contains invalid values.
    pub fn to_frame(&self) -> io::Result<Frame> {
        match self {
            Self::Parse(message) => message.to_frame(),
            Self::Bind(message) => message.to_frame(),
            Self::Describe(message) => message.to_frame(),
            Self::Recognised(frame) => Ok(frame.clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parse {
    pub statement: Bytes,
    pub query: Bytes,
    pub parameter_types: Vec<u32>,
}

impl Parse {
    /// Reconstructs a checked Parse frame after inspection or rewriting.
    ///
    /// # Errors
    ///
    /// Returns an error for NUL-containing strings or too many parameter types.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        put_cstr(&self.statement, &mut body)?;
        put_cstr(&self.query, &mut body)?;
        put_count(self.parameter_types.len(), &mut body)?;
        for oid in &self.parameter_types {
            body.put_u32(*oid);
        }
        Ok(Frame {
            tag: b'P',
            body: body.freeze(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bind {
    pub portal: Bytes,
    pub statement: Bytes,
    pub parameter_formats: Vec<i16>,
    pub parameters: Vec<Option<Bytes>>,
    pub result_formats: Vec<i16>,
}

impl Bind {
    /// Reconstructs a checked Bind frame, retaining every format code and value.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid names, excessive counts, or oversized values.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        put_cstr(&self.portal, &mut body)?;
        put_cstr(&self.statement, &mut body)?;
        put_i16_vec(&self.parameter_formats, &mut body)?;
        put_count(self.parameters.len(), &mut body)?;
        for parameter in &self.parameters {
            match parameter {
                None => body.put_i32(-1),
                Some(value) => {
                    let length = i32::try_from(value.len())
                        .map_err(|_| invalid_input("Bind parameter is too large"))?;
                    body.put_i32(length);
                    body.extend_from_slice(value);
                }
            }
        }
        put_i16_vec(&self.result_formats, &mut body)?;
        Ok(Frame {
            tag: b'B',
            body: body.freeze(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Describe {
    pub target: DescribeTarget,
    pub name: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescribeTarget {
    Statement,
    Portal,
}

impl Describe {
    /// Reconstructs a checked Describe frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the name contains a NUL byte.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        body.put_u8(match self.target {
            DescribeTarget::Statement => b'S',
            DescribeTarget::Portal => b'P',
        });
        put_cstr(&self.name, &mut body)?;
        Ok(Frame {
            tag: b'D',
            body: body.freeze(),
        })
    }
}

impl Direction for Frontend {
    type Message = FrontendMessage;

    fn decode(frame: Frame) -> io::Result<Self::Message> {
        match frame.tag {
            b'P' => decode_parse(frame.body).map(FrontendMessage::Parse),
            b'B' => decode_bind(frame.body).map(FrontendMessage::Bind),
            b'D' => decode_describe(frame.body).map(FrontendMessage::Describe),
            b'C' | b'E' | b'F' | b'H' | b'Q' | b'S' | b'X' | b'c' | b'd' | b'f' | b'p' => {
                Ok(FrontendMessage::Recognised(frame))
            }
            tag => Err(unknown_tag("frontend", tag)),
        }
    }
}

/// Backend row metadata retained in reconstructable form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowDescription {
    pub fields: Vec<FieldDescription>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldDescription {
    pub name: Bytes,
    pub table_oid: u32,
    pub column: i16,
    pub type_oid: u32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format: i16,
}

impl RowDescription {
    /// Reconstructs checked result metadata after proxy rewriting.
    ///
    /// # Errors
    ///
    /// Returns an error for excessive fields or NUL-containing field names.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        put_count(self.fields.len(), &mut body)?;
        for field in &self.fields {
            put_cstr(&field.name, &mut body)?;
            body.put_u32(field.table_oid);
            body.put_i16(field.column);
            body.put_u32(field.type_oid);
            body.put_i16(field.type_size);
            body.put_i32(field.type_modifier);
            body.put_i16(field.format);
        }
        Ok(Frame {
            tag: b'T',
            body: body.freeze(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Authentication {
    Ok,
    KerberosV5,
    CleartextPassword,
    Md5Password { salt: [u8; 4] },
    Gss,
    GssContinue(Bytes),
    Sspi,
    Sasl { mechanisms: Vec<Bytes> },
    SaslContinue(Bytes),
    SaslFinal(Bytes),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionStatus {
    Idle,
    InTransaction,
    FailedTransaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiateProtocolVersion {
    pub newest: ProtocolVersion,
    pub unsupported_options: Vec<Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendMessage {
    RowDescription(RowDescription),
    Authentication(Authentication),
    ParameterStatus {
        name: Bytes,
        value: Bytes,
    },
    NoticeResponse(Bytes),
    NotificationResponse {
        process_id: u32,
        channel: Bytes,
        payload: Bytes,
    },
    BackendKeyData {
        process_id: u32,
        secret_key: Bytes,
    },
    ReadyForQuery(TransactionStatus),
    NegotiateProtocolVersion(NegotiateProtocolVersion),
    /// A recognised message not yet lifted into a more specific representation.
    Recognised(Frame),
}

impl BackendMessage {
    /// Reconstructs a backend frame after inspection or modification.
    ///
    /// # Errors
    ///
    /// Returns an error when a structured message contains invalid values.
    pub fn to_frame(&self) -> io::Result<Frame> {
        match self {
            Self::RowDescription(message) => message.to_frame(),
            Self::Authentication(message) => authentication_frame(message),
            Self::ParameterStatus { name, value } => {
                let mut body = BytesMut::new();
                put_cstr(name, &mut body)?;
                put_cstr(value, &mut body)?;
                Ok(Frame {
                    tag: b'S',
                    body: body.freeze(),
                })
            }
            Self::NoticeResponse(body) => Ok(Frame {
                tag: b'N',
                body: body.clone(),
            }),
            Self::NotificationResponse {
                process_id,
                channel,
                payload,
            } => {
                let mut body = BytesMut::new();
                body.put_u32(*process_id);
                put_cstr(channel, &mut body)?;
                put_cstr(payload, &mut body)?;
                Ok(Frame {
                    tag: b'A',
                    body: body.freeze(),
                })
            }
            Self::BackendKeyData {
                process_id,
                secret_key,
            } => {
                if !(4..=256).contains(&secret_key.len()) {
                    return Err(invalid_input("cancellation key length is outside 4..=256"));
                }
                let mut body = BytesMut::with_capacity(4 + secret_key.len());
                body.put_u32(*process_id);
                body.extend_from_slice(secret_key);
                Ok(Frame {
                    tag: b'K',
                    body: body.freeze(),
                })
            }
            Self::ReadyForQuery(status) => Ok(Frame {
                tag: b'Z',
                body: Bytes::copy_from_slice(&[status.as_byte()]),
            }),
            Self::NegotiateProtocolVersion(message) => message.to_frame(),
            Self::Recognised(frame) => Ok(frame.clone()),
        }
    }
}

impl TransactionStatus {
    const fn as_byte(self) -> u8 {
        match self {
            Self::Idle => b'I',
            Self::InTransaction => b'T',
            Self::FailedTransaction => b'E',
        }
    }
}

impl NegotiateProtocolVersion {
    /// Reconstructs protocol negotiation, including unsupported option names.
    ///
    /// # Errors
    ///
    /// Returns an error for too many options or NUL-containing names.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        body.put_u32((u32::from(self.newest.major) << 16) | u32::from(self.newest.minor));
        let count = u32::try_from(self.unsupported_options.len())
            .map_err(|_| invalid_input("unsupported option count exceeds u32"))?;
        body.put_u32(count);
        for option in &self.unsupported_options {
            put_cstr(option, &mut body)?;
        }
        Ok(Frame {
            tag: b'v',
            body: body.freeze(),
        })
    }
}

fn authentication_frame(authentication: &Authentication) -> io::Result<Frame> {
    let mut body = BytesMut::new();
    match authentication {
        Authentication::Ok => body.put_u32(0),
        Authentication::KerberosV5 => body.put_u32(2),
        Authentication::CleartextPassword => body.put_u32(3),
        Authentication::Md5Password { salt } => {
            body.put_u32(5);
            body.extend_from_slice(salt);
        }
        Authentication::Gss => body.put_u32(7),
        Authentication::GssContinue(data) => {
            body.put_u32(8);
            body.extend_from_slice(data);
        }
        Authentication::Sspi => body.put_u32(9),
        Authentication::Sasl { mechanisms } => {
            body.put_u32(10);
            for mechanism in mechanisms {
                put_cstr(mechanism, &mut body)?;
            }
            body.put_u8(0);
        }
        Authentication::SaslContinue(data) => {
            body.put_u32(11);
            body.extend_from_slice(data);
        }
        Authentication::SaslFinal(data) => {
            body.put_u32(12);
            body.extend_from_slice(data);
        }
    }
    Ok(Frame {
        tag: b'R',
        body: body.freeze(),
    })
}

impl Direction for Backend {
    type Message = BackendMessage;

    fn decode(frame: Frame) -> io::Result<Self::Message> {
        match frame.tag {
            b'T' => decode_row_description(frame.body).map(BackendMessage::RowDescription),
            b'R' => decode_authentication(frame.body).map(BackendMessage::Authentication),
            b'S' => decode_parameter_status(frame.body),
            b'N' => Ok(BackendMessage::NoticeResponse(frame.body)),
            b'A' => decode_notification(frame.body),
            b'K' => decode_backend_key_data(frame.body),
            b'Z' => decode_ready(frame.body),
            b'v' => decode_negotiate_protocol_version(frame.body),
            b'1' | b'2' | b'3' | b'c' | b'C' | b'd' | b'D' | b'E' | b'G' | b'H' | b'I' | b'n'
            | b's' | b't' | b'V' | b'W' => Ok(BackendMessage::Recognised(frame)),
            tag => Err(unknown_tag("backend", tag)),
        }
    }
}

fn decode_authentication(mut body: Bytes) -> io::Result<Authentication> {
    let kind = take_u32(&mut body)?;
    let auth = match kind {
        0 => Authentication::Ok,
        2 => Authentication::KerberosV5,
        3 => Authentication::CleartextPassword,
        5 => {
            require(&body, 4)?;
            let salt = body.split_to(4);
            Authentication::Md5Password {
                salt: salt[..].try_into().expect("four-byte slice"),
            }
        }
        7 => Authentication::Gss,
        8 => Authentication::GssContinue(body.split_to(body.len())),
        9 => Authentication::Sspi,
        10 => {
            let mut mechanisms = Vec::new();
            while !body.is_empty() && body[0] != 0 {
                mechanisms.push(take_cstr(&mut body)?);
            }
            require(&body, 1)?;
            body.advance(1);
            Authentication::Sasl { mechanisms }
        }
        11 => Authentication::SaslContinue(body.split_to(body.len())),
        12 => Authentication::SaslFinal(body.split_to(body.len())),
        _ => return Err(invalid("unknown authentication request")),
    };
    require_empty(&body)?;
    Ok(auth)
}

fn decode_parameter_status(mut body: Bytes) -> io::Result<BackendMessage> {
    let name = take_cstr(&mut body)?;
    let value = take_cstr(&mut body)?;
    require_empty(&body)?;
    Ok(BackendMessage::ParameterStatus { name, value })
}

fn decode_notification(mut body: Bytes) -> io::Result<BackendMessage> {
    let process_id = take_u32(&mut body)?;
    let channel = take_cstr(&mut body)?;
    let payload = take_cstr(&mut body)?;
    require_empty(&body)?;
    Ok(BackendMessage::NotificationResponse {
        process_id,
        channel,
        payload,
    })
}

fn decode_backend_key_data(mut body: Bytes) -> io::Result<BackendMessage> {
    let process_id = take_u32(&mut body)?;
    if !(4..=256).contains(&body.len()) {
        return Err(invalid("cancellation key length is outside 4..=256"));
    }
    let secret_key = body;
    Ok(BackendMessage::BackendKeyData {
        process_id,
        secret_key,
    })
}

fn decode_ready(mut body: Bytes) -> io::Result<BackendMessage> {
    require(&body, 1)?;
    let status = match body.get_u8() {
        b'I' => TransactionStatus::Idle,
        b'T' => TransactionStatus::InTransaction,
        b'E' => TransactionStatus::FailedTransaction,
        _ => return Err(invalid("unknown transaction status")),
    };
    require_empty(&body)?;
    Ok(BackendMessage::ReadyForQuery(status))
}

fn decode_negotiate_protocol_version(mut body: Bytes) -> io::Result<BackendMessage> {
    let newest = take_u32(&mut body)?;
    let major = u16::try_from(newest >> 16).map_err(|_| invalid("protocol major overflow"))?;
    let minor = u16::try_from(newest & 0xffff).map_err(|_| invalid("protocol minor overflow"))?;
    let count = take_u32(&mut body)?;
    let capacity = usize::try_from(count).map_err(|_| invalid("option count overflow"))?;
    let mut unsupported_options = Vec::with_capacity(capacity);
    for _ in 0..count {
        unsupported_options.push(take_cstr(&mut body)?);
    }
    require_empty(&body)?;
    Ok(BackendMessage::NegotiateProtocolVersion(
        NegotiateProtocolVersion {
            newest: ProtocolVersion { major, minor },
            unsupported_options,
        },
    ))
}

fn decode_parse(mut body: Bytes) -> io::Result<Parse> {
    let statement = take_cstr(&mut body)?;
    let query = take_cstr(&mut body)?;
    let count = take_u16(&mut body)?;
    let mut parameter_types = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        parameter_types.push(take_u32(&mut body)?);
    }
    require_empty(&body)?;
    Ok(Parse {
        statement,
        query,
        parameter_types,
    })
}

fn decode_bind(mut body: Bytes) -> io::Result<Bind> {
    let portal = take_cstr(&mut body)?;
    let statement = take_cstr(&mut body)?;
    let parameter_formats = take_i16_vec(&mut body)?;
    let parameter_count = take_u16(&mut body)?;
    let mut parameters = Vec::with_capacity(usize::from(parameter_count));
    for _ in 0..parameter_count {
        let length = take_i32(&mut body)?;
        if length == -1 {
            parameters.push(None);
        } else {
            let length =
                usize::try_from(length).map_err(|_| invalid("negative parameter length"))?;
            require(&body, length)?;
            parameters.push(Some(body.split_to(length)));
        }
    }
    let result_formats = take_i16_vec(&mut body)?;
    require_empty(&body)?;
    Ok(Bind {
        portal,
        statement,
        parameter_formats,
        parameters,
        result_formats,
    })
}

fn decode_describe(mut body: Bytes) -> io::Result<Describe> {
    require(&body, 1)?;
    let target = match body.get_u8() {
        b'S' => DescribeTarget::Statement,
        b'P' => DescribeTarget::Portal,
        _ => return Err(invalid("invalid Describe target")),
    };
    let name = take_cstr(&mut body)?;
    require_empty(&body)?;
    Ok(Describe { target, name })
}

fn decode_row_description(mut body: Bytes) -> io::Result<RowDescription> {
    let count = take_u16(&mut body)?;
    let mut fields = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        fields.push(FieldDescription {
            name: take_cstr(&mut body)?,
            table_oid: take_u32(&mut body)?,
            column: take_i16(&mut body)?,
            type_oid: take_u32(&mut body)?,
            type_size: take_i16(&mut body)?,
            type_modifier: take_i32(&mut body)?,
            format: take_i16(&mut body)?,
        });
    }
    require_empty(&body)?;
    Ok(RowDescription { fields })
}

fn take_i16_vec(body: &mut Bytes) -> io::Result<Vec<i16>> {
    let count = take_u16(body)?;
    (0..count).map(|_| take_i16(body)).collect()
}

fn put_i16_vec(values: &[i16], body: &mut BytesMut) -> io::Result<()> {
    put_count(values.len(), body)?;
    for value in values {
        body.put_i16(*value);
    }
    Ok(())
}

fn put_count(count: usize, body: &mut BytesMut) -> io::Result<()> {
    let count =
        u16::try_from(count).map_err(|_| invalid_input("message item count exceeds u16"))?;
    body.put_u16(count);
    Ok(())
}

fn put_cstr(value: &[u8], body: &mut BytesMut) -> io::Result<()> {
    if value.contains(&0) {
        return Err(invalid_input("message string contains a NUL byte"));
    }
    body.extend_from_slice(value);
    body.put_u8(0);
    Ok(())
}

fn take_cstr(body: &mut Bytes) -> io::Result<Bytes> {
    let end = body
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("unterminated string"))?;
    let value = body.split_to(end);
    body.advance(1);
    Ok(value)
}

fn take_u16(body: &mut Bytes) -> io::Result<u16> {
    require(body, 2)?;
    Ok(body.get_u16())
}

fn take_i16(body: &mut Bytes) -> io::Result<i16> {
    require(body, 2)?;
    Ok(body.get_i16())
}

fn take_u32(body: &mut Bytes) -> io::Result<u32> {
    require(body, 4)?;
    Ok(body.get_u32())
}

fn take_i32(body: &mut Bytes) -> io::Result<i32> {
    require(body, 4)?;
    Ok(body.get_i32())
}

fn require(body: &Bytes, length: usize) -> io::Result<()> {
    if body.len() < length {
        Err(invalid("truncated message body"))
    } else {
        Ok(())
    }
}

fn require_empty(body: &Bytes) -> io::Result<()> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(invalid("trailing message bytes"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unknown_tag(direction: &str, tag: u8) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unknown {direction} message tag 0x{tag:02x}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_disambiguates_s_tag() {
        let frontend_frame = Frame {
            tag: b'S',
            body: Bytes::new(),
        };
        assert!(matches!(
            Frontend::decode(frontend_frame),
            Ok(FrontendMessage::Recognised(_))
        ));
        assert_eq!(
            Backend::decode(Frame {
                tag: b'S',
                body: Bytes::from_static(b"client_encoding\0UTF8\0"),
            })
            .expect("valid ParameterStatus"),
            BackendMessage::ParameterStatus {
                name: Bytes::from_static(b"client_encoding"),
                value: Bytes::from_static(b"UTF8"),
            }
        );
    }

    #[test]
    fn parse_is_losslessly_structured() {
        let mut bytes = BytesMut::from(&b"P\0\0\0\x19stmt\0select $1\0\0\x01\0\0\0\x17"[..]);
        let original = bytes.clone();
        let message = PgCodec::<Frontend>::default()
            .decode(&mut bytes)
            .expect("valid frame")
            .expect("complete frame");
        let expected = FrontendMessage::Parse(Parse {
            statement: Bytes::from_static(b"stmt"),
            query: Bytes::from_static(b"select $1"),
            parameter_types: vec![23],
        });
        assert_eq!(message, expected);

        let FrontendMessage::Parse(parsed) = message else {
            unreachable!()
        };
        let frame = parsed.to_frame().expect("reconstructable Parse");
        let mut encoded = BytesMut::new();
        PgCodec::<Frontend>::default()
            .encode(frame, &mut encoded)
            .expect("encodable frame");
        assert_eq!(encoded, original);
    }

    #[test]
    fn incomplete_frame_does_not_consume_input() {
        let mut bytes = BytesMut::from(&b"S\0\0\0\x04"[..4]);
        let original = bytes.clone();
        assert!(
            PgCodec::<Frontend>::default()
                .decode(&mut bytes)
                .expect("incomplete input is not an error")
                .is_none()
        );
        assert_eq!(bytes, original);
    }

    #[test]
    fn bind_round_trips_nulls_formats_and_values() {
        let bind = Bind {
            portal: Bytes::from_static(b"portal"),
            statement: Bytes::from_static(b"statement"),
            parameter_formats: vec![1, 0],
            parameters: vec![None, Some(Bytes::from_static(b"value"))],
            result_formats: vec![1],
        };
        let frame = bind.to_frame().expect("valid Bind");
        assert_eq!(
            Frontend::decode(frame).expect("decodable Bind"),
            FrontendMessage::Bind(bind)
        );
    }

    #[test]
    fn row_description_round_trips_all_metadata() {
        let description = RowDescription {
            fields: vec![FieldDescription {
                name: Bytes::from_static(b"answer"),
                table_oid: 16_384,
                column: 2,
                type_oid: 23,
                type_size: 4,
                type_modifier: -1,
                format: 1,
            }],
        };
        let frame = description.to_frame().expect("valid RowDescription");
        assert_eq!(
            Backend::decode(frame).expect("decodable RowDescription"),
            BackendMessage::RowDescription(description)
        );
    }
}
