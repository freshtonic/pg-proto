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
    max_frame_len: usize,
    _direction: PhantomData<fn() -> D>,
}

const MAX_PROTOCOL_FRAME_LEN: usize = i32::MAX as usize + 1;

impl<D> Default for PgCodec<D> {
    fn default() -> Self {
        Self {
            max_frame_len: MAX_PROTOCOL_FRAME_LEN,
            _direction: PhantomData,
        }
    }
}

impl<D> PgCodec<D> {
    /// Creates a codec with a total tagged-frame limit, including tag and length.
    ///
    /// # Errors
    ///
    /// Rejects limits smaller than an empty frame or larger than `PostgreSQL`'s
    /// signed int32 length field can represent.
    pub fn with_max_frame_len(max_frame_len: usize) -> io::Result<Self> {
        if !(5..=MAX_PROTOCOL_FRAME_LEN).contains(&max_frame_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame limit is outside PostgreSQL's tagged-frame range",
            ));
        }
        Ok(Self {
            max_frame_len,
            _direction: PhantomData,
        })
    }
}

impl<D: Direction> Decoder for PgCodec<D> {
    type Item = D::Message;
    type Error = io::Error;

    fn decode(&mut self, source: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        let Some(frame) = decode_frame(source, self.max_frame_len)? else {
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
        let frame_len = item
            .body
            .len()
            .checked_add(5)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
        if frame_len > self.max_frame_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame exceeds configured limit",
            ));
        }
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

fn decode_frame(source: &mut BytesMut, max_frame_len: usize) -> io::Result<Option<Frame>> {
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
    if frame_length > MAX_PROTOCOL_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message length exceeds PostgreSQL's signed int32 range",
        ));
    }
    if frame_length > max_frame_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds configured frame limit",
        ));
    }
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
    Close(Close),
    Execute(Execute),
    FunctionCall(FunctionCall),
    Query(Bytes),
    Flush,
    Sync,
    Terminate,
    CopyData(Bytes),
    CopyDone,
    CopyFail(Bytes),
    /// Context determines whether this is password, GSS, or a SASL response.
    PasswordResponse(Bytes),
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
            Self::Close(message) => message.to_frame(),
            Self::Execute(message) => message.to_frame(),
            Self::FunctionCall(message) => message.to_frame(),
            Self::Query(query) => cstr_message(b'Q', query),
            Self::Flush => Ok(empty_message(b'H')),
            Self::Sync => Ok(empty_message(b'S')),
            Self::Terminate => Ok(empty_message(b'X')),
            Self::CopyData(data) => Ok(Frame {
                tag: b'd',
                body: data.clone(),
            }),
            Self::CopyDone => Ok(empty_message(b'c')),
            Self::CopyFail(message) => cstr_message(b'f', message),
            Self::PasswordResponse(data) => Ok(Frame {
                tag: b'p',
                body: data.clone(),
            }),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Close {
    pub target: DescribeTarget,
    pub name: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Execute {
    pub portal: Bytes,
    pub max_rows: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionCall {
    pub function_oid: u32,
    pub argument_formats: Vec<i16>,
    pub arguments: Vec<Option<Bytes>>,
    pub result_format: i16,
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

impl Close {
    /// # Errors
    ///
    /// Returns an error if the name contains a NUL byte.
    pub fn to_frame(&self) -> io::Result<Frame> {
        named_target_frame(b'C', self.target, &self.name)
    }
}

impl Execute {
    /// # Errors
    ///
    /// Returns an error if the portal name contains a NUL byte.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        put_cstr(&self.portal, &mut body)?;
        body.put_i32(self.max_rows);
        Ok(Frame {
            tag: b'E',
            body: body.freeze(),
        })
    }
}

impl FunctionCall {
    /// # Errors
    ///
    /// Returns an error for excessive counts or oversized argument values.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        body.put_u32(self.function_oid);
        put_i16_vec(&self.argument_formats, &mut body)?;
        put_count(self.arguments.len(), &mut body)?;
        for argument in &self.arguments {
            put_nullable(argument.as_ref(), &mut body)?;
        }
        body.put_i16(self.result_format);
        Ok(Frame {
            tag: b'F',
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
            b'C' => decode_close(frame.body).map(FrontendMessage::Close),
            b'E' => decode_execute(frame.body).map(FrontendMessage::Execute),
            b'F' => decode_function_call(frame.body).map(FrontendMessage::FunctionCall),
            b'H' => decode_empty(&frame.body).map(|()| FrontendMessage::Flush),
            b'Q' => decode_cstr_body(frame.body).map(FrontendMessage::Query),
            b'S' => decode_empty(&frame.body).map(|()| FrontendMessage::Sync),
            b'X' => decode_empty(&frame.body).map(|()| FrontendMessage::Terminate),
            b'c' => decode_empty(&frame.body).map(|()| FrontendMessage::CopyDone),
            b'd' => Ok(FrontendMessage::CopyData(frame.body)),
            b'f' => decode_cstr_body(frame.body).map(FrontendMessage::CopyFail),
            b'p' => Ok(FrontendMessage::PasswordResponse(frame.body)),
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
pub struct DiagnosticResponse {
    pub fields: Vec<DiagnosticField>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticField {
    pub code: u8,
    pub value: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyResponse {
    pub overall_format: u8,
    pub column_formats: Vec<i16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataRow {
    pub columns: Vec<Option<Bytes>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendMessage {
    RowDescription(RowDescription),
    Authentication(Authentication),
    ParseComplete,
    BindComplete,
    CloseComplete,
    CommandComplete(Bytes),
    CopyData(Bytes),
    CopyDone,
    CopyInResponse(CopyResponse),
    CopyOutResponse(CopyResponse),
    CopyBothResponse(CopyResponse),
    DataRow(DataRow),
    EmptyQueryResponse,
    ErrorResponse(DiagnosticResponse),
    NoData,
    ParameterStatus {
        name: Bytes,
        value: Bytes,
    },
    NoticeResponse(DiagnosticResponse),
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
    ParameterDescription(Vec<u32>),
    PortalSuspended,
    FunctionCallResponse(Bytes),
    NegotiateProtocolVersion(NegotiateProtocolVersion),
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
            Self::ParseComplete => Ok(empty_message(b'1')),
            Self::BindComplete => Ok(empty_message(b'2')),
            Self::CloseComplete => Ok(empty_message(b'3')),
            Self::CommandComplete(tag) => cstr_message(b'C', tag),
            Self::CopyData(data) => Ok(Frame {
                tag: b'd',
                body: data.clone(),
            }),
            Self::CopyDone => Ok(empty_message(b'c')),
            Self::CopyInResponse(response) => copy_response_frame(b'G', response),
            Self::CopyOutResponse(response) => copy_response_frame(b'H', response),
            Self::CopyBothResponse(response) => copy_response_frame(b'W', response),
            Self::DataRow(row) => row.to_frame(),
            Self::EmptyQueryResponse => Ok(empty_message(b'I')),
            Self::ErrorResponse(response) => diagnostic_frame(b'E', response),
            Self::NoData => Ok(empty_message(b'n')),
            Self::ParameterStatus { name, value } => {
                let mut body = BytesMut::new();
                put_cstr(name, &mut body)?;
                put_cstr(value, &mut body)?;
                Ok(Frame {
                    tag: b'S',
                    body: body.freeze(),
                })
            }
            Self::NoticeResponse(response) => diagnostic_frame(b'N', response),
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
            Self::ParameterDescription(types) => {
                let mut body = BytesMut::new();
                put_count(types.len(), &mut body)?;
                for oid in types {
                    body.put_u32(*oid);
                }
                Ok(Frame {
                    tag: b't',
                    body: body.freeze(),
                })
            }
            Self::PortalSuspended => Ok(empty_message(b's')),
            Self::FunctionCallResponse(data) => Ok(Frame {
                tag: b'V',
                body: data.clone(),
            }),
            Self::NegotiateProtocolVersion(message) => message.to_frame(),
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

impl DataRow {
    /// # Errors
    ///
    /// Returns an error for too many columns or oversized values.
    pub fn to_frame(&self) -> io::Result<Frame> {
        let mut body = BytesMut::new();
        put_count(self.columns.len(), &mut body)?;
        for column in &self.columns {
            put_nullable(column.as_ref(), &mut body)?;
        }
        Ok(Frame {
            tag: b'D',
            body: body.freeze(),
        })
    }
}

fn diagnostic_frame(tag: u8, response: &DiagnosticResponse) -> io::Result<Frame> {
    let mut body = BytesMut::new();
    for field in &response.fields {
        if field.code == 0 {
            return Err(invalid_input("diagnostic field code cannot be zero"));
        }
        body.put_u8(field.code);
        put_cstr(&field.value, &mut body)?;
    }
    body.put_u8(0);
    Ok(Frame {
        tag,
        body: body.freeze(),
    })
}

fn copy_response_frame(tag: u8, response: &CopyResponse) -> io::Result<Frame> {
    let mut body = BytesMut::new();
    body.put_u8(response.overall_format);
    put_i16_vec(&response.column_formats, &mut body)?;
    Ok(Frame {
        tag,
        body: body.freeze(),
    })
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
            b'1' => decode_empty(&frame.body).map(|()| BackendMessage::ParseComplete),
            b'2' => decode_empty(&frame.body).map(|()| BackendMessage::BindComplete),
            b'3' => decode_empty(&frame.body).map(|()| BackendMessage::CloseComplete),
            b'C' => decode_cstr_body(frame.body).map(BackendMessage::CommandComplete),
            b'c' => decode_empty(&frame.body).map(|()| BackendMessage::CopyDone),
            b'd' => Ok(BackendMessage::CopyData(frame.body)),
            b'D' => decode_data_row(frame.body).map(BackendMessage::DataRow),
            b'E' => decode_diagnostic(frame.body).map(BackendMessage::ErrorResponse),
            b'G' => decode_copy_response(frame.body).map(BackendMessage::CopyInResponse),
            b'H' => decode_copy_response(frame.body).map(BackendMessage::CopyOutResponse),
            b'I' => decode_empty(&frame.body).map(|()| BackendMessage::EmptyQueryResponse),
            b'n' => decode_empty(&frame.body).map(|()| BackendMessage::NoData),
            b's' => decode_empty(&frame.body).map(|()| BackendMessage::PortalSuspended),
            b't' => {
                decode_parameter_description(frame.body).map(BackendMessage::ParameterDescription)
            }
            b'T' => decode_row_description(frame.body).map(BackendMessage::RowDescription),
            b'V' => Ok(BackendMessage::FunctionCallResponse(frame.body)),
            b'W' => decode_copy_response(frame.body).map(BackendMessage::CopyBothResponse),
            b'R' => decode_authentication(frame.body).map(BackendMessage::Authentication),
            b'S' => decode_parameter_status(frame.body),
            b'N' => decode_diagnostic(frame.body).map(BackendMessage::NoticeResponse),
            b'A' => decode_notification(frame.body),
            b'K' => decode_backend_key_data(frame.body),
            b'Z' => decode_ready(frame.body),
            b'v' => decode_negotiate_protocol_version(frame.body),
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
    let target = take_target(&mut body)?;
    let name = take_cstr(&mut body)?;
    require_empty(&body)?;
    Ok(Describe { target, name })
}

fn decode_data_row(mut body: Bytes) -> io::Result<DataRow> {
    let count = take_u16(&mut body)?;
    let mut columns = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        columns.push(take_nullable(&mut body)?);
    }
    require_empty(&body)?;
    Ok(DataRow { columns })
}

fn decode_diagnostic(mut body: Bytes) -> io::Result<DiagnosticResponse> {
    let mut fields = Vec::new();
    loop {
        require(&body, 1)?;
        let code = body.get_u8();
        if code == 0 {
            break;
        }
        fields.push(DiagnosticField {
            code,
            value: take_cstr(&mut body)?,
        });
    }
    require_empty(&body)?;
    Ok(DiagnosticResponse { fields })
}

fn decode_copy_response(mut body: Bytes) -> io::Result<CopyResponse> {
    require(&body, 1)?;
    let overall_format = body.get_u8();
    let column_formats = take_i16_vec(&mut body)?;
    require_empty(&body)?;
    Ok(CopyResponse {
        overall_format,
        column_formats,
    })
}

fn decode_parameter_description(mut body: Bytes) -> io::Result<Vec<u32>> {
    let count = take_u16(&mut body)?;
    let mut types = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        types.push(take_u32(&mut body)?);
    }
    require_empty(&body)?;
    Ok(types)
}

fn decode_close(mut body: Bytes) -> io::Result<Close> {
    let target = take_target(&mut body)?;
    let name = take_cstr(&mut body)?;
    require_empty(&body)?;
    Ok(Close { target, name })
}

fn decode_execute(mut body: Bytes) -> io::Result<Execute> {
    let portal = take_cstr(&mut body)?;
    let max_rows = take_i32(&mut body)?;
    require_empty(&body)?;
    Ok(Execute { portal, max_rows })
}

fn decode_function_call(mut body: Bytes) -> io::Result<FunctionCall> {
    let function_oid = take_u32(&mut body)?;
    let argument_formats = take_i16_vec(&mut body)?;
    let count = take_u16(&mut body)?;
    let mut arguments = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        arguments.push(take_nullable(&mut body)?);
    }
    let result_format = take_i16(&mut body)?;
    require_empty(&body)?;
    Ok(FunctionCall {
        function_oid,
        argument_formats,
        arguments,
        result_format,
    })
}

fn decode_cstr_body(mut body: Bytes) -> io::Result<Bytes> {
    let value = take_cstr(&mut body)?;
    require_empty(&body)?;
    Ok(value)
}

fn decode_empty(body: &Bytes) -> io::Result<()> {
    require_empty(body)
}

fn take_target(body: &mut Bytes) -> io::Result<DescribeTarget> {
    require(body, 1)?;
    match body.get_u8() {
        b'S' => Ok(DescribeTarget::Statement),
        b'P' => Ok(DescribeTarget::Portal),
        _ => Err(invalid("invalid statement or portal target")),
    }
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

fn take_nullable(body: &mut Bytes) -> io::Result<Option<Bytes>> {
    let length = take_i32(body)?;
    if length == -1 {
        return Ok(None);
    }
    let length = usize::try_from(length).map_err(|_| invalid("negative value length"))?;
    require(body, length)?;
    Ok(Some(body.split_to(length)))
}

fn put_i16_vec(values: &[i16], body: &mut BytesMut) -> io::Result<()> {
    put_count(values.len(), body)?;
    for value in values {
        body.put_i16(*value);
    }
    Ok(())
}

fn put_nullable(value: Option<&Bytes>, body: &mut BytesMut) -> io::Result<()> {
    match value {
        None => body.put_i32(-1),
        Some(value) => {
            let length =
                i32::try_from(value.len()).map_err(|_| invalid_input("value is too large"))?;
            body.put_i32(length);
            body.extend_from_slice(value);
        }
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

fn named_target_frame(tag: u8, target: DescribeTarget, name: &[u8]) -> io::Result<Frame> {
    let mut body = BytesMut::new();
    body.put_u8(match target {
        DescribeTarget::Statement => b'S',
        DescribeTarget::Portal => b'P',
    });
    put_cstr(name, &mut body)?;
    Ok(Frame {
        tag,
        body: body.freeze(),
    })
}

fn cstr_message(tag: u8, value: &[u8]) -> io::Result<Frame> {
    let mut body = BytesMut::new();
    put_cstr(value, &mut body)?;
    Ok(Frame {
        tag,
        body: body.freeze(),
    })
}

fn empty_message(tag: u8) -> Frame {
    Frame {
        tag,
        body: Bytes::new(),
    }
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
            Ok(FrontendMessage::Sync)
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
    fn frame_limits_reject_oversized_input_before_allocation() {
        let mut codec = PgCodec::<Frontend>::with_max_frame_len(9).unwrap();
        let mut oversized = BytesMut::from(&b"Q\0\0\0\x09"[..]);
        let error = codec.decode(&mut oversized).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(oversized.len(), 5);

        let mut signed_overflow = BytesMut::from(&[b'Q', 0x80, 0, 0, 0][..]);
        let error = PgCodec::<Frontend>::default()
            .decode(&mut signed_overflow)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = codec
            .encode(
                Frame {
                    tag: b'Q',
                    body: Bytes::from_static(b"12345"),
                },
                &mut BytesMut::new(),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
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

    #[test]
    fn frontend_message_family_round_trips_structurally() {
        let messages = vec![
            FrontendMessage::Close(Close {
                target: DescribeTarget::Portal,
                name: Bytes::from_static(b"p"),
            }),
            FrontendMessage::Execute(Execute {
                portal: Bytes::from_static(b"p"),
                max_rows: 10,
            }),
            FrontendMessage::FunctionCall(FunctionCall {
                function_oid: 42,
                argument_formats: vec![1],
                arguments: vec![Some(Bytes::from_static(b"arg")), None],
                result_format: 1,
            }),
            FrontendMessage::Query(Bytes::from_static(b"select 1")),
            FrontendMessage::Flush,
            FrontendMessage::Sync,
            FrontendMessage::Terminate,
            FrontendMessage::CopyData(Bytes::from_static(b"row\n")),
            FrontendMessage::CopyDone,
            FrontendMessage::CopyFail(Bytes::from_static(b"cancelled")),
            FrontendMessage::PasswordResponse(Bytes::from_static(b"opaque response")),
        ];
        for message in messages {
            let frame = message
                .to_frame()
                .expect("reconstructable frontend message");
            assert_eq!(
                Frontend::decode(frame).expect("decodable frontend message"),
                message
            );
        }
    }

    #[test]
    fn backend_message_family_round_trips_structurally() {
        let diagnostic = DiagnosticResponse {
            fields: vec![
                DiagnosticField {
                    code: b'S',
                    value: Bytes::from_static(b"ERROR"),
                },
                DiagnosticField {
                    code: b'M',
                    value: Bytes::from_static(b"rewritable message"),
                },
            ],
        };
        let copy = CopyResponse {
            overall_format: 0,
            column_formats: vec![0, 1],
        };
        let messages = vec![
            BackendMessage::ParseComplete,
            BackendMessage::BindComplete,
            BackendMessage::CloseComplete,
            BackendMessage::CommandComplete(Bytes::from_static(b"SELECT 1")),
            BackendMessage::CopyData(Bytes::from_static(b"row\n")),
            BackendMessage::CopyDone,
            BackendMessage::CopyInResponse(copy.clone()),
            BackendMessage::CopyOutResponse(copy.clone()),
            BackendMessage::CopyBothResponse(copy),
            BackendMessage::DataRow(DataRow {
                columns: vec![Some(Bytes::from_static(b"42")), None],
            }),
            BackendMessage::EmptyQueryResponse,
            BackendMessage::ErrorResponse(diagnostic.clone()),
            BackendMessage::NoticeResponse(diagnostic),
            BackendMessage::NoData,
            BackendMessage::ParameterDescription(vec![23, 25]),
            BackendMessage::PortalSuspended,
            BackendMessage::FunctionCallResponse(Bytes::from_static(b"result")),
        ];
        for message in messages {
            let frame = message.to_frame().expect("reconstructable backend message");
            assert_eq!(
                Backend::decode(frame).expect("decodable backend message"),
                message
            );
        }
    }
}
