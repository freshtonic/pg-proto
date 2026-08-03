use bytes::BytesMut;
use pg_proto::codec::{
    Authentication, Backend, BackendMessage, Frontend, FrontendMessage, PgCodec,
};
use tokio_util::codec::Decoder;

#[test]
fn sanitised_authentication_capture_covers_supported_families() {
    for fixture in fixtures(include_str!("fixtures/authentication.hex")) {
        match fixture.direction {
            "backend" => {
                let message = decode::<Backend>(&fixture.hex);
                match (fixture.label, message) {
                    ("auth_ok", BackendMessage::Authentication(Authentication::Ok))
                    | (
                        "cleartext",
                        BackendMessage::Authentication(Authentication::CleartextPassword),
                    )
                    | ("kerberos_v5", BackendMessage::Authentication(Authentication::KerberosV5))
                    | ("md5", BackendMessage::Authentication(Authentication::Md5Password { .. }))
                    | ("gss", BackendMessage::Authentication(Authentication::Gss))
                    | (
                        "gss_continue",
                        BackendMessage::Authentication(Authentication::GssContinue(_)),
                    )
                    | ("sspi", BackendMessage::Authentication(Authentication::Sspi))
                    | ("sasl", BackendMessage::Authentication(Authentication::Sasl { .. }))
                    | (
                        "sasl_continue",
                        BackendMessage::Authentication(Authentication::SaslContinue(_)),
                    )
                    | (
                        "sasl_final",
                        BackendMessage::Authentication(Authentication::SaslFinal(_)),
                    ) => {}
                    (label, message) => panic!("fixture {label} decoded as {message:?}"),
                }
            }
            "frontend" => assert!(matches!(
                decode::<Frontend>(&fixture.hex),
                FrontendMessage::PasswordResponse(_)
            )),
            direction => panic!("unknown fixture direction {direction}"),
        }
    }
}

#[test]
fn sanitised_query_capture_covers_simple_extended_and_copy_families() {
    for fixture in fixtures(include_str!("fixtures/query.hex")) {
        match fixture.direction {
            "frontend" => {
                let message = decode::<Frontend>(&fixture.hex);
                let valid = matches!(
                    (fixture.label, message),
                    ("query", FrontendMessage::Query(_))
                        | ("parse", FrontendMessage::Parse(_))
                        | ("bind", FrontendMessage::Bind(_))
                        | ("describe", FrontendMessage::Describe(_))
                        | ("sync", FrontendMessage::Sync)
                        | ("copy_data", FrontendMessage::CopyData(_))
                );
                assert!(valid, "unexpected frontend fixture {}", fixture.label);
            }
            "backend" => {
                let message = decode::<Backend>(&fixture.hex);
                let valid = matches!(
                    (fixture.label, message),
                    ("copy_in", BackendMessage::CopyInResponse(_))
                        | ("copy_out", BackendMessage::CopyOutResponse(_))
                        | ("copy_both", BackendMessage::CopyBothResponse(_))
                        | ("ready", BackendMessage::ReadyForQuery(_))
                );
                assert!(valid, "unexpected backend fixture {}", fixture.label);
            }
            direction => panic!("unknown fixture direction {direction}"),
        }
    }
}

struct Fixture<'a> {
    label: &'a str,
    direction: &'a str,
    hex: String,
}

fn fixtures(input: &str) -> impl Iterator<Item = Fixture<'_>> {
    input.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut fields = line.split_whitespace();
        Some(Fixture {
            label: fields.next().expect("fixture label"),
            direction: fields.next().expect("fixture direction"),
            hex: fields.next().expect("fixture bytes").to_owned(),
        })
    })
}

fn decode<D: pg_proto::codec::Direction>(hex: &str) -> D::Message {
    let mut bytes = BytesMut::from(hex_bytes(hex).as_slice());
    let message = PgCodec::<D>::default()
        .decode(&mut bytes)
        .expect("valid recorded frame")
        .expect("complete recorded frame");
    assert!(bytes.is_empty());
    message
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}
