use bytes::Bytes;
use pg_proto::{
    codec::FrontendMessage, demux::CancelKey, integrations::TokenStep,
    server_auth::SaslInitialResponse,
};

#[test]
fn authentication_secrets_are_redacted_from_debug_output() {
    let password = format!(
        "{:?}",
        FrontendMessage::PasswordResponse(Bytes::from_static(b"highly-secret-password"))
    );
    let cancellation = format!(
        "{:?}",
        CancelKey {
            process_id: 42,
            secret_key: Bytes::from_static(b"cancel-secret"),
        }
    );
    let sasl = format!(
        "{:?}",
        SaslInitialResponse {
            mechanism: Bytes::from_static(b"SCRAM-SHA-256"),
            response: Some(Bytes::from_static(b"client-proof")),
        }
    );
    let token = format!(
        "{:?}",
        TokenStep::Continue(Bytes::from_static(b"platform-token"))
    );

    for (rendered, secret) in [
        (password, "highly-secret-password"),
        (cancellation, "cancel-secret"),
        (sasl, "client-proof"),
        (token, "platform-token"),
    ] {
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("REDACTED") || rendered.contains("Some("));
    }
}
