//! Credential transforms shared by client and proxy-side authentication policy.

use subtle::ConstantTimeEq as _;

/// Computes the wire value for `AuthenticationMD5Password`.
#[must_use]
pub(crate) fn md5_response(username: &[u8], password: &[u8], salt: [u8; 4]) -> String {
    postgres_protocol::authentication::md5_hash(username, password, salt)
}

/// Verifies an MD5 password response without a data-dependent comparison.
#[must_use]
pub(crate) fn verify_md5_response(
    response: &[u8],
    username: &[u8],
    password: &[u8],
    salt: [u8; 4],
) -> bool {
    response
        .ct_eq(md5_response(username, password, salt).as_bytes())
        .into()
}

/// Verifies a cleartext password response without a data-dependent comparison.
#[must_use]
pub(crate) fn verify_cleartext(response: &[u8], expected: &[u8]) -> bool {
    response.ct_eq(expected).into()
}

#[cfg(test)]
/// Tests for PostgreSQL credential verification helpers.
mod tests {
    use super::*;

    #[test]
    fn computes_and_verifies_postgres_md5_response() {
        let salt = [0x2a, 0x3d, 0x8f, 0xe0];
        let response = md5_response(b"md5_user", b"password", salt);
        assert_eq!(response, "md562af4dd09bbb41884907a838a3233294");
        assert!(verify_md5_response(
            response.as_bytes(),
            b"md5_user",
            b"password",
            salt
        ));
        assert!(!verify_md5_response(
            b"md500000000000000000000000000000000",
            b"md5_user",
            b"password",
            salt
        ));
    }

    #[test]
    fn verifies_cleartext_credentials() {
        assert!(verify_cleartext(b"secret", b"secret"));
        assert!(!verify_cleartext(b"secret", b"different"));
    }
}
