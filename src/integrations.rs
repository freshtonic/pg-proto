//! Integration boundaries for platform-specific GSSAPI, Kerberos, and SSPI engines.

use std::future::Future;

use bytes::Bytes;

/// Upgrades a transport after the typed GSSENC negotiation has accepted it.
///
/// Implementations can wrap MIT Kerberos, Heimdal, Windows SSPI, or a remote
/// credential service without making `pg-proto` select or configure that stack.
pub trait GssEncUpgrade<Stream> {
    type SecuredStream;
    type Error;

    /// Performs the platform-specific encrypted transport handshake.
    fn upgrade(
        self,
        stream: Stream,
    ) -> impl Future<Output = Result<Self::SecuredStream, Self::Error>>;
}

/// One output from a recursive GSSAPI, Kerberos, or SSPI token engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenStep {
    Continue(Bytes),
    Complete(Option<Bytes>),
}

/// Platform-neutral token exchange consumed by the typed authentication loop.
pub trait TokenAuthEngine {
    type Error;

    /// Produces the first token, if the selected mechanism requires one.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific credential or mechanism error.
    fn initial(&mut self) -> Result<TokenStep, Self::Error>;

    /// Processes one peer token and either continues or completes authentication.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific validation or credential error.
    fn step(&mut self, peer_token: &[u8]) -> Result<TokenStep, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ExampleEngine(bool);

    impl TokenAuthEngine for ExampleEngine {
        type Error = std::convert::Infallible;

        fn initial(&mut self) -> Result<TokenStep, Self::Error> {
            Ok(TokenStep::Continue(Bytes::from_static(b"initial")))
        }

        fn step(&mut self, peer_token: &[u8]) -> Result<TokenStep, Self::Error> {
            self.0 = true;
            Ok(TokenStep::Complete(Some(Bytes::copy_from_slice(
                peer_token,
            ))))
        }
    }

    #[test]
    fn recursive_token_engine_is_not_coupled_to_platform_credentials() {
        let mut engine = ExampleEngine(false);
        assert!(matches!(engine.initial().unwrap(), TokenStep::Continue(_)));
        assert_eq!(
            engine.step(b"challenge").unwrap(),
            TokenStep::Complete(Some(Bytes::from_static(b"challenge")))
        );
        assert!(engine.0);
    }
}
