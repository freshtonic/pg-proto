//! Session-external cancellation-key translation for proxies.

use std::collections::HashMap;

use bytes::Bytes;

use crate::demux::CancelKey;

/// Application policy for minting client-facing cancellation keys.
///
/// Implementations may use cryptographic randomness, an external allocator, or
/// another process-specific strategy. The protocol library does not prescribe
/// key lifecycle or storage.
pub trait CancelKeyMint {
    type Error;

    /// Mints a key to expose in client-facing `BackendKeyData`.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined allocation or entropy error.
    fn mint_cancel_key(&mut self) -> Result<CancelKey, Self::Error>;
}

/// Application-owned translation policy for out-of-band cancellation keys.
///
/// A proxy can implement this over local memory, shared storage, or routing
/// metadata. [`CancelKeyMap`] is deliberately only a small reference
/// implementation.
pub trait CancelKeyRegistry {
    type Error;

    /// Observes the association between a client-facing and upstream key.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined validation, collision, or storage
    /// error.
    fn register_cancel_key(
        &mut self,
        client: CancelKey,
        upstream: CancelKey,
    ) -> Result<(), Self::Error>;

    /// Resolves an incoming client cancellation request without borrowing the
    /// registry, so the result can safely cross an asynchronous boundary.
    fn resolve_cancel_key(&self, client: &CancelKey) -> Option<CancelKey>;

    /// Removes an association when either side of a session is detached.
    fn remove_cancel_key(&mut self, client: &CancelKey) -> Option<CancelKey>;
}

/// Client-facing cancellation keys mapped to their current upstream keys.
#[derive(Debug, Default)]
pub struct CancelKeyMap {
    mappings: HashMap<CancelKey, CancelKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterError {
    InvalidClientKeyLength(usize),
    InvalidUpstreamKeyLength(usize),
    ClientKeyCollision,
}

impl CancelKeyMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one proxy-minted client key for an attached upstream session.
    ///
    /// # Errors
    ///
    /// Rejects keys outside the protocol's 4–256 byte range and client-key
    /// collisions. Existing mappings are never silently replaced.
    pub fn register(
        &mut self,
        client: CancelKey,
        upstream: CancelKey,
    ) -> Result<(), RegisterError> {
        validate_key(&client).map_err(RegisterError::InvalidClientKeyLength)?;
        validate_key(&upstream).map_err(RegisterError::InvalidUpstreamKeyLength)?;
        if self.mappings.contains_key(&client) {
            return Err(RegisterError::ClientKeyCollision);
        }
        self.mappings.insert(client, upstream);
        Ok(())
    }

    /// Resolves an inspected client `CancelRequest` to its upstream key.
    #[must_use]
    pub fn resolve(&self, process_id: u32, secret_key: &[u8]) -> Option<&CancelKey> {
        self.mappings.get(&CancelKey {
            process_id,
            secret_key: Bytes::copy_from_slice(secret_key),
        })
    }

    /// Detaches a client key when its upstream session is released or replaced.
    pub fn remove(&mut self, client: &CancelKey) -> Option<CancelKey> {
        self.mappings.remove(client)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

impl CancelKeyRegistry for CancelKeyMap {
    type Error = RegisterError;

    fn register_cancel_key(
        &mut self,
        client: CancelKey,
        upstream: CancelKey,
    ) -> Result<(), Self::Error> {
        self.register(client, upstream)
    }

    fn resolve_cancel_key(&self, client: &CancelKey) -> Option<CancelKey> {
        self.mappings.get(client).cloned()
    }

    fn remove_cancel_key(&mut self, client: &CancelKey) -> Option<CancelKey> {
        self.remove(client)
    }
}

fn validate_key(key: &CancelKey) -> Result<(), usize> {
    if (4..=256).contains(&key.secret_key.len()) {
        Ok(())
    } else {
        Err(key.secret_key.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_variable_length_client_keys_without_overwriting_collisions() {
        let client = CancelKey {
            process_id: 7,
            secret_key: Bytes::from(vec![0xAA; 32]),
        };
        let upstream = CancelKey {
            process_id: 42,
            secret_key: Bytes::from_static(b"upstream"),
        };
        let mut map = CancelKeyMap::new();
        map.register(client.clone(), upstream.clone()).unwrap();

        assert_eq!(map.resolve(7, &[0xAA; 32]), Some(&upstream));
        assert_eq!(
            map.register(client.clone(), upstream.clone()),
            Err(RegisterError::ClientKeyCollision)
        );
        assert_eq!(map.remove(&client), Some(upstream));
        assert!(map.is_empty());
    }

    #[test]
    fn rejects_keys_which_cannot_be_encoded_as_cancel_requests() {
        let mut map = CancelKeyMap::new();
        let client = CancelKey {
            process_id: 1,
            secret_key: Bytes::from_static(b"bad"),
        };
        let upstream = CancelKey {
            process_id: 2,
            secret_key: Bytes::from_static(b"valid"),
        };
        assert_eq!(
            map.register(client, upstream),
            Err(RegisterError::InvalidClientKeyLength(3))
        );
    }

    #[test]
    fn reference_map_can_be_used_through_the_policy_hook() {
        let client = CancelKey {
            process_id: 11,
            secret_key: Bytes::from_static(b"client"),
        };
        let upstream = CancelKey {
            process_id: 22,
            secret_key: Bytes::from_static(b"server"),
        };
        let registry: &mut dyn CancelKeyRegistry<Error = RegisterError> = &mut CancelKeyMap::new();

        registry
            .register_cancel_key(client.clone(), upstream.clone())
            .unwrap();
        assert_eq!(registry.resolve_cancel_key(&client), Some(upstream.clone()));
        assert_eq!(registry.remove_cancel_key(&client), Some(upstream));
    }
}
