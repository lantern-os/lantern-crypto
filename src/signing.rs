//! Ed25519 signing behind a fixed-size API — [RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md)/
//! [ADR-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0011-cryptographic-primitive-set.md) fix
//! Ed25519 as the Phase 1/2 signature default. As with [`crate::aead`], this
//! module never sources its own randomness — see
//! [`SigningKey::from_random_bytes`].

use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey as DalekVerifyingKey};

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Signature verification failed, or a public key/signature was malformed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SigningError;

/// A signing (private) key. Zeroised on drop — `ed25519_dalek::SigningKey`
/// itself implements `ZeroizeOnDrop` (its own `zeroize` feature is on by
/// default), so this wrapper inherits that without redoing the work.
pub struct SigningKey(DalekSigningKey);

impl SigningKey {
    /// Builds a key from a caller-supplied random seed — see
    /// [`crate::aead::AeadKey::from_random_bytes`]'s doc for why this module
    /// takes bytes rather than generating them itself.
    pub fn from_random_bytes(seed: [u8; SEED_LEN]) -> Self {
        Self(DalekSigningKey::from_bytes(&seed))
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(message).to_bytes()
    }

    pub fn verifying_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.verifying_key().to_bytes()
    }
}

/// Verification needs only the public key, never the signing key — so unlike
/// [`SigningKey::sign`], [`crate::Keystore::verify`] doesn't gate this behind
/// a capability badge (there's no secret asset here to protect, X1).
pub fn verify(public_key: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), SigningError> {
    let key = DalekVerifyingKey::from_bytes(public_key).map_err(|_| SigningError)?;
    key.verify(message, &Signature::from_bytes(signature)).map_err(|_| SigningError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = SigningKey::from_random_bytes([9u8; SEED_LEN]);
        let sig = key.sign(b"a message");
        verify(&key.verifying_key(), b"a message", &sig).unwrap();
    }

    #[test]
    fn tampered_message_fails_verification() {
        let key = SigningKey::from_random_bytes([9u8; SEED_LEN]);
        let sig = key.sign(b"a message");
        assert!(verify(&key.verifying_key(), b"a different message", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = SigningKey::from_random_bytes([9u8; SEED_LEN]);
        let other = SigningKey::from_random_bytes([1u8; SEED_LEN]);
        let sig = key.sign(b"a message");
        assert!(verify(&other.verifying_key(), b"a message", &sig).is_err());
    }
}
