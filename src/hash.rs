//! BLAKE3 hashing — [RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md)/
//! [ADR-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0011-cryptographic-primitive-set.md) fix
//! BLAKE3 as the Phase 1/2 hashing/content-addressing default. Two distinct
//! uses, kept in this one module since they're the same primitive:
//!
//! - [`hash`]/[`Hasher`] — plain, unkeyed hashing. No secret material, so
//!   unlike everything [`crate::Keystore`] gates, these are free functions:
//!   content-addressing (the eventual `lantern-filesystem` CAS block-naming
//!   use RFC-0007 names) needs no capability to compute a hash, only to
//!   store/retrieve the block it names.
//! - [`MacKey`] — BLAKE3's native keyed mode, used as a MAC. RFC-0007
//!   explicitly reserved this rather than adding a separate primitive
//!   ("a signature or keyed-hash/MAC scheme ... already exist in the
//!   ratified set") for exactly this: authenticating something without
//!   [`crate::signing`]'s asymmetric machinery — most concretely, RFC-0003's
//!   still-unbuilt sealed-capability token format. Unlike a hash, a MAC key
//!   *is* secret material, so [`MacKey`] follows [`crate::aead::AeadKey`]/
//!   [`crate::signing::SigningKey`]'s shape (caller-supplied random bytes,
//!   zeroised on drop) and [`crate::Keystore`] gates it the same way.

use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

pub const HASH_LEN: usize = 32;
pub const MAC_KEY_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Constant-time equality (`subtle::ConstantTimeEq`) — see
    /// [`MacKey::verify`]'s doc for why a MAC comparison must never
    /// short-circuit.
    pub fn ct_eq(&self, other: &Hash) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// Hashes `data` in one call — content-addressing's block-naming operation.
pub fn hash(data: &[u8]) -> Hash {
    Hash(*blake3::hash(data).as_bytes())
}

/// A streaming hasher for content too large to hold in memory at once (a
/// large CAS block/file) — fixed-size state, no heap, matching every other
/// no-alloc primitive in this crate.
#[derive(Default)]
pub struct Hasher(blake3::Hasher);

impl Hasher {
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    pub fn finalize(&self) -> Hash {
        Hash(*self.0.finalize().as_bytes())
    }
}

/// MAC verification failed (constant-time — see [`MacKey::verify`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MacError;

/// A BLAKE3 keyed-mode key, used as a MAC — see this module's top-level doc.
#[derive(ZeroizeOnDrop)]
pub struct MacKey([u8; MAC_KEY_LEN]);

impl MacKey {
    /// Builds a key from raw bytes — [`MacKey::from_random_bytes`] is the
    /// entropy-sourced case (a fresh key); [`crate::sealed`]'s MAC-chaining
    /// construction also uses this directly to turn a *previous* chain link's
    /// MAC output into the next link's key, which isn't "random" in the
    /// entropy-sourcing sense but is exactly as valid a BLAKE3 key.
    pub fn from_bytes(bytes: [u8; MAC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Builds a key from caller-supplied random bytes — see
    /// [`crate::aead::AeadKey::from_random_bytes`]'s doc for why the bytes
    /// come from the caller, not this module.
    pub fn from_random_bytes(bytes: [u8; MAC_KEY_LEN]) -> Self {
        Self::from_bytes(bytes)
    }

    pub fn compute(&self, data: &[u8]) -> Hash {
        Hash(*blake3::keyed_hash(&self.0, data).as_bytes())
    }

    /// Constant-time comparison ([`Hash::ct_eq`]) — a MAC verification that
    /// short-circuits on the first differing byte leaks the correct MAC one
    /// byte at a time to a timing attacker (X6, `THREAT_MODEL.md`);
    /// recomputing and branching on `==` would do exactly that.
    pub fn verify(&self, data: &[u8], mac: &Hash) -> Result<(), MacError> {
        let computed = self.compute(data);
        if computed.ct_eq(mac) {
            Ok(())
        } else {
            Err(MacError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_content_dependent() {
        assert_eq!(hash(b"hello"), hash(b"hello"));
        assert_ne!(hash(b"hello"), hash(b"world"));
    }

    #[test]
    fn hasher_streaming_matches_one_shot() {
        let mut h = Hasher::new();
        h.update(b"hel").update(b"lo");
        assert_eq!(h.finalize(), hash(b"hello"));
    }

    #[test]
    fn mac_round_trips_and_rejects_tampering() {
        let key = MacKey::from_random_bytes([5u8; MAC_KEY_LEN]);
        let mac = key.compute(b"a message");
        key.verify(b"a message", &mac).unwrap();
        assert!(key.verify(b"a different message", &mac).is_err());
    }

    #[test]
    fn mac_is_keyed_not_just_a_hash() {
        let key_a = MacKey::from_random_bytes([1u8; MAC_KEY_LEN]);
        let key_b = MacKey::from_random_bytes([2u8; MAC_KEY_LEN]);
        assert_ne!(key_a.compute(b"same data"), key_b.compute(b"same data"));
    }
}
