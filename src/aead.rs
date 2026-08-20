//! AEAD encryption behind a fixed-size, no-heap API — [RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md)/
//! [ADR-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0011-cryptographic-primitive-set.md) fix
//! XChaCha20-Poly1305 as the Phase 1/2 AEAD default (192-bit nonce, so random
//! per-message nonces don't need a counter to stay collision-safe — X4,
//! `lantern-crypto/THREAT_MODEL.md`). In-place/detached so the caller's own
//! buffer is encrypted in place and only a fixed-size tag comes back — no
//! allocation, matching every other Phase 1/2 kernel-adjacent crate's `no_std`
//! discipline.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::ZeroizeOnDrop;

pub const AEAD_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// Authentication failed on decrypt, or encryption otherwise rejected the
/// input — the underlying `chacha20poly1305` crate deliberately doesn't say
/// more than this (an AEAD auth failure must not leak *why* it failed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AeadError;

/// A raw AEAD key. Zeroised on drop (X6, `lantern-crypto/THREAT_MODEL.md`) —
/// this is the one representation of the secret this crate ever hands back to
/// a caller; [`crate::Keystore`] never returns key bytes to a client, only
/// operation results (X1).
#[derive(ZeroizeOnDrop)]
pub struct AeadKey([u8; AEAD_KEY_LEN]);

impl AeadKey {
    /// Builds a key from caller-supplied random bytes. This crate has no
    /// entropy source of its own — the "hardware-seeded CSPRNG" ADR-0011
    /// actually calls for is a `lantern-hal` concern not yet built
    /// (`lantern-crypto/STATUS.md`'s "Blocked on"); callers (today: tests;
    /// eventually: the real keystore's boot-time RNG plumbing) supply the
    /// bytes so this module stays entropy-source-agnostic.
    pub fn from_random_bytes(bytes: [u8; AEAD_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Encrypts `buffer` in place; returns the detached authentication tag.
    /// `nonce` must never repeat under the same key (X4) — generating it is
    /// the caller's responsibility, same as [`AeadKey::from_random_bytes`]'s
    /// entropy split.
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], AeadError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.0));
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, buffer)
            .map_err(|_| AeadError)?;
        Ok(tag.into())
    }

    /// Decrypts `buffer` in place against the detached `tag`. On
    /// authentication failure `buffer` is left as the (still-ciphertext,
    /// unusable) input the underlying crate leaves it in — callers must not
    /// use `buffer`'s contents unless this returns `Ok`.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AeadError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.0));
        cipher
            .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, buffer, tag.into())
            .map_err(|_| AeadError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_authenticates() {
        let key = AeadKey::from_random_bytes([7u8; AEAD_KEY_LEN]);
        let nonce = [3u8; NONCE_LEN];
        let mut buf = *b"a secret message";
        let tag = key.encrypt_in_place_detached(&nonce, b"ctx", &mut buf).unwrap();
        assert_ne!(&buf[..], b"a secret message");

        key.decrypt_in_place_detached(&nonce, b"ctx", &mut buf, &tag).unwrap();
        assert_eq!(&buf[..], b"a secret message");
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let key = AeadKey::from_random_bytes([7u8; AEAD_KEY_LEN]);
        let nonce = [3u8; NONCE_LEN];
        let mut buf = *b"a secret message";
        let tag = key.encrypt_in_place_detached(&nonce, b"ctx", &mut buf).unwrap();

        buf[0] ^= 1;
        assert!(key.decrypt_in_place_detached(&nonce, b"ctx", &mut buf, &tag).is_err());
    }

    #[test]
    fn wrong_aad_fails_to_decrypt() {
        let key = AeadKey::from_random_bytes([7u8; AEAD_KEY_LEN]);
        let nonce = [3u8; NONCE_LEN];
        let mut buf = *b"a secret message";
        let tag = key.encrypt_in_place_detached(&nonce, b"ctx", &mut buf).unwrap();

        assert!(key.decrypt_in_place_detached(&nonce, b"other", &mut buf, &tag).is_err());
    }
}
