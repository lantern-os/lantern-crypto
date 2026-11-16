//! `Noise_XX_25519_ChaChaPoly_BLAKE2s` ([The Noise Protocol Framework](https://noiseprotocol.org/noise.html), revision
//! 34), for the wallet's sessions ([RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)).
//!
//! Only the state machine is here: X25519, ChaCha20-Poly1305 and BLAKE2s are reviewed crates. It allocates nothing, so a
//! confined service can hold sessions without a heap that frees. The host tests check it byte for byte against `snow`, an
//! independent implementation, and that each can finish a handshake the other starts.
//!
//! `XX`:
//! ```text
//!   -> e
//!   <- e, ee, s, es
//!   -> s, se
//! ```
//! Each side learns the other's static key, which is the identity it presents. Ephemeral keys come from the caller, so
//! this module never needs randomness of its own.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hmac::{Mac, SimpleHmac};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const DH_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// Noise's limit on any message.
pub const MAX_MESSAGE: usize = 65535;
const PROTOCOL: &[u8] = b"Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Why a message was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoiseError {
    /// Out of order, or the handshake is over.
    State,
    /// Too short, too long, or its buffer is too small.
    Length,
    /// Authentication failed: the message was altered, or isn't from who it claims.
    Decrypt,
    /// The nonce ran out (2^64 - 1 messages).
    Exhausted,
    /// A Diffie-Hellman result was all zeros: a low-order point.
    BadKey,
}

fn hash(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut m = <SimpleHmac<Blake2s256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Noise's HKDF: two outputs from the chaining key and `ikm`.
fn hkdf(ck: &[u8; HASH_LEN], ikm: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    let mut temp = hmac(ck, &[ikm]);
    let one = hmac(&temp, &[&[1]]);
    let two = hmac(&temp, &[&one, &[2]]);
    temp.zeroize();
    (one, two)
}

/// A key and its nonce.
#[derive(Clone)]
pub struct CipherState {
    key: Option<[u8; 32]>,
    n: u64,
}

impl Drop for CipherState {
    fn drop(&mut self) {
        if let Some(k) = self.key.as_mut() {
            k.zeroize();
        }
    }
}

fn nonce(n: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(bytes)
}

impl CipherState {
    const fn empty() -> Self {
        Self { key: None, n: 0 }
    }

    /// Encrypts `buf[..len]` in place and appends the tag, or copies it as it is with no key. Returns the new length.
    fn encrypt(&mut self, ad: &[u8], buf: &mut [u8], len: usize) -> Result<usize, NoiseError> {
        let Some(key) = &self.key else { return Ok(len) };
        if self.n == u64::MAX {
            return Err(NoiseError::Exhausted);
        }
        if buf.len() < len + TAG_LEN {
            return Err(NoiseError::Length);
        }
        let tag = ChaCha20Poly1305::new(Key::from_slice(key))
            .encrypt_in_place_detached(&nonce(self.n), ad, &mut buf[..len])
            .map_err(|_| NoiseError::Length)?;
        buf[len..len + TAG_LEN].copy_from_slice(&tag);
        self.n += 1;
        Ok(len + TAG_LEN)
    }

    /// Decrypts `buf` (ciphertext and tag) in place, or takes it as it is with no key. Returns the plaintext's length.
    fn decrypt(&mut self, ad: &[u8], buf: &mut [u8]) -> Result<usize, NoiseError> {
        let Some(key) = &self.key else { return Ok(buf.len()) };
        if self.n == u64::MAX {
            return Err(NoiseError::Exhausted);
        }
        let len = buf.len().checked_sub(TAG_LEN).ok_or(NoiseError::Length)?;
        let (text, tag) = buf.split_at_mut(len);
        ChaCha20Poly1305::new(Key::from_slice(key))
            .decrypt_in_place_detached(&nonce(self.n), ad, text, Tag::from_slice(tag))
            .map_err(|_| NoiseError::Decrypt)?;
        self.n += 1;
        Ok(len)
    }
}

/// A finished handshake's two directions, and who the other side is.
pub struct Transport {
    send: CipherState,
    recv: CipherState,
    /// The other side's static key: the identity it presented.
    pub remote_static: [u8; DH_LEN],
}

impl Transport {
    /// Encrypts `buf[..len]` in place, appending the tag. Returns the message's length.
    pub fn write(&mut self, buf: &mut [u8], len: usize) -> Result<usize, NoiseError> {
        if len + TAG_LEN > MAX_MESSAGE {
            return Err(NoiseError::Length);
        }
        self.send.encrypt(&[], buf, len)
    }

    /// Decrypts a message in place. Returns the plaintext's length.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, NoiseError> {
        if buf.len() > MAX_MESSAGE {
            return Err(NoiseError::Length);
        }
        self.recv.decrypt(&[], buf)
    }
}

/// An `XX` handshake in progress.
pub struct Handshake {
    initiator: bool,
    /// How many of the three messages have been written or read.
    step: u8,
    ck: [u8; HASH_LEN],
    h: [u8; HASH_LEN],
    cipher: CipherState,
    s: StaticSecret,
    e: StaticSecret,
    re: Option<[u8; DH_LEN]>,
    rs: Option<[u8; DH_LEN]>,
}

impl Handshake {
    /// Starts a handshake as `static_key`, with the fresh ephemeral `ephemeral` (32 random bytes: never reuse them), and
    /// `prologue`, which both sides must agree on.
    pub fn new(initiator: bool, static_key: [u8; 32], ephemeral: [u8; 32], prologue: &[u8]) -> Self {
        // A name longer than HASH_LEN is hashed; this one is 33 bytes.
        let h = hash(&[PROTOCOL]);
        let mut hs = Self {
            initiator,
            step: 0,
            ck: h,
            h,
            cipher: CipherState::empty(),
            s: StaticSecret::from(static_key),
            e: StaticSecret::from(ephemeral),
            re: None,
            rs: None,
        };
        hs.mix_hash(prologue);
        hs
    }

    /// Whether all three messages have been exchanged.
    pub fn is_finished(&self) -> bool {
        self.step == 3
    }

    /// Whether it's this side's turn to write.
    pub fn is_my_turn(&self) -> bool {
        !self.is_finished() && self.step.is_multiple_of(2) == self.initiator
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.cipher = CipherState { key: Some(k), n: 0 };
    }

    fn dh(secret: &StaticSecret, public: &[u8; DH_LEN]) -> Result<[u8; DH_LEN], NoiseError> {
        let shared = secret.diffie_hellman(&PublicKey::from(*public));
        if shared.was_contributory() {
            Ok(*shared.as_bytes())
        } else {
            Err(NoiseError::BadKey)
        }
    }

    fn ee(&mut self) -> Result<(), NoiseError> {
        let shared = Self::dh(&self.e, self.re.as_ref().ok_or(NoiseError::State)?)?;
        self.mix_key(&shared);
        Ok(())
    }

    /// `es` from either side: the initiator's ephemeral with the responder's static.
    fn es(&mut self) -> Result<(), NoiseError> {
        let shared = if self.initiator {
            Self::dh(&self.e, self.rs.as_ref().ok_or(NoiseError::State)?)?
        } else {
            Self::dh(&self.s, self.re.as_ref().ok_or(NoiseError::State)?)?
        };
        self.mix_key(&shared);
        Ok(())
    }

    /// `se`: the initiator's static with the responder's ephemeral.
    fn se(&mut self) -> Result<(), NoiseError> {
        let shared = if self.initiator {
            Self::dh(&self.s, self.re.as_ref().ok_or(NoiseError::State)?)?
        } else {
            Self::dh(&self.e, self.rs.as_ref().ok_or(NoiseError::State)?)?
        };
        self.mix_key(&shared);
        Ok(())
    }

    fn encrypt_and_hash(&mut self, buf: &mut [u8], len: usize) -> Result<usize, NoiseError> {
        let h = self.h;
        let out = self.cipher.encrypt(&h, buf, len)?;
        self.mix_hash(&buf[..out]);
        Ok(out)
    }

    fn decrypt_and_hash(&mut self, buf: &mut [u8]) -> Result<usize, NoiseError> {
        let h = self.h;
        let ciphertext_hash = hash(&[&h, buf]);
        let len = self.cipher.decrypt(&h, buf)?;
        self.h = ciphertext_hash;
        Ok(len)
    }

    /// Writes this side's next handshake message, carrying `payload`, into `out`. Returns its length.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        if !self.is_my_turn() {
            return Err(NoiseError::State);
        }
        let mut at = 0;
        let put = |out: &mut [u8], at: &mut usize, bytes: &[u8]| -> Result<(), NoiseError> {
            out.get_mut(*at..*at + bytes.len()).ok_or(NoiseError::Length)?.copy_from_slice(bytes);
            *at += bytes.len();
            Ok(())
        };
        let e_pub = PublicKey::from(&self.e).to_bytes();
        let s_pub = PublicKey::from(&self.s).to_bytes();
        match self.step {
            0 => {
                put(out, &mut at, &e_pub)?;
                self.mix_hash(&e_pub);
            }
            1 => {
                put(out, &mut at, &e_pub)?;
                self.mix_hash(&e_pub);
                self.ee()?;
                put(out, &mut at, &s_pub)?;
                at = at - DH_LEN + self.encrypt_and_hash(&mut out[at - DH_LEN..], DH_LEN)?;
                self.es()?;
            }
            _ => {
                put(out, &mut at, &s_pub)?;
                at = at - DH_LEN + self.encrypt_and_hash(&mut out[at - DH_LEN..], DH_LEN)?;
                self.se()?;
            }
        }
        put(out, &mut at, payload)?;
        let len = payload.len();
        at = at - len + self.encrypt_and_hash(&mut out[at - len..], len)?;
        if at > MAX_MESSAGE {
            return Err(NoiseError::Length);
        }
        self.step += 1;
        Ok(at)
    }

    /// Reads the other side's next handshake message from `message`, writing its payload into `payload`. Returns the
    /// payload's length. A message that doesn't authenticate leaves this handshake unusable: start again.
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, NoiseError> {
        if self.is_finished() || self.is_my_turn() || message.len() > MAX_MESSAGE {
            return Err(NoiseError::State);
        }
        let mut rest = message;
        let mut take = |n: usize| -> Result<&[u8], NoiseError> {
            if rest.len() < n {
                return Err(NoiseError::Length);
            }
            let (head, tail) = rest.split_at(n);
            rest = tail;
            Ok(head)
        };
        let tag = |h: &Self| if h.cipher.key.is_some() { TAG_LEN } else { 0 };
        match self.step {
            0 => {
                let re: [u8; DH_LEN] = take(DH_LEN)?.try_into().unwrap();
                self.mix_hash(&re);
                self.re = Some(re);
            }
            1 => {
                let re: [u8; DH_LEN] = take(DH_LEN)?.try_into().unwrap();
                self.mix_hash(&re);
                self.re = Some(re);
                self.ee()?;
                let mut s = [0u8; DH_LEN + TAG_LEN];
                let n = DH_LEN + tag(self);
                s[..n].copy_from_slice(take(n)?);
                self.decrypt_and_hash(&mut s[..n])?;
                self.rs = Some(s[..DH_LEN].try_into().unwrap());
                self.es()?;
            }
            _ => {
                let mut s = [0u8; DH_LEN + TAG_LEN];
                let n = DH_LEN + tag(self);
                s[..n].copy_from_slice(take(n)?);
                self.decrypt_and_hash(&mut s[..n])?;
                self.rs = Some(s[..DH_LEN].try_into().unwrap());
                self.se()?;
            }
        }
        let body = rest;
        let dest = payload.get_mut(..body.len()).ok_or(NoiseError::Length)?;
        dest.copy_from_slice(body);
        let len = self.decrypt_and_hash(dest)?;
        self.step += 1;
        Ok(len)
    }

    /// The other side's static key, once it's been read.
    pub fn remote_static(&self) -> Option<[u8; DH_LEN]> {
        self.rs
    }

    /// Ends a finished handshake: the initiator sends with the first key, the responder with the second.
    pub fn into_transport(self) -> Result<Transport, NoiseError> {
        if !self.is_finished() {
            return Err(NoiseError::State);
        }
        let (mut k1, mut k2) = hkdf(&self.ck, &[]);
        let (send, recv) = if self.initiator { (k1, k2) } else { (k2, k1) };
        k1.zeroize();
        k2.zeroize();
        Ok(Transport {
            send: CipherState { key: Some(send), n: 0 },
            recv: CipherState { key: Some(recv), n: 0 },
            remote_static: self.rs.ok_or(NoiseError::State)?,
        })
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

/// The public key for a static or ephemeral secret.
pub fn public_key(secret: [u8; 32]) -> [u8; DH_LEN] {
    PublicKey::from(&StaticSecret::from(secret)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    const NAME: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
    const PROLOGUE: &[u8] = b"lantern-test";

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn snow(initiator: bool, s: [u8; 32], e: [u8; 32]) -> snow::HandshakeState {
        let b = snow::Builder::new(NAME.parse().unwrap())
            .local_private_key(&s)
            .prologue(PROLOGUE)
            .fixed_ephemeral_key_for_testing_only(&e);
        if initiator { b.build_initiator() } else { b.build_responder() }.unwrap()
    }

    /// Ours as the initiator and snow as the responder: every message is byte for byte what snow, as the initiator with
    /// the same keys, would write, and each side reads the other's.
    #[test]
    fn every_message_is_byte_for_byte_what_snow_writes_and_each_reads_the_other() {
        let (si, ei, sr, er) = (key(1), key(2), key(3), key(4));
        let mut ours = Handshake::new(true, si, ei, PROLOGUE);
        let mut twin = snow(true, si, ei);
        let mut peer = snow(false, sr, er);
        let (mut a, mut b, mut p) = ([0u8; 256], [0u8; 256], [0u8; 256]);
        // -> e, with a payload
        let n = ours.write_message(b"hello", &mut a).unwrap();
        let m = twin.write_message(b"hello", &mut b).unwrap();
        assert_eq!(&a[..n], &b[..m]);
        assert_eq!(peer.read_message(&a[..n], &mut p).unwrap(), 5);
        // <- e, ee, s, es
        let n = peer.write_message(b"from bob", &mut a).unwrap();
        let mut twin_buf = [0u8; 256];
        twin.read_message(&a[..n], &mut twin_buf).unwrap();
        let got = ours.read_message(&a[..n], &mut p).unwrap();
        assert_eq!(&p[..got], b"from bob");
        assert_eq!(ours.remote_static(), Some(public_key(sr)), "it learns who the responder is");
        // -> s, se
        let n = ours.write_message(b"", &mut a).unwrap();
        let m = twin.write_message(b"", &mut b).unwrap();
        assert_eq!(&a[..n], &b[..m]);
        peer.read_message(&a[..n], &mut p).unwrap();
        assert_eq!(peer.get_remote_static().unwrap(), public_key(si), "and the responder who it is");
        // Transport, both ways.
        let mut ours = ours.into_transport().unwrap();
        let mut peer = peer.into_transport_mode().unwrap();
        let mut msg = [0u8; 64];
        msg[..4].copy_from_slice(b"ping");
        let n = ours.write(&mut msg, 4).unwrap();
        assert_eq!(peer.read_message(&msg[..n], &mut p).unwrap(), 4);
        assert_eq!(&p[..4], b"ping");
        let n = peer.write_message(b"pong!", &mut a).unwrap();
        let mut back: Vec<u8> = a[..n].to_vec();
        let len = ours.read(&mut back).unwrap();
        assert_eq!(&back[..len], b"pong!");
    }

    /// Ours as the responder, snow as the initiator.
    #[test]
    fn as_the_responder_it_finishes_snows_handshake() {
        let (si, ei, sr, er) = (key(5), key(6), key(7), key(8));
        let mut init = snow(true, si, ei);
        let mut ours = Handshake::new(false, sr, er, PROLOGUE);
        let (mut a, mut p) = ([0u8; 256], [0u8; 256]);
        let n = init.write_message(&[], &mut a).unwrap();
        assert!(!ours.is_my_turn(), "the initiator goes first");
        ours.read_message(&a[..n], &mut p).unwrap();
        let n = ours.write_message(b"resp", &mut a).unwrap();
        init.read_message(&a[..n], &mut p).unwrap();
        let n = init.write_message(b"fin", &mut a).unwrap();
        let got = ours.read_message(&a[..n], &mut p).unwrap();
        assert_eq!(&p[..got], b"fin");
        assert_eq!(ours.remote_static(), Some(public_key(si)));
        let mut ours = ours.into_transport().unwrap();
        let mut init = init.into_transport_mode().unwrap();
        let n = init.write_message(b"data", &mut a).unwrap();
        let mut m = a[..n].to_vec();
        let len = ours.read(&mut m).unwrap();
        assert_eq!(&m[..len], b"data");
    }

    #[test]
    fn a_changed_byte_or_a_message_out_of_turn_is_refused() {
        let mut init = Handshake::new(true, key(1), key(2), PROLOGUE);
        let mut resp = Handshake::new(false, key(3), key(4), PROLOGUE);
        let (mut a, mut p) = ([0u8; 256], [0u8; 256]);
        assert_eq!(resp.write_message(b"", &mut a), Err(NoiseError::State), "the responder doesn't go first");
        let n = init.write_message(b"", &mut a).unwrap();
        resp.read_message(&a[..n], &mut p).unwrap();
        let n = resp.write_message(b"", &mut a).unwrap();
        // The same handshake twice, from the same keys: one reads the message altered, the other as it was.
        let mut twin = Handshake::new(true, key(1), key(2), PROLOGUE);
        twin.write_message(b"", &mut [0u8; 256]).unwrap();
        let mut bad = a;
        bad[40] ^= 1; // inside the encrypted static key
        assert_eq!(twin.read_message(&bad[..n], &mut p), Err(NoiseError::Decrypt));
        assert!(init.read_message(&a[..n], &mut p).is_ok());
        assert_eq!(init.read_message(&a[..n], &mut p), Err(NoiseError::State), "its turn to write, not read");
        // A different prologue fails at the first encrypted field.
        let mut other = Handshake::new(false, key(3), key(4), b"other");
        let mut i2 = Handshake::new(true, key(1), key(2), PROLOGUE);
        let n = i2.write_message(b"", &mut a).unwrap();
        other.read_message(&a[..n], &mut p).unwrap();
        let n = other.write_message(b"", &mut a).unwrap();
        assert_eq!(i2.read_message(&a[..n], &mut p), Err(NoiseError::Decrypt));
        assert!(Handshake::new(true, key(1), key(2), PROLOGUE).into_transport().is_err(), "not finished");
    }

    #[test]
    fn a_low_order_ephemeral_is_refused() {
        let mut resp = Handshake::new(false, key(3), key(4), PROLOGUE);
        let mut p = [0u8; 64];
        // The all-zero point: any Diffie-Hellman with it is zero.
        resp.read_message(&[0u8; 32], &mut p).unwrap();
        let mut out = [0u8; 256];
        assert_eq!(resp.write_message(b"", &mut out), Err(NoiseError::BadKey));
    }
}
