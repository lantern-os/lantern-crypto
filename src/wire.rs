//! The `keystore` half of
//! [RFC-0019](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0019-confined-service-call-protocol.md)'s
//! wire protocol ([ADR-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0024-confined-service-call-protocol.md)):
//! SIGN/ENCRYPT/DECRYPT request parsing and reply construction, as a pure
//! function so it's fully testable without a confined program, `Recv`, or a
//! shared `Frame`. A confined `keystore-service` (`lantern-boot`) pairs
//! [`handle_request`] with `lantern_abi::frame::Channel` for the actual I/O:
//! `Channel::recv_request` reassembles the request bytes, this module decides
//! what they mean and what to do about them, `Channel::reply` sends the
//! result — the same "one place, reviewed once" split
//! [`lantern_abi::frame`]'s own doc describes for the framing layer.
//!
//! **A confined service's request parser is a trust boundary**
//! (RFC-0019's own Motivation) — every parse here is bounds-checked against
//! the actual slice, never trusts a length field past what the buffer
//! contains, and the badge → [`crate::KeyId`] lookup
//! ([`crate::Keystore::key_for_badge`]) happens *before* any parsing of the
//! operation-specific payload, so a request for a badge this keystore never
//! granted is rejected before the parser even looks at the rest of the
//! bytes.

use crate::aead::{NONCE_LEN, TAG_LEN};
use crate::{Keystore, KeystoreError};

/// Operation codes, per RFC-0019's `keystore` wire format.
pub const OP_SIGN: u16 = 1;
pub const OP_ENCRYPT: u16 = 2;
pub const OP_DECRYPT: u16 = 3;

/// Reply status codes, per RFC-0019's four-value error map.
pub mod status {
    pub const OK: u16 = 0;
    pub const ACCESS: u16 = 1;
    pub const INVALID: u16 = 2;
    pub const FAILED: u16 = 3;
}

/// Handles one already-reassembled request (chunking/framing is
/// [`lantern_abi::frame::Channel`]'s job, not this module's) against
/// `keystore`, on behalf of `badge` (the kernel-delivered sender identity —
/// RFC-0019 never puts the key on the wire). Writes the reply payload into
/// `reply_buf` and returns `(status, len)`: `reply_buf[..len]` is the reply
/// payload iff `status == `[`status::OK`]; every other status's payload is
/// empty (`len == 0`) — including `FAILED`, so a `DECRYPT` tag mismatch never
/// leaks a partial plaintext (RFC-0019's explicit rule).
pub fn handle_request(keystore: &Keystore, badge: u64, op: u16, request: &[u8], reply_buf: &mut [u8]) -> (u16, usize) {
    let Some(key) = keystore.key_for_badge(badge) else {
        return (status::ACCESS, 0);
    };
    match op {
        OP_SIGN => handle_sign(keystore, badge, key, request, reply_buf),
        OP_ENCRYPT => handle_encrypt(keystore, badge, key, request, reply_buf),
        OP_DECRYPT => handle_decrypt(keystore, badge, key, request, reply_buf),
        _ => (status::INVALID, 0),
    }
}

fn status_for(err: KeystoreError) -> u16 {
    match err {
        KeystoreError::UnknownBadge | KeystoreError::BadgeRevoked | KeystoreError::WrongKey | KeystoreError::OpNotGranted => {
            status::ACCESS
        }
        KeystoreError::KeyDestroyed | KeystoreError::CryptoFailure => status::FAILED,
        _ => status::INVALID,
    }
}

/// Reads a `[u32 len][bytes...]`-prefixed field, returning `(field, rest)`.
/// `None` on any length that would read past `bytes` — never trusts the
/// prefix past what's actually there (this module's own trust-boundary
/// discipline, see the module doc).
fn read_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?) as usize;
    let field = bytes.get(4..4 + len)?;
    let rest = bytes.get(4 + len..)?;
    Some((field, rest))
}

/// Writes a `[u32 len][bytes...]`-prefixed field into `buf` at `offset`,
/// returning the offset just past it, or `None` if it wouldn't fit. The
/// client-side counterpart to [`read_prefixed`].
fn write_prefixed(buf: &mut [u8], offset: usize, field: &[u8]) -> Option<usize> {
    let end = offset.checked_add(4)?.checked_add(field.len())?;
    if end > buf.len() {
        return None;
    }
    buf[offset..offset + 4].copy_from_slice(&(field.len() as u32).to_le_bytes());
    buf[offset + 4..end].copy_from_slice(field);
    Some(end)
}

// -- Client-side request/reply codecs — the counterpart to `handle_request`
// -- above, for whatever confined program (`lantern-boot`'s `keystore-client`,
// -- eventually `lantern-filesystem`'s `Store` reaching a keystore-service
// -- over IPC) is the one *calling* SIGN/ENCRYPT/DECRYPT rather than serving
// -- them. Kept here, not re-derived at each call site, so RFC-0019's wire
// -- shape is reviewed in exactly one place (ADR-0024's own framing for why
// -- this split exists).

/// Encodes a SIGN request — the raw message, unchanged; a real function only
/// for symmetry with the other two ops' encoders.
pub fn encode_sign_request(message: &[u8]) -> &[u8] {
    message
}

/// Decodes a SIGN reply payload — the raw signature bytes, unchanged.
pub fn decode_sign_reply(reply: &[u8]) -> &[u8] {
    reply
}

/// Encodes an ENCRYPT request (`[nonce_len][nonce][aad_len][aad][plaintext]`)
/// into `buf`, returning the bytes written, or `None` if `buf` is too small.
pub fn encode_encrypt_request(nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8], buf: &mut [u8]) -> Option<usize> {
    let off = write_prefixed(buf, 0, nonce)?;
    let off = write_prefixed(buf, off, aad)?;
    let end = off.checked_add(plaintext.len())?;
    if end > buf.len() {
        return None;
    }
    buf[off..end].copy_from_slice(plaintext);
    Some(end)
}

/// Decodes an ENCRYPT reply (`[tag_len][tag][ciphertext]`) into
/// `(tag, ciphertext)`, or `None` if malformed or the tag isn't
/// [`TAG_LEN`] bytes.
pub fn decode_encrypt_reply(reply: &[u8]) -> Option<([u8; TAG_LEN], &[u8])> {
    let (tag, ciphertext) = read_prefixed(reply)?;
    Some((tag.try_into().ok()?, ciphertext))
}

/// Encodes a DECRYPT request
/// (`[nonce_len][nonce][aad_len][aad][tag_len][tag][ciphertext]`) into `buf`,
/// returning the bytes written, or `None` if `buf` is too small.
pub fn encode_decrypt_request(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    tag: &[u8; TAG_LEN],
    ciphertext: &[u8],
    buf: &mut [u8],
) -> Option<usize> {
    let off = write_prefixed(buf, 0, nonce)?;
    let off = write_prefixed(buf, off, aad)?;
    let off = write_prefixed(buf, off, tag)?;
    let end = off.checked_add(ciphertext.len())?;
    if end > buf.len() {
        return None;
    }
    buf[off..end].copy_from_slice(ciphertext);
    Some(end)
}

/// Decodes a DECRYPT reply payload — the raw plaintext, unchanged (empty on
/// any non-`OK` status, including `FAILED` — RFC-0019's no-partial-plaintext
/// rule; the caller checks `status` before trusting this).
pub fn decode_decrypt_reply(reply: &[u8]) -> &[u8] {
    reply
}

/// SIGN — request payload is the raw message; reply is the signature,
/// `status = OK`; `FAILED` if the key was destroyed (RFC-0019).
fn handle_sign(keystore: &Keystore, badge: u64, key: crate::KeyId, request: &[u8], reply_buf: &mut [u8]) -> (u16, usize) {
    match keystore.sign(badge, key, request) {
        Ok(sig) if reply_buf.len() >= sig.len() => {
            reply_buf[..sig.len()].copy_from_slice(&sig);
            (status::OK, sig.len())
        }
        Ok(_) => (status::INVALID, 0),
        Err(e) => (status_for(e), 0),
    }
}

/// ENCRYPT — request payload is `[u32 nonce_len][nonce][u32 aad_len][aad][plaintext…]`;
/// reply is `[u32 tag_len][tag][ciphertext…]` (RFC-0019).
fn handle_encrypt(keystore: &Keystore, badge: u64, key: crate::KeyId, request: &[u8], reply_buf: &mut [u8]) -> (u16, usize) {
    let Some((nonce, rest)) = read_prefixed(request) else {
        return (status::INVALID, 0);
    };
    let Some((aad, plaintext)) = read_prefixed(rest) else {
        return (status::INVALID, 0);
    };
    let Ok(nonce): Result<[u8; NONCE_LEN], _> = nonce.try_into() else {
        return (status::INVALID, 0);
    };
    let needed = 4 + TAG_LEN + plaintext.len();
    if reply_buf.len() < needed {
        return (status::INVALID, 0);
    }
    reply_buf[4 + TAG_LEN..needed].copy_from_slice(plaintext);
    match keystore.encrypt(badge, key, &nonce, aad, &mut reply_buf[4 + TAG_LEN..needed]) {
        Ok(tag) => {
            reply_buf[0..4].copy_from_slice(&(TAG_LEN as u32).to_le_bytes());
            reply_buf[4..4 + TAG_LEN].copy_from_slice(&tag);
            (status::OK, needed)
        }
        Err(e) => (status_for(e), 0),
    }
}

/// DECRYPT — request payload is
/// `[u32 nonce_len][nonce][u32 aad_len][aad][u32 tag_len][tag][ciphertext…]`;
/// reply is the plaintext. `FAILED` (empty payload — no partial-plaintext
/// leak) on a tag mismatch (RFC-0019).
fn handle_decrypt(keystore: &Keystore, badge: u64, key: crate::KeyId, request: &[u8], reply_buf: &mut [u8]) -> (u16, usize) {
    let Some((nonce, rest)) = read_prefixed(request) else {
        return (status::INVALID, 0);
    };
    let Some((aad, rest)) = read_prefixed(rest) else {
        return (status::INVALID, 0);
    };
    let Some((tag, ciphertext)) = read_prefixed(rest) else {
        return (status::INVALID, 0);
    };
    let Ok(nonce): Result<[u8; NONCE_LEN], _> = nonce.try_into() else {
        return (status::INVALID, 0);
    };
    let Ok(tag): Result<[u8; TAG_LEN], _> = tag.try_into() else {
        return (status::INVALID, 0);
    };
    if reply_buf.len() < ciphertext.len() {
        return (status::INVALID, 0);
    }
    reply_buf[..ciphertext.len()].copy_from_slice(ciphertext);
    match keystore.decrypt(badge, key, &nonce, aad, &mut reply_buf[..ciphertext.len()], &tag) {
        Ok(()) => (status::OK, ciphertext.len()),
        Err(e) => (status_for(e), 0),
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn encrypt_request_round_trips_through_encode_and_the_server_side_parser() {
        let nonce = [1u8; NONCE_LEN];
        let aad = b"context";
        let plaintext = b"a plaintext message";
        let mut buf = [0u8; 128];
        let len = encode_encrypt_request(&nonce, aad, plaintext, &mut buf).unwrap();

        let (parsed_nonce, rest) = read_prefixed(&buf[..len]).unwrap();
        assert_eq!(parsed_nonce, &nonce);
        let (parsed_aad, parsed_plaintext) = read_prefixed(rest).unwrap();
        assert_eq!(parsed_aad, aad);
        assert_eq!(parsed_plaintext, plaintext);
    }

    #[test]
    fn encrypt_request_too_small_a_buffer_is_none() {
        let nonce = [1u8; NONCE_LEN];
        let mut tiny = [0u8; 4];
        assert_eq!(encode_encrypt_request(&nonce, b"aad", b"plaintext", &mut tiny), None);
    }

    #[test]
    fn encrypt_reply_round_trips() {
        let tag = [7u8; TAG_LEN];
        let ciphertext = b"ciphertext bytes";
        let mut buf = [0u8; 64];
        let end = write_prefixed(&mut buf, 0, &tag).unwrap();
        buf[end..end + ciphertext.len()].copy_from_slice(ciphertext);
        let total = end + ciphertext.len();

        let (decoded_tag, decoded_ciphertext) = decode_encrypt_reply(&buf[..total]).unwrap();
        assert_eq!(decoded_tag, tag);
        assert_eq!(decoded_ciphertext, ciphertext);
    }

    #[test]
    fn encrypt_reply_with_a_wrong_length_tag_is_none() {
        // A 4-byte "tag" -- the length prefix says 4, not TAG_LEN.
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&4u32.to_le_bytes());
        buf[4..8].copy_from_slice(&[9u8; 4]);
        assert_eq!(decode_encrypt_reply(&buf[..8]), None);
    }

    #[test]
    fn decrypt_request_round_trips_through_encode_and_the_server_side_parser() {
        let nonce = [2u8; NONCE_LEN];
        let aad = b"ctx";
        let tag = [3u8; TAG_LEN];
        let ciphertext = b"encrypted bytes here";
        let mut buf = [0u8; 128];
        let len = encode_decrypt_request(&nonce, aad, &tag, ciphertext, &mut buf).unwrap();

        let (parsed_nonce, rest) = read_prefixed(&buf[..len]).unwrap();
        assert_eq!(parsed_nonce, &nonce);
        let (parsed_aad, rest) = read_prefixed(rest).unwrap();
        assert_eq!(parsed_aad, aad);
        let (parsed_tag, parsed_ciphertext) = read_prefixed(rest).unwrap();
        assert_eq!(parsed_tag, &tag);
        assert_eq!(parsed_ciphertext, ciphertext);
    }

    #[test]
    fn sign_codec_is_the_identity() {
        assert_eq!(encode_sign_request(b"hello"), b"hello");
        assert_eq!(decode_sign_reply(b"a signature"), b"a signature");
        assert_eq!(decode_decrypt_reply(b"plaintext"), b"plaintext");
    }
}

#[cfg(all(test, feature = "kernel-backend"))]
mod tests {
    use super::*;
    use crate::aead;
    use crate::KeyOps;

    /// Builds a fresh `Keystore` (plus the throwaway `KernelState`/`TcbId`
    /// its grant needs, real IPC underneath — same shape as `lib.rs`'s own
    /// `tests` module, which this can't reach directly since it's private),
    /// generates one key via `make_key`, and grants `ops` on it. Returns the
    /// keystore, the badge, and the key — this module only needs a
    /// `&Keystore` with a real grant on it, not the IPC machinery itself.
    fn granted_keystore(
        ops: KeyOps,
        make_key: impl FnOnce(&mut Keystore) -> crate::KeyId,
    ) -> (Keystore, u64, crate::KeyId) {
        use lantern_capabilities::KernelBackend;
        use lantern_kernel::cap::{CNode, CNodeId, Capability, NotificationId, Rights, TcbId};
        use lantern_kernel::object::{Notification, Tcb};
        use lantern_kernel::state::KernelState;

        let mut state = KernelState::new();
        let cnode_idx = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(cnode_idx);
        *state.cnodes.get_mut(cnode_idx.0 as usize).unwrap().slot_mut(0).unwrap() = Capability::CNode(cnode_idx);
        let notif_idx = state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification { id: NotificationId(notif_idx as u16), badge: 0, rights: Rights::WRITE.union(Rights::GRANT) };
        *state.cnodes.get_mut(cnode_idx.0 as usize).unwrap().slot_mut(5).unwrap() = source;

        let mut keystore = Keystore::new(0);
        let key = make_key(&mut keystore);
        let badge =
            keystore.request_key_access(&mut KernelBackend::new(&mut state, tcb), key, ops, 5, 6).unwrap();
        (keystore, badge, key)
    }

    fn granted_encrypt_decrypt_keystore() -> (Keystore, u64, crate::KeyId) {
        granted_keystore(KeyOps::ENCRYPT.union(KeyOps::DECRYPT), |ks| {
            ks.generate_aead_key([9u8; aead::AEAD_KEY_LEN]).unwrap()
        })
    }

    fn granted_sign_keystore() -> (Keystore, u64, crate::KeyId) {
        granted_keystore(KeyOps::SIGN, |ks| ks.generate_signing_key([2u8; crate::signing::SEED_LEN]).unwrap())
    }

    #[test]
    fn sign_round_trips_through_the_wire_format() {
        let (keystore, badge, key) = granted_sign_keystore();

        let mut reply = [0u8; 128];
        let (s, len) = handle_request(&keystore, badge, OP_SIGN, b"hello wire", &mut reply);
        assert_eq!(s, status::OK);
        assert_eq!(len, crate::signing::SIGNATURE_LEN);
        keystore.verify(key, b"hello wire", reply[..len].try_into().unwrap()).unwrap();
    }

    #[test]
    fn encrypt_then_decrypt_round_trips_through_the_wire_format() {
        let (keystore, badge, _key) = granted_encrypt_decrypt_keystore();

        let nonce = [7u8; NONCE_LEN];
        let aad = b"ctx";
        let plaintext = b"a shared-frame secret";
        let mut request = [0u8; 128];
        let mut off = 0;
        request[off..off + 4].copy_from_slice(&(NONCE_LEN as u32).to_le_bytes());
        off += 4;
        request[off..off + NONCE_LEN].copy_from_slice(&nonce);
        off += NONCE_LEN;
        request[off..off + 4].copy_from_slice(&(aad.len() as u32).to_le_bytes());
        off += 4;
        request[off..off + aad.len()].copy_from_slice(aad);
        off += aad.len();
        request[off..off + plaintext.len()].copy_from_slice(plaintext);
        off += plaintext.len();

        let mut reply = [0u8; 128];
        let (s, len) = handle_request(&keystore, badge, OP_ENCRYPT, &request[..off], &mut reply);
        assert_eq!(s, status::OK);
        let tag_len = u32::from_le_bytes(reply[0..4].try_into().unwrap()) as usize;
        assert_eq!(tag_len, TAG_LEN);
        let tag = &reply[4..4 + TAG_LEN];
        let ciphertext = &reply[4 + TAG_LEN..len];
        assert_ne!(ciphertext, plaintext);

        // DECRYPT request: [nonce_len][nonce][aad_len][aad][tag_len][tag][ciphertext]
        let mut decrypt_req = [0u8; 128];
        let mut off = 0;
        decrypt_req[off..off + 4].copy_from_slice(&(NONCE_LEN as u32).to_le_bytes());
        off += 4;
        decrypt_req[off..off + NONCE_LEN].copy_from_slice(&nonce);
        off += NONCE_LEN;
        decrypt_req[off..off + 4].copy_from_slice(&(aad.len() as u32).to_le_bytes());
        off += 4;
        decrypt_req[off..off + aad.len()].copy_from_slice(aad);
        off += aad.len();
        decrypt_req[off..off + 4].copy_from_slice(&(TAG_LEN as u32).to_le_bytes());
        off += 4;
        decrypt_req[off..off + TAG_LEN].copy_from_slice(tag);
        off += TAG_LEN;
        decrypt_req[off..off + ciphertext.len()].copy_from_slice(ciphertext);
        off += ciphertext.len();

        let mut decrypted = [0u8; 128];
        let (s, len) = handle_request(&keystore, badge, OP_DECRYPT, &decrypt_req[..off], &mut decrypted);
        assert_eq!(s, status::OK);
        assert_eq!(&decrypted[..len], plaintext);
    }

    #[test]
    fn decrypt_with_a_tampered_tag_fails_and_leaks_nothing() {
        let (keystore, badge, _key) = granted_encrypt_decrypt_keystore();
        let nonce = [7u8; NONCE_LEN];
        let mut request = [0u8; 64];
        let mut off = 0;
        request[off..off + 4].copy_from_slice(&(NONCE_LEN as u32).to_le_bytes());
        off += 4;
        request[off..off + NONCE_LEN].copy_from_slice(&nonce);
        off += NONCE_LEN;
        request[off..off + 4].copy_from_slice(&0u32.to_le_bytes()); // empty aad
        off += 4;
        request[off..off + 4].copy_from_slice(&(TAG_LEN as u32).to_le_bytes());
        off += 4;
        request[off..off + TAG_LEN].copy_from_slice(&[0xAAu8; TAG_LEN]); // bogus tag
        off += TAG_LEN;
        request[off..off + 4].copy_from_slice(b"evil");
        off += 4;

        let mut reply = [0xFFu8; 64]; // poison the buffer to prove nothing leaks
        let (s, len) = handle_request(&keystore, badge, OP_DECRYPT, &request[..off], &mut reply);
        assert_eq!(s, status::FAILED);
        assert_eq!(len, 0, "a tag mismatch must never carry a partial plaintext");
    }

    #[test]
    fn unknown_badge_is_access_denied_before_any_parsing() {
        let (keystore, _badge, _key) = granted_encrypt_decrypt_keystore();
        let mut reply = [0u8; 16];
        // Malformed payload -- if this were parsed at all it would be
        // INVALID, not ACCESS; the badge check must come first.
        let (s, len) = handle_request(&keystore, 0xDEAD_BEEF, OP_ENCRYPT, b"\xFF\xFF\xFF\xFF", &mut reply);
        assert_eq!(s, status::ACCESS);
        assert_eq!(len, 0);
    }

    #[test]
    fn unknown_op_is_invalid() {
        let (keystore, badge, _key) = granted_encrypt_decrypt_keystore();
        let mut reply = [0u8; 16];
        let (s, len) = handle_request(&keystore, badge, 99, b"", &mut reply);
        assert_eq!(s, status::INVALID);
        assert_eq!(len, 0);
    }

    #[test]
    fn truncated_encrypt_request_is_invalid_not_a_panic() {
        let (keystore, badge, _key) = granted_encrypt_decrypt_keystore();
        let mut reply = [0u8; 16];
        // Claims a huge nonce_len the buffer doesn't actually contain.
        let bogus = [0xFFu8, 0xFF, 0xFF, 0x7F];
        let (s, len) = handle_request(&keystore, badge, OP_ENCRYPT, &bogus, &mut reply);
        assert_eq!(s, status::INVALID);
        assert_eq!(len, 0);
    }

    #[test]
    fn a_reply_buffer_too_small_for_the_signature_is_invalid() {
        let (keystore, badge, _key) = granted_sign_keystore();

        let mut too_small = [0u8; 4];
        let (s, len) = handle_request(&keystore, badge, OP_SIGN, b"hi", &mut too_small);
        assert_eq!(s, status::INVALID);
        assert_eq!(len, 0);
    }
}
