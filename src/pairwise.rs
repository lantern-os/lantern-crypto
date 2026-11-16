//! Pairwise identities ([RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)): one X25519 key per
//! context, from one secret root, so that no two contexts' keys can be linked without it.
//!
//! A context is an app (its principal, which the binder names) and a peer (its name). The secret for a context is keyed
//! BLAKE3, a pseudorandom function, of the root over a domain separator and both, each length-prefixed. Two outputs for
//! different inputs are independent to anyone without the root, which is the whole of the unlinkability claim: two peers
//! comparing keys learn nothing.

/// The secret key for `(principal, peer)` under `root`.
pub fn secret(root: &[u8; 32], principal: u64, peer: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(root);
    h.update(b"lantern-pairwise-v1");
    h.update(&principal.to_le_bytes());
    h.update(&(peer.len() as u64).to_le_bytes());
    h.update(peer);
    *h.finalize().as_bytes()
}

/// The public key a peer sees for `(principal, peer)` under `root`.
pub fn public(root: &[u8; 32], principal: u64, peer: &[u8]) -> [u8; 32] {
    crate::noise::public_key(secret(root, principal, peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_context_keeps_its_key_and_any_other_context_gets_another() {
        let root = [7u8; 32];
        let alice = public(&root, 0xa1, b"alice.test");
        assert_eq!(alice, public(&root, 0xa1, b"alice.test"), "stable");
        assert_ne!(alice, public(&root, 0xa1, b"bob.test"), "another peer");
        assert_ne!(alice, public(&root, 0xa1, b"carol.test"), "another peer whose name is as long");
        assert_ne!(alice, public(&root, 0xa2, b"alice.test"), "another app, the same peer");
        assert_ne!(alice, public(&[8u8; 32], 0xa1, b"alice.test"), "another root");
        // Lengths keep `("ab", "c")`-style splits apart: the principal is fixed-width and the peer prefixed.
        assert_ne!(secret(&root, 0, b"x"), secret(&root, 0, b"x\0"));
    }
}
