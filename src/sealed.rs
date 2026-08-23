//! Sealed capabilities — [RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)/
//! [ADR-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0015-sealed-capability-token-format.md) fix a
//! macaroon-style, BLAKE3-keyed-MAC-chained token as RFC-0003/ADR-0006's
//! third capability layer: a bearer credential for delegation that crosses
//! machines or persists.
//!
//! This module owns the token structure and the pure MAC-chaining
//! construction ([`seal`]/[`attenuate`]/[`verify_chain`]); [`crate::Keystore`]
//! wires it to real root-key custody and revocation
//! (`Keystore::seal`/`Keystore::unseal`/`Keystore::revoke_seal`) the same way
//! [`crate::hash`]'s [`crate::hash::MacKey`] is a bare primitive that
//! `Keystore` separately gates. [`attenuate`] is the one operation here that
//! deliberately does **not** go through `Keystore` — see its doc for why.
//!
//! **What this is not:** the "then mint a live capability" half of `unseal`.
//! Per RFC-0011's design, a verified token only ever *justifies* whichever
//! service unsealed it calling an ordinary
//! [`lantern_capabilities::Broker::mint`]/`grant` on the live capability the
//! token's `identifier` designates — this crate has no notion of what an
//! `identifier` designates (that's the future issuing service's own table,
//! the same "mechanism, not policy" line [`crate::Keystore`]'s own doc draws
//! for `Broker`). This module only ever proves "this token is genuine, is
//! not revoked, and its caveats are satisfied" — never grants anything
//! itself.

use crate::hash::{self, Hash};
use lantern_kernel::cap::Rights;

pub const IDENTIFIER_LEN: usize = 16;
/// Phase 2's deliberately small cap, per RFC-0011's "narrowest slice that
/// closes the concrete gap" precedent — raising it later is additive, not a
/// format break.
pub const MAX_CAVEATS: usize = 4;
/// Tag byte + the largest payload any [`Caveat`] variant needs
/// ([`Caveat::ExpiresAt`]'s `u64`) — every caveat encodes to exactly this
/// many bytes, so there is no variable-length framing to get wrong.
const ENCODED_CAVEAT_LEN: usize = 9;

/// A first-party restriction, checked locally by whichever service unseals a
/// token — see this module's top-level doc on why third-party caveats
/// (macaroons' discharge mechanism) aren't here yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Caveat {
    /// The eventual minted live capability's rights must be a subset of
    /// this.
    RightsSubset(Rights),
    /// A Unix-style timestamp after which this token (and everything
    /// attenuated from it) must be treated as expired. Checking this
    /// requires a clock source `lantern-hal` doesn't have yet — see
    /// [`Keystore::unseal`](crate::Keystore::unseal)'s `now` parameter doc.
    ExpiresAt(u64),
}

impl Caveat {
    fn encode(&self) -> [u8; ENCODED_CAVEAT_LEN] {
        let mut buf = [0u8; ENCODED_CAVEAT_LEN];
        match self {
            Caveat::RightsSubset(rights) => {
                buf[0] = 0;
                buf[1] = rights.bits();
            }
            Caveat::ExpiresAt(timestamp) => {
                buf[0] = 1;
                buf[1..9].copy_from_slice(&timestamp.to_be_bytes());
            }
        }
        buf
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SealedError;

/// A macaroon-style sealed capability — see this module's top-level doc.
/// `Copy`, fixed-size, no heap: the token itself is just bytes, matching
/// every other pool/record type in this project.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SealedToken {
    identifier: [u8; IDENTIFIER_LEN],
    caveat_count: u8,
    caveats: [Option<Caveat>; MAX_CAVEATS],
    mac: Hash,
}

impl SealedToken {
    pub const fn identifier(&self) -> &[u8; IDENTIFIER_LEN] {
        &self.identifier
    }

    pub fn caveats(&self) -> &[Option<Caveat>] {
        &self.caveats[..self.caveat_count as usize]
    }
}

/// Issues a fresh root token: `mac_0 = root_key.compute(identifier)`, then
/// chains one link per initial caveat. `root_key` never appears in the
/// returned token — only its effect (the final MAC) does.
pub fn seal(root_key: &hash::MacKey, identifier: [u8; IDENTIFIER_LEN], caveats: &[Caveat]) -> Result<SealedToken, SealedError> {
    if caveats.len() > MAX_CAVEATS {
        return Err(SealedError);
    }
    let mut mac = root_key.compute(&identifier);
    let mut stored = [None; MAX_CAVEATS];
    for (slot, caveat) in stored.iter_mut().zip(caveats) {
        mac = hash::MacKey::from_bytes(*mac.as_bytes()).compute(&caveat.encode());
        *slot = Some(*caveat);
    }
    Ok(SealedToken { identifier, caveat_count: caveats.len() as u8, caveats: stored, mac })
}

/// Appends `caveat` and rechains the MAC from `token`'s own current `mac` —
/// **no root key required**. This is the offline-attenuation property
/// RFC-0011's Guide-level explanation walks through: the holder has `mac_n`
/// (it's a field of `token`), which is exactly the key the next link needs,
/// but has none of the earlier links or `root_key` itself, so this can only
/// ever narrow, never forge a token with a caveat removed.
pub fn attenuate(token: &SealedToken, caveat: Caveat) -> Result<SealedToken, SealedError> {
    let n = token.caveat_count as usize;
    if n >= MAX_CAVEATS {
        return Err(SealedError);
    }
    let next_mac = hash::MacKey::from_bytes(*token.mac.as_bytes()).compute(&caveat.encode());
    let mut caveats = token.caveats;
    caveats[n] = Some(caveat);
    Ok(SealedToken { identifier: token.identifier, caveat_count: token.caveat_count + 1, caveats, mac: next_mac })
}

/// Recomputes the MAC chain from `root_key` through every caveat `token`
/// carries and compares it, in constant time, against `token`'s own `mac` —
/// the cryptographic half of `unseal`. Does **not** evaluate whether any
/// caveat is actually *satisfied* (expiry, rights) — that's context-
/// dependent and left to the caller
/// ([`Keystore::unseal`](crate::Keystore::unseal)), the same
/// separation macaroons draw between "is this token genuine" and "does the
/// current request satisfy it."
pub(crate) fn verify_chain(root_key: &hash::MacKey, token: &SealedToken) -> bool {
    let mut mac = root_key.compute(&token.identifier);
    for caveat in token.caveats() {
        let Some(caveat) = caveat else { return false };
        mac = hash::MacKey::from_bytes(*mac.as_bytes()).compute(&caveat.encode());
    }
    mac.ct_eq(&token.mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; IDENTIFIER_LEN] = [7u8; IDENTIFIER_LEN];

    fn root() -> hash::MacKey {
        hash::MacKey::from_random_bytes([1u8; hash::MAC_KEY_LEN])
    }

    #[test]
    fn a_freshly_sealed_token_verifies_against_its_root_key() {
        let token = seal(&root(), ID, &[]).unwrap();
        assert!(verify_chain(&root(), &token));
    }

    #[test]
    fn verification_fails_under_the_wrong_root_key() {
        let token = seal(&root(), ID, &[]).unwrap();
        let wrong = hash::MacKey::from_random_bytes([2u8; hash::MAC_KEY_LEN]);
        assert!(!verify_chain(&wrong, &token));
    }

    #[test]
    fn attenuation_needs_no_root_key_and_still_verifies() {
        let token = seal(&root(), ID, &[Caveat::RightsSubset(Rights::ALL)]).unwrap();
        let narrowed = attenuate(&token, Caveat::ExpiresAt(1000)).unwrap();
        assert_eq!(narrowed.caveats().len(), 2);
        assert!(verify_chain(&root(), &narrowed));
    }

    #[test]
    fn tampering_with_a_caveat_after_the_fact_fails_verification() {
        let mut token = seal(&root(), ID, &[Caveat::RightsSubset(Rights::READ)]).unwrap();
        // Simulate a forger rewriting a caveat without redoing the chain --
        // the stored mac no longer matches what re-chaining produces.
        token.caveats[0] = Some(Caveat::RightsSubset(Rights::ALL));
        assert!(!verify_chain(&root(), &token));
    }

    #[test]
    fn too_many_caveats_is_rejected() {
        let caveats = [Caveat::ExpiresAt(1); MAX_CAVEATS + 1];
        assert_eq!(seal(&root(), ID, &caveats), Err(SealedError));
    }
}
