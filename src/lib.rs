//! `lantern-crypto` — the keystore and crypto-operation service
//! ([RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md),
//! [ADR-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0011-cryptographic-primitive-set.md)).
//! Phase 2's first prototype code in this crate
//! ([RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/
//! [ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md)):
//! a fixed-capacity [`Keystore`] holding AEAD ([`aead`]), signing
//! ([`signing`]), and BLAKE3-keyed-MAC ([`hash`]) key material, gating every
//! operation on a [`lantern_capabilities::Broker`]-issued badge — "no raw
//! keys to apps, only operation capabilities" (`ARCHITECTURE.md`'s first
//! principle, X1 in `THREAT_MODEL.md`). [`hash`] also has BLAKE3's *unkeyed*
//! hashing ([`hash::hash`]/[`hash::Hasher`]) as free functions — no secret
//! material, so nothing to gate; see that module's doc for the content-
//! addressing use RFC-0007 names for it. [`sealed`] builds RFC-0003's third
//! capability layer ([RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)/
//! [ADR-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0015-sealed-capability-token-format.md)) on top of
//! [`hash::MacKey`]: [`Keystore::seal`]/[`Keystore::unseal`]/
//! [`Keystore::revoke_seal`] wire a macaroon-style token to real root-key
//! custody and revocation, the same badge-gated shape as every other
//! `Keystore` operation.
//!
//! [`Keystore`] is the concrete object semantics
//! `lantern-capabilities/src/lib.rs`'s own doc names as `Broker`'s job to stay
//! out of: `Broker` mints and grants a badge over real IPC and tracks
//! revocation; it knows nothing about what that badge is *for*. This crate
//! adds the missing half — a badge here also names a specific [`KeyId`] and a
//! specific [`KeyOps`] subset (encrypt/decrypt/sign/mac), checked on every
//! operation in [`Keystore::check_access`] before any key material is
//! touched.
//!
//! **Randomness is deliberately out of scope here.** ADR-0011's "OS CSPRNG
//! seeded from hardware entropy" is a `lantern-hal` concern that doesn't
//! exist yet (`STATUS.md`'s "Blocked on"). [`Keystore::generate_aead_key`]/
//! [`Keystore::generate_signing_key`]/[`Keystore::generate_mac_key`] take
//! caller-supplied random bytes rather than sourcing entropy themselves, so
//! this crate stays correct and
//! entropy-source-agnostic regardless of where that source ends up living —
//! real callers are expected to pass bytes from a real CSPRNG once one
//! exists; today's tests pass fixed/counter-derived bytes, which is only
//! safe because it's a test.
//!
//! **What this is not yet**, matching `lantern-capabilities`'s own honesty
//! about `Broker`: a real, standalone confined program. [`Keystore`]'s
//! methods take `&mut lantern_kernel::state::KernelState` directly, the same
//! privileged-code-only shape `Broker` has today — turning this into
//! deployable confined-service code still needs `lantern-runtime`'s
//! not-yet-built confined execution environment, not more work here.
#![cfg_attr(not(test), no_std)]

pub mod aead;
pub mod hash;
pub mod sealed;
pub mod signing;

use lantern_capabilities::Broker;
use lantern_kernel::cap::{CPtr, Rights, TcbId};
use lantern_kernel::error::SyscallError;
use lantern_kernel::state::KernelState;

/// Fixed capacity, no heap — matches [`lantern_capabilities::Broker`]'s own
/// `MAX_GRANTS` convention.
const MAX_KEYS: usize = 16;
const MAX_GRANTS: usize = 32;
/// Outstanding sealed-token identifiers this `Keystore` has issued —
/// [`Keystore::seal`]/[`Keystore::unseal`]/[`Keystore::revoke_seal`].
const MAX_SEALS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyId(u16);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyPurpose {
    Aead,
    Signing,
    /// A BLAKE3 keyed-mode MAC key ([`crate::hash::MacKey`]) — unlike
    /// [`crate::hash::hash`] itself (unkeyed, ungated, see that module's
    /// doc), a MAC key is secret material and goes through the same
    /// gating as every other key purpose here.
    Mac,
}

/// The operations a granted badge may be scoped to — orthogonal to
/// [`lantern_kernel::cap::Rights`], which governs the *kernel* capability
/// `Broker::mint` transfers, not what a client is allowed to do with the key
/// it names. `VERIFY` has no bit here: verification only needs a public key,
/// never gated (see [`Keystore::verify`]'s doc).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyOps(u8);

impl KeyOps {
    pub const NONE: KeyOps = KeyOps(0);
    pub const ENCRYPT: KeyOps = KeyOps(1 << 0);
    pub const DECRYPT: KeyOps = KeyOps(1 << 1);
    pub const SIGN: KeyOps = KeyOps(1 << 2);
    /// Covers both computing *and* verifying a MAC — unlike
    /// [`KeyOps::SIGN`]/verify, both directions need the same secret key
    /// (see [`crate::hash`]'s doc), so there's no ungated-verify split here.
    pub const MAC: KeyOps = KeyOps(1 << 3);

    pub const fn union(self, other: KeyOps) -> KeyOps {
        KeyOps(self.0 | other.0)
    }

    pub const fn contains(self, other: KeyOps) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether every bit in `self` is a meaningful operation for a key of
    /// `purpose` — [`Keystore::request_key_access`] rejects, e.g., `SIGN`
    /// against an AEAD key up front, rather than minting a badge that would
    /// only ever fail [`Keystore::check_access`] later.
    const fn valid_for(self, purpose: KeyPurpose) -> bool {
        match purpose {
            KeyPurpose::Aead => self.is_subset_of(KeyOps::ENCRYPT.union(KeyOps::DECRYPT)),
            KeyPurpose::Signing => self.is_subset_of(KeyOps::SIGN),
            KeyPurpose::Mac => self.is_subset_of(KeyOps::MAC),
        }
    }

    const fn is_subset_of(self, other: KeyOps) -> bool {
        self.0 & !other.0 == 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeystoreError {
    NoSuchKey,
    /// The key exists but [`Keystore::destroy`] already zeroised it.
    KeyDestroyed,
    /// The requested [`KeyOps`] don't make sense for the key's
    /// [`KeyPurpose`] (checked in [`Keystore::request_key_access`]).
    WrongPurpose,
    NotEnoughCapacity,
    /// A badge [`Keystore`] never granted, or has forgotten — deny by
    /// default, same convention as
    /// [`lantern_capabilities::Broker::is_revoked`].
    UnknownBadge,
    BadgeRevoked,
    /// The badge is valid but wasn't granted the operation being attempted.
    OpNotGranted,
    /// The badge names a different key than the one passed in — deny without
    /// revealing which key it *does* match.
    WrongKey,
    /// The underlying AEAD/signature primitive rejected the operation
    /// (authentication failure on decrypt, bad signature on verify, or a
    /// malformed public key/signature encoding).
    CryptoFailure,
    /// [`sealed::seal`]/[`sealed::attenuate`] rejected the request (too many
    /// caveats — [`sealed::MAX_CAVEATS`]).
    TooManyCaveats,
    /// [`Keystore::unseal`] was given an `identifier` this `Keystore` never
    /// sealed a root token under — deny by default, same convention as the
    /// [`KeystoreError::UnknownBadge`] variant above.
    UnknownSeal,
    /// [`Keystore::revoke_seal`] was already called for this `identifier`.
    SealRevoked,
    /// The token's MAC chain doesn't recompute to its own `mac` field —
    /// forged, corrupted, or sealed under a different root key.
    TokenInvalid,
    /// The token is genuine and unrevoked, but at least one
    /// [`sealed::Caveat`] isn't satisfied by the current request (rights not
    /// a subset, or expired/no clock source to check against).
    CaveatNotSatisfied,
    /// A real kernel-level failure surfaced by the composed
    /// [`lantern_capabilities::Broker`] (e.g. `Broker::mint`'s own
    /// `Rights::GRANT` check, or a kernel `CNodeInvoke`/IPC error) — this
    /// crate never invents its own meaning for these, just forwards them.
    Kernel(SyscallError),
}

enum KeyMaterial {
    Aead(aead::AeadKey),
    Signing(signing::SigningKey),
    Mac(hash::MacKey),
    /// [`Keystore::destroy`] leaves a tombstone here rather than freeing the
    /// slot: [`KeyId`]s are never reused (see [`Keystore::alloc_key_slot`]'s
    /// doc for why reuse would be a real bug, not just a wart), the same
    /// no-reclaim discipline
    /// [`lantern_capabilities::Broker::revoke`] documents for badge slots.
    Destroyed,
}

struct KeyRecord {
    purpose: KeyPurpose,
    material: KeyMaterial,
}

#[derive(Clone, Copy)]
struct GrantRecord {
    badge: u64,
    key: KeyId,
    ops: KeyOps,
}

/// Tracks one [`Keystore::seal`]-issued root token's binding to the
/// [`KeyId`] that holds its root key, plus revocation — the same
/// `identifier → revoked` shape RFC-0011/ADR-0015 mandate, alongside the
/// binding [`Keystore::unseal`] needs to actually recompute the MAC chain.
#[derive(Clone, Copy)]
struct SealRecord {
    identifier: [u8; sealed::IDENTIFIER_LEN],
    key: KeyId,
    revoked: bool,
}

/// The crypto keystore: owns key material and a composed
/// [`lantern_capabilities::Broker`] for the kernel-level mint/grant
/// mechanism, adding the key-and-operation-scoped object semantics `Broker`
/// itself deliberately doesn't know about.
pub struct Keystore {
    broker: Broker,
    keys: [Option<KeyRecord>; MAX_KEYS],
    grants: [Option<GrantRecord>; MAX_GRANTS],
    seals: [Option<SealRecord>; MAX_SEALS],
}

impl Keystore {
    /// `self_tcb`/`self_cnode_cptr` — forwarded to
    /// [`lantern_capabilities::Broker::new`]; see its doc for the
    /// self-CNode-capability precondition the caller is responsible for.
    pub fn new(self_tcb: TcbId, self_cnode_cptr: CPtr) -> Self {
        Self {
            broker: Broker::new(self_tcb, self_cnode_cptr),
            keys: [const { None }; MAX_KEYS],
            grants: [None; MAX_GRANTS],
            seals: [None; MAX_SEALS],
        }
    }

    /// First empty slot, permanently owned by whichever key lands there —
    /// never reused, even after [`Keystore::destroy`]. Reusing a slot would
    /// let a badge minted against the *old* key at that index silently start
    /// naming an unrelated *new* key of the same [`KeyId`] — exactly the kind
    /// of confused-deputy bug capability systems exist to rule out, so this
    /// crate doesn't reintroduce it at the object-semantics layer even though
    /// nothing at the kernel layer would catch it.
    fn alloc_key_slot(&mut self) -> Result<KeyId, KeystoreError> {
        let idx = self.keys.iter().position(Option::is_none).ok_or(KeystoreError::NotEnoughCapacity)?;
        Ok(KeyId(idx as u16))
    }

    fn key_record(&self, id: KeyId) -> Result<&KeyRecord, KeystoreError> {
        self.keys.get(id.0 as usize).and_then(Option::as_ref).ok_or(KeystoreError::NoSuchKey)
    }

    /// Generates and stores a new AEAD key from caller-supplied random bytes
    /// — see this crate's top-level doc on why the bytes come from the
    /// caller, not this method.
    pub fn generate_aead_key(&mut self, random_bytes: [u8; aead::AEAD_KEY_LEN]) -> Result<KeyId, KeystoreError> {
        let id = self.alloc_key_slot()?;
        self.keys[id.0 as usize] =
            Some(KeyRecord { purpose: KeyPurpose::Aead, material: KeyMaterial::Aead(aead::AeadKey::from_random_bytes(random_bytes)) });
        Ok(id)
    }

    /// Generates and stores a new Ed25519 signing key from a caller-supplied
    /// random seed — same entropy-sourcing caveat as
    /// [`Keystore::generate_aead_key`].
    pub fn generate_signing_key(&mut self, random_seed: [u8; signing::SEED_LEN]) -> Result<KeyId, KeystoreError> {
        let id = self.alloc_key_slot()?;
        self.keys[id.0 as usize] =
            Some(KeyRecord { purpose: KeyPurpose::Signing, material: KeyMaterial::Signing(signing::SigningKey::from_random_bytes(random_seed)) });
        Ok(id)
    }

    /// Generates and stores a new BLAKE3 keyed-mode MAC key — same
    /// entropy-sourcing caveat as [`Keystore::generate_aead_key`].
    pub fn generate_mac_key(&mut self, random_bytes: [u8; hash::MAC_KEY_LEN]) -> Result<KeyId, KeystoreError> {
        let id = self.alloc_key_slot()?;
        self.keys[id.0 as usize] =
            Some(KeyRecord { purpose: KeyPurpose::Mac, material: KeyMaterial::Mac(hash::MacKey::from_random_bytes(random_bytes)) });
        Ok(id)
    }

    /// Zeroises `key`'s material and tombstones its slot (see
    /// [`Keystore::alloc_key_slot`]). Does **not** touch any badge already
    /// granted against it: those badges keep passing
    /// [`Keystore::check_access`]'s badge/ops checks, but every operation
    /// they'd unlock now fails with [`KeystoreError::KeyDestroyed`] instead —
    /// the same "kernel capability still works, service-level semantics stop
    /// honouring it" split [`lantern_capabilities::Broker::revoke`] documents
    /// for its own badges.
    pub fn destroy(&mut self, key: KeyId) -> Result<(), KeystoreError> {
        let record = self.keys.get_mut(key.0 as usize).and_then(Option::as_mut).ok_or(KeystoreError::NoSuchKey)?;
        record.material = KeyMaterial::Destroyed;
        Ok(())
    }

    /// Mints a badge (via the composed [`lantern_capabilities::Broker`])
    /// scoped to `key` and `ops`, and records that scoping locally. Rejects
    /// up front if `ops` doesn't make sense for `key`'s [`KeyPurpose`]
    /// ([`KeyOps::valid_for`]) or if `key` is unknown/destroyed — a badge
    /// that could only ever fail [`Keystore::check_access`] later is a bug to
    /// catch here, not at first use.
    ///
    /// This only mints and records the local grant; it does **not** transfer
    /// anything to a client yet — call [`Keystore::deliver_grant`] (or
    /// [`Keystore::deliver_grant_via_reply`]) next, same two-step shape as
    /// `Broker::mint` then `Broker::grant`.
    pub fn request_key_access(
        &mut self,
        state: &mut KernelState,
        key: KeyId,
        ops: KeyOps,
        source_slot: CPtr,
        scratch_slot: CPtr,
    ) -> Result<u64, KeystoreError> {
        let record = self.key_record(key)?;
        if matches!(record.material, KeyMaterial::Destroyed) {
            return Err(KeystoreError::KeyDestroyed);
        }
        if !ops.valid_for(record.purpose) {
            return Err(KeystoreError::WrongPurpose);
        }

        let slot = self.grants.iter().position(Option::is_none).ok_or(KeystoreError::NotEnoughCapacity)?;
        let badge = self.broker.mint(state, source_slot, scratch_slot, Rights::READ.union(Rights::GRANT)).map_err(KeystoreError::Kernel)?;
        self.grants[slot] = Some(GrantRecord { badge, key, ops });
        Ok(badge)
    }

    /// Transfers the badge [`Keystore::request_key_access`] just minted to a
    /// client blocked in `Recv` on `endpoint_cptr` — forwards to
    /// [`lantern_capabilities::Broker::grant`]; see its doc.
    pub fn deliver_grant(&self, state: &mut KernelState, endpoint_cptr: CPtr, scratch_slot: CPtr, payload: (usize, usize)) -> Result<(), KeystoreError> {
        self.broker.grant(state, endpoint_cptr, scratch_slot, payload).map_err(KeystoreError::Kernel)
    }

    /// Like [`Keystore::deliver_grant`], but replies to a `Call` this
    /// keystore is currently holding a `reply_to` link for — forwards to
    /// [`lantern_capabilities::Broker::grant_via_reply`]; see its doc for the
    /// request/response shape this fits (a client asking for access to a
    /// specific key, granted in the same round trip).
    pub fn deliver_grant_via_reply(&self, state: &mut KernelState, scratch_slot: CPtr, payload: (usize, usize)) -> Result<(), KeystoreError> {
        self.broker.grant_via_reply(state, scratch_slot, payload).map_err(KeystoreError::Kernel)
    }

    /// Marks `badge` revoked — forwards to
    /// [`lantern_capabilities::Broker::revoke`]; see its doc. Every
    /// [`Keystore`] operation checks this via [`Keystore::check_access`].
    pub fn revoke_access(&mut self, badge: u64) -> Result<(), KeystoreError> {
        self.broker.revoke(badge).map_err(KeystoreError::Kernel)
    }

    /// **Deny by default.** Checks, in order: the badge isn't revoked
    /// (delegating to [`lantern_capabilities::Broker::is_revoked`], itself
    /// deny-by-default for a badge this keystore never minted), the badge
    /// was actually granted by this keystore, it names `key` (not merely
    /// *a* key), and its granted [`KeyOps`] include `op`. Every
    /// key-material-touching method below calls this before touching
    /// anything.
    fn check_access(&self, badge: u64, key: KeyId, op: KeyOps) -> Result<(), KeystoreError> {
        if self.broker.is_revoked(badge) {
            return Err(KeystoreError::BadgeRevoked);
        }
        let grant = self.grants.iter().flatten().find(|g| g.badge == badge).ok_or(KeystoreError::UnknownBadge)?;
        if grant.key != key {
            return Err(KeystoreError::WrongKey);
        }
        if !grant.ops.contains(op) {
            return Err(KeystoreError::OpNotGranted);
        }
        Ok(())
    }

    /// Encrypts `buffer` in place under `key`, gated on `badge` having been
    /// granted [`KeyOps::ENCRYPT`] for `key` (see [`Keystore::check_access`]).
    pub fn encrypt(
        &self,
        badge: u64,
        key: KeyId,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; aead::TAG_LEN], KeystoreError> {
        self.check_access(badge, key, KeyOps::ENCRYPT)?;
        match &self.key_record(key)?.material {
            KeyMaterial::Aead(k) => k.encrypt_in_place_detached(nonce, aad, buffer).map_err(|_| KeystoreError::CryptoFailure),
            KeyMaterial::Destroyed => Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Signing(_) | KeyMaterial::Mac(_) => Err(KeystoreError::WrongPurpose),
        }
    }

    /// Decrypts `buffer` in place under `key`, gated on `badge` having been
    /// granted [`KeyOps::DECRYPT`] for `key`.
    pub fn decrypt(
        &self,
        badge: u64,
        key: KeyId,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; aead::TAG_LEN],
    ) -> Result<(), KeystoreError> {
        self.check_access(badge, key, KeyOps::DECRYPT)?;
        match &self.key_record(key)?.material {
            KeyMaterial::Aead(k) => k.decrypt_in_place_detached(nonce, aad, buffer, tag).map_err(|_| KeystoreError::CryptoFailure),
            KeyMaterial::Destroyed => Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Signing(_) | KeyMaterial::Mac(_) => Err(KeystoreError::WrongPurpose),
        }
    }

    /// Signs `message` under `key`, gated on `badge` having been granted
    /// [`KeyOps::SIGN`] for `key`.
    pub fn sign(&self, badge: u64, key: KeyId, message: &[u8]) -> Result<[u8; signing::SIGNATURE_LEN], KeystoreError> {
        self.check_access(badge, key, KeyOps::SIGN)?;
        match &self.key_record(key)?.material {
            KeyMaterial::Signing(k) => Ok(k.sign(message)),
            KeyMaterial::Destroyed => Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Aead(_) | KeyMaterial::Mac(_) => Err(KeystoreError::WrongPurpose),
        }
    }

    /// Computes a BLAKE3 keyed-mode MAC over `message` under `key`, gated on
    /// `badge` having been granted [`KeyOps::MAC`] for `key`.
    pub fn mac(&self, badge: u64, key: KeyId, message: &[u8]) -> Result<hash::Hash, KeystoreError> {
        self.check_access(badge, key, KeyOps::MAC)?;
        match &self.key_record(key)?.material {
            KeyMaterial::Mac(k) => Ok(k.compute(message)),
            KeyMaterial::Destroyed => Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Aead(_) | KeyMaterial::Signing(_) => Err(KeystoreError::WrongPurpose),
        }
    }

    /// Verifies a MAC against `key` in constant time
    /// ([`crate::hash::MacKey::verify`]) — gated the same as
    /// [`Keystore::mac`], unlike [`Keystore::verify`]'s public-key
    /// operation: MAC verification needs the same secret the badge scopes
    /// access to.
    pub fn verify_mac(&self, badge: u64, key: KeyId, message: &[u8], mac: &hash::Hash) -> Result<(), KeystoreError> {
        self.check_access(badge, key, KeyOps::MAC)?;
        match &self.key_record(key)?.material {
            KeyMaterial::Mac(k) => k.verify(message, mac).map_err(|_| KeystoreError::CryptoFailure),
            KeyMaterial::Destroyed => Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Aead(_) | KeyMaterial::Signing(_) => Err(KeystoreError::WrongPurpose),
        }
    }

    /// Returns `key`'s public verifying key — not gated by a badge, since a
    /// public key isn't the secret asset [`Keystore`] exists to protect
    /// (X1, `THREAT_MODEL.md`).
    pub fn verifying_key(&self, key: KeyId) -> Result<[u8; signing::PUBLIC_KEY_LEN], KeystoreError> {
        match &self.key_record(key)?.material {
            KeyMaterial::Signing(k) => Ok(k.verifying_key()),
            KeyMaterial::Destroyed => Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Aead(_) | KeyMaterial::Mac(_) => Err(KeystoreError::WrongPurpose),
        }
    }

    /// Verifies a signature against `key`'s public half — like
    /// [`Keystore::verifying_key`], not gated by a badge.
    pub fn verify(&self, key: KeyId, message: &[u8], signature: &[u8; signing::SIGNATURE_LEN]) -> Result<(), KeystoreError> {
        let public = self.verifying_key(key)?;
        signing::verify(&public, message, signature).map_err(|_| KeystoreError::CryptoFailure)
    }

    /// Issues a fresh root [`sealed::SealedToken`] naming `identifier`,
    /// gated on `badge` having been granted [`KeyOps::MAC`] for `key` — a
    /// sealed token's root key *is* a `KeyPurpose::Mac` key, so this reuses
    /// exactly the badge/key pairing [`Keystore::mac`] does. Records the
    /// `identifier → key` binding locally so [`Keystore::unseal`] can later
    /// recompute the chain — see [`sealed`]'s module doc for why minting the
    /// eventual live capability is deliberately not this method's job.
    pub fn seal(
        &mut self,
        badge: u64,
        key: KeyId,
        identifier: [u8; sealed::IDENTIFIER_LEN],
        caveats: &[sealed::Caveat],
    ) -> Result<sealed::SealedToken, KeystoreError> {
        self.check_access(badge, key, KeyOps::MAC)?;
        let root = match &self.key_record(key)?.material {
            KeyMaterial::Mac(k) => k,
            KeyMaterial::Destroyed => return Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Aead(_) | KeyMaterial::Signing(_) => return Err(KeystoreError::WrongPurpose),
        };
        let token = sealed::seal(root, identifier, caveats).map_err(|_| KeystoreError::TooManyCaveats)?;

        let slot = self.seals.iter().position(Option::is_none).ok_or(KeystoreError::NotEnoughCapacity)?;
        self.seals[slot] = Some(SealRecord { identifier, key, revoked: false });
        Ok(token)
    }

    /// Verifies `token` cryptographically and evaluates its caveats against
    /// the current request. `now` is the caller's best available clock
    /// reading, or `None` if no clock source exists yet (`lantern-hal` has
    /// none — RFC-0011's own unresolved question); a `Caveat::ExpiresAt`
    /// caveat with `now = None` is treated as **unsatisfied**, not
    /// "unchecked" — deny-by-default, same as everywhere else in this crate.
    /// `requested_rights` is what the caller intends the eventual minted
    /// live capability to carry; every `Caveat::RightsSubset` present must
    /// be a superset of it.
    ///
    /// On `Ok`, **the caller** — not this method — is responsible for
    /// actually minting a live capability via
    /// [`lantern_capabilities::Broker`]; see [`sealed`]'s module doc.
    pub fn unseal(&self, badge: u64, token: &sealed::SealedToken, now: Option<u64>, requested_rights: Rights) -> Result<(), KeystoreError> {
        let record = self.seals.iter().flatten().find(|s| s.identifier == *token.identifier()).ok_or(KeystoreError::UnknownSeal)?;
        if record.revoked {
            return Err(KeystoreError::SealRevoked);
        }
        self.check_access(badge, record.key, KeyOps::MAC)?;
        let root = match &self.key_record(record.key)?.material {
            KeyMaterial::Mac(k) => k,
            KeyMaterial::Destroyed => return Err(KeystoreError::KeyDestroyed),
            KeyMaterial::Aead(_) | KeyMaterial::Signing(_) => return Err(KeystoreError::WrongPurpose),
        };
        if !sealed::verify_chain(root, token) {
            return Err(KeystoreError::TokenInvalid);
        }

        for caveat in token.caveats() {
            let satisfied = match caveat {
                Some(sealed::Caveat::RightsSubset(allowed)) => requested_rights.is_subset_of(*allowed),
                Some(sealed::Caveat::ExpiresAt(expiry)) => now.is_some_and(|n| n <= *expiry),
                None => false,
            };
            if !satisfied {
                return Err(KeystoreError::CaveatNotSatisfied);
            }
        }
        Ok(())
    }

    /// Revokes every token ever sealed under `identifier` — and everything
    /// attenuated from any of them, since every descendant's chain bottoms
    /// out at the same root key — in one write. Mirrors
    /// [`Keystore::revoke_access`]/[`lantern_capabilities::Broker::revoke`]'s
    /// no-reclaim, deny-by-default shape exactly.
    pub fn revoke_seal(&mut self, identifier: &[u8; sealed::IDENTIFIER_LEN]) -> Result<(), KeystoreError> {
        let record = self.seals.iter_mut().flatten().find(|s| s.identifier == *identifier).ok_or(KeystoreError::UnknownSeal)?;
        record.revoked = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_kernel::cap::{CNode, CNodeId, Capability, EndpointId, NotificationId};
    use lantern_kernel::object::{Notification, Tcb};
    use lantern_hal::{MessageTag, TrapFrame};
    use lantern_kernel::ipc;

    /// Same two-party shape as `lantern-capabilities`'s own `Broker` tests:
    /// a service thread (its own CSpace: a self-CNode cap at slot 0, a shared
    /// endpoint at slot 1, and a stand-in `Notification { GRANT }` at slot 5
    /// naming "this keystore's own authority" — what `Broker::mint`
    /// attenuates from, same as any real service's own retained capability)
    /// and a client thread (its own CSpace, holding the same shared endpoint
    /// at slot 1).
    struct Fixture {
        state: KernelState,
        keystore: Keystore,
        keystore_tcb: TcbId,
        client_tcb: TcbId,
        ep_cptr: CPtr,
    }

    const SOURCE_SLOT: CPtr = 5;
    const SCRATCH_SLOT: CPtr = 6;
    const CLIENT_DEST_SLOT: usize = 9;

    fn setup() -> Fixture {
        let mut state = KernelState::new();

        let keystore_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let keystore_tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(keystore_tcb.0 as usize).unwrap().cspace = Some(keystore_cnode);
        *state.cnodes.get_mut(keystore_cnode.0 as usize).unwrap().slot_mut(0).unwrap() = Capability::CNode(keystore_cnode);

        let ep_idx = state.endpoints.alloc(lantern_kernel::object::Endpoint::new()).unwrap();
        let ep = Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(keystore_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;

        let notif_idx = state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification { id: NotificationId(notif_idx as u16), badge: 0, rights: Rights::READ.union(Rights::GRANT) };
        *state.cnodes.get_mut(keystore_cnode.0 as usize).unwrap().slot_mut(SOURCE_SLOT).unwrap() = source;

        let client_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let client_tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(client_tcb.0 as usize).unwrap().cspace = Some(client_cnode);
        *state.cnodes.get_mut(client_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;

        let keystore = Keystore::new(keystore_tcb, 0);
        Fixture { state, keystore, keystore_tcb, client_tcb, ep_cptr: 1 }
    }

    /// Client blocks in `Recv`, registering [`CLIENT_DEST_SLOT`] as its
    /// destination, then the keystore mints+delivers a badge scoped to `key`
    /// and `ops`. Returns the badge.
    fn grant_access(f: &mut Fixture, key: KeyId, ops: KeyOps) -> u64 {
        f.state.make_ready(f.keystore_tcb);
        f.state.scheduler.current = Some(f.client_tcb);
        let mut recv_frame = TrapFrame::zeroed();
        recv_frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
        recv_frame.set_mr(1, CLIENT_DEST_SLOT);
        ipc::recv(&mut f.state, f.client_tcb, f.ep_cptr, &mut recv_frame).unwrap();
        assert_eq!(f.state.scheduler.current, Some(f.keystore_tcb));

        let badge = f.keystore.request_key_access(&mut f.state, key, ops, SOURCE_SLOT, SCRATCH_SLOT).unwrap();
        f.keystore.deliver_grant(&mut f.state, f.ep_cptr, SCRATCH_SLOT, (0, 0)).unwrap();
        badge
    }

    #[test]
    fn granted_badge_can_encrypt_and_decrypt() {
        let mut f = setup();
        let key = f.keystore.generate_aead_key([1u8; aead::AEAD_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::ENCRYPT.union(KeyOps::DECRYPT));

        let nonce = [2u8; aead::NONCE_LEN];
        let mut buf = *b"a secret message";
        let tag = f.keystore.encrypt(badge, key, &nonce, b"ctx", &mut buf).unwrap();
        assert_ne!(&buf[..], b"a secret message");

        f.keystore.decrypt(badge, key, &nonce, b"ctx", &mut buf, &tag).unwrap();
        assert_eq!(&buf[..], b"a secret message");
    }

    #[test]
    fn granted_badge_can_sign_anyone_can_verify() {
        let mut f = setup();
        let key = f.keystore.generate_signing_key([3u8; signing::SEED_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::SIGN);

        let sig = f.keystore.sign(badge, key, b"a message").unwrap();
        // Verification needs no badge at all (public-key operation, X1).
        f.keystore.verify(key, b"a message", &sig).unwrap();
    }

    #[test]
    fn granted_badge_can_mac_and_verify() {
        let mut f = setup();
        let key = f.keystore.generate_mac_key([4u8; hash::MAC_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::MAC);

        let mac = f.keystore.mac(badge, key, b"a message").unwrap();
        // Unlike signature verification, MAC verification needs the same
        // secret key, so it's gated exactly like computing the MAC.
        f.keystore.verify_mac(badge, key, b"a message", &mac).unwrap();
        assert!(f.keystore.verify_mac(badge, key, b"a different message", &mac).is_err());
    }

    #[test]
    fn mac_key_cannot_sign() {
        let mut f = setup();
        let key = f.keystore.generate_mac_key([4u8; hash::MAC_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::MAC);
        assert_eq!(f.keystore.sign(badge, key, b"a message"), Err(KeystoreError::OpNotGranted));
    }

    #[test]
    fn sealed_token_round_trips_through_seal_and_unseal() {
        let mut f = setup();
        let key = f.keystore.generate_mac_key([6u8; hash::MAC_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::MAC);

        let token = f
            .keystore
            .seal(badge, key, [1u8; sealed::IDENTIFIER_LEN], &[sealed::Caveat::RightsSubset(Rights::READ)])
            .unwrap();
        f.keystore.unseal(badge, &token, None, Rights::READ).unwrap();
    }

    #[test]
    fn attenuated_token_still_unseals_and_narrows_further() {
        let mut f = setup();
        let key = f.keystore.generate_mac_key([6u8; hash::MAC_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::MAC);

        let token = f.keystore.seal(badge, key, [1u8; sealed::IDENTIFIER_LEN], &[sealed::Caveat::RightsSubset(Rights::ALL)]).unwrap();
        // Attenuation needs no badge/Keystore at all -- it's a free function.
        let narrowed = sealed::attenuate(&token, sealed::Caveat::ExpiresAt(1000)).unwrap();

        f.keystore.unseal(badge, &narrowed, Some(999), Rights::READ).unwrap();
        assert_eq!(f.keystore.unseal(badge, &narrowed, Some(1001), Rights::READ), Err(KeystoreError::CaveatNotSatisfied));
        // No clock source is treated as unsatisfied, not "unchecked".
        assert_eq!(f.keystore.unseal(badge, &narrowed, None, Rights::READ), Err(KeystoreError::CaveatNotSatisfied));
    }

    #[test]
    fn unseal_rejects_rights_wider_than_caveat_allows() {
        let mut f = setup();
        let key = f.keystore.generate_mac_key([6u8; hash::MAC_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::MAC);

        let token = f
            .keystore
            .seal(badge, key, [1u8; sealed::IDENTIFIER_LEN], &[sealed::Caveat::RightsSubset(Rights::READ)])
            .unwrap();
        assert_eq!(
            f.keystore.unseal(badge, &token, None, Rights::READ.union(Rights::WRITE)),
            Err(KeystoreError::CaveatNotSatisfied)
        );
    }

    #[test]
    fn revoked_seal_rejects_unseal_even_with_a_cryptographically_valid_token() {
        let mut f = setup();
        let key = f.keystore.generate_mac_key([6u8; hash::MAC_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::MAC);

        let identifier = [1u8; sealed::IDENTIFIER_LEN];
        let token = f.keystore.seal(badge, key, identifier, &[]).unwrap();
        f.keystore.revoke_seal(&identifier).unwrap();

        assert_eq!(f.keystore.unseal(badge, &token, None, Rights::NONE), Err(KeystoreError::SealRevoked));
    }

    #[test]
    fn unknown_seal_identifier_is_rejected_deny_by_default() {
        let f = setup();
        let bogus = sealed::seal(&hash::MacKey::from_random_bytes([9u8; hash::MAC_KEY_LEN]), [2u8; sealed::IDENTIFIER_LEN], &[]).unwrap();
        assert_eq!(f.keystore.unseal(0, &bogus, None, Rights::NONE), Err(KeystoreError::UnknownSeal));
    }

    #[test]
    fn badge_scoped_to_encrypt_cannot_decrypt() {
        let mut f = setup();
        let key = f.keystore.generate_aead_key([1u8; aead::AEAD_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::ENCRYPT);

        let mut buf = [0u8; 4];
        let tag = [0u8; aead::TAG_LEN];
        assert_eq!(f.keystore.decrypt(badge, key, &[0; aead::NONCE_LEN], b"", &mut buf, &tag), Err(KeystoreError::OpNotGranted));
    }

    #[test]
    fn badge_scoped_to_a_different_key_is_rejected() {
        let mut f = setup();
        let key_a = f.keystore.generate_aead_key([1u8; aead::AEAD_KEY_LEN]).unwrap();
        let key_b = f.keystore.generate_aead_key([2u8; aead::AEAD_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key_a, KeyOps::ENCRYPT);

        let mut buf = [0u8; 4];
        assert_eq!(
            f.keystore.encrypt(badge, key_b, &[0; aead::NONCE_LEN], b"", &mut buf),
            Err(KeystoreError::WrongKey)
        );
    }

    #[test]
    fn revoked_badge_is_rejected() {
        let mut f = setup();
        let key = f.keystore.generate_aead_key([1u8; aead::AEAD_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::ENCRYPT);

        f.keystore.revoke_access(badge).unwrap();

        let mut buf = [0u8; 4];
        assert_eq!(
            f.keystore.encrypt(badge, key, &[0; aead::NONCE_LEN], b"", &mut buf),
            Err(KeystoreError::BadgeRevoked)
        );
    }

    #[test]
    fn unknown_badge_reads_as_revoked_deny_by_default() {
        let f = setup();
        let key = KeyId(0);
        let mut buf = [0u8; 4];
        assert_eq!(
            f.keystore.encrypt(999, key, &[0; aead::NONCE_LEN], b"", &mut buf),
            Err(KeystoreError::BadgeRevoked)
        );
    }

    #[test]
    fn destroyed_key_rejects_further_operations_even_with_a_valid_badge() {
        let mut f = setup();
        let key = f.keystore.generate_aead_key([1u8; aead::AEAD_KEY_LEN]).unwrap();
        let badge = grant_access(&mut f, key, KeyOps::ENCRYPT);

        f.keystore.destroy(key).unwrap();

        let mut buf = [0u8; 4];
        assert_eq!(
            f.keystore.encrypt(badge, key, &[0; aead::NONCE_LEN], b"", &mut buf),
            Err(KeystoreError::KeyDestroyed)
        );
    }

    #[test]
    fn requesting_wrong_purpose_ops_is_rejected_before_minting() {
        let mut f = setup();
        let key = f.keystore.generate_aead_key([1u8; aead::AEAD_KEY_LEN]).unwrap();
        f.state.scheduler.current = Some(f.keystore_tcb);
        assert_eq!(
            f.keystore.request_key_access(&mut f.state, key, KeyOps::SIGN, SOURCE_SLOT, SCRATCH_SLOT),
            Err(KeystoreError::WrongPurpose)
        );
    }

    #[test]
    fn destroyed_key_id_is_never_reused_by_a_later_generate_call() {
        let mut f = setup();
        let key_a = f.keystore.generate_aead_key([1u8; aead::AEAD_KEY_LEN]).unwrap();
        f.keystore.destroy(key_a).unwrap();
        let key_b = f.keystore.generate_aead_key([2u8; aead::AEAD_KEY_LEN]).unwrap();
        assert_ne!(key_a, key_b, "a destroyed slot must never be handed to a new, unrelated key");
    }
}
