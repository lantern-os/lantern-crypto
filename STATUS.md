# lantern-crypto — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). First prototype code now exists — see "Done".

## Done
- Service surface and initial primitive set drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Crypto-agility + PQC-readiness stance set.
- Threat model drafted and reviewed.
- Phase 1 primitive set accepted ([RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md);
  see [ADR-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0011-cryptographic-primitive-set.md)): BLAKE3(+SHA-256)/
  XChaCha20-Poly1305(+AES-256-GCM)/HKDF+Argon2id/Ed25519/X25519/hardware-seeded CSPRNG,
  with PQC-hybrid identifier slots reserved (ML-DSA, ML-KEM) but not yet implemented.
- **First prototype code merged** (`src/`): a fixed-capacity `Keystore` (`src/lib.rs`) holding
  AEAD (`src/aead.rs`, real `chacha20poly1305` XChaCha20-Poly1305, in-place/detached so no
  heap allocation) and Ed25519 signing (`src/signing.rs`, real `ed25519-dalek`) key material —
  the ADR-0011 AEAD and signature primitives, real crate implementations per
  `ARCHITECTURE.md`'s "prefer reviewed crates over rolling our own", not hand-rolled. `Keystore`
  is this crate's first concrete consumer of
  [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)'s `Broker` (that crate's own STATUS.md
  named exactly this as its "Next"): every operation is gated on a real, badged
  `Broker`-minted-and-granted capability, plus this crate's own object semantics `Broker`
  deliberately stays out of — a badge names a specific key *and* a specific operation subset
  (`KeyOps::ENCRYPT`/`DECRYPT`/`SIGN`), checked in `Keystore::check_access` before any key
  material is touched (deny-by-default, same convention as `Broker::is_revoked`). Key material
  is zeroised on drop (`zeroize`, X6) and on `Keystore::destroy` (which tombstones the slot
  rather than freeing it for reuse — reusing a `KeyId` after destruction would let a stale
  badge silently start naming an unrelated new key, the confused-deputy bug capabilities exist
  to rule out). 15 unit tests pass (6 exercising `aead`/`signing` in isolation, 9 driving the
  full `Keystore` mint→grant→operate flow against a real `lantern_kernel::state::KernelState`
  with two real threads over real IPC, the same discipline `lantern-capabilities`'s own tests
  follow), `cargo clippy -D warnings` clean on host and `riscv64gc-unknown-none-elf` (debug and
  release).
- **Randomness is deliberately not sourced by this crate.** ADR-0011's "hardware-seeded CSPRNG"
  is a `lantern-hal` concern that doesn't exist yet (see "Blocked on", now narrowed to just
  this). `Keystore::generate_aead_key`/`generate_signing_key`/`generate_mac_key` take
  caller-supplied random bytes instead, so this crate's correctness doesn't depend on where
  that source ends up living.
- **BLAKE3 hashing** (`src/hash.rs`, real `blake3` crate): [`hash`]/[`Hasher`] are plain,
  unkeyed, ungated free functions (`hash`/`Hasher::update`/`finalize`) — content-addressing's
  block-naming operation needs no capability, only whatever governs storing/retrieving the
  block it names (the future `lantern-filesystem`'s job). `MacKey` is BLAKE3's native keyed
  mode used as a MAC — RFC-0007 reserved exactly this rather than adding a separate
  primitive ("a signature or keyed-hash/MAC scheme ... already exist in the ratified set"),
  concretely for RFC-0003's still-unbuilt sealed-capability token format. Unlike a hash, a
  MAC key *is* secret material, so it's a third `Keystore` key purpose
  (`KeyPurpose::Mac`/`KeyOps::MAC`), gated the same as AEAD/signing — including
  `Keystore::verify_mac`, which (unlike Ed25519 `verify`) needs the same badge/key access as
  computing the MAC, since verification needs the shared secret, not a public half. MAC
  verification is constant-time (`subtle::ConstantTimeEq`, not a hand-rolled compare) to
  avoid the exact timing side channel X6 (`THREAT_MODEL.md`) exists to rule out. 6 more unit
  tests for `hash` in isolation, 2 more `Keystore` integration tests
  (mint→grant→mac→verify_mac, and confirming a MAC-only badge can't sign) — 21 total, same
  clippy/target coverage as above.
- **Sealed capabilities** (`src/sealed.rs`) — [RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)/
  [ADR-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0015-sealed-capability-token-format.md) (Accepted)
  implemented: a macaroon-style `SealedToken` chaining `hash::MacKey` over a fixed, closed
  `Caveat` set (`RightsSubset`, `ExpiresAt` — Phase 2's deliberately small starting set).
  `sealed::seal`/`sealed::attenuate` are the pure chaining construction (`attenuate` needs no
  root key, by design — it rechains from the token's own current `mac`, which is exactly why
  any holder can narrow a token offline without the issuer). `Keystore::seal`/
  `Keystore::unseal`/`Keystore::revoke_seal` wire this to real root-key custody: a root key is
  an ordinary `KeyPurpose::Mac` key, `seal`/`unseal` are gated by the same badge/key access as
  `Keystore::mac`, and revocation is a deny-by-default `identifier → revoked` table checked
  before any MAC work, mirroring `Broker::is_revoked` exactly. `unseal` verifies the token and
  evaluates its caveats (constant-time MAC compare via `Hash::ct_eq`, `now: Option<u64>`
  treated as **unsatisfied** rather than unchecked for `ExpiresAt` when no clock source is
  given) but deliberately stops there — actually minting a live capability from a verified
  token is left to the calling service, per RFC-0011's "never a second path to authority"
  design. 10 more unit tests (6 for `sealed`'s pure chaining in isolation — including that
  tampering with a stored caveat after the fact breaks verification, and that attenuation
  needs no root key — 5 more `Keystore` integration tests covering the full seal→unseal round
  trip, an over-wide rights request, an expired/no-clock caveat, and post-revocation denial)
  — 31 total, same clippy/target coverage as above.

## Next
- A real clock source for `Caveat::ExpiresAt` — `lantern-hal` has none yet
  (RFC-0011/ADR-0015's own left-open question); `Keystore::unseal`'s `now: Option<u64>`
  already treats "no clock" as "unsatisfied," so this is additive, not a correctness gap.
- A concrete consumer that calls `Keystore::unseal` and then actually mints a live capability
  via `lantern-capabilities::Broker` — `lantern-filesystem`'s `Store` now exists and is the
  natural candidate (its own `STATUS.md` names wiring sealed-capability unsealing into
  file-access grants as its own "Next"), but doesn't do this yet; `sealed.rs`'s own tests
  still only exercise the crypto/caveat half, by design (see its module doc).
- HKDF/Argon2id key derivation — the one ADR-0011 primitive category this prototype still
  doesn't need yet (no consumer until a real key-hierarchy/backup flow exists).
- Wire a real hardware-seeded CSPRNG into key generation once `lantern-hal` has one, replacing
  today's caller-supplied-bytes placeholder.
- Turning `Keystore` into deployable confined-service code needs `lantern-runtime`'s not-yet-built
  confined execution environment, same gap `lantern-capabilities/STATUS.md` documents for
  `Broker` itself — this crate's methods still take `&mut KernelState` directly, valid only for
  privileged, same-address-space code.

## Blocked on
- Hardware enclave story ([`lantern-hal`](https://github.com/lantern-os/lantern-hal), [`lantern-boot`](https://github.com/lantern-os/lantern-boot))
  — a Phase 4 concern (hardware-backed key custody), not blocking this software-only keystore
  prototype.
- ~~A first keystore prototype behind capabilities also needs `lantern-capabilities`'s
  brokering work.~~ Resolved — `Broker` is real and proven (`lantern-capabilities/STATUS.md`),
  and this crate now builds on it.
