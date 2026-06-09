# lantern-crypto — Architecture

Companion to [wiki/Cryptography](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Cryptography.md).

## Services provided
- **Keystore & lifecycle** — generate, store, rotate, destroy; per-key policy
  (non-exportable, requires-user-presence).
- **Signing/verification** — as a capability; optional hardware confirmation.
- **Sealed encryption** — encrypt-to-context/identity without exposing keys.
- **Sealed capabilities** — macaroon-style attenuable, revocable tokens, the cryptographic
  form of LanternOS caps ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).
- **Attestation** — hardware-rooted statements about measured-boot state ([`lantern-boot`](https://github.com/lantern-os/lantern-boot)).
- **ZK primitives (direction)** — prove claims without revealing identifiers ([Identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)).

## Primitive set (initial; RFC-governed)
Hashing/CAS: BLAKE3 (+SHA-256 interop) · AEAD: XChaCha20-Poly1305 (AES-256-GCM where
HW-accelerated) · KDF: HKDF, Argon2id · Signatures: Ed25519 (+ML-DSA hybrid) · KEX: X25519
(+ML-KEM hybrid) · RNG: OS CSPRNG from hardware entropy, health-checked.

These are defaults recorded as ADR once RFC'd; any change requires an RFC.

## Principles in practice
- **No raw keys to apps** — only operation capabilities.
- **Crypto-agility** — every key/ciphertext/signature is versioned + algorithm-tagged so
  primitives rotate without breaking stored data.
- **PQC readiness** — hybrid classical+PQC for long-lived secrets ("harvest now, decrypt later").
- **Audited implementations** — constant-time, no secret-dependent branching, zeroisation;
  prefer reviewed crates over rolling our own; isolate any HW-crypto `unsafe`.

## Open questions
- Exact hybrid-PQC construction and default timing.
- Humane, secure key backup/recovery (social recovery? hardware tokens? sharding?).
- Attestation vs. privacy (attestation is a fingerprint).
- Whether to expose any low-level primitives to apps at all.
