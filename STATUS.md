# lantern-crypto — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md).

## Done
- Service surface and initial primitive set drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Crypto-agility + PQC-readiness stance set.
- Threat model drafted and reviewed.
- Phase 1 primitive set accepted ([RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md);
  see [ADR-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0011-cryptographic-primitive-set.md)):
  BLAKE3(+SHA-256)/XChaCha20-Poly1305(+AES-256-GCM)/HKDF+Argon2id/Ed25519/X25519/
  hardware-seeded CSPRNG, with PQC-hybrid identifier slots reserved (ML-DSA, ML-KEM) but
  not yet implemented.

## Next
- Specify the sealed-capability token format (with [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)),
  against the primitives ADR-0011 fixed.
- Phase 2: keystore + signing/AEAD operations behind capabilities.

## Blocked on
- Hardware enclave story ([`lantern-hal`](https://github.com/lantern-os/lantern-hal), [`lantern-boot`](https://github.com/lantern-os/lantern-boot))
  — a Phase 4 concern (hardware-backed key custody), not blocking a first software-only
  keystore prototype.
- A first keystore prototype behind capabilities also needs
  [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)'s
  brokering work, itself only just unblocked (RFC-0009/ADR-0014) with no prototype code
  yet.
