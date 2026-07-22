# lantern-crypto — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Service surface and initial primitive set drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Crypto-agility + PQC-readiness stance set.
- Threat model drafted and reviewed.

## Next
- RFC to ratify the primitive set (→ ADR).
- Specify the sealed-capability token format (with [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).
- Phase 2: keystore + signing/AEAD operations behind capabilities.

## Blocked on
- Hardware enclave story ([`lantern-hal`](https://github.com/lantern-os/lantern-hal), [`lantern-boot`](https://github.com/lantern-os/lantern-boot)).
