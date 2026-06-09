# lantern-crypto — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Service surface and initial primitive set drafted ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Crypto-agility + PQC-readiness stance set.
- Threat model drafted.

## Next
- RFC to ratify the primitive set (→ ADR).
- Specify the sealed-capability token format (with [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).
- Phase 2: keystore + signing/AEAD operations behind capabilities.

## Blocked on
- Capability model acceptance ([RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md)).
- Hardware enclave story ([`lantern-hal`](https://github.com/lantern-os/lantern-hal), [`lantern-boot`](https://github.com/lantern-os/lantern-boot)).
