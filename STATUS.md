# lantern-crypto — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Service surface and initial primitive set drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Crypto-agility + PQC-readiness stance set.
- Threat model drafted and reviewed.

## Next
- [RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md)
  (Draft): ratify the Phase 1 primitive set — under review.
- Specify the sealed-capability token format (with [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities))
  — blocked on RFC-0007 landing.
- Phase 2: keystore + signing/AEAD operations behind capabilities.

## Blocked on
- Hardware enclave story ([`lantern-hal`](https://github.com/lantern-os/lantern-hal), [`lantern-boot`](https://github.com/lantern-os/lantern-boot)).
