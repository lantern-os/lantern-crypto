# lantern-crypto

Cryptography as an **operating-system service**: key custody, signing, encryption, sealed
capabilities, attestation, and the primitives that [identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md),
[filesystem](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Filesystem.md), and [networking](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Networking.md)
build on. Applications get *capabilities to operations*, never raw keys.

- **Layer:** system service (confined user space; key custody ideally hardware-backed).
- **System context:** [wiki/Cryptography](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Cryptography.md).

> **Phase 2 complete** (RFC-0017/ADR-0021), roadmap gate now Phase 3. The `Keystore` prototype (primitive *choices* RFC-governed) is real; making it a confined IPC service is Phase 3's first work. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Stance
Keys never leave the keystore in the clear · hardware-backed where possible ·
misuse-resistant high-level APIs · crypto-agility (versioned, algorithm-tagged) ·
post-quantum readiness (hybrid).
