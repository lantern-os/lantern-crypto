# lantern-crypto

Cryptography as an **operating-system service**: key custody, signing, encryption, sealed
capabilities, attestation, and the primitives that [identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md),
[filesystem](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Filesystem.md), and [networking](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Networking.md)
build on. Applications get *capabilities to operations*, never raw keys.

- **Layer:** system service (confined user space; key custody ideally hardware-backed).
- **System context:** [wiki/Cryptography](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Cryptography.md).

> **Phase 4** ([RFC-0036](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0036-phase-3-to-phase-4-transition.md)): hardware and assurance. The keystore runs as a confined service; Noise sessions and pairwise identities serve the
> wallet. Its keys are software-held demo keys until Phase 4's hardware root of trust
> ([RFC-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0023-hardware-key-custody-in-phase-4.md)). See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Stance
Keys never leave the keystore in the clear · hardware-backed where possible ·
misuse-resistant high-level APIs · crypto-agility (versioned, algorithm-tagged) ·
post-quantum readiness (hybrid).
