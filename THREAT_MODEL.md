# lantern-crypto — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). The crypto service
holds the system's most sensitive asset — user keys — so it is high in the assurance ordering
(system threats T6, T8).

## Assets
- Private key material (must never leave custody in the clear).
- Integrity of signing/decryption operations.
- Integrity of sealed capabilities and attestations.
- Quality of randomness.

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| X1 | Key extraction by a compromised app | Apps get operation capabilities, not keys; keys stay in service/enclave. |
| X2 | Compromise of the crypto service itself | Confined user space; hardware-backed custody so keys resist even service compromise; least privilege. |
| X3 | Weak/biased randomness | Hardware entropy + CSPRNG with health checks; never app-supplied. |
| X4 | Nonce reuse / primitive misuse | Misuse-resistant high-level APIs; large-nonce AEAD; no raw-primitive foot-guns. |
| X5 | Algorithm obsolescence / "harvest now, decrypt later" | Crypto-agility (versioned/tagged) + hybrid PQC for long-lived secrets. |
| X6 | Side-channel key leakage | Constant-time code; no secret-dependent branching; zeroisation. |
| X7 | Attestation used to fingerprint/track | Mediate who can request attestation; minimise linkable detail. |

## Non-goals
- Defeating a fully malicious enclave/hardware root of trust (system non-goal).
- Sophisticated physical key-extraction attacks at Phase 0.
