# Security Policy

SendBeam is peer-to-peer file transfer software engineered with end-to-end encryption, strict fail-closed boundary validation, and zero-knowledge signaling. We treat security bugs as critical defects and welcome responsible disclosure from researchers and developers.

## Supported Versions

Only the current and immediately preceding minor releases receive security patches. Older versions must be upgraded.

| Version | Supported          | Status                                      |
| ------- | ------------------ | ------------------------------------------- |
| 1.8.x   | :white_check_mark: | Current active release (Protocol assurance) |
| 1.7.x   | :white_check_mark: | Maintained for critical security patches    |
| 1.6.x   | :x:                | Unsupported — upgrade to 1.7.x or 1.8.x     |
| < 1.6.0 | :x:                | Unsupported — upgrade immediately           |

## Reporting a Vulnerability

We request coordinated disclosure to give maintainers time to produce and distribute a patch before public release.

### Preferred Reporting Method

Please report security issues using **GitHub Private Vulnerability Reporting**:

> **[Report a vulnerability](https://github.com/Akshay7273/sendbeam/security/advisories/new)**

This creates an encrypted, confidential advisory workspace accessible only to the reporter and repository maintainers.

### Maintainer Response Commitment

As an open-source project maintained with dedicated care, we commit to the following realistic timeline:

- **Initial Acknowledgment:** Within **48 hours** of report receipt.
- **Triage & Severity Assessment:** Within **7 days** with reproducible confirmation or clarification requests.
- **Remediation & Advisory:** Target fix within **30 days**, coordinated with the reporter before public release.
- **Credit:** Public acknowledgment in release notes and CVE attribution (if applicable), unless reporter requests anonymity.

### What to Include

Please provide:

1. Description of the vulnerability and affected components (`packages/wire`, `packages/engine`, `apps/server`, `apps/web`, `apps/cli`, `apps/desktop`).
2. Exact version or commit SHA tested.
3. Step-by-step reproduction instructions or proof-of-concept (PoC) code.
4. Impact assessment (e.g., cryptographic bypass, remote denial-of-service, path traversal).

## Scope & Threat Model

SendBeam's security architecture is formally documented in [Threat Model](docs/threat-model.md) and backed by a 20-vector automated attack matrix and 22 continuous fuzzing targets ([Fuzzing Guide](docs/fuzzing.md)).

### In Scope

- **Cryptographic Failures:** Weaknesses in SPAKE2+ key exchange, AES-256-GCM frame sequencing, directional key schedules, HKDF derivations, or traffic padding.
- **Wire Framing & Parsing:** Memory corruption, panics, out-of-bounds reads/writes, or CPU exhaustion from untrusted network frames in Go (`packages/wire`) or TypeScript (`packages/protocol`).
- **Filesystem Traversal:** Escaping designated receive directories via crafted filenames or symlinks (`NormalizeTransferPath`).
- **Mesh Trust & Revocation:** Forged revocation records, sequence number rollback attacks, or unauthorized device trust additions (`packages/engine/trust`).
- **Relay / Signaling Attacks:** Server-side tampering, frame injection, or payload modification not detected by client AEAD.
- **Self-Updater Integrity:** Downgrade attacks, Minisign signature verification bypasses, or malicious update manifest application (`packages/engine/updater`).

### Out of Scope

- Attacks requiring existing root/administrative code execution on the local host.
- Physical theft or forensic extraction from an unlocked device with unencrypted disk storage.
- Theoretical relay cover-traffic timing correlation within known, documented bounds (see [Threat Model](docs/threat-model.md)).
- Spamming public WebRTC STUN/TURN servers without SendBeam software vulnerabilities.
- Denial-of-service against self-hosted test servers not involving memory safety bugs.

## Supply Chain & Verification

All official releases provide SLSA Level 3 build provenance, SPDX SBOMs, Minisign signatures, and Sigstore/cosign keyless OIDC attestations. For verification instructions, refer to [Supply Chain Security](docs/supply-chain.md).
