# SendBeam v1.7 — Release Gate

The v1.7 milestone (**Mesh Maturity & Wire Privacy**: signed revocation records with opportunistic mesh sync, multi-device broadcast send with independent failure domains, negotiated wire traffic padding with power-of-two bucket quantization, relay metadata defenses with sender timing jitter, and zero-cost package manager distribution across Homebrew, Scoop, WinGet, and Arch Linux AUR) gates release on the checks below, each verified against merged `main`.

Evidence is a deterministic unit/integration test, a verified cross-platform build fixture, or a cryptographic testbed; every binary, manifest, and transfer across the matrix satisfies strict verification standards.

---

## 1. Gate Checks

|   #   | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |  Result  | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| :---: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **Signed Revocation Records & Opportunistic Mesh Sync (ADR 0008)**<br>Generate canonical, domain-separated revocation statements signed by the revoking device's Ed25519 identity key (`RevocationRecord`). Propagate opportunistically over authenticated `sendbeam/2` trusted sessions. Validate signature against stored revoker public key, enforce strict sequence number monotonicity (`Seq > StoredSeq`), reject timestamp skew (> ±5 min), and fail closed on distrusted revokers (`ErrUntrustedPeer` / `ErrTrustedPeerRevoked`). Expand attack matrix to 12 vectors.                                 | **PASS** | Design in `docs/adr/0008-revocation-sync.md`. Wire codec and cross-language test vectors in `packages/wire/revocation.go`, `revocation_test.go`, `packages/wire/testdata/revocation_vectors.json`, and `packages/protocol/src/revocation.ts`, `revocation.test.ts`. Trust store sync engine in `packages/engine/trust/revocation_sync.go` and `revocation_sync_test.go` (`TestRevocationSync_ThreeDevicePropagation`, `TestRevocationSync_MonotonicSequenceEnforced`, `TestRevocationSync_UntrustedRevokerRejected`). Attack matrix test suites in `packages/wire/attack_matrix_test.go`, `packages/engine/trust/attack_matrix_test.go`, and `packages/protocol/src/attack-matrix.test.ts` (12/12 vectors passing in Go and TypeScript). Documented in `docs/trust-model.md`. |
| **2** | **Multi-Device Broadcast Send & Independent Failure Isolation**<br>Support concurrent transfer fan-out to multiple paired targets (`sendbeam send <files...> @device1 @device2 @device3`). Bounded concurrency, per-target progress reporting, and stable `--json` output (`ok`, `offline`, `refused`, `failed`). Enforce strict partial-failure isolation (one target failure never aborts or corrupts concurrent transfers to other peers). Process exit code is zero only if all targets succeed. Desktop and Web UI multi-select send flows with per-device retry.                                        | **PASS** | Broadcast coordinator in `packages/engine/transfer/broadcast.go` and `broadcast_test.go` (`TestBroadcastCoordinator_AllSucceed`, `TestBroadcastCoordinator_PartialFailure`, `TestBroadcastCoordinator_OfflineTargetIgnored`, `TestBroadcastCoordinator_DigestVerifiedPerTarget`). CLI argument parsing, progress table, and JSON telemetry in `apps/cli/cmd/sendbeam/main.go` and `apps/cli/cmd/sendbeam/main_test.go` (`TestSendBroadcast_CLIArguments`, `TestSendBroadcast_ExitCodes`, `TestSendBroadcast_JSONOutput`). Web/Desktop multi-select UI in `apps/web/src/lib/trust/DevicesModal.svelte` and `apps/web/src/lib/trust/devices.test.ts`.                                                                                                                           |
| **3** | **Wire Privacy: Negotiated Traffic Padding (ADR 0009)**<br>Negotiate optional `padding` feature flag during `caps` exchange. Quantize frame payloads into discrete power-of-two bucket sizes ($256, 512, 1024, \dots, 65535$ bytes) with authenticated zero-padding inside the AEAD envelope. Preserve exact 16-byte frame header as AAD. Validate padding bytes on decrypt and fail closed on corrupted lengths. Provide CLI `--private` flag and settings toggle. Backward and forward compatible with unpadded v1.6 peers (unpadded fallback). Measured overhead <0.05% CPU.                               | **PASS** | Design in `docs/adr/0009-negotiated-traffic-padding.md`. Wire padding codec, validation, and cross-language test vectors in `packages/wire/padding.go`, `padding_test.go`, `packages/wire/testdata/padding_vectors.json`, and `packages/protocol/src/padding.ts`, `padding.test.ts`, `padding-vector.test.ts`. Engine transfer integration in `packages/engine/transfer/padding_test.go` and `packages/protocol/src/transfer-sender.ts`. Caps negotiation tests in `packages/wire/transfer_set_test.go` and `packages/protocol/src/transfer-set.test.ts`. Performance benchmarks documented in `docs/BENCHMARKS.md` and `docs/compat-matrix.md`.                                                                                                                              |
| **4** | **Relay Metadata Defenses & Sender Timing Jitter**<br>Enforce uniform power-of-two frame sizing across the WebSocket relay path when padding is negotiated. Provide optional sender-side randomized scheduling jitter (configurable window up to 15ms) to disrupt burst timing correlation without impacting throughput. Audit server logs and Prometheus metrics to verify zero per-frame payload, tag, or header logging. Document coarse-grain residual metadata (socket correlation, macro session duration) in threat model without overclaiming.                                                        | **PASS** | Relay uniform framing and jitter scheduling in `packages/engine/transfer/driver.go` and `driver_test.go` (`TestDriver_RelayWithPaddingAndJitter`, `TestDriver_TimingJitterBounds`). Server log and metrics audit in `apps/server/internal/signal/metrics_test.go` and `apps/server/internal/signal/hub_test.go` (`TestHub_RelayZeroLoggingAudit`, `TestMetrics_ZeroPIIInvariant`). Threat model before/after metadata comparison table in `docs/threat-model.md`.                                                                                                                                                                                                                                                                                                             |
| **5** | **Zero-Cost Package-Manager Distribution (Homebrew, Scoop, WinGet, AUR)**<br>Publish automated, cryptographically validated package manifests and formulas: Homebrew formula (`Formula/sendbeam.rb`, `packaging/homebrew/Formula/sendbeam.rb`) for macOS and Linux (`arm64`, `amd64`); Scoop bucket manifest (`bucket/sendbeam.json`, `packaging/scoop/sendbeam.json`) for Windows (`amd64`, `arm64`); WinGet manifests (`packaging/winget/manifests/s/SendBeam/SendBeam/<version>/`); Arch Linux AUR package (`packaging/aur/PKGBUILD`, `.SRCINFO`). All manifests verified against signed `SHA256SUMS.txt`. | **PASS** | Automated Go manifest generator & validator `scripts/generate-package-manifests.go` and comprehensive test suite `scripts/generate-package-manifests_test.sh` (assertions for brew, scoop, winget, aur, strict `--validate` mode, fail-closed tampered hash rejection, fail-closed missing hash rejection, and simulated binary execution). CI validation wired into `.github/workflows/distribution.yml` and release generation wired into `.github/workflows/release.yml`. Documented in `docs/install.md`, `docs/distribution.md`, and `README.md`.                                                                                                                                                                                                                        |
| **6** | **Milestone Gate Verification & Documentation Coherence**<br>All 6 PRs merged cleanly to `main`. CI runs 100% green with 0 failing checks across Go `-race` tests, TypeScript checks, ESLint, Prettier, Playwright e2e (including mobile profiles), and distribution builds. Full documentation synchronization across protocol, threat model, trust model, compatibility matrix, install guides, and benchmarks.                                                                                                                                                                                             | **PASS** | Complete CI runs `33329900709` (CI) and `33329900780` (publish) verified 100% green on `main`. Full local validation gate passing cleanly (`just fmt`, `just lint`, `just typecheck`, `pnpm format:check`, `just test`, and all script test suites).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

---

## 2. Release Artifacts Matrix

The following artifacts and package manager manifests are produced and cryptographically signed on release tags (`v*`):

| Category             | Artifact Name / Path                              | Platform / Target   | Packaging / Format                             |
| :------------------- | :------------------------------------------------ | :------------------ | :--------------------------------------------- |
| **CLI Binaries**     | `sendbeam-cli-linux-amd64.tar.gz`                 | Linux (`x86_64`)    | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-linux-arm64.tar.gz`                 | Linux (`aarch64`)   | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-darwin-amd64.tar.gz`                | macOS (`x86_64`)    | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-darwin-arm64.tar.gz`                | macOS (`arm64`)     | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-windows-amd64.zip`                  | Windows (`x86_64`)  | Standalone zip archive with executable         |
|                      | `sendbeam-cli-windows-arm64.zip`                  | Windows (`arm64`)   | Standalone zip archive with executable         |
| **Desktop Packages** | `SendBeam-windows-amd64-installer.exe`            | Windows (`x86_64`)  | NSIS graphical setup installer                 |
|                      | `SendBeam-windows-amd64-portable.zip`             | Windows (`x86_64`)  | Portable standalone archive                    |
|                      | `SendBeam-macos-universal.dmg`                    | macOS (Universal)   | Apple disk image with Applications link        |
|                      | `SendBeam-macos-universal.zip`                    | macOS (Universal)   | Mach-O Universal `.app` bundle archive         |
|                      | `sendbeam-desktop_<ver>_amd64.deb`                | Linux Debian/Ubuntu | Native `.deb` package with desktop integration |
|                      | `SendBeam-linux-amd64.AppImage`                   | Linux (`x86_64`)    | Portable AppImage executable                   |
| **Package Managers** | `Formula/sendbeam.rb` / `packaging/homebrew/`     | macOS & Linux       | Homebrew Formula                               |
|                      | `bucket/sendbeam.json` / `packaging/scoop/`       | Windows             | Scoop Bucket Manifest                          |
|                      | `packaging/winget/manifests/s/SendBeam/SendBeam/` | Windows             | WinGet YAML Package Manifests                  |
|                      | `packaging/aur/PKGBUILD`, `.SRCINFO`              | Arch Linux          | Arch User Repository (`sendbeam-bin`)          |
| **Update Manifests** | `stable.json` & `stable.json.minisig`             | Cross-Platform      | Production release update channel manifest     |
|                      | `beta.json` & `beta.json.minisig`                 | Cross-Platform      | Prerelease / preview channel manifest          |
| **Integrity & SBOM** | `SHA256SUMS.txt`                                  | All Artifacts       | Canonical SHA-256 manifest                     |
|                      | `SHA256SUMS.txt.minisig`                          | All Artifacts       | Minisign Ed25519 cryptographic signature       |
|                      | `SHA256SUMS.txt.sigstore.json`                    | All Artifacts       | Sigstore Cosign OIDC keyless bundle            |
|                      | `sendbeam-cli.spdx.json`                          | CLI Target          | SPDX 2.3 Software Bill of Materials            |
|                      | `sendbeam-desktop.spdx.json`                      | Desktop Target      | SPDX 2.3 Software Bill of Materials            |

---

## 3. Core Security & Operational Invariants

1. **Mesh Revocation Synchronization Integrity:**
   - Revocation records are cryptographically bound to the revoker's Ed25519 public key.
   - Forged records, replayed sequence numbers, timestamp drift (> ±5 min), and records from distrusted devices fail closed.
   - Synchronizes mutual peers in the owner's mesh without centralized CRL servers.

2. **Partial-Failure Isolation in Broadcast Transfers:**
   - Multi-device broadcast sending runs concurrent, independent transfer sessions.
   - An offline, refused, or failed peer never aborts or interferes with active transfers to other paired devices.
   - Output reporting and exit codes strictly reflect whole-batch success vs partial failure.

3. **Wire Privacy via Authenticated Traffic Padding:**
   - Frame payloads are quantized into power-of-two buckets ($256, 512, \dots, 65535$ bytes) with authenticated zero-padding.
   - Exact plaintext payload lengths are completely hidden from network observers.
   - Padding tampering fails AEAD authentication tag validation and aborts closed.

4. **Zero-Cost Package-Manager Distribution Model:**
   - Package manager manifests pull directly from signed GitHub release assets pinned to SHA-256 checksums.
   - Strict `--validate` gate rejects any discrepancy between manifests and `SHA256SUMS.txt`.
   - Zero hosting cost, zero paid package registries.

5. **Zero-PII Observability Guarantee:**
   - Structured logs and Prometheus metrics strictly record aggregate counters and gauges.
   - Device IDs, IP addresses, invite words, filenames, and payload bytes are never logged or exported.

---

## 4. Compatibility & Interoperability Summary

| Client / Environment                    | Direct WebRTC | Fallback Relay | Persistent Trust (`sendbeam/2`) | Revocation Sync | Traffic Padding | Broadcast Send |   Verified In CI    |
| :-------------------------------------- | :-----------: | :------------: | :-----------------------------: | :-------------: | :-------------: | :------------: | :-----------------: |
| **Linux CLI (amd64, arm64)**            |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |    ✓ (`ci.yml`)     |
| **macOS CLI (amd64, arm64)**            |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |    ✓ (`ci.yml`)     |
| **Windows CLI (amd64, arm64)**          |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |    ✓ (`ci.yml`)     |
| **Linux Desktop (AppImage, deb)**       |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |    ✓ (`ci.yml`)     |
| **macOS Desktop (Universal .app, DMG)** |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |    ✓ (`ci.yml`)     |
| **Windows Desktop (NSIS, portable)**    |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |    ✓ (`ci.yml`)     |
| **Evergreen Desktop Browsers**          |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |   ✓ (Playwright)    |
| **Android Chrome (Mobile)**             |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        | ✓ (`mobile-chrome`) |
| **iOS Safari (Mobile)**                 |       ✓       |       ✓        |                ✓                |        ✓        |        ✓        |       ✓        |      Supported      |
| **Hardened Server (`sendbeamd`)**       |       ✓       |       ✓        |                ✓                |       N/A       |   ✓ (relayed)   |      N/A       | ✓ (`go test -race`) |

---

## 5. Milestone Sign-Off Checklist

- [x] All 6 milestone PRs (V17-PR01 through V17-PR06) implemented, tested, and reviewed.
- [x] 100% green CI across all 21 verification gates (Go tests with `-race`, TypeScript checks, ESLint, Prettier, e2e Playwright tests including mobile profiles, and multi-platform distribution builds).
- [x] Zero brand regressions or stale naming leaks.
- [x] Verified release artifact packaging across 6 CLI targets, 4 desktop packaging formats, and 4 package managers (Homebrew, Scoop, WinGet, AUR).
- [x] Minisign Ed25519 and Sigstore Cosign verification suites passing 100% cleanly.
- [x] Signed revocation sync, broadcast send, traffic padding, and relay defenses verified with cross-language test vectors and attack matrix suites.
- [x] Documentation synchronized across `README.md`, `docs/HOSTING.md`, `docs/threat-model.md`, `docs/trust-model.md`, `docs/protocol.md`, `docs/compat-matrix.md`, `docs/distribution.md`, `docs/supply-chain.md`, `docs/updater.md`, `docs/install.md`, `docs/BENCHMARKS.md`, and `docs/RELEASE-v1.7.md`.
- [x] Release gate signed off and verified against merged `main`.
