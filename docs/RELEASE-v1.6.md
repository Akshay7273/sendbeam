# SendBeam v1.6 — Release Gate

The v1.6 milestone (**Public Release Readiness**: formal signed distribution pipelines, zero-cost Minisign & Sigstore cryptographic verification, signed update manifests with downgrade prevention, desktop & CLI self-update engine with atomic rollback, mobile web PWA with responsive transfer UX and Playwright mobile CI, and hardened signaling server with per-IP rate limiting, anti-brute-force room enumeration defense, trusted reverse-proxy resolution, health/readiness endpoints, and zero-PII Prometheus metrics) gates release on the checks below, each verified against merged `main`.

Evidence is a deterministic unit/integration test, a verified cross-platform build fixture, or a cryptographic testbed; every binary, manifest, and transfer across the matrix satisfies strict verification standards.

---

## 1. Gate Checks

|   #   | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |  Result  | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| :---: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **Formal GitHub Releases Pipeline & Multi-Platform Packaging**<br>Produce deterministic release packages across 6 CLI targets (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`) and 4 desktop packaging formats (Windows NSIS + portable ZIP, macOS Universal DMG + ZIP, Linux Debian `.deb` + AppImage) with canonical `SHA256SUMS.txt`, in-toto build provenance attestations (`actions/attest-build-provenance@v2`), and SPDX 2.3 SBOMs (`sendbeam-cli.spdx.json`, `sendbeam-desktop.spdx.json`). Staged safely via draft releases.              | **PASS** | Workflow `.github/workflows/release.yml`, version metadata engine in `scripts/version-metadata.sh`, and unit test suite `scripts/version-metadata_test.sh` (10/10 test cases passing). Packaging build verified in `.github/workflows/distribution.yml` and documented in `docs/distribution.md`.                                                                                                                                                                                                                                                               |
| **2** | **Zero-Cost Binary Signing & Supply-Chain Verification**<br>Dual cryptographic signature generation on all release manifests using Minisign Ed25519 (`BA67BC598735C8DC` in `minisign.pub`) and Sigstore Cosign keyless OIDC identity tokens (`SHA256SUMS.txt.sigstore.json`). Provide standalone verification script `scripts/verify-release.sh` and assert strict tamper rejection across all failure modes.                                                                                                                                                                                      | **PASS** | Pure Go Minisign tool in `scripts/minisign.go`, release workflow in `.github/workflows/release.yml`, automated verification tool `scripts/verify-release.sh`, and unit test suite `scripts/verify-release_test.sh` (8/8 test cases passing asserting tamper rejection for corrupted payloads, tampered manifests, forged signatures, and mismatched keys). Documented in `docs/supply-chain.md` and `docs/install.md`.                                                                                                                                          |
| **3** | **Signed Update Manifest & Release Channels**<br>Publish canonical update channel manifests (`stable.json`, `beta.json`) signed with Minisign Ed25519. Client updater strictly verifies cryptographic signature before parsing manifest contents or trusting hashes/download URLs, and enforces monotonic version advancement with strict downgrade rejection.                                                                                                                                                                                                                                     | **PASS** | Manifest generator in `scripts/generate-update-manifest.go` with test suite `scripts/generate-update-manifest_test.sh` (3/3 test cases passing). Pinned release public key in `apps/cli/internal/updater/verify.go` (`RWTcyDWHWbxnuo3LVM5mWoZrx0HDwSQzAZvXK1lPRcdtJxshUDxJh+rE`). Signature verification in `verify.go` and downgrade prevention in `updater.go` (`TestVerifyMinisignSignature`, `TestUpdater_CheckForUpdate_DowngradeIgnored`). Documented in `docs/updater.md`.                                                                               |
| **4** | **Desktop & CLI Self-Update Engine with Rollback Safety**<br>Shared engine updater package (`packages/engine/updater`) providing platform-specific atomic apply strategies: Linux AppImage in-place replacement, macOS `.app` bundle staged swap, Windows NSIS installer relaunch flow. All update paths enforce same-filesystem atomic staging (`.tmp-*`), `.old` backup, automatic rollback on failure, and package manager detection (`DetectPackageManager`) preventing destructive self-update when managed by apt/deb, Homebrew, or WinGet.                                                  | **PASS** | Shared updater core in `packages/engine/updater/updater.go` and `apply.go`. Unit test suite `packages/engine/updater/updater_test.go` (`TestUpdater_Apply_Success`, `TestUpdater_Apply_RollbackOnFailure`, `TestDetectPackageManager`). Desktop `UpdateService` in `apps/desktop/internal/engine/update_service.go` and `update_service_test.go` (`TestUpdateService_CheckForUpdates`, `TestUpdateService_ApplyUpdate`). Desktop web UI integration in `apps/web/src/lib/settings/UpdateSettings.svelte` and `apps/web/src/lib/components/UpdateBanner.svelte`. |
| **5** | **Mobile Web PWA & Responsive Transfer UX**<br>Installable Progressive Web App (PWA) on mobile (Android Chrome & iOS Safari) with Web App Manifest (`manifest.webmanifest`), maskable icons, Screen Wake Lock integration, native Web Share API (`navigator.share`), 1-tap invite link sharing, deep-link parameter parsing (`?code=...`), min 44px touch targets, mobile notch safe-area insets, and storage capability probing. Strict online-only transfer semantics in Service Worker (`sw.js`).                                                                                               | **PASS** | Web App Manifest `apps/web/public/manifest.webmanifest`, touch icons in `apps/web/public/icons/`, service worker in `apps/web/public/sw.js` with online-only invariant. Capability probing in `packages/protocol/src/capability.ts` and `capability.test.ts`. Mobile responsive UI in `apps/web/src/App.svelte` and `TransferView.svelte`. Playwright mobile e2e test suite in `apps/web/e2e/mobile-transfer.spec.ts` executed under CI `mobile-chrome` profile. Documented in `docs/compat-matrix.md`.                                                         |
| **6** | **Server Hardening for Public Operation**<br>Multi-dimensional per-IP rate limiting (`ConnBurst`/`ConnPerSec`, `RoomCreateBurst`/`RoomCreatePerSec`), connection concurrency caps (`MaxConnsPerIP`, `MaxConnections`, `MaxRooms`), anti-brute-force room code guessing penalty bucket (`JoinFailBurst`, `JoinFailPerSec`), trusted reverse-proxy CIDR filtering (`SENDBEAM_TRUSTED_PROXIES`), multi-hop `X-Forwarded-For`/`CF-Connecting-IP` client IP extraction, health/readiness endpoints (`/healthz`, `/readyz`), graceful drain (`hub.Drain`), and zero-PII Prometheus metrics (`/metrics`). | **PASS** | Server rate limiting and anti-brute-force engine in `apps/server/internal/signal/ratelimit.go`, proxy parsing in `proxy.go` and `proxy_test.go`, hub operations and churn/reaper storm tests in `hub.go`, `hub_test.go`, and `churn_test.go`, HTTP server probes and graceful shutdown in `apps/server/internal/httpserver/server.go` and `server_test.go`, Prometheus metrics and zero-PII invariant in `signal/metrics.go` and `metrics_test.go`. Full suite passing under `go test -race ./...`. Documented in `docs/HOSTING.md` and `docs/threat-model.md`. |

---

## 2. Release Artifacts Matrix

The following artifacts are produced and cryptographically signed on release tags (`v*`):

| Category             | Artifact Name                          | Platform / Target   | Packaging / Format                             |
| :------------------- | :------------------------------------- | :------------------ | :--------------------------------------------- |
| **CLI Binaries**     | `sendbeam-cli-linux-amd64.tar.gz`      | Linux (`x86_64`)    | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-linux-arm64.tar.gz`      | Linux (`aarch64`)   | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-darwin-amd64.tar.gz`     | macOS (`x86_64`)    | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-darwin-arm64.tar.gz`     | macOS (`arm64`)     | Standalone tarball with license & readme       |
|                      | `sendbeam-cli-windows-amd64.zip`       | Windows (`x86_64`)  | Standalone zip archive with executable         |
|                      | `sendbeam-cli-windows-arm64.zip`       | Windows (`arm64`)   | Standalone zip archive with executable         |
| **Desktop Packages** | `SendBeam-windows-amd64-installer.exe` | Windows (`x86_64`)  | NSIS graphical setup installer                 |
|                      | `SendBeam-windows-amd64-portable.zip`  | Windows (`x86_64`)  | Portable standalone archive                    |
|                      | `SendBeam-macos-universal.dmg`         | macOS (Universal)   | Apple disk image with Applications link        |
|                      | `SendBeam-macos-universal.zip`         | macOS (Universal)   | Mach-O Universal `.app` bundle archive         |
|                      | `sendbeam-desktop_<ver>_amd64.deb`     | Linux Debian/Ubuntu | Native `.deb` package with desktop integration |
|                      | `SendBeam-linux-amd64.AppImage`        | Linux (`x86_64`)    | Portable AppImage executable                   |
| **Update Manifests** | `stable.json` & `stable.json.minisig`  | Cross-Platform      | Production release update channel manifest     |
|                      | `beta.json` & `beta.json.minisig`      | Cross-Platform      | Prerelease / preview channel manifest          |
| **Integrity & SBOM** | `SHA256SUMS.txt`                       | All Artifacts       | Canonical SHA-256 manifest                     |
|                      | `SHA256SUMS.txt.minisig`               | All Artifacts       | Minisign Ed25519 cryptographic signature       |
|                      | `SHA256SUMS.txt.sigstore.json`         | All Artifacts       | Sigstore Cosign OIDC keyless bundle            |
|                      | `sendbeam-cli.spdx.json`               | CLI Target          | SPDX 2.3 Software Bill of Materials            |
|                      | `sendbeam-desktop.spdx.json`           | Desktop Target      | SPDX 2.3 Software Bill of Materials            |

---

## 3. Core Security & Operational Invariants

1. **Zero-Cost Cryptographic Trust:**
   - All binaries and update manifests are signed with Ed25519 (Minisign) and keyless OIDC (Sigstore Cosign).
   - Verification fails closed: corrupted archives, tampered manifests, modified URLs, and forged signatures are rejected before any binary execution or replacement.

2. **Downgrade Attack Resistance:**
   - The shared updater core strictly checks candidate versions against the currently executing version (`candidate.Version.IsGreaterThan(currentVersion)`).
   - Any attempt to push a lower or identical version via modified or replayed manifests is ignored.

3. **Atomic Replacement & Rollback Safety:**
   - Self-update operations write downloads to temporary files on the same filesystem (`.tmp-*`), verify whole-file SHA-256 digests against the authenticated manifest, preserve `.old` backups of the current executable, and roll back automatically if the target binary fails validation.

4. **Strict Online-Only Transfer Semantics:**
   - The PWA Service Worker (`sw.js`) precaches static shell assets (HTML, CSS, JS, SVG) for fast loading while strictly bypassing cache for `/ws`, WebSockets, WebRTC signaling, Range audio/video streams, and live file chunks.
   - File data is never persisted in service worker cache storage or browser HTTP caches.

5. **Zero-PII Observability Guarantee:**
   - Prometheus metrics (`/metrics`) and structured logs (`slog`) strictly record aggregate counters, gauges, error codes, and message types.
   - Client IP addresses, room codes, invite words, device IDs, filenames, and secret credentials are never exposed in metrics, logs, or diagnostic traces.

6. **Anti-Brute-Force Room Code Defense:**
   - Failed join attempts consume tokens from a dedicated penalty bucket (`JoinFailBurst=10`, `JoinFailPerSec=1.0`). Sockets exceeding failure thresholds are blocked with HTTP 429 / WebSocket `errRateLimited`, mitigating online enumeration attacks against 3-word invite phrases.

7. **Trusted Reverse-Proxy Header Containment:**
   - Forwarded headers (`X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP`) are strictly ignored unless the direct socket connection originates from an explicitly configured trusted reverse-proxy CIDR block (`SENDBEAM_TRUSTED_PROXIES`).
   - Client IP extraction navigates `X-Forwarded-For` from right to left, stopping at the first untrusted upstream IP to prevent header spoofing.

---

## 4. Compatibility & Interoperability Summary

| Client / Environment                    | Direct WebRTC | Fallback Relay | Persistent Trust (`sendbeam/2`) | Self-Update  | PWA / Mobile UX |   Verified In CI    |
| :-------------------------------------- | :-----------: | :------------: | :-----------------------------: | :----------: | :-------------: | :-----------------: |
| **Linux CLI (amd64, arm64)**            |       ✓       |       ✓        |                ✓                |  ✓ (binary)  |       N/A       |    ✓ (`ci.yml`)     |
| **macOS CLI (amd64, arm64)**            |       ✓       |       ✓        |                ✓                |  ✓ (binary)  |       N/A       |    ✓ (`ci.yml`)     |
| **Windows CLI (amd64, arm64)**          |       ✓       |       ✓        |                ✓                |  ✓ (binary)  |       N/A       |    ✓ (`ci.yml`)     |
| **Linux Desktop (AppImage, deb)**       |       ✓       |       ✓        |                ✓                | ✓ (AppImage) |       N/A       |    ✓ (`ci.yml`)     |
| **macOS Desktop (Universal .app, DMG)** |       ✓       |       ✓        |                ✓                |   ✓ (.app)   |       N/A       |    ✓ (`ci.yml`)     |
| **Windows Desktop (NSIS, portable)**    |       ✓       |       ✓        |                ✓                |   ✓ (NSIS)   |       N/A       |    ✓ (`ci.yml`)     |
| **Evergreen Desktop Browsers**          |       ✓       |       ✓        |                ✓                |     N/A      |        ✓        |   ✓ (Playwright)    |
| **Android Chrome (Mobile)**             |       ✓       |       ✓        |                ✓                |     N/A      |     ✓ (PWA)     | ✓ (`mobile-chrome`) |
| **iOS Safari (Mobile)**                 |       ✓       |       ✓        |                ✓                |     N/A      |     ✓ (PWA)     |      Supported      |
| **Hardened Server (`sendbeamd`)**       |       ✓       |       ✓        |                ✓                |     N/A      |       N/A       | ✓ (`go test -race`) |

---

## 5. Milestone Sign-Off Checklist

- [x] All 7 milestone PRs (V16-PR01 through V16-PR07) implemented, tested, and reviewed.
- [x] 100% green CI across all 21 verification gates (Go tests with `-race`, TypeScript checks, ESLint, Prettier, e2e Playwright tests including mobile profiles, and multi-platform distribution builds).
- [x] Zero brand regressions or stale naming leaks.
- [x] Verified release artifact packaging across 6 CLI targets and 4 desktop packaging formats.
- [x] Minisign Ed25519 and Sigstore Cosign verification suites passing 100% cleanly.
- [x] Documentation synchronized across `README.md`, `docs/HOSTING.md`, `docs/threat-model.md`, `docs/compat-matrix.md`, `docs/distribution.md`, `docs/supply-chain.md`, `docs/updater.md`, and `docs/install.md`.
- [x] Release gate signed off and verified against merged `main`.
