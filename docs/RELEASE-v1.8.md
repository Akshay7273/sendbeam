# SendBeam v1.8 — Release Gate

The v1.8 milestone (**Protocol Assurance & Mobile Hardening**: continuous native fuzzing across all untrusted input boundaries, deterministic cross-language differential parity harness, mobile WebKit / iOS Safari transfer hardening with dedicated CI profiling, expanded 20-vector adversarial attack matrix, and enhanced repository supply-chain posture with OpenSSF Scorecard and SHA-pinned GitHub Actions) gates release on the checks below, each verified against merged `main`.

Every gate check requires deterministic test evidence, green CI execution, and complete documentation synchronization.

---

## 1. Gate Checks

|   #   | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  Result  | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| :---: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **1** | **Continuous Fuzzing Infrastructure**<br>Establish comprehensive continuous fuzzing covering every untrusted byte boundary across Go packages (`packages/wire`, `packages/engine`, `apps/server`). Commit deterministic seed corpora under standard `testdata/fuzz/` paths. Integrate fast corpus replay smoke gate into pull request CI. Schedule matrix-parallel nightly fuzzing via GitHub Actions (`fuzz.yml`) with automated crash artifact retention and manual dispatch. Provide developer runner scripts (`scripts/run_fuzz.sh`), `just` recipes (`just fuzz-smoke`, `just fuzz`), and Google OSS-Fuzz container build script (`scripts/oss-fuzz-build.sh`). Document fuzzing architecture in `docs/fuzzing.md`.                                               | **PASS** | 22 native Go fuzz targets implemented in `packages/wire/fuzz_test.go`, `journal_fuzz_test.go`, `padding_fuzz_test.go`, `pairing_fuzz_test.go`, `trusted_auth_fuzz_test.go`, `words_fuzz_test.go`, `revocation_fuzz_test.go`; `packages/engine/transfer/journal_fuzz_test.go`, `packages/engine/trust/trust_fuzz_test.go`, `packages/engine/updater/manifest_fuzz_test.go`; `apps/server/internal/signal/fuzz_test.go`. Committed seed corpora across all targets under `testdata/fuzz/`. Fuzz smoke replay integrated in `.github/workflows/ci.yml`. Nightly matrix workflow `.github/workflows/fuzz.yml`. Runner script `scripts/run_fuzz.sh` and OSS-Fuzz container build script `scripts/oss-fuzz-build.sh`. Documented in `docs/fuzzing.md` and README. Merged via PR #161 (`c305f9c`). |
| **2** | **Differential Cross-Language Parity Harness (Go ↔ TS)**<br>Build automated, deterministic differential testing harness synthesizing identical inputs across Go and TypeScript wire codecs. Generate 2,000 cases per surface per run using deterministic pseudo-random seeds. Verify byte-for-byte serialization identity and identical fail-closed rejection on invalid inputs across frame headers, revocation records, SPAKE2+ credentials, trusted-auth session challenges, invite codes, and safe transfer paths. Verify sensitivity via deliberate 1-byte encoder mutations. Gate CI on differential parity and run 10,000 cases nightly.                                                                                                                        | **PASS** | Go vector generator `packages/wire/differential_vector_gen_test.go` synthesizing 2,000 cases per codec. TypeScript consumer suite `packages/protocol/src/differential.test.ts`. TS reverse generator exporting to `packages/wire/testdata/diffgen-ts.jsonl` and Go consumer suite `packages/wire/differential_test.go`. Verified deliberate 1-byte mutation pinpointing exact case ID `fh_edge_0`. CI differential gate in `.github/workflows/ci.yml` (2,000 cases/codec) and nightly workflow in `.github/workflows/fuzz.yml` (10,000 cases/codec). Developer tooling `scripts/run_differential.sh` and `just differential`. Documented in `docs/fuzzing.md` (Section 9). Merged via PR #162 (`e192311`).                                                                                  |
| **3** | **Mobile WebKit & iOS Safari Hardening + Dedicated CI Profile**<br>Harden mobile transfer path against iOS Safari and WebKit browser engine constraints. Add dedicated Playwright `mobile-webkit` profile (iPhone 14 viewport, WebKit engine) to CI test matrix. Test mobile layout, responsive touch targets (>= 44x44px), PWA app-shell join flows, WebKit DataChannel backpressure (`bufferedAmountLowThreshold`) throttling, Page Visibility API suspension handling, and memory-bounded OPFS stream sink fallback. Enforce WebRTC trickle candidate sequencing and resolve engine supervisor lock inversions.                                                                                                                                                     | **PASS** | Playwright mobile WebKit project added to `apps/web/playwright.config.ts`. 11 targeted end-to-end tests in `apps/web/e2e/mobile-transfer.spec.ts` passing green under mobile WebKit. Memory-bounded stream sink fallback in `apps/web/src/lib/transfer/sink.ts`. Worker-to-host streaming fix in `apps/web/src/lib/transfer/transfer-core.ts`. Receiver session teardown race fix in `apps/web/src/lib/session/transfer.ts`. Trickle candidate SDP serialization in `packages/engine/rtc/peer.go`. Supervisor relay cutover deadlock resolution in `packages/engine/supervisor/supervisor.go` and `adaptive_conn.go`. Updated `docs/compat-matrix.md`. Merged via PR #163 (`e111e41`).                                                                                                      |
| **4** | **Adversarial Attack Matrix Expansion (12 → 20+ Vectors)**<br>Expand the adversarial security attack matrix to 20 vectors across Go and TypeScript packages, enforcing existing protocol rules against malformed inputs and hostile peers: padding-oracle probe (13), bucket-downgrade coercion (14), update-manifest replay rejection (15), revocation race condition (16), revocation sequence rollback & domain monotonicity (17), relay frame corruption/reordering/truncation (18), durable transfer journal tampering (19), and pairing confirmation misuse (20). Update threat model with full 20-vector matrix table.                                                                                                                                          | **PASS** | New adversarial test suites implemented in `packages/wire/attack_matrix_test.go` (Vectors 13, 14, 17, 18, 19, 20), `packages/engine/trust/attack_matrix_test.go` (Vector 16), `packages/engine/updater/attack_matrix_test.go` (Vector 15), and `packages/protocol/src/attack-matrix.test.ts` (Vectors 1–20 complete parity). Comprehensive 20-vector attack matrix table and cross-references documented in `docs/threat-model.md`. Merged via PR #164 (`3eaf8a4`).                                                                                                                                                                                                                                                                                                                         |
| **5** | **Security Posture: Disclosure Policy, OpenSSF Scorecard, SHA-Pinned Actions**<br>Formalize coordinated vulnerability disclosure policy (`SECURITY.md`) with supported versions table, GitHub Private Vulnerability Reporting instructions, defined maintainer response SLAs, and scope boundaries. Configure low-noise grouped weekly automated dependency management in `.github/dependabot.yml`. Add OpenSSF Scorecard automated analysis workflow (`.github/workflows/scorecard.yml`) publishing SARIF to GitHub Code Scanning. Pin 100% of third-party GitHub Actions across all workflows by immutable 40-character commit SHA with inline version comments. Document branch protection and OpenSSF Best Practices self-certification in `docs/supply-chain.md`. | **PASS** | `SECURITY.md` established at repository root. `.github/dependabot.yml` configured for weekly grouped updates. `.github/workflows/scorecard.yml` publishing to Security tab; OpenSSF Scorecard and Best Practices badges added to `README.md`. All third-party GitHub Actions pinned to full commit SHAs across `.github/workflows/*.yml`. `docs/supply-chain.md` updated with pinned action reference table, branch protection rulesets on `main`, and OpenSSF Best Practices questionnaire answers (Passing tier). Merged via PR #165 (`73f5f42`).                                                                                                                                                                                                                                         |
| **6** | **Milestone Gate Verification & Documentation Coherence**<br>Verify all 5 milestone PRs merged to `main`. CI runs 100% green with 0 failing checks across Go `-race` tests, TypeScript checks, ESLint, Prettier, Playwright e2e (including mobile-webkit and mobile-chrome), and distribution builds. Full documentation sweep: `protocol.md` (no wire changes invariant), `threat-model.md` (20-vector matrix), `compat-matrix.md` (mobile WebKit rows), `fuzzing.md` (continuous fuzzing guide), `supply-chain.md` (scorecard & pinned actions), `SECURITY.md` (security disclosure), `README.md` (badges, mobile support, security policy). Version metadata verification.                                                                                          | **PASS** | Complete CI validation passing 100% green on `main` across all 22 checks. Local gate suite clean (`just fmt`, `just lint`, `just typecheck`, `pnpm format:check`, `just test`, `just build`). Full documentation synchronization complete across all references. Invariant verified: zero wire format changes in v1.8.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

---

## 2. Release Artifacts Matrix

The standard SendBeam distribution artifact set is produced and cryptographically signed on release tags (`v*`):

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

## 3. Core Security & Assurance Invariants

1. **Continuous Fuzzing Verification:**
   - 22 native Go fuzz targets continuously validate all untrusted parser boundaries.
   - Committed seed corpora are replayed in fast smoke gates on every commit and PR.
   - Nightly matrix workflows run extended fuzzing iterations across all modules.

2. **Differential Parity Guarantee:**
   - Go (`packages/wire`) and TypeScript (`packages/protocol`) produce identical wire bytes across all codecs.
   - 2,000 cases per codec surface are deterministically verified in PR CI; 10,000 cases nightly.
   - Encoder mutations are detected and failed closed immediately.

3. **Mobile WebKit Transfer Resiliency:**
   - Mobile Safari transfers operate under strict memory ceilings without accumulating chunks in JS heap memory.
   - WebKit DataChannel backpressure avoids SCTP buffer exhaustion and socket stalls.
   - Page Visibility suspensions degrade honestly to a paused state with resume capabilities.

4. **20-Vector Adversarial Regression Coverage:**
   - Both Go and TypeScript test suites execute 20 distinct adversarial attack vectors.
   - Validates padding-oracle immunity, bucket downgrade coercion rejection, update manifest replay defense, revocation race condition settlement, monotonic sequence enforcement, relay frame integrity, journal tampering rejection, and SPAKE2+ confirmation misuse prevention.

5. **Supply Chain Security & Immutable Action Pinning:**
   - All third-party GitHub Actions are pinned to full 40-character commit SHAs.
   - OpenSSF Scorecard automated analysis verifies repository security posture.
   - Builds produce SLSA Level 3 provenance, SPDX 2.3 SBOMs, and dual cryptographic signatures (Minisign + Sigstore Cosign OIDC).

6. **Zero Wire Format Changes:**
   - Wire protocols (`sendbeam/1`, `sendbeam/2`, `sendbeam/pairing/1`) remain frozen and backwards compatible.
   - No breaking changes to framing, capability sets, or serialization layouts.

---

## 4. Compatibility & Interoperability Summary

| Client / Environment                             | Direct WebRTC | Fallback Relay | Persistent Trust (`sendbeam/2`) | Traffic Padding | Mobile WebKit Tested |   Verified In CI    |
| :----------------------------------------------- | :-----------: | :------------: | :-----------------------------: | :-------------: | :------------------: | :-----------------: |
| **Linux CLI (amd64, arm64)**                     |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          |    ✓ (`ci.yml`)     |
| **macOS CLI (amd64, arm64)**                     |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          |    ✓ (`ci.yml`)     |
| **Windows CLI (amd64, arm64)**                   |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          |    ✓ (`ci.yml`)     |
| **Linux Desktop (AppImage, deb)**                |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          |    ✓ (`ci.yml`)     |
| **macOS Desktop (Universal .app, DMG)**          |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          |    ✓ (`ci.yml`)     |
| **Windows Desktop (NSIS, portable)**             |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          |    ✓ (`ci.yml`)     |
| **Desktop Browsers (Chromium, Firefox, WebKit)** |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          |   ✓ (Playwright)    |
| **Android Chrome (Pixel 7)**                     |       ✓       |       ✓        |                ✓                |        ✓        |         N/A          | ✓ (`mobile-chrome`) |
| **iOS Safari (iPhone 14)**                       |       ✓       |       ✓        |                ✓                |        ✓        |          ✓           | ✓ (`mobile-webkit`) |
| **Hardened Server (`sendbeamd`)**                |       ✓       |       ✓        |                ✓                |   ✓ (relayed)   |         N/A          | ✓ (`go test -race`) |

---

## 5. Milestone Sign-Off Checklist

- [x] V18-PR01 — Continuous fuzzing infrastructure merged (`c305f9c`)
- [x] V18-PR02 — Differential cross-language parity harness merged (`e192311`)
- [x] V18-PR03 — Mobile WebKit/iOS Safari hardening + CI profile merged (`e111e41`)
- [x] V18-PR04 — Attack matrix expansion: 12 → 20+ vectors merged (`3eaf8a4`)
- [x] V18-PR05 — Security posture: disclosure policy, scorecard, pinned actions merged (`73f5f42`)
- [x] V18-PR06 — Release gate: RELEASE-v1.8.md + docs sweep + version metadata
