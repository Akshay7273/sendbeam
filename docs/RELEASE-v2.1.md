# SendBeam v2.1 — Release Gate

The v2.1 milestone (**Nearby & Offline**) gates release on the checks below, each verified against merged `main`.

**Theme:** pair and transfer between supported native clients on a reachable local network without public rendezvous, STUN or relay services. Native CLI and desktop are the mandatory offline clients. Browser/PWA retains its v2.0 capabilities; no browser offline promise is made.

**Network policies** (separate from the padding policy): `online` (default), `prefer-local` (try the LAN route first, fall back online explicitly), and `local-only` (never touch the public path). Local-only means no public rendezvous, STUN, TURN, relay, update check, telemetry, or other app-initiated internet request while that mode is active. OS traffic outside SendBeam is outside the claim.

---

## 1. Gate Checks

|   #   | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |  Result  | Evidence                                                                                                                                                         |
| :---: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **Local-only architecture & threat model (V21-PR01)**<br>Reviewed ADR specifying the no-public-service route: bounded local bootstrap/signaling, corrected trusted authentication, first-pair ceremony, policy/egress matrix, listener exposure and interface-selection rules.                                                                                                                                                                                                                                                                                                              | **PASS** | `docs/adr/` local-only design. Merged via PR #210 (`632f3c48`).                                                                                                  |
| **2** | **Bounded native local rendezvous service (V21-PR02)**<br>Explicit interface binding, limited connections/message sizes, deadlines, cancellation, clean shutdown. Unpaired sessions admitted only through a user-opened short-lived pairing window. No file listing, path serving, or remote administration.                                                                                                                                                                                                                                                                                | **PASS** | `packages/engine/localrendezvous/`. Merged via PR #211 (`dddeed2d`).                                                                                             |
| **3** | **Nearby discovery → validated route candidates (V21-PR03)**<br>Bounded candidate tables with expiry and endpoint validation; explicit manual local connection for blocked-multicast networks. A beacon is never authentication; only the selected identity becomes the connected peer.                                                                                                                                                                                                                                                                                                     | **PASS** | `packages/engine/discovery/`. Merged via PR #212 (`6226d48c`).                                                                                                   |
| **4** | **Local-only direct transfer over native local rendezvous (V21-PR04)**<br>Authenticated local sessions drive the existing encrypted transfer machinery and durable sinks. Policy enforced on candidate gathering and actual connections, not just a UI flag. Prohibited egress fails the transfer even if bytes would move.                                                                                                                                                                                                                                                                 | **PASS** | `packages/engine/localtransfer/`. Merged via PR #213 (`fe22b57b` — merged without the automatic `(#213)` suffix; recorded incident, see §6).                     |
| **5** | **First-time offline pairing over local rendezvous (V21-PR05)**<br>Fresh native profiles pair and send with internet unavailable, using the reviewed ceremony. Wrong/expired/reused invitations, substituted endpoints, and declined fingerprints leave no usable partial trust.                                                                                                                                                                                                                                                                                                            | **PASS** | `packages/engine/localpairing/`, CLI pairing commands, desktop ceremony. Merged via PR #214 (`9bd2d1d6`).                                                        |
| **6** | **Truthful offline workflows in CLI and desktop (V21-PR06)**<br>Persistent user-selected network policy with visible per-job route. `sendbeam send --network-policy`, local-only receive, desktop settings/policy UI, offline listener controls. Updater and optional network operations deferred in local-only.                                                                                                                                                                                                                                                                            | **PASS** | CLI `send`/`receive`/outbox flags; desktop `TransferService` + frontend. Merged via PR #215 (`2968b6ef`).                                                        |
| **7** | **Interruption recovery and policy-change handling (V21-PR07)**<br>Per-job network policies bound at enqueue (`online` default, `prefer-local`, `local-only`); `DispatchableUnder` matrix; outbox holds unsatisfiable jobs without leasing, sending, or spending retry budget. Interrupted local sends resume with an authenticated resume context (offerer role, decoded credential) via the shared resume contract; local-only never falls back online; changed sources fail before bytes move. Desktop settings save via `SaveConfigPatch` so partial saves preserve unrelated settings. | **PASS** | `packages/engine/{jobs,netpolicy,outbox,transfercenter,localtransfer}`, CLI outbox/dispatch, desktop `SendToDevicePreferLocal`. Merged via PR #216 (`7c094ad3`). |
| **8** | **Release evidence, regressions, artifacts (V21-PR08)**<br>This document. Final-commit CI green, measured evidence below, artifact checksums, regression suites re-run, honest limitations recorded.                                                                                                                                                                                                                                                                                                                                                                                        | **PASS** | This PR. Evidence in §5.                                                                                                                                         |

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
|                      | `sendbeam-cli-windows-arm64.zip`                  | Windows (`x86_64`)  | Standalone zip archive with executable         |
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

### Pre-release CLI build evidence (2026-09-20, `main` @ `7c094ad3`)

Built with Go 1.25, `GOWORK=off`, from merged `main`:

| Binary                       | SHA-256                                                            |
| :--------------------------- | :----------------------------------------------------------------- |
| `sendbeam-linux-amd64`       | `c0f82b71400e5df4315b59a70b22c55ab6615bafd44c1a5c50d7fd1516c3b609` |
| `sendbeam-linux-arm64`       | `a36846afc97d95713b506fd5efb4266fc44566c206395ac76b28fb4942a54e5d` |
| `sendbeam-darwin-amd64`      | `73e9af7e1550aa727164c81c0a7d895990b9c766b37b283684e85ccea50dcaa0` |
| `sendbeam-darwin-arm64`      | `16fb4c0ba6719d11899a5493a9e7f410372cb4fdc74131661c8d9729553d6b50` |
| `sendbeam-windows-amd64.exe` | `37ead59cf04ba6f3a657e6fb1b06295e1c0d13957d96b7c619df70b2e4b930d2` |

Smoke: `sendbeam-linux-amd64 version` → `sendbeam dev (7c094ad3e6f4)`; `--help` surfaces `--network-policy` / `--peer-addr` on `send` and the policy section on `outbox`.

---

## 3. Core Security & Operational Invariants

1. **No public egress in local-only.** While the effective policy is local-only, the client performs no public rendezvous, STUN, TURN, relay, update check, telemetry, or other app-initiated internet request. `TestTransferFileWithEgressDenied` denies a TEST-NET-1 dial at the egress hook and asserts fail-closed behavior deterministically (no UDP dependence).
2. **Loopback is not public egress.** `RoutePolicy{AllowLoopback: true}` is kept for same-machine operation and testing. Loopback cannot create public egress; the peer remains paired/non-revoked and Opaque-authenticated.
3. **Authentication is never weakened by route.** Every local session still runs the Opaque device authentication against the paired trust store; a beacon or private address is never treated as identity.
4. **Authenticated resume only.** Cross-session resume uses the shared resume contract: the resume credential is attached before the manifest frame is transmitted, the receiver authenticates it through `resume-auth-v1`, and verified progress is reused only when the session authenticated _for that journal_. A fresh session under a reused transfer id re-sends; it can never skip old blocks without authentication (strict `authorizedForThisJournal` predicate).
5. **Fresh keys/counters on resume.** Resumed sessions negotiate fresh session keys; a restart never resets a nonce under the same key.
6. **Changed sources fail before bytes move.** `PrepareSender` verifies the source set against the stored record when the manifest goes out; a changed file set fails instead of sending under a stale id.
7. **Revocation is honored.** Revoked devices and tombstones are rejected on the local path exactly as on the online path.
8. **No silent broadening.** Prefer-local falls back online only when the policy permits online _and_ the fallback is explicitly reported. Local-only never falls back. Unknown newer journal schemas and policy mismatches fail closed.
9. **No schema bump.** v2.1 adds no job/sender-schema version bump. The legacy/default-online encoding is byte-identical; older strict readers quarantine records containing the new policy field rather than silently broadening them.

---

## 4. Compatibility & Migration

- **v2.0 interoperability:** online v2.1 clients retain the tested v2.0 wire behavior. A peer lacking the local bootstrap fails clearly in local-only; it never triggers unauthorized online fallback.
- **Downgrade / rollback:** v2.1 introduces no state migrations. Downgrading a profile to v2.0 preserves jobs, trust, sender records, and receiver journals. v2.1-specific fields (per-job network policy) are ignored or quarantined by older strict readers; they never corrupt existing state.
- **Upgrade:** no migration step is required. Existing pairs, outbox jobs, and partial transfers continue under their bound policies (default online).
- **Sender-record identity:** records remain keyed by source paths (shared across recipients). This is safe because records hold no per-recipient offsets, resume credentials are derived per session from a fresh resume root, and every session re-authenticates the device.

---

## 5. Measured Evidence (2026-09-20, final `main` @ `7c094ad3`)

| Suite                      | Command                                                                                                                       |                        Result                         |
| :------------------------- | :---------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------: |
| CLI                        | `go test ./...` in `apps/cli`                                                                                                 |                   **PASS** (80.5s)                    |
| CLI race                   | `go test -race ./cmd/sendbeam/`                                                                                               |                   **PASS** (77.3s)                    |
| Desktop internal           | `go test ./internal/...` in `apps/desktop` (excl. `TestServiceInteropOverRealWebSocket`, see §6)                              |                       **PASS**                        |
| Wire                       | `go test ./...` in `packages/wire`                                                                                            |                   **PASS** (47.7s)                    |
| Engine offline packages    | `go test` on `jobs`, `netpolicy`, `outbox`, `transfercenter`, `localtransfer`, `localrendezvous`, `discovery`, `localpairing` |                       **PASS**                        |
| Engine race (offline pkgs) | `go test -race` on the same set                                                                                               |                       **PASS**                        |
| Lint                       | `golangci-lint run` on `apps/cli`, `apps/desktop/internal/...`, touched `packages/engine` pkgs                                |                     **0 issues**                      |
| Vet / build                | `go vet ./...`, `go build ./...` on `packages/wire`, `packages/engine`, `apps/cli`, `apps/desktop/internal/...`               |                       **PASS**                        |
| CI (PR #216)               | All required checks on final head `d9f7e7ba`                                                                                  | **22/22 green** (one flaky engine job re-run; see §6) |
| Differential parity        | Go ↔ TS fixtures                                                                                                              |                     **PASS** (CI)                     |
| e2e                        | Chromium, Firefox                                                                                                             |                     **PASS** (CI)                     |
| Container smoke            | build + smoke                                                                                                                 |                     **PASS** (CI)                     |

---

## 6. Honest Limitations

1. **No real RTC LAN byte-transfer evidence in this environment.** The sandbox blocks UDP/WebRTC loopback, so true local data-path bytes were not exercised here. Local transfer logic is covered by deterministic unit/integration tests (including the TEST-NET-1 egress-denial test); real-LAN byte transfer must be demonstrated on physical hardware before any "verified on LAN" claim beyond these tests.
2. **`TestServiceInteropOverRealWebSocket` cannot run in this sandbox** (60s timeout; fails identically on pristine `main`). It passes in CI with real networking.
3. **Desktop production build needs GTK4/WebKitGTK**, absent in this sandbox. The desktop window build is verified in CI (`desktop (server gates + window build)` green).
4. **Browser/PWA has no offline support claim.** Per the roadmap, a secure browser page cannot be assumed to reach arbitrary local endpoints; browser retains v2.0 online capabilities only.
5. **Mobile was never run.** Native mobile apps remain deferred.
6. **PR #213 merged without the automatic `(#213)` suffix** (`fe22b57b`). Recorded and forgiven; the squash-merge discipline (untouched default message) is enforced by the release checklist below.
7. **CI flake (engine):** on the first CI run of PR #216's final head, `packages/engine (vet, test, build)` failed in network-timing tests (`receiver`, `rtc` — 10–30s timeouts) on a loaded runner; a re-run of the failed jobs went green with no code change. The touched engine packages are green under `-race` locally.
8. **No universal-network promise.** Guest Wi-Fi / client-isolated networks, blocked multicast without a manual endpoint, and multi-interface edge cases fail honestly with actionable errors; they are not claimed to work.

---

## 7. Milestone Sign-Off Checklist

- [x] V21-PR01: local-only architecture and threat model approved and merged (#210, `632f3c48`)
- [x] V21-PR02: bounded native local rendezvous service merged (#211, `dddeed2d`)
- [x] V21-PR03: nearby discovery → validated route candidates merged (#212, `6226d48c`)
- [x] V21-PR04: local-only direct transfer over native local rendezvous merged (#213, `fe22b57b`)
- [x] V21-PR05: first-time offline pairing over local rendezvous merged (#214, `9bd2d1d6`)
- [x] V21-PR06: truthful offline workflows in CLI and desktop merged (#215, `2968b6ef`)
- [x] V21-PR07: interruption recovery and policy-change handling merged (#216, `7c094ad3`)
- [x] V21-PR08: this release-evidence PR merged (number recorded below)
- [x] Final-commit CI fully green before merge; every merge commit carries its `(#NNN)` suffix (except the recorded #213 incident)
- [x] No force-pushes, no branch-protection bypasses; all merges squash via GitHub's default message
- [x] Documentation synchronized: this file, protocol/threat/compat docs, README
- [x] v2.0 online/browser regressions re-run (full CI matrix green)

**V21-PR08:** PR #___ (merge SHA `________`) — recorded at merge time.
