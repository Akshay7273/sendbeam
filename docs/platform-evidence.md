# Cross-Platform Capability & Evidence Ledger

Status ledger for every advertised platform and capability, at five distinct
evidence levels. Maintained under V221-PR01; each row records what was
**observed**, not assumed. Levels:

1. **Code** — implemented and merged (tests exist; CI green on the merge commit)
2. **Package** — published artifact on GitHub Releases for that platform
3. **Automated tests** — the automated suite actually exercised that platform/feature
4. **Packaged UI** — the _published artifact_ was installed and exercised (not just CI)
5. **Physical device** — real hardware, real network, end-to-end human workflow

`NOT RUN` means no evidence exists in this environment; it is never inferred
from a lower level. Emulation never counts as level 4 or 5.

Observed baseline: main `726360d`, release `v2.2.0` (tag → `87d2628`, #225).
Automated-evidence reference: CI run `35528318440` (all 11 required jobs green
on the release commit, 2026-09-20). Artifact verification performed for this
ledger on 2026-09-30: `SHA256SUMS.txt` minisign verification **OK** against the
committed `minisign.pub` (key ID `BA67BC598735C8DC`).

> **Follow-up addendum (2026-09-30, post-#243):** the `offlinelab` CI job now
> supplies automated **Linux network-namespace transfer evidence** for the
> offline workflows: real `unshare -Urnm` namespaces with a dual-homed sender
> (packet-level egress capture), fresh offline pairing, paired local-only
> delivery with SHA-256 verification, cancellation and recovery,
> unpaired-receiver and revocation fail-closed checks, the policy gate, and a
> zero-prohibited-egress assertion. This is real two-**namespace** evidence —
> it still does **not** constitute physical two-machine LAN evidence, packaged
> desktop UI verification, or physical mobile testing, which remain **NOT
> RUN**. Namespace tests are never promoted to physical-device proof here.
> (The first run also surfaced and fixed real production-path defects: the
> always-expiring parsed invitation, missing pair-secret persistence on
> offline pairing, and the cross-host LAN ICE candidate filter — see #243.)

## CLI (`sendbeam`)

| Capability                                | Code | Package                                                      | Automated tests                                                                                                                                    | Packaged UI | Physical device                                                                                                                        |
| ----------------------------------------- | ---- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Send / receive (direct + relay)           | ✓    | ✓ darwin/amd64+arm64, linux/amd64+arm64, windows/amd64+arm64 | ✓ (linux/amd64 CI: engine, wire, cli suites; e2e real server)                                                                                      | N/A (CLI)   | **NOT RUN**                                                                                                                            |
| Pairing (SPAKE2, trusted-device mesh)     | ✓    | ✓ (same artifacts)                                           | ✓ (linux/amd64 CI)                                                                                                                                 | N/A         | **NOT RUN**                                                                                                                            |
| Targeted delivery (`send @device`)        | ✓    | ✓                                                            | ✓ (linux/amd64 CI)                                                                                                                                 | N/A         | **NOT RUN**                                                                                                                            |
| Durable resume / crash recovery           | ✓    | ✓                                                            | ✓ (linux/amd64 CI)                                                                                                                                 | N/A         | **NOT RUN**                                                                                                                            |
| Verified completion (SHA-256)             | ✓    | ✓                                                            | ✓                                                                                                                                                  | N/A         | **NOT RUN**                                                                                                                            |
| Offline / local-only operation            | ✓    | ✓                                                            | ✓ (unit/integration, real local fs) + automated network-namespace evidence since #243 (two-host topology, digest-verified, zero prohibited egress) | N/A         | **NOT RUN** — real two-machine LAN byte-transfer evidence (physical); historical sandbox note preserved in `docs/RELEASE-v2.2.md` §8.6 |
| Automation (recipes, watchers, schedules) | ✓    | ✓                                                            | ✓ (deterministic tests; fsnotify against real filesystem)                                                                                          | N/A         | **NOT RUN** — foreground process only, no daemon                                                                                       |

Notes: release workflow **cross-compiles and publishes** all six CLI targets but
the full Go test suite runs on **linux/amd64 only** in CI; darwin/windows/arm64
rows carry build-plus-smoke evidence, not test evidence.

## Desktop app (SendBeam Desktop, Wails v3)

| Capability                                                                  | Code                                                                                                                                                                                                                                                                                                                                                                                                        | Package                                                                                                        | Automated tests                                                                                  | Packaged UI | Physical device |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------- | --------------- |
| Send / receive / pairing / targeted delivery / resume / verified completion | ✓                                                                                                                                                                                                                                                                                                                                                                                                           | ✓ (NSIS installer + portable ZIP, Universal .app + .dmg, AppImage + .deb; amd64; macOS universal covers arm64) | partial — "desktop (server gates + window build)" CI job + engine suites; **no packaged-UI e2e** | **NOT RUN** | **NOT RUN**     |
| Recipe UI (create/preview/approve/status)                                   | backend `RecipeService` exists and is service-bound (List/Get/Preview/Plan/Approve/Grant/Revoke/Disable/Enable/Watch/Scheduler controls/Run/Delete); the embedded frontend contains **text/link handoff controls only — zero recipe/schedule/watch elements** (verified against the built `dist/`: no recipe/schedule/watch ids or bindings); **no maintainable frontend source exists in-repo** (V23-PR01) | ✓ (same installers)                                                                                            | service-level tests only                                                                         | **NOT RUN** | **NOT RUN**     |
| Self-updater (notify → atomic apply → rollback)                             | ✓ (`update_service.go` + local-only skip tests)                                                                                                                                                                                                                                                                                                                                                             | ✓                                                                                                              | ✓ (unit, incl. offline-skip behavior)                                                            | **NOT RUN** | **NOT RUN**     |

## Web app (browser / PWA)

| Platform              | Code | Package                                                                  | Automated tests (CI)                                                       | Packaged UI | Physical device                                              |
| --------------------- | ---- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------- | ----------- | ------------------------------------------------------------ |
| Chromium (desktop)    | ✓    | ✓ (container image `ghcr.io/akshay7273/sendbeam`; container smoke in CI) | ✓ (chromium e2e, real server round-trips)                                  | N/A         | **NOT RUN**                                                  |
| Firefox (desktop)     | ✓    | ✓                                                                        | ✓ (firefox e2e)                                                            | N/A         | **NOT RUN**                                                  |
| Safari (desktop)      | ✓    | ✓                                                                        | ✓ (WebKit engine via Playwright on Linux — engine-level, not macOS Safari) | N/A         | **NOT RUN**                                                  |
| Android browser / PWA | ✓    | ✓                                                                        | ✓ (Pixel 7 **emulation** profile)                                          | N/A         | **NOT RUN** (matrix §"Mobile Web & PWA" already states this) |
| iOS browser / PWA     | ✓    | ✓                                                                        | ✓ (iPhone 14 **emulation**, Linux WebKit)                                  | N/A         | **NOT RUN**                                                  |

## Native mobile (Android app / iOS app)

|                    | Availability                                                                             |
| ------------------ | ---------------------------------------------------------------------------------------- |
| Android native app | **Does not exist.** No code, no package, no claim. Deferred by design (v2.3 exclusions). |
| iOS native app     | **Does not exist.** Same as above.                                                       |

## Verification-status summary

- Level 1–3 evidence: strong for linux/amd64, browser (Chromium/Firefox), and
  engine-level parity; **build-only** for darwin/windows CLI targets and desktop.
  Since #243, offline workflows also carry automated real-network-namespace
  evidence (two-host topology, digest-verified, egress-captured).
- Level 4 (packaged UI exercised): **no evidence anywhere** — requires manual
  installs on each OS family (guide: `docs/install.md`, `docs/distribution.md`).
  Tracked as V221-PR03 scope.
- Level 5 (physical device): **no evidence anywhere** — requires two-machine
  real-network runs and real Android/iOS devices for the mobile browser rows.
  Namespace and emulation evidence does not substitute.
- Artifact-chain verification (level-independent): minisign verification of
  `SHA256SUMS.txt` **performed and OK** (2026-09-30); sigstore bundle present;
  update-channel manifests reference matching digests.
