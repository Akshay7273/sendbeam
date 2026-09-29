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

## CLI (`sendbeam`)

| Capability                                | Code | Package                                                      | Automated tests                                               | Packaged UI | Physical device                                                                                                            |
| ----------------------------------------- | ---- | ------------------------------------------------------------ | ------------------------------------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------- |
| Send / receive (direct + relay)           | ✓    | ✓ darwin/amd64+arm64, linux/amd64+arm64, windows/amd64+arm64 | ✓ (linux/amd64 CI: engine, wire, cli suites; e2e real server) | N/A (CLI)   | **NOT RUN**                                                                                                                |
| Pairing (SPAKE2, trusted-device mesh)     | ✓    | ✓ (same artifacts)                                           | ✓ (linux/amd64 CI)                                            | N/A         | **NOT RUN**                                                                                                                |
| Targeted delivery (`send @device`)        | ✓    | ✓                                                            | ✓ (linux/amd64 CI)                                            | N/A         | **NOT RUN**                                                                                                                |
| Durable resume / crash recovery           | ✓    | ✓                                                            | ✓ (linux/amd64 CI)                                            | N/A         | **NOT RUN**                                                                                                                |
| Verified completion (SHA-256)             | ✓    | ✓                                                            | ✓                                                             | N/A         | **NOT RUN**                                                                                                                |
| Offline / local-only operation            | ✓    | ✓                                                            | ✓ (unit/integration, real local fs)                           | N/A         | **NOT RUN** — no real RTC LAN byte-transfer evidence exists (sandbox blocks UDP loopback); see `docs/RELEASE-v2.2.md` §8.6 |
| Automation (recipes, watchers, schedules) | ✓    | ✓                                                            | ✓ (deterministic tests; fsnotify against real filesystem)     | N/A         | **NOT RUN** — foreground process only, no daemon                                                                           |

Notes: release workflow **cross-compiles and publishes** all six CLI targets but
the full Go test suite runs on **linux/amd64 only** in CI; darwin/windows/arm64
rows carry build-plus-smoke evidence, not test evidence.

## Desktop app (SendBeam Desktop, Wails v3)

| Capability                                                                  | Code                                                                                                                                                          | Package                                                                                                        | Automated tests                                                                                  | Packaged UI | Physical device |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------- | --------------- |
| Send / receive / pairing / targeted delivery / resume / verified completion | ✓                                                                                                                                                             | ✓ (NSIS installer + portable ZIP, Universal .app + .dmg, AppImage + .deb; amd64; macOS universal covers arm64) | partial — "desktop (server gates + window build)" CI job + engine suites; **no packaged-UI e2e** | **NOT RUN** | **NOT RUN**     |
| Recipe UI (create/preview/approve/status)                                   | markup exists in embedded built `dist/` (observed: 86 recipe/handoff/schedule references) but **maintainable frontend source is not in this repo** (V23-PR01) | ✓ (same installers)                                                                                            | service-level tests only                                                                         | **NOT RUN** | **NOT RUN**     |
| Self-updater (notify → atomic apply → rollback)                             | ✓ (`update_service.go` + local-only skip tests)                                                                                                               | ✓                                                                                                              | ✓ (unit, incl. offline-skip behavior)                                                            | **NOT RUN** | **NOT RUN**     |

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
- Level 4 (packaged UI exercised): **no evidence anywhere** — requires manual
  installs on each OS family (guide: `docs/install.md`, `docs/distribution.md`).
  Tracked as V221-PR03 scope.
- Level 5 (physical device): **no evidence anywhere** — requires two-machine
  real-network runs (V221-PR02) and real Android/iOS devices for the mobile
  browser rows. Emulation does not substitute.
- Artifact-chain verification (level-independent): minisign verification of
  `SHA256SUMS.txt` **performed and OK** (2026-09-30); sigstore bundle present;
  update-channel manifests reference matching digests.
