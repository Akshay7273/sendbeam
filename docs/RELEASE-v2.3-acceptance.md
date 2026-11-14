# v2.3 Desktop Handoff Workspace — Acceptance & Release Gate (V23-PR06 scope)

Status: **in-progress milestone gate.** Rows below record exactly what is
verified. Physical-device rows remain **NOT RUN** and do not gate independent
desktop development; they DO gate any future v2.3 release publication.

Observed baseline: main at the merge of V23-PR05 (#259) plus V23-PR06
workflow changes.

## Automated evidence (CI, linux/amd64)

| Check                                                                                                                                     | Status                                                | Evidence                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Desktop engine suite (vet/test/build, race where configured)                                                                              | PASS (CI `desktop (server gates + window build)` job) | ci.yml, all PRs                                                                                                                                                  |
| Recipe editor service regressions                                                                                                         | PASS                                                  | `TestRecipeServiceCreateStartsInert`, `...RejectsUntrustedRecipient`, `...RejectsMissingSource`, `...EditMaterialChangeDropsGrant`, `...DuplicateIsInert` (#256) |
| Delivery-status service regressions                                                                                                       | PASS                                                  | `TestRecipeDeliveryStatusNoRunYet`, `...RefusedRunHasNoJob` (#258)                                                                                               |
| Frontend determinism gate                                                                                                                 | PASS                                                  | `desktop frontend source determinism` CI job — dist byte-for-byte reproducible from `frontend/src/` (#255)                                                       |
| Frontend jsdom smoke (all controls present, zero script errors, desktop-render literal-text invariants incl. interrupted-tab XSS vectors) | PASS (web suite)                                      | `web (lint, typecheck, test, build)` + `desktop-render.test.ts`                                                                                                  |
| Documentation consistency                                                                                                                 | PASS                                                  | `docs consistency` job (#252)                                                                                                                                    |
| Real-network offline regression (namespaced two-host)                                                                                     | PASS                                                  | `offlinelab` job (#243)                                                                                                                                          |

## Pipeline evidence

| Check                                                                                    | Status                                                                              | Evidence                                                                                                                                   |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Release/distribution builds rebuild the embedded frontend from sources before `go build` | PASS (workflow-validated; YAML + bash -n; full path exercised on next tag/dispatch) | V23-PR06: `python3 frontend/tools/build.py` inserted before all 4 desktop builds in release.yml and all desktop builds in distribution.yml |

## NOT RUN — physical acceptance rows (BLOCKED; gate release publication)

| Row                                                                                                                    | Why blocked                                                                          |
| ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Recipe create → preview → approve → run → delivered, exercised in the **packaged UI** on Windows/macOS/Linux           | No packaged-desktop hosts available to the agent                                     |
| Recipe scope-change → re-approval prompt visible in packaged UI                                                        | Same                                                                                 |
| Watch/schedule start/stop controls govern the real runtime in the packaged UI                                          | Same                                                                                 |
| Update/rollback of the desktop app with recipes intact (upgrade v2.2 profile → v2.3, rollback → recipes inert on disk) | Same                                                                                 |
| Physical two-machine LAN byte-transfer via recipes                                                                     | Requires two real machines (V221-PR02 harness exists; hardware does not)             |
| Android/iOS browsers + native mobile                                                                                   | Native mobile deferred by design; mobile browsers NOT RUN (see platform-evidence.md) |

## SB-R10 acceptance evidence (2026-11-14; recorder-validated)

Evidence recorded with `scripts/acceptance-record.sh` (anti-fabrication
gate: PASS requires full provenance; tampered files cannot render). Source
commit: `df96fe8eefe29750e759d25e8abb699330433e67`. Operator: jarvis-r10.

### Phase A — artifacts built and inspected (NOT installed)

Distribution run `43573458273` (workflow `distribution.yml`, event
`pull_request`, pinned head `f796513f3b64f6b99fc24e07205c5871d38d34b1` —
the PR-#297 merge preview commit `a34ded23bbd1d7ead5eaea3942b942ba78a275dc`
which all binaries embed as `vcs.revision`). All jobs success. Bundle
`sendbeam-distribution-a34ded23…`: **SHA256SUMS 14/14 verified OK**; SBOMs
(CLI + desktop SPDX) present; build-provenance and SBOM attestations are
generated by the workflow (attest-build-provenance v4.2.2,
attest-sbom v4.1.0) — verification of the attestation bundles was NOT
possible from this environment (GitHub's attestation API returned 404 for

> **SEC01 correction (2026-11-14):** the attestation-404 limitation above is **superseded** — the R10 distribution bundle IS independently verified (build provenance + SBOM via `gh attestation verify`; identity `distribution.yml@refs/pull/297/merge`). The recorded 404s stemmed from the API query shape plus post-publish digest churn (2026-09-29 re-uploads). See docs/SECURITY-INCIDENT-SB-SEC01.md #7.
> these subjects), recorded honestly as a limitation, NOT as a failure of
> attestation.

| Artifact                                                | SHA256 (see bundle SHA256SUMS) | Structural inspection                                                                                                                                                           |
| ------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sendbeam-desktop_0.0.0~dev+git.a34ded23bbd1_amd64.deb` | `a630a4b3…`                    | `dpkg-deb -I/-c`: pkg sendbeam-desktop, arch amd64, gtk/webkit deps, `/usr/bin/sendbeam-desktop` (18.9 MB ELF x86-64), `.desktop` + icons + copyright                           |
| `SendBeam-linux-amd64.AppImage`                         | `c92160c2…`                    | `--appimage-extract` OK; binary sha256 `39b18a01…`; `.desktop` entry verified; SB-R09 markers (policy-degraded-banner CSS, `CancelRecipeJobResult` symbols) embedded            |
| `SendBeam-windows-amd64-portable.zip`                   | `39702969…`                    | `unzip -l`: LICENSE + README + `sendbeam-desktop.exe` (19.3 MB); exe sha256 `e33afdeb…`; `vcs.revision=a34ded23` embedded                                                       |
| `SendBeam-windows-amd64-installer.exe`                  | `da6d415b…`                    | NSIS v3.13 firstheader validated (`NullsoftInst` @74760, payload 7.57 MB, requireAdministrator); CI PE-resources validation passed; deep extraction needs 7z (unavailable here) |
| `SendBeam-macos-universal.dmg`                          | `29aa4f54…`                    | UDIF `koly` trailer verified; 15.9 MB; CI "Validate macOS artifacts" passed; content listing requires a macOS host                                                              |
| CLI archives (6 platforms)                              | (bundle)                       | built + smoke-tested by the `smoke` job of the same run                                                                                                                         |

These rows prove **build + package structure**, not installation.

### Phase C — native desktop (Linux/AMD64 under Xvfb — the only GUI-capable host)

The **installed AppImage binary** (not a source build) was executed under
Xvfb + WebKitGTK:

- **PASS** — launch: real Wails v3 window ("SendBeam Desktop", 1040×720,
  IsViewable), GTK 4.14.5 / WebKitGTK 2.52.6; config/identity/trust/jobs/
  recipes stores created under `~/.config/sendbeam`.
- **PASS** — restart/clean exit: relaunch re-created runtime state;
  single-instance lock (`forward.json`) served; processes terminated cleanly.
- **PASS** — keyboard accessibility: xdotool Tab/Space delivered into the
  real WebView — focus rings cycled (window diffs 547/9827/396 px) and
  Space activated a panel (52 842 px change): navigation and activation
  work in the installed app.
- **BLOCKED** — interactive recipe flows in the real window (CRUD, preview,
  approve, grant, cancel, watch/schedule): XTEST mouse clicks do not
  navigate (WM-less Xvfb; WebKit remote inspector speaks its binary
  protocol, not HTTP/WS). Requires a desktop session with a WM +
  accessibility bridge. DOM-level equivalents are proven in jsdom
  (#297, 12 tests) — recorded as component evidence, NOT as native rows.
- **NOT RUN** — uninstall row (blocked with the interactive rows).
- **BLOCKED** — Windows install/launch rows (no Windows host);
  **BLOCKED** — macOS install/launch rows (no macOS host).

### Phase D — physical network

- **BLOCKED** — two-device LAN, NAT/relay route, cross-version: requires a
  second physical machine (fryday is a single VPS; veronica unreachable;
  Android/Termux is not a desktop peer).
- **PASS (traceability only)** — loopback real-transfer VERIFIED with
  byte+digest equality at the engine/desktop layers (#294/#295); loopback
  is NOT two-device evidence and never counts toward the physical rows.

### Honest counts (this SB-R10 pass)

| Result  | Rows                                                                  |
| ------- | --------------------------------------------------------------------- |
| PASS    | 10 (6 artifact-inspection + 3 native-Linux + 1 loopback-traceability) |
| BLOCKED | 6                                                                     |
| NOT RUN | 1                                                                     |

**Nothing above is a release publication or a claim that v2.3 is accepted.**
The physical rows below continue to gate any future v2.3 release.

### Artifact retention

GitHub Actions artifacts expire after **14 days** (`retention-days: 14` in
`distribution.yml`). Before authorizing a release, re-run the distribution
workflow at the release commit and copy the bundle (SHA256SUMS + SBOMs)
into owner-controlled storage; the evidence rows above reference run
`43573458273` and will outlive the artifact only in this document.

## Release gate (future v2.3 publication)

Physical rows above are mandatory before any release publication. Automated
rows must also be green at the release commit. The gate document is updated —
not rewritten — as rows complete.
