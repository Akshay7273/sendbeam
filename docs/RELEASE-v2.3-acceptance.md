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

## Release gate (future v2.3 publication)

Physical rows above are mandatory before any release publication. Automated
rows must also be green at the release commit. The gate document is updated —
not rewritten — as rows complete.
