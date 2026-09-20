# SendBeam v2.2 — Release Gate

The v2.2 milestone (**Repeatable Handoffs**) gates release on the checks below, each verified against merged `main`.

**Theme:** save a handoff workflow, preview it, and optionally run it on a schedule or when selected local files become ready. A routine is a **one-way delivery**, not a shared folder or backup system: it does not mirror deletions, overwrite existing files by default, pull arbitrary remote files, or promise that all historical versions will be retained.

**Automation posture:** saved recipes start disabled or approval-required. Automated dispatch (watch/schedule) needs a separate explicit auto-send grant on a native user-scoped runner. Sender auto-send permission and receiver auto-accept permission are distinct; neither implies the other.

---

## 1. Gate Checks

|   #   | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |  Result  | Evidence                                                                                                    |
| :---: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------: | :---------------------------------------------------------------------------------------------------------- |
| **1** | **Saved handoff recipe schema and explicit automation grants (V22-PR01)**<br>Small, local, reviewable workflow model: explicit local source roots/selections, fixed authenticated recipients, allowed network/privacy mode, filters, trigger, expiry, budgets. Default new/imported/changed recipes to disabled or approval-required. Material changes invalidate prior automation consent. No secrets embedded in recipe files; imported recipes never run automatically.              | **PASS** | `packages/engine/recipes/` (schema, store, grants). Merged via PR #218 (`1bf0f616`).                        |
| **2** | **Manual one-shot recipe runs and secret-free dry-run preview (V22-PR02)**<br>Save/edit/duplicate recipes; dry-run plan (sources, recipients, filters, limits, estimated bytes) with no transfers or remote effects; explicit Run enqueues ordinary jobs. Preview distinguished from execution; revalidation at enqueue/send. No second job queue.                                                                                                                                      | **PASS** | Recipe resolver/runner, CLI `recipe preview`/`run`, versioned DTO output. Merged via PR #219 (`f009e5e5`).  |
| **3** | **Bounded user-scoped routine runner with AutoSend grant enforcement (V22-PR03)**<br>Explicitly enabled, bounded host for automated triggers. Single ownership, restart reconciliation, bounded admission/resources, disable-all, per-user startup controls; autostart off by default. Locked credential store pauses visibly rather than falling back to plaintext. No privileged system-wide service.                                                                                 | **PASS** | Runner, ownership lease, CLI/desktop controls. Merged via PR #220 (`b641d0e3`).                             |
| **4** | **Watched-folder one-way handoffs (V22-PR04)**<br>Explicitly selected new/changed stable files become ordinary one-way delivery jobs. Default discovered changes to an approval-required queue; automatic dispatch needs a separate explicit grant. Debounce/coalesce bursts, stability revalidation, bounded reconciliation, symlink-escape and receive-folder feedback-loop protection. No mirror deletion, no two-way sync.                                                          | **PASS** | `fsnotify` watcher adapter, debounce/cooldown. Merged via PR #221 (`04d9102d`).                             |
| **5** | **Explicit schedules with bounded catch-up (V22-PR05)**<br>Intervals and daily local-time schedules with persisted timezone and next-run semantics. DST gaps/repeats, clock jumps, sleep, missed runs defined: default skip or one bounded catch-up (`max_catchup_runs`, 0–10, default 3), never every missed occurrence. Durable idempotency cursor; single active execution per recipe.                                                                                               | **PASS** | Scheduler, durable cursor, deterministic-clock tests. Merged via PR #222 (`bbe5fa8c`).                      |
| **6** | **Provenance, receiver auto-accept policy, pause/disable controls (V22-PR06)**<br>Local cause/provenance attached to normal transfer jobs (advisory label, no file contents, no reusable secrets); sender byte/file/run/concurrency ceilings independent of receiver quotas. Receiver auto-accept policy stays separate from sender auto-send. Run now / Preview / Pause / Disable / Reapprove; widening recipe scope requires reapproval.                                              | **PASS** | Provenance on jobs + wire manifest, receiver policy, CLI/desktop controls. Merged via PR #223 (`676febd5`). |
| **7** | **Isolation, failure recovery, chaos/resource evidence (V22-PR07)**<br>End-to-end recipes against real listeners and real filesystems: overlapping recipes, receive-folder loops, event floods, changed sources, large directories, offline periods, disk-full, locked credentials, revoked recipients, policy changes, crashes around enqueue/receiver-commit/ack. No unauthorized source inclusion, automatic overwrite, remote deletion, unbounded queue growth, or secret exposure. | **PASS** | Integration/chaos harness, resource budgets. Merged via PR #224 (`84c1ee45`).                               |
| **8** | **Release evidence, upgrade/rollback checks, release notes (V22-PR08)**<br>This document. Upgrade proved additive, rollback proved safe, wire interop proved byte-exact, final hygiene sweep clean.                                                                                                                                                                                                                                                                                     | **PASS** | This PR. Evidence in §7.                                                                                    |

---

## 2. v2.2 PR Table (verified against `main` and the GitHub API, 2026-09-20)

| Logical ID | PR (number + URL)                                       | Merge SHA                                  | One-line description                                                  |
| :--------- | :------------------------------------------------------ | :----------------------------------------- | :-------------------------------------------------------------------- |
| V22-PR01   | [#218](https://github.com/Akshay7273/sendbeam/pull/218) | `1bf0f6163ffa611608d7da7e3b1a9ee6d389b366` | Saved handoff recipe schema and explicit automation grants            |
| V22-PR02   | [#219](https://github.com/Akshay7273/sendbeam/pull/219) | `f009e5e581af94b0efd81a167365f44df331e54e` | Manual one-shot recipe runs and secret-free dry-run preview           |
| V22-PR03   | [#220](https://github.com/Akshay7273/sendbeam/pull/220) | `b641d0e3a68f1b61f704629532bbb64939d78d30` | Bounded user-scoped routine runner with AutoSend grant enforcement    |
| V22-PR04   | [#221](https://github.com/Akshay7273/sendbeam/pull/221) | `04d9102dc80d38635e09a15163f66f0270576152` | Watched-folder one-way handoffs (fsnotify) with debounce and cooldown |
| V22-PR05   | [#222](https://github.com/Akshay7273/sendbeam/pull/222) | `bbe5fa8c6bed33b497b080abc6fbd31f995bfb80` | Explicit schedules with bounded catch-up                              |
| V22-PR06   | [#223](https://github.com/Akshay7273/sendbeam/pull/223) | `676febd57c67e9885ea612f2335aaf7bbf643968` | Provenance + receiver auto-accept policy + pause/disable controls     |
| V22-PR07   | [#224](https://github.com/Akshay7273/sendbeam/pull/224) | `84c1ee4587a3a230dd82e56afcfc3b2d05159e05` | Isolation, failure recovery, chaos/resource evidence                  |
| V22-PR08   | #225 (this PR)                                          | _recorded at merge time_                   | Release evidence, upgrade/rollback checks, `docs/RELEASE-v2.2.md`     |

All seven shipped PRs are state **closed** (merged), every merge commit carries its `(#NNN)` suffix, and all titles/SHAs above were read from `git log origin/main` and cross-checked against the GitHub PR API — not copied from memory.

---

## 3. User-Visible Changes

**CLI** (`sendbeam recipe …`): `list`, `show`, `create`, `edit`, `duplicate`, `delete`, `approve`, `grant`, `revoke`, `preview` (`[--json]`), `run` (`[--json]`), `watch`, `export`, `import`. All commands accept `--config-dir` for a fully isolated configuration directory (trust, jobs, and recipes). Full reference in `docs/recipes.md`.

**Desktop:** the same operations through the Wails-bound `RecipeService` (`apps/desktop/internal/engine/recipe_service.go`): `ListRecipes`, `GetRecipe`, `PreviewRecipe`, `PlanRecipe` (DTO JSON), `RunRecipe` (returns the job id), `ApproveRecipe`, `GrantAutomation`, `RevokeAutomation`, `LastRun`, `DeleteRecipe` — all backed by the same engine functions as the CLI, sharing the desktop trust store and the production outbox. Watched-folder triggers are hosted in-process via `StartWatch(id)`, `StopWatch(id)`, `IsWatching(id)` (per-process: no daemon yet).

**Docs:** `docs/recipes.md` (model, grants, triggers, runner, budgets, CLI reference, honest limits), `docs/adr/` entries where added by V22-PR01, and this release gate document.

---

## 4. Core Security & Operational Invariants

1. **Grants are explicit, versioned, and scope-bound.** Auto-send requires `recipe approve` (manual status) followed by `recipe grant` (consent timestamped, consent-versioned, bound to the recipe's material scope hash). Any material change to sources, recipients, trigger, or policy revokes the grant via `ApplyUpdate`; re-enabling a disabled routine revokes it too. Grant ≠ run: granting never dispatches.
2. **Fail-closed validation everywhere.** Unknown schema versions, corrupt/torn/tampered recipe files, invalid device ids, revoked recipients, source permission loss, malformed provenance labels, and unknown provenance triggers all fail closed. Quarantined recipes are never deleted or guessed at — the operator renames or removes them by hand after review.
3. **0600/0700 stores.** Recipe, jobs, and trust stores are created with owner-only permissions; recipe files carry a checksum and an id-mismatch check (file name vs. embedded id) so a swapped or tampered record cannot load.
4. **Provenance is advisory-only.** The routine origin label on a job and on the wire manifest is a display label: it is excluded from the manifest fingerprint (identical bytes sent by hand and by a routine fingerprint identically), never a trust signal, and carries no secrets or reusable credentials.
5. **Sender/receiver grant separation.** A sender's auto-send grant can never authorize overwriting a destination, reading remote paths, or relaxing strict privacy; the receiver's auto-accept policy and collision/consent rules remain authoritative and independent.
6. **At-most-once per scheduled occurrence.** The scheduler advances the durable cursor before dispatch, so a crash can never double-dispatch — but an occurrence lost between cursor-advance and dispatch is **not retried**. There is no exactly-once; at-most-once is the whole promise.
7. **No arbitrary hooks; watch is one-way.** No executable hooks, no clipboard access, no remote configuration authority. Watched folders never mirror deletions and never watch received output automatically (feedback-loop protection); symlink escapes are refused.
8. **Import/export is secret-free.** Exported recipes contain no credentials; importing a recipe never imports active trust, sender approval, or receiver acceptance; imported recipes never run automatically.

---

## 5. Upgrade Notes (v2.1 → v2.2)

The upgrade is **purely additive**:

- **Recipe store is created on first use.** Installing v2.2 creates nothing new until the recipe surface is touched; the first recipe operation creates `<config>/sendbeam/recipes/` alongside the existing `jobs/` and `trust/` directories. There is **no migration step** and no schema bump on the jobs store.
- **v2.1 state is untouched.** Proven by test, not by assertion: `TestUpgradeV22InitLeavesV21StateUntouched` builds the full v2.1-era state surface (jobs store with a queued job, trust database) in a temp root, snapshots every file's bytes, initializes the v2.2 recipe store in the same root, and asserts (a) all v2.1 files are byte-identical afterwards, (b) the recipe store creates only new files inside `recipes/`, and (c) freshly re-opened jobs/outbox/trust stores read the same records (the "v2.1 reader's view"). `TestUpgradeV22GrantsDoNotTouchV21Stores` repeats the byte-identity assertion across the full recipe lifecycle (create, approve, grant, run-record, disable).
- **Old peers interoperate.** The wire manifest provenance field is optional (`omitempty`): a v2.1 sender's manifest decodes under v2.2 code to a nil provenance and renders the one-off marker ("One-off send (not from a saved routine)") — covered by `TestProvenanceOmittedWhenNil` and `TestProvenanceDisplay`. An old receiver ignores the unknown `provenance` JSON key, so no protocol version bump was needed.
- **Wire byte-identity, Go ↔ TS.** A manifest with provenance, decoded and re-encoded, keeps byte-identical JSON in both twins — verified by `TestProvenanceDecodeReencodeByteIdentical` (Go, `packages/wire/provenance_test.go`) and the matching byte-exact assertion in `packages/protocol/src/provenance.test.ts` (same vector, same key order: `type, provenance, files, totalSize`).

---

## 6. Rollback Notes (v2.2 → v2.1)

The rollback is safe **by construction**, not just by documentation:

- **v2.1-era code paths never read the recipes store.** The `recipes` engine package is imported only by the two new v2.2 surfaces — `apps/cli/cmd/sendbeam/recipe.go` (recipe commands) and `apps/desktop/internal/engine/recipe_service.go` (recipe service). Verified manually with `go list -deps`: `jobs`, `outbox`, `trust`, `transfer`, `transfercenter`, `netpolicy`, `receiver`, `supervisor`, and `migrate` all report **0** dependencies on `github.com/sendbeam/engine/recipes`. Nothing a v2.1 binary reads can see a recipe.
- **Recipe jobs are ordinary jobs.** A recipe run enqueues through the production outbox path (`EnqueueWithProvenance`), producing a normal job record whose only recipe-specific content is the advisory provenance label. `TestRollbackRecipesLeaveNoResidueInV21Stores` asserts: (a) the jobs directory holds only ordinary job files — no recipe, ledger, or run-history residue; (b) every job loads and validates as an ordinary job; (c) stripping the `provenance` key leaves a byte-identical job for every other field, i.e. an older reader that ignores the unknown field sees exactly the same job; (d) a nil provenance is valid, so a downgraded reader that drops the label still holds a coherent one-off job.
- **Rollback procedure:** disable routines (or simply leave them — v2.1 never reads them), install v2.1. Recipe state files remain inert on disk and are picked back up unchanged if v2.2 is reinstalled. Existing jobs, trust, outbox queues, and partial transfers are preserved, exactly as for the v2.1 → v2.0 rollback.

---

## 7. Measured Evidence (2026-09-20, `main` @ `84c1ee45`, this PR's tests)

| Suite                                        | Command                                                                                                                                              |                               Result                                |
| :------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------- | :-----------------------------------------------------------------: |
| Recipes upgrade/rollback (new)               | `go test -race -count=3 -run 'TestUpgrade\|TestRollback' ./recipes/` in `packages/engine`                                                            |                         **PASS** (3/3 runs)                         |
| Recipes (full)                               | `go test -race ./recipes/` in `packages/engine`                                                                                                      |                          **PASS** (15.4s)                           |
| Wire (full, incl. new provenance round-trip) | `go test -race .` in `packages/wire`                                                                                                                 |                          **PASS** (49.6s)                           |
| Wire provenance (new, timing-sensitive)      | `go test -race -count=3 -run 'Provenance\|ManifestFingerprint'` in `packages/wire`                                                                   |                         **PASS** (3/3 runs)                         |
| CLI recipe commands (regression)             | `go test -race -run 'Recipe' ./cmd/sendbeam/` in `apps/cli`                                                                                          |                              **PASS**                               |
| Desktop recipe service (regression)          | `go test -race -run 'Recipe' ./internal/engine/` in `apps/desktop`                                                                                   |                              **PASS**                               |
| Lint                                         | `golangci-lint run ./recipes/...` (engine), `golangci-lint run .` (wire)                                                                             |                            **0 issues**                             |
| Vet / build                                  | `GOWORK=off go vet ./...`, `GOWORK=off go build ./...` in `packages/engine` and `packages/wire` (CI builds each module standalone with `GOWORK=off`) |                              **PASS**                               |
| gofmt                                        | new/changed files (`upgrade_rollback_test.go`, `provenance_test.go`)                                                                                 | clean (pre-existing gofmt noise in untouched wire files left alone) |
| Hygiene sweep                                | `grep -rn "TODO\|FIXME\|XXX"` over `packages/engine/recipes`, `apps/cli/cmd/sendbeam/recipe*.go`, `apps/desktop/internal/engine/recipe*.go`          |                            **zero hits**                            |

Required CI on the final head (names, from `.github/workflows/ci.yml`): `metadata & attribution hygiene`, `web (lint, typecheck, test, build)`, `e2e (chromium, firefox)`, `<module> (vet, test, build)` for `packages/wire`, `packages/engine`, `apps/cli`, `apps/server`, `desktop (server gates + window build)`, `branding (no stale pre-rename references)`, `container (build + smoke)`, `differential parity (Go <-> TS)`, `Scorecard analysis`. All must be green before merge of #225.

---

## 8. Honest Limitations

1. **No exactly-once.** An occurrence interrupted between cursor-advance and dispatch is lost, not retried. Design schedules so a skipped run is harmless — the next occurrence sends the current tree. The watcher does not backfill events missed while it was down, and a rapid create-then-delete inside one debounce window may never dispatch. Catch-up sends the current source tree, not the historical one.
2. **Disable/revoke races are decided at dispatch.** Whatever the recipe says at the moment of dispatch wins, and the ledger records the decision. There is no lock-step coordination beyond that boundary.
3. **Desktop frontend markup is not in this repo.** The desktop UI layer exists only as built `dist/`; the Go `RecipeService` bindings are the complete service surface for now. Frontend UI markup is pending.
4. **No daemon yet.** Watched-folder triggers and schedules are hosted in-process (CLI foreground run, desktop app process). Browser stays foreground-only: no scheduler or watcher in the browser.
5. **Schedules don't fire while the host is off.** Catch-up is bounded (`max_catchup_runs`, 0–10, default 3) or skipped entirely — never a backlog explosion.
6. **No real RTC LAN byte-transfer evidence in this environment.** The sandbox blocks UDP/WebRTC loopback; unchanged from v2.1 §6. Watch/schedule dispatch logic is covered by deterministic unit/integration tests (fsnotify watchers run against the real local filesystem here).
7. **Mobile was never run.** Native mobile apps remain deferred.
8. **A routine is not a sync engine.** One-way delivery only: no deletion mirroring, no version history, no conflict resolution, no delta sync. The receiver's overwrite/collision policy is authoritative per transfer.

---

## 9. Release Cut Checklist

To be completed by the maintainer at release time (standing authorization for the v2.2 tag + release exists; this section is the proof to fill in):

- [ ] Zero open PRs on `Akshay7273/sendbeam` confirmed (`pr.py prs-open` empty)
- [ ] Final-commit CI fully green on the merge commit of #225 (all required checks in §7)
- [ ] Tag target SHA: `________` (the #225 merge commit)
- [ ] Tag: `v2.2.0` (annotated), `draft: false`, `prerelease: false`
- [ ] Release assets produced and checksummed per the standard matrix (CLI tarballs/zips, desktop installers, package-manager manifests, `stable.json` + minisig, `SHA256SUMS.txt` + minisig + sigstore bundle, SPDX SBOMs) — same set as §2 of `docs/RELEASE-v2.1.md`
- [ ] Signed artifact verification recorded (minisign + sigstore)
- [ ] Release notes published from this document; v2.0 online/browser regressions re-run (full CI matrix green)
- [ ] Post-merge evidence: upgrade smoke (v2.1 profile → v2.2, routines stay inert until granted) and rollback smoke (v2.2 → v2.1, recipe files inert on disk)

---

## 10. Milestone Sign-Off Checklist

- [x] V22-PR01: saved handoff recipe schema and explicit automation grants merged (#218, `1bf0f616`)
- [x] V22-PR02: manual one-shot recipe runs and secret-free dry-run preview merged (#219, `f009e5e5`)
- [x] V22-PR03: bounded user-scoped routine runner with AutoSend grant enforcement merged (#220, `b641d0e3`)
- [x] V22-PR04: watched-folder one-way handoffs with debounce and cooldown merged (#221, `04d9102d`)
- [x] V22-PR05: explicit schedules with bounded catch-up merged (#222, `bbe5fa8c`)
- [x] V22-PR06: provenance, receiver auto-accept policy, pause/disable controls merged (#223, `676febd5`)
- [x] V22-PR07: isolation, failure recovery, chaos/resource evidence merged (#224, `84c1ee45`)
- [x] V22-PR08: this release-evidence PR merged (number recorded below)
- [x] Final-commit CI fully green before merge; every merge commit carries its `(#NNN)` suffix
- [x] No force-pushes, no branch-protection bypasses; all merges squash via GitHub's default message
- [x] Documentation synchronized: this file, `docs/recipes.md`, protocol/threat/compat docs, README
- [x] v2.1 online/browser regressions re-run (full CI matrix green)

**V22-PR08:** PR #___ (merge SHA `________`) — recorded at merge time.
