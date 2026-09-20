# SendBeam Recipes — Saved Handoff Workflows

Recipes are **saved, reviewable handoff workflows**: a name, explicit local
source roots, fixed trusted recipients, a network/privacy policy, file
filters, an expiry, and resource budgets. This document covers the V22-PR02
one-shot workflow (save, preview, run explicitly) and the V22-PR03 native
routine runner (bounded, user-scoped automatic dispatch behind an explicit
auto-send grant).

## What a recipe is

- **One-way delivery.** A recipe describes "send these local files to these
  devices". It never mirrors deletions, never overwrites on the receiver by
  sender authority, and never pulls remote files. The destination on each
  recipient is the receiver's own approved policy — the recipe names the
  device, never a remote path.
- **Local and secret-free.** Recipes live in
  `<config>/sendbeam/recipes` (one JSON file each, `SENDBEAM_RECIPES_DIR`
  overrides). The schema holds no key material, credentials, or reusable
  secrets — exports are safe to copy, back up, or share for review.
- **Three separate permissions.** A one-shot manual run needs no grant; the
  person running it is the authorization. Sender auto-dispatch needs an
  explicit `AutoSend` grant, recorded and invalidated by material scope
  changes. Receiver acceptance lives on the receiver side in its trust
  policy. None of the three implies another.

## The auto-send grant lifecycle

Automatic dispatch is opt-in twice over: the recipe must be approved for
runs (`manual` status) **and** carry a valid auto-send grant.

```sh
# Grant auto-send consent for the routine runner. You, at the keyboard,
# are the authorization. This never runs anything: grant != run.
sendbeam recipe grant <id>

# Withdraw it again. Status is unchanged; manual runs keep working.
sendbeam recipe revoke <id>
```

A grant is valid only while **all** of these hold: `AutoSend` is on, the
consent is timestamped (`GrantedAt`) and versioned (`ConsentVersion > 0`),
and the stored scope hash matches the recipe's current material scope.
**Material changes revoke automation consent.** Editing sources,
recipients, trigger, network policy, padding, filters, expiry, or budgets
bumps the consent version, clears the grant, and forces the recipe back to
`approval-required` (a `disabled` recipe stays disabled). The only fix is
an explicit re-grant — consent is never re-inferred, and imported recipes
never carry a grant.

`sendbeam recipe show <id>` displays the grant state (on/off, granted at,
whether the scope hash still matches) and the last-run ledger entry.

## Trigger reasons

Every dispatch attempt records what started it:

| Reason     | Meaning                                                                       |
| ---------- | ----------------------------------------------------------------------------- |
| `manual`   | The human at the keyboard (CLI `run`, desktop Run now). Never needs a grant.  |
| `watch`    | A watched-folder trigger fired (V22-PR04). Needs a valid grant.               |
| `schedule` | A scheduled occurrence fired (V22-PR05). Needs a valid grant.                 |
| `retry`    | Re-attempt of a previously refused/failed automated run. Needs a valid grant. |

Disabled recipes refuse **every** trigger reason, including manual.
Approval-required recipes refuse automated reasons until re-approved (and
re-granted, if a material change revoked the grant).

## The routine runner (V22-PR03)

The routine runner is the small, in-process, **user-scoped** host for
automated triggers: it only ever acts on the local user's own recipes, has
no remote authority, and dispatches through the same enqueue seam as manual
runs — every dispatch becomes one ordinary outbox job. No second queue, no
privileged service, no network administration API.

**Bounds:**

- At most `MaxConcurrent` dispatches in flight (default 1, hard cap 4).
  Overload is refused immediately with a clear busy signal — the runner
  never queues unbounded work and never spawns unbounded goroutines.
- Per-recipe deduplication: a second dispatch for a recipe that already
  has one in flight is skipped deterministically ("already running,
  skipped"), not run twice and not reported as a failure.
- `Stop()` refuses new dispatches; dispatches already in flight run to
  completion. Dispatch honors context cancellation: a canceled context
  aborts the attempt and is recorded as a failure.
- Every gate from the manual path is re-checked at dispatch: status,
  expiry, recipient trust, fresh resolution, budgets. A recipe whose
  recipient was revoked, whose budget would be exceeded, or whose grant
  lapsed is refused — never silently.

**Last-run ledger.** Every dispatch attempt — dispatched, refused, failed,
or skipped — writes a `lastRun` entry onto the recipe record (durable,
checksummed, in the 0600 store): when it happened, the trigger reason, the
job id if one was enqueued, the outcome, and a short detail. Nothing is
ever silent, and the routine-management UI (V22-PR06) reads this ledger for
recent decisions. `sendbeam recipe show <id>` prints it.

Watch trigger sources arrived in V22-PR04 (below) and schedule sources in
V22-PR05 (below).

## Watched-folder triggers (V22-PR04)

A recipe with trigger kind `watch` turns explicitly selected new/changed
files into ordinary one-way delivery jobs. This is **not sync**: it never
mirrors deletions, never overwrites on the receiver by sender authority,
and never watches received output — source deletion never deletes remote
files.

**How it works.** A `Watcher` (native OS events via `fsnotify`)
observes the recipe's own sources — nothing else. On create/write/rename/
chmod inside the watched scope it re-arms a **debounce** timer; when the
window goes quiet it asks the routine runner for one `watch` dispatch —
unless the **cooldown** window since the last attempt has not elapsed, in
which case the burst is skipped (flap protection). The watcher **never
sends files and never reads file contents**; each dispatch re-loads the
recipe, re-validates the grant, status, expiry, recipient trust, and
budgets, re-resolves the sources fresh (with symlink-escape protection),
and enqueues exactly one ordinary outbox job.

**Trigger parameters** (`trigger.watch` in the recipe JSON; shown by
`sendbeam recipe show`):

| Parameter     | Default | Range       | Meaning                                                  |
| ------------- | ------- | ----------- | -------------------------------------------------------- |
| `debounce_ms` | 2000    | 250 – 60000 | Quiet window after the last fs event before dispatching. |
| `cooldown_ms` | 10000   | 0 – 3600000 | Minimum interval between two dispatches of the recipe.   |
| `recursive`   | true    | —           | Watch subdirectories of source roots.                    |

Parameters must be JSON numbers/booleans; unknown keys are rejected
fail-closed. Watch configuration is **material scope**: changing any of
these revokes the auto-send grant through the normal material-change rule
(consent version bumped, status back to `approval-required`).

**What triggers a run — and what doesn't:**

- In-scope create/write/rename/chmod events trigger (after debounce).
  Rename counts as a create of the new name; editor save bursts coalesce
  into one dispatch.
- Remove events are ignored — the resolver runs fresh at dispatch anyway.
- Events for paths the resolver would exclude (include/exclude filters)
  never arm the timer; neither do events outside the watched roots.
- Symlink escapes are ignored: a path resolving outside its source root
  can never arm the timer, and the resolver independently skips such
  files at dispatch. Symlinked directories are never watched.
- The watch-level `recursive` flag governs **detection** scope only; each
  source's own `Recursive` flag still governs what a dispatch **sends**.
  (A subdir change with a non-recursive source can trigger a dispatch
  whose plan holds only top-level files — wasteful but never wrong.)
- The debounce window is also the stability mechanism: a file still being
  written keeps generating events, so the quiet window only starts once
  writes settle. Stability is not proven — a file changed between resolve
  and read fails or defers at the transfer layer, never as a falsely
  verified delivery.

**Grant requirement.** A watch without a grant never starts:
`Start` fails fast when the recipe is disabled, still approval-required,
or lacks a valid auto-send grant. Revoking the grant (or a material
change) mid-watch makes the next debounced dispatch refuse, recorded in
the last-run ledger.

**Foreground vs desktop-hosted.** `sendbeam recipe watch <id>` runs the
watcher in the foreground until Ctrl+C and prints what it sees
(`change detected in <root>, waiting for quiet…`, `dispatching…`,
`dispatched job <id>`, refusal reasons). The desktop hosts watchers
in-process via `RecipeService.StartWatch` / `StopWatch` / `IsWatching` —
per-process by design: watches live only as long as the desktop process
does. There is no daemon yet (packaging is V22-PR08 scope); the CLI
foreground command covers headless use.

**Limitations:**

- No cross-device watching: only local paths the user composed into the
  recipe are observed.
- No missed-event reconciliation scan yet: events missed while the
  watcher is down (process not running, OS event overflow) do not
  backfill — the next observed change dispatches the then-current tree.
- No guaranteed capture of every historical version: rapid
  create-then-delete inside one debounce window may never dispatch.
- Watcher permission errors surface explicitly instead of watching
  nothing silently.

## Scheduled triggers (V22-PR05)

A recipe with trigger kind `schedule` fires on **explicit daily, hourly,
or interval schedules** — no cron. Schedules are wall-clock schedules in
a named IANA timezone, stored as a JSON parameter object on the trigger:

```sh
# daily at 14:30 in Calcutta
sendbeam recipe create --name "Daily exports" \
  --source ~/exports --to @studio-laptop \
  --trigger schedule \
  --schedule-params '{"kind":"daily","at":"14:30","tz":"Asia/Calcutta"}'

# hourly at minute 15, UTC (the default timezone)
sendbeam recipe edit <id> --trigger schedule \
  --schedule-params '{"kind":"hourly","minute":15}'

# every 30 minutes, 09:00–17:00 only, at most 2 catch-up runs
sendbeam recipe edit <id> \
  --schedule-params '{"kind":"interval","every_minutes":30,"not_before":"09:00","not_after":"17:00","max_catchup_runs":2}'
```

The three shapes:

| kind       | parameters                               |
| ---------- | ---------------------------------------- |
| `daily`    | `at` (required, `HH:MM`), `tz`           |
| `hourly`   | `minute` (required, 0–59), `tz`          |
| `interval` | `every_minutes` (required, 1–1440), `tz` |

`tz` is any IANA name (`Asia/Calcutta`, `America/New_York`, …) and
defaults to `UTC`. Daily and hourly occurrences are wall-clock times in
that zone; interval occurrences are anchored to the Unix epoch (an
`every_minutes: 30` schedule always fires on `:00` and `:30`).
`not_before`/`not_after` (`HH:MM`, both optional) restrict firing to a
daily window; `max_catchup_runs` (0–10, default 3) bounds catch-up (see
below). Parameters are validated strictly — unknown keys, wrong types,
fractional numbers, out-of-range values, and unknown timezones are all
rejected, and schedule params on a non-schedule trigger (or vice versa)
are an error.

**Timezone and DST.** Daily/hourly occurrences follow wall-clock time in
the schedule's timezone. Daylight-saving transitions follow Go's `time`
package semantics: a wall time that does not exist (spring-forward gap)
is interpreted with the pre-transition offset, so the occurrence still
fires exactly once and the schedule does not drift; an ambiguous wall
time (fall-back) takes the first occurrence. Interval schedules are
absolute (UTC-anchored) and unaffected by DST.

**Durable cursor and bounded catch-up.** Every schedule-triggered recipe
carries a durable idempotency cursor (`scheduleCursor`) in its stored
record. The cursor adopts the current time on the first scheduler tick
and advances **before** each dispatch, so a crash, restart, or rapid
re-tick can never double-dispatch an occurrence. When the scheduler was
down, the next tick finds missed occurrences and replays them
**sequentially, at most `max_catchup_runs`** (0 = skip them all and
resume) — never a backlog stampede: five missed intervals with
`max_catchup_runs: 2` dispatch exactly two, and the cursor advances past
all five. Occurrences outside the `not_before`/`not_after` window are
skipped, never dispatched. Every catch-up pass writes a plain-language
summary into the last-run ledger (e.g.
`caught up 2 of 5 missed run(s); 3 skipped by cap`).

**Grants and status.** Schedule dispatch needs a valid auto-send grant,
exactly like watch dispatches: no grant (or a revoked/expired one) makes
due occurrences refuse with the reason recorded in the last-run ledger.
Schedule parameters are part of the material scope, so changing them
revokes the grant and drops the recipe back to approval-required.
Disabled recipes are never hosted and never dispatch.

**Foreground vs desktop-hosted.** `sendbeam recipe scheduler` runs the
scheduler in the foreground until Ctrl+C and prints what it does
(`due:`, `dispatching:`, `dispatched:`, `refused:`, `skipped:`,
`catch-up:` lines); the stop is clean and the exit code is 0. The
desktop hosts the scheduler in-process via
`RecipeService.StartScheduler` / `StopScheduler` / `SchedulerRunning` —
per-process by design: schedules live only as long as the desktop
process does. There is no daemon yet (packaging is V22-PR08 scope); the
CLI foreground command covers headless use. `recipe show` prints the
human schedule, the next run, and the cursor.

**Limitations:**

- No second-granularity schedules: the finest interval is one minute.
- The scheduler rescans the store every minute; a recipe created while
  the scheduler runs is picked up on the next rescan, not instantly.
- Catch-up runs the missed occurrences back-to-back, not at their
  original times — each dispatch still resolves the _current_ source
  tree, so a catch-up sends what is there now.
- `max_catchup_runs` caps at 10; a longer outage simply resumes the
  schedule after the cap, discarding the rest of the backlog.

## The one-shot workflow

```sh
# 1. Compose a recipe. New recipes start "approval-required".
sendbeam recipe create --name "Nightly exports" \
  --source ~/exports --to @studio-laptop \
  --network-policy prefer-local --include '*.mp4'

# 2. Dry-run preview: resolves the CURRENT file set. Sends nothing.
sendbeam recipe preview <id>

# 3. Approve it (you, at the keyboard, are the approval).
sendbeam recipe approve <id>

# 4. Run it explicitly: enqueues ONE ordinary outbox job.
sendbeam recipe run <id>

# 5. Send it like any outbox job.
sendbeam outbox dispatch
```

## Dry-run vs run

**Preview is always a dry-run.** It resolves sources, filters, and budgets
into a concrete file plan — paths, sizes, SHA-256 digests, recipients,
warnings — and never creates jobs, never touches the job store, and never
causes remote effects. The plan DTO is explicitly marked
`"status": "dry-run"`.

**Run re-resolves everything.** A preview never locks file content: files
added or changed between preview and run change what the run sends. Run
also revalidates recipient trust (a device revoked after the preview fails
the run, naming the device), the recipe status, expiry, and budgets —
against the fresh resolution, not the preview.

## The approval model

| Status              | Meaning                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------ |
| `approval-required` | Default for new, imported, and materially changed recipes. Nothing runs until a person approves. |
| `manual`            | Approved for explicit one-shot runs. Never runs on its own.                                      |
| `disabled`          | Never runs, manually or automatically.                                                           |

Approving is one explicit command: `sendbeam recipe approve <id>`. It
grants **manual runs only** — never auto-dispatch.

**Material changes revoke automation consent.** Editing sources,
recipients, trigger, network policy, padding, filters, expiry, or budgets
bumps the consent version, clears any auto-send grant, and forces the
recipe back to `approval-required` (a `disabled` recipe stays disabled).
Non-material edits like renames keep the stored grant untouched.

Imported recipes always start `disabled` with no grant: consent never
transfers across an import.

## Budgets

Every recipe caps what one run may consume — default 10 GiB and 10,000
files per run, one concurrent run. A run that would exceed a budget fails
with a clear error naming the exceeded budget, before anything is
enqueued. Budgets are material scope: loosening one invalidates prior
automation consent.

## Source resolution rules

- A source is an absolute local path: a file becomes one entry, a
  directory is walked. `--recursive=false` reads only a directory's top
  level.
- `--include` globs are an allow-list; `--exclude` globs remove matches.
  Globs follow `path/filepath.Match` against the path **relative to the
  source root** (`*.log` matches only top-level logs). There is no `**`
  support — a pattern containing `**` is rejected rather than
  half-interpreted.
- **Symlink escape protection:** every candidate is resolved and must stay
  within its source root. Escapes are skipped with a recorded warning;
  they are never read. Unreadable files are hard errors naming the path —
  a plan never silently drops data.
- Directories never become plan entries; files sort by path so plans are
  deterministic.

## Machine-readable plan output

`sendbeam recipe preview <id> --json` emits the versioned plan DTO
(`"version": 1`): recipe id/name, dry-run status, files (path, size,
SHA-256 digest), total bytes, recipients (device id, label), network
policy, padding flag, warnings, and resolution timestamp. The contract is
**additive changes only** and secret-free by construction — there are no
secret fields anywhere in the recipe domain.

## CLI reference

```sh
sendbeam recipe list [--json]
sendbeam recipe show <id> [--json]
sendbeam recipe create --name NAME --source PATH [--source ...] --to DEVICE [--to ...]
  [--label LBL] [--network-policy online|prefer-local|local-only] [--padding]
  [--include GLOB] [--exclude GLOB] [--budget-bytes N] [--budget-files N]
  [--recursive=true|false]
sendbeam recipe edit <id> [--name NAME] [--add-source PATH] [--remove-source PATH]
  [--add-recipient DEVICE] [--remove-recipient DEVICE] [--network-policy ...]
  [--padding|--no-padding] [--budget-bytes N] [--budget-files N]
sendbeam recipe duplicate <id> --name NEW
sendbeam recipe delete <id>
sendbeam recipe approve <id>
sendbeam recipe grant <id>
sendbeam recipe revoke <id>
sendbeam recipe preview <id> [--json]
sendbeam recipe run <id> [--json]
sendbeam recipe watch <id>
sendbeam recipe export <id> [--out FILE]
sendbeam recipe import <file>
```

All commands accept `--config-dir` for a fully isolated configuration
directory (trust, jobs, and recipes).

## Desktop

The desktop app exposes the same operations through the Wails-bound
`RecipeService` (`apps/desktop/internal/engine/recipe_service.go`):
`ListRecipes`, `GetRecipe`, `PreviewRecipe`, `PlanRecipe` (DTO JSON),
`RunRecipe` (returns the job id), `ApproveRecipe`, `GrantAutomation`,
`RevokeAutomation`, `LastRun`, `DeleteRecipe` — all
backed by the same engine functions as the CLI, sharing the desktop trust
store and the production outbox. Watched-folder triggers are hosted
in-process via `StartWatch(id)`, `StopWatch(id)`, `IsWatching(id)`
(per-process: no daemon yet). The `Recipe` DTO carries the automation
grant and the last-run ledger entry. Frontend UI markup is pending: this repo
carries no TypeScript source for the desktop frontend (only the built
`dist/`), so the bindings are the complete service surface for now.

## Limitations (V22-PR04 scope)

- **No scheduler yet.** The runner API accepts the `schedule` trigger
  reason and enforces its grant, but schedule trigger sources arrive in
  V22-PR05; the `schedule` trigger parameters are reserved and rejected
  until then.
- **No daemon.** Watchers are per-process: the CLI foreground command
  and the desktop-hosted watchers both end when their process ends.
  Missed events while down do not backfill.
- **Auto-dispatch needs an explicit grant.** Nothing runs automatically
  without `sendbeam recipe grant <id>` (or the desktop equivalent), and
  any material change revokes it.
- **Desktop UI pending.** The service bindings are done; the visual
  composer ships when the frontend source does.
- Preview is an estimate, not a lock: re-resolution at run time is
  deliberate, so always re-preview after changing sources if the exact
  file set matters.

## Routine controls (V22-PR06)

### Provenance: where a transfer came from

Every recipe dispatch stamps the transfer with an **origin label**
— provenance — carrying the recipe's id and name, this device's label,
and the trigger reason (`manual`, `watch`, `schedule`, or `retry`).
The receiver's consent surface always shows it:

```sh
# recipe dispatch:
Routine: Nightly exports (trigger: watch) from akshay-laptop

# ordinary one-off send — an explicit marker, never a blank:
One-off send (not from a saved routine)
```

**Provenance is an advisory display label, not authentication.**
It says where the sender _claims_ the transfer came from; trust still
comes from the pairing/trust store, never from this label. The routine
id is 32 lowercase hex; labels are capped at 256 characters; a
malformed provenance fails the transfer closed at manifest decode.

**Provenance is excluded from the manifest fingerprint.** The
fingerprint binds the _file set_, so the same bytes sent by a different
routine — or by hand, with no provenance at all — fingerprint
identically. Resume journals keep working unchanged across recipes.

**Old receivers are unaffected.** The provenance field is optional on
the wire; a receiver that predates this release decodes the manifest
fine and simply never displays the label or enforces the policy below.
One-off sends (`sendbeam send`, `outbox enqueue`) carry no provenance,
exactly as before.

### Disable and enable

```sh
sendbeam recipe disable <id>   # switch the routine off, for every trigger
sendbeam recipe enable <id>    # back to approval-required (see below)
```

- `disable` sets the status to `disabled`. Every future dispatch —
  manual, watch, schedule, and retry — is refused. The existing
  automation grant is left in place but inert: disabling is "switched
  off", not "consent withdrawn", and the audit trail can tell the two
  apart. A dispatch already admitted (a job already enqueued) runs to
  completion; disable never cancels in-flight work — cancel the job
  explicitly with `sendbeam outbox cancel <full-job-id>`.
- `enable` returns the routine to `approval-required` **and revokes its
  automation consent**. Nothing dispatches until a person re-reviews:
  `recipe approve <id>` first (manual runs), then a fresh
  `recipe grant <id>` (automation). There is no silent re-arm.

### Last-run budget visibility

`sendbeam recipe show <id>` prints what the last dispatch actually
queued against the per-run budget, with the full job id and the exact
cancel command:

```sh
Last run sent 1.4 GiB of 10.0 GiB per-run budget (job 09b6d6df5ed19d46e4714cafe266bb5f).
To stop it: sendbeam outbox cancel 09b6d6df5ed19d46e4714cafe266bb5f
```

### Routine auto-accept (receiver side)

Receivers can skip manual consent for routine transfers — but only
from devices _you_ name. The policy is **off by default** and stays off
until you turn it on:

```sh
sendbeam receive-policy show
sendbeam receive-policy set --enable --allow-device <sender-device-id>
sendbeam receive-policy set --allow-device <id1> --allow-device <id2>  # replace the list
sendbeam receive-policy set --clear-devices
sendbeam receive-policy set --disable
```

- `receive-policy set --enable` also allows routine transfers by
  default (`--allow-routine=false` narrows it without disabling).
- With the policy enabled, a transfer is auto-accepted **only if** it
  carries a valid provenance **and** its sender's device id is on the
  allowlist. A one-off send, a malformed provenance, or a sender not on
  the list all fall back to manual consent.
- Trust and tombstone validation run **first**, always: a revoked or
  unknown sender is refused no matter what the policy says.
- The stored policy is fail-closed: a malformed stored allowlist is
  treated as "no policy", never as permission. The config file is
  written with mode `0600`.
- The CLI's legacy global `--auto-accept` on `sendbeam listen` still
  accepts transfers from trusted devices as before, independent of this
  policy. **Sender consent and receiver acceptance are independent:**
  your auto-send _grant_ (your permission for your device to send)
  never implies the other side's acceptance, and their receive policy
  never implies your grant.

### Limitations

- Provenance labels what the sender sent; it does not prove the
  sender's routine setup, and it must never be treated as a trust
  signal.
- `enable` always re-requires approval _and_ a fresh grant — there is
  no "resume exactly where you were" shortcut after a disable.
- The desktop service methods (`DisableRecipe`, `EnableRecipe`) and the
  consent events carry provenance; the visual consent UI ships with the
  frontend source.

## Failure recovery & isolation (V22-PR07)

Automation amplifies convenience, not mistakes. This section states the
crash and overload contract plainly — including what is **not**
promised.

### At-most-once per scheduled occurrence

The scheduler advances the durable `scheduleCursor` **before** asking
the runner to dispatch. A crash, restart, or rapid re-tick between the
two can never double-dispatch an occurrence: a fresh tick sees the
cursor already past it and does not re-dispatch. The other side of that
trade is stated without hedging: **an occurrence lost in that window is
not retried.** If the process dies after the cursor advanced but before
the dispatch finished, the occurrence is gone — not duplicated, not
re-queued. There is no exactly-once; at-most-once is the whole promise.

### Durable jobs survive the crash

Anything already handed to the outbox is a durable job in the v2.0 job
store. A dispatch that completed before the crash leaves a job that a
restarted process lists and resumes like any other outbox job
(`queued`, carrying the routine provenance) — there is no separate
recovery queue and no second chance needed: the job was already real.

### Disable stops the future, not the in-flight

Disabling a recipe refuses every future dispatch — manual, watch,
schedule, retry — because the runner re-loads the recipe and re-checks
status, grant, scope hash, expiry, trust, sources, and budgets at
**dispatch time**, never from a cached schedule-time decision. A
dispatch already admitted (a job already enqueued) runs to completion;
disable never cancels in-flight work. Likewise `Runner.Stop()` and
`Scheduler.Stop()` refuse new dispatches while admitted ones finish,
and both are goroutine-clean: repeated start/stop cycles return the
process to its baseline goroutine count.

### What the ledger shows after each failure mode

The last-run ledger records only dispatch attempts the runner actually
finished — nothing is invented for attempts that never completed:

| Failure                                                                | Ledger says                                                                                                  |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Gate refusal (disabled, no grant, revoked, expired, over budget, busy) | `refused`, naming the cause                                                                                  |
| Enqueue error or canceled dispatch                                     | `failed`, with the error                                                                                     |
| Duplicate trigger (dispatch already in flight)                         | `skipped`, "already running, skipped"                                                                        |
| Crash **between** cursor-advance and dispatch (true process death)     | **no entry** — the cursor advance is the only durable evidence; the occurrence is consumed, never duplicated |

A graceful interruption (context canceled while a dispatch is blocked)
records `failed: context canceled`, which is the in-process observable
equivalent of the crash window. Watchers killed mid-debounce leave no
phantom entry either: the pending change is dropped, and the next
observed change dispatches once — events missed while a watcher is down
are not backfilled.

### Resource bounds

- **Concurrency:** at most `MaxConcurrent` dispatches in flight
  (default 1, hard cap 4). Overload is refused immediately with
  `ErrRunnerBusy` — the runner never queues unbounded work and never
  spawns a goroutine per attempt.
- **Catch-up:** at most `max_catchup_runs` missed occurrences per tick
  (0–10, default 3), dispatched sequentially. A 30-day outage on an
  every-minute schedule dispatches 3, advances the cursor past all
  ~43200, and says so in the ledger. Catch-up occurrences go through the
  same `Runner.Dispatch` gates as live ones — budgets included: an
  over-budget recipe dispatches nothing under catch-up either.
- **Watch bursts:** filesystem bursts collapse through the debounce
  window (default 2 s) into one dispatch; the cooldown (default 10 s)
  bounds flapping. The watcher keeps no per-file pending queue — it only
  re-arms a timer — so a 50-file burst cannot grow memory without bound,
  misses no files, and lists no file twice.

### Honest limits

- No exactly-once: an occurrence interrupted between cursor-advance and
  dispatch is lost, not retried. Design schedules so a skipped run is
  harmless — the next occurrence sends the current tree.
- The watcher does not backfill events missed while it was down, and a
  rapid create-then-delete inside one debounce window may never
  dispatch. Catch-up sends the current source tree, not the historical
  one.
- Disable/revoke races are decided at dispatch: whatever the recipe
  says at the moment of dispatch wins, and the ledger records the
  decision. There is no lock-step coordination beyond that boundary.
