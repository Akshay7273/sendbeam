# SendBeam Recipes — Saved Handoff Workflows

Recipes are **saved, reviewable handoff workflows**: a name, explicit local
source roots, fixed trusted recipients, a network/privacy policy, file
filters, an expiry, and resource budgets. This document covers the V22-PR02
one-shot workflow: save a recipe, dry-run preview it, and run it explicitly.
No daemon, watcher, or scheduler is involved yet — a recipe is useful with
nothing running in the background.

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
  person running it is the authorization. Sender auto-dispatch (a future
  runner feature) needs an explicit `AutoSend` grant, recorded and
  invalidated by material scope changes. Receiver acceptance lives on the
  receiver side in its trust policy. None of the three implies another.

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
sendbeam recipe preview <id> [--json]
sendbeam recipe run <id> [--json]
sendbeam recipe export <id> [--out FILE]
sendbeam recipe import <file>
```

All commands accept `--config-dir` for a fully isolated configuration
directory (trust, jobs, and recipes).

## Desktop

The desktop app exposes the same operations through the Wails-bound
`RecipeService` (`apps/desktop/internal/engine/recipe_service.go`):
`ListRecipes`, `GetRecipe`, `PreviewRecipe`, `PlanRecipe` (DTO JSON),
`RunRecipe` (returns the job id), `ApproveRecipe`, `DeleteRecipe` — all
backed by the same engine functions as the CLI, sharing the desktop trust
store and the production outbox. Frontend UI markup is pending: this repo
carries no TypeScript source for the desktop frontend (only the built
`dist/`), so the bindings are the complete service surface for now.

## Limitations (V22-PR02 scope)

- **No daemon, watcher, or scheduler.** Recipes run only when you run
  them. Watch-folder handoffs and schedules arrive in V22-PR04/PR05; the
  `watch`/`schedule` trigger parameters are reserved and rejected
  until then.
- **No auto-dispatch yet.** The grant model exists and is enforced
  (material changes revoke consent), but no runner consumes `AutoSend`
  until V22-PR03.
- **Desktop UI pending.** The service bindings are done; the visual
  composer ships when the frontend source does.
- Preview is an estimate, not a lock: re-resolution at run time is
  deliberate, so always re-preview after changing sources if the exact
  file set matters.
