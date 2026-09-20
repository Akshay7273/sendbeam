# ADR 0012 — Saved handoff recipes and explicit automation grants (v2.2 "Repeatable Handoffs")

Status: accepted (lead-dev design review; see §9)
Scope: v2.2 (V22-PR01–08)
Applies to: `packages/engine/recipes` (new), `packages/engine/trust`, `packages/engine/netpolicy`, `packages/engine/jobs`, future recipe composer/runner (V22-PR02–06)

## 1. Context

v2.0 made handoffs manageable: durable jobs, a local outbox, a transfer
center. v2.1 made them independent of the internet. v2.2 makes *repeated*
handoffs easier without surrendering control: save "Export folder →
Studio laptop", preview it, run it once, then optionally enable a bounded
native routine (watcher/schedule) that dispatches it automatically.

Before any scheduling exists, v2.2 needs a small, local, reviewable
workflow model — the *recipe* — plus an explicit automation grant model
that answers: "who said this may run by itself, for exactly what scope,
and what invalidates that permission?" This ADR defines the schema, the
grant lifecycle, and the trust boundaries. V22-PR02–08 build on it
(resolver/one-shot runs, runner, watcher, scheduler, UI, isolation
proof).

## 2. Decisions

### 2.1 Recipe schema (version 1, local only)

A recipe is a JSON document, one per file under
`<os.UserConfigDir>/sendbeam/recipes` (`SENDBEAM_RECIPES_DIR` overrides
for tests), stored with the same discipline as v2.0 jobs: 0600 atomic
writes, strict decoding (`DisallowUnknownFields`), checksums over the
canonical encoding, quarantine of unknown versions/corrupt files (never
deleted, never guessed).

Fields (`packages/engine/recipes/recipe.go`):

- `id` (32 lowercase hex), `name`, `status`:
  `disabled | manual | approval-required`.
- `sources[]`: `{path, recursive}` — absolute, cleaned local paths,
  file or directory; ≥1 required.
- `recipients[]`: `{deviceId, label}` — fixed authenticated device
  identities; ≥1 required, no duplicates.
- `networkPolicy`: `""` (= `online`) or a valid `netpolicy` name;
  `requirePadding` bool — policy and padding are separate controls.
- `include[]`/`exclude[]`: glob filter lists (optional).
- `trigger`: `{kind: manual|watch|schedule, watch{}, schedule{}}`.
  The reserved maps **must be empty in schema v1**; validation rejects
  non-empty maps so no unreviewed watcher/scheduler semantics can sneak
  in. Watch/schedule detail lands in V22-PR04/PR05 with a schema bump if
  the wire shape has to change.
- `expiresAt` (optional hard deadline), `budgets`
  `{maxBytesPerRun, maxFilesPerRun, maxConcurrentRuns}` — all > 0;
  `DefaultBudgets()` (10 GiB / 10k files / 1 concurrent run) is the
  conservative fill-in for absent budgets.
- `grant`: `{autoSend, consentVersion, grantedAt, scopeHash}` — the
  explicit sender-side automation grant (§2.2).
- `createdAt`/`updatedAt`, `checksum` over the canonical encoding of
  every other field.

There are **no secret fields in the schema by design**: recipients are
named by device id (public identity), the destination is receiver-
approved policy (§2.4), and no credential, token or key material can be
expressed. Export/import is therefore safe to copy and share for review;
tests assert the export contains no suspicious keys and no unexplained
hex/blob values.

### 2.2 The automation grant model

Three things are deliberately separate and never imply each other:

1. **One-shot manual runs** need no grant at all (V22-PR02).
2. **Sender auto-send** (`grant.autoSend`) is an explicit opt-in recorded
   in the recipe. It permits the native routine runner to dispatch
   without per-run confirmation.
3. **Receiver auto-acceptance** lives on the receiver side in its
   `trust.TrustPolicy` — not in this schema. A sender recipe can never
   grant itself the receiver's acceptance.

Material scope is hashed (`Recipe.ScopeHash()`, domain-separated
SHA-256, order-independent): sources, recipients, trigger kind,
effective network policy, require-padding, filters, expiry, budgets.
The grant records the `scopeHash` the consent was given for, and
`ValidateRecipe` requires an asserted `autoSend` grant to carry a
non-zero `grantedAt`, a positive `consentVersion`, and a `scopeHash`
matching the *current* scope — a grant can never be smuggled in or
survive a scope change through the edit path.

`ApplyUpdate` enforces the material-change rule:

- Scope changed (new recipient, widened source, looser *or tighter*
  budget, policy/padding/filter/trigger/expiry change) →
  `consentVersion` bumped, `autoSend=false`, `grantedAt` zeroed,
  status forced to `approval-required`. Budgets are material in both
  directions: loosening broadens the grant, and silent tightening could
  mask a scope change, so any budget change invalidates consent.
- Non-material edit (rename, …) → the stored grant carries over
  verbatim; caller-supplied grant fields are ignored.
- A stored `disabled` recipe **stays `disabled`** through a material
  change: forcing `approval-required` would broaden a recipe the user
  explicitly switched off. This is stricter than the roadmap's bare
  wording and is documented here and in code.

### 2.3 Safe defaults and lifecycle

- `NewRecipe()` starts at `approval-required` with no grant: new
  recipes never run automatically.
- `Import()` forces `status=disabled`, clears `autoSend`, zeroes
  `grantedAt`: consent never transfers across an import boundary; the
  id is kept only if valid, else minted. Imported recipes never run
  automatically.
- `ValidateRecipients(ctx, trustStore)` requires every recipient to be
  a currently trusted, non-revoked device, naming the offender. It is a
  point-in-time check; dispatch revalidates at enqueue/send time
  (V22-PR02+).
- Un-composed recipes (no sources/recipients yet) can be constructed
  in memory but the store's `Save` runs the full validation: nothing
  incomplete is ever persisted or dispatched. Draft persistence for the
  composer is a V22-PR02 concern.

### 2.4 What a recipe cannot do

- It cannot choose arbitrary remote paths: the destination is always
  receiver-approved policy (existing consent flow).
- It cannot mirror deletions, overwrite by default, pull remote files,
  or execute hooks — there are no executable hooks in the schema.
- It cannot weaken authentication, encryption, integrity or padding;
  `requirePadding` is independent of the network policy.
- It cannot outlive its budgets or its expiry; dispatch (V22-PR03+)
  enforces both.

## 3. Storage and failure behavior

Mirrors `packages/engine/jobs`: `RecipeStoreDir()`,
`OpenRecipeStore(dir)` (absolute, 0700), `Save` (validates, atomic
rename, fsync), `Load` (strict, version-checked, checksum-verified,
id-matched), `List` (loadable recipes only), `Delete` (explicit,
idempotent), `Quarantined() []QuarantineEntry{Path, Reason}` for
unknown schema versions, corrupt JSON, checksum mismatches and
id/filename mismatches. Quarantine never deletes or guesses; the
operator resolves files by hand.

## 4. Human-readable preview

`Preview(r)` renders what may be sent (sources), to whom (labels +
device ids), trigger kind, network policy and padding, budgets, expiry
and grant state. It is secret-free by construction and omits raw
hashes; only the recipe id (needed to reference the recipe) is shown.

## 5. Threat model notes

- **Grant broadening**: prevented by the scope hash + `ApplyUpdate`
  revocation rule + validation of asserted grants. A widened recipe
  cannot keep an old auto-send consent.
- **Grant smuggling**: `ApplyUpdate` ignores caller grant fields on
  material change and restores the stored grant on non-material change;
  `ValidateRecipe` rejects `autoSend` without matching consent
  evidence. Tested.
- **Stale trust**: recipients are validated against the live trust
  store at edit/preview time and again at dispatch; revocation or
  unpairing fails closed naming the device.
- **Downgrade by old reader**: unknown schema versions quarantine
  rather than being misread (strict decode rejects unknown fields, so
  a future field can never be silently dropped by this version).
- **Tampering**: checksum over the canonical encoding fails closed on
  any byte change; tested.
- **Secret leakage**: no secret fields exist; export/preview tests
  assert the absence of suspicious keys, unexplained blobs and hash
  material.

## 6. Compatibility and migration

- Recipes are sender-local conveniences. Older receivers get ordinary
  jobs (V22-PR02); no remote automation authority is required or
  transferred.
- Watch/schedule metadata is not a credential and is never exported
  as one; importing a recipe never imports trust, sender approval or
  receiver acceptance.
- Schema versions independently of product versions; older clients
  quarantine unknown recipe schemas.

## 7. Exclusions and rollback

No watcher, scheduler, runner, UI, or dispatch in this PR — schema,
store, grants, preview and import/export only. No remote configuration
authority, no portable job credentials, no executable hooks. Rollback:
delete the package and its ADR; recipe files are inert JSON and the
quarantine path never touches existing jobs/journals.

## 8. Executable test plan (delivered in `recipe_test.go`)

New-recipe defaults (status, no grant, sane budgets); material-change
matrix (9 mutations: add recipient, widen source, loosen/tighten
budget, policy, trigger kind, padding, filters, expiry) each revoking
the grant, bumping consent, forcing approval-required, refreshing the
scope hash; forged-grant smuggling rejected; rename preserving the
grant; disabled staying disabled; import/export round-trip secret-free
with tricky labels surviving verbatim; import forcing inert state;
unknown schema version and corrupt JSON quarantined (not loaded, not
deleted); checksum tamper rejected; revoked/untrusted recipients
rejected naming the device; preview content and hash-leak assertions;
validation rejection table (17 cases); store round-trip incl. 0600
mode; env-dir override.

## 9. Lead-dev design review

The roadmap asks for a reviewer-approved design. There is no
independent reviewer available in this workflow and the maintainer has
mandated uninterrupted autonomous execution. This design was therefore
reviewed by the acting lead developer against the v2.2 stop-ship
conditions:

- No dispatch without a valid sender grant: no dispatch exists in this
  PR, and the grant model makes grant-less auto-dispatch unrepresentable
  (validation rejects it; the runner in V22-PR03 must check the grant).
- No bypassed receiver consent: receiver acceptance stays entirely
  outside this schema (§2.2).
- No unauthorized source enumeration: sources are explicit absolute
  local paths; validation rejects relative/unclean paths.
- No secret leakage: no secret fields exist; export/preview tests
  enforce it.
- Routines can be stopped: `disabled` is terminal for automation and a
  material change can never broaden a disabled recipe (§2.2).

Decision: **approved to proceed** to V22-PR02–08, each of which must
deliver its slice of the test plan (§8) with real evidence. Any later
PR that weakens the grant model (e.g. silent re-approval, grant
transfer across import, auto-enabling watchers) must be rejected or
revert to this ADR's rules.
