# SendBeam — Contributor & Coding-Agent Guide

This is the repository-visible contract for human contributors and coding
agents. It mirrors what CI and the branch ruleset actually enforce
(`.github/workflows/ci.yml`, the `main-protection` ruleset) — where an external
instruction (e.g. an out-of-repo planning contract) disagrees with this file,
**this file and CI win**.

## PR title conventions (CI-enforced)

The `metadata & attribution hygiene` check validates every PR title:

- **Conventional Commits format is required:** `type(scope): description`
  (e.g. `fix(cli): bind sends to authenticated peers`, `feat(web): ...`,
  `docs: ...`, `chore(deps): ...`).
- **Internal planning tags are rejected:** titles must NOT contain logical
  milestone IDs like `V19-PR07` or `V221-PR01`. Put logical IDs in the PR body
  (and the finding/ledger section) instead.
- **Manual `(#N)` suffixes are rejected:** GitHub appends ` (#NNN)` automatically
  on squash merge; do not add it yourself.
- **Attribution is enforced:** no AI co-authorship tags (`Co-Authored-By: ...`
  for bots/agents), no auto-generated bot footers.

## Merge process (ruleset-enforced)

- All changes land via **squash-merge PRs** against `main`; linear history is
  required; force-pushes and deletions are blocked.
- Ten required status checks must pass on the exact final commit (see
  `docs/supply-chain.md` §8 for the live list). Additional jobs
  (`differential parity`, path-filtered `distribution/*` jobs) run as evidence
  but are **not** merge gates today.
- `required_approving_review_count` is currently **0** — independent review is a
  contract expectation, not an enforced gate. Owner decision pending; do not
  represent a self-merge as independently reviewed.

## Working rules for agents

1. Read the current docs first; revalidate baselines before editing — the
   repository evolves and stale observations must not be re-certified.
2. **One logical PR at a time.** No unrelated refactors, dependency upgrades,
   protocol changes, or silent scope expansion.
3. Trace the **production path** (real command/UI → real service → real
   artifact). Helpers, mocks, and enqueued-but-never-dispatched work are not
   delivery proof.
4. Write production-path regressions and negative/failure tests; missing tools,
   hardware, network, or approval means **BLOCKED** — never PASS.
5. Never fabricate PR/CI/review/artifact URLs or evidence; record what was
   actually observed, with SHAs.
6. Opening PRs, merging, tagging, publishing releases, and security disclosure
   follow the owner's standing authorization; destructive operations and
   release publication always require explicit owner approval.
7. Security invariants: no custom crypto, no authentication/privacy downgrades,
   no secrets in logs/UI/diagnostics, local-only policy must govern actual
   egress. See [docs/threat-model.md](docs/threat-model.md) before touching
   anything security-adjacent.

## Local vs CI

`just test` / `just lint` are fast local loops (no `-race`; vet runs even
without golangci-lint). CI runs race-enabled Go tests, differential parity, and
the full e2e matrix. Use `just ci-test` for CI parity before pushing.
