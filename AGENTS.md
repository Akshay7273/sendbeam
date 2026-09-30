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
- Fourteen required status checks must pass on the exact final commit (see
  `docs/supply-chain.md` §8 for the live list): the CI suite, the
  cross-language parity gate, the real-network offline evidence job, the docs
  consistency gate, and the always-running distribution aggregate gate (which
  waits for the applicable distribution jobs when a PR touches
  distribution-relevant paths and passes with an explicit _skipped — not
  applicable_ verdict otherwise).
- **Review policy (owner decision, 2026-09-30):** solo-maintainer exception —
  SendBeam has a single maintainer who has granted standing automation
  authorization (open and merge scoped PRs when required checks and repository
  protections pass). Independent human review is not enforced or claimed;
  agent self-review is **never** represented as independent approval.
  Assurance comes from required checks, the hard binding/verification gates in
  the release pipeline, and honest evidence ledgers.

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
