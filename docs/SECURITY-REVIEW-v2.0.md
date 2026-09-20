# SendBeam v2.0 — Security Review

**Scope:** the v2.0 local transfer workspace (durable jobs, outbox, transfer
center, receive preflight, streaming ZIP64, encrypted text/link handoffs, OS
share entry points, state migrations, onboarding) on top of the v1.9 trusted
handoff stack. This is a focused review of the v2.0 changes against the
standing [threat model](./threat-model.md); it is not an independent
third-party audit.

**Method:** source inspection of the v2.0 diffs, adversarial test review
(attack-matrix suites, fuzz corpus replay, differential Go↔TS runs), and
re-running the security-relevant test suites. Findings below cite the exact
test or control; anything not verified is listed under Limitations.

## 1. Controls verified

### 1.1 No secret exposure in public surfaces

- CLI JSON output uses allowlisted DTOs (`PublicOutcome` /
  `PublicFileOutcome` in `packages/engine/transfer/broadcast.go`); internal
  handshake secrets are never serialized.
  Evidence: `TestBroadcastResult_JSON_NoSecretsExposed`
  (`packages/engine/transfer/broadcast_test.go`).
- Device identity private keys are `json:"-"` (`wire.DeviceIdentity`);
  `identity.key` is 0600 and a corrupt/zero-length file fails closed — it is
  never silently regenerated (`packages/engine/trust/identity_manager.go`).

### 1.2 Trusted targeting binds the selected peer

- Targeted sends resolve the recipient to a trusted device record and bind
  the session to that peer's identity; discovery labels and last-seen
  timestamps are not used as authentication.
- Pairing an ordinary contact never grants admin/revocation authority over
  other devices; revocation denials are kept as evidence separate from
  credential deletion.

### 1.3 Authenticated resume invariants preserved

- Job IDs are scheduler metadata only — they never authorize resume.
  Resume authorization still comes from the cryptographic journals/credentials,
  kept separate from job metadata (`packages/engine/jobs`, `packages/wire`
  journal + `resumeauth.go`).
- Journals and envelopes remain checksummed and versioned; corrupt journals
  fail closed.

### 1.4 Untrusted input handling

- Remote filenames, manifests, and deep-link fields are treated as untrusted:
  literal text rendering, filesystem containment enforced at open/finalization
  (including symlink/junction and race handling from the v2.0 receive
  preflight work), no automatic overwrite, no auto-open, no clipboard
  surveillance/sync, no HTML execution.

### 1.5 Migrations are non-destructive with rollback

- New in v2.0: `packages/engine/migrate` runs ordered state upgrades at
  startup with per-migration backup → apply → verify → commit; any failure
  restores the pre-migration bytes and leaves the old generation marker in
  place. Migrations never delete user state.
- State from a newer generation is quarantined (`ErrNewerState`): older
  binaries refuse to read or modify it instead of truncating it.
  Evidence: `packages/engine/migrate/migrate_test.go` (fresh bootstrap,
  idempotence, quarantine, rollback, v1→v2 trust upgrade, corrupt-store
  fail-closed, future job-schema quarantine).
- Credential migration keeps the write → verify → switch order with the
  recoverable plaintext preserved (renamed to `*.migrated`, zeroized) until
  the protected store verifies read-back.

### 1.6 Update integrity and package-manager ownership

- Update manifests are minisign-verified (pinned Ed25519 key) before any
  URL, version, or hash inside is trusted; strict SemVer downgrade rejection.
  Evidence: `packages/engine/updater` tests including
  `attack_matrix_test.go`, and `scripts/verify-release_test.sh` (now also run
  in CI on every distribution build).
- Installs owned by a package manager (Homebrew, WinGet/Scoop, apt/deb) are
  detected (`DetectPackageManager`) and the self-updater refuses to overwrite
  them, directing the user to the owning manager instead.

### 1.7 Adversarial and differential testing

- Attack-matrix suites: `packages/wire/attack_matrix_test.go`,
  `packages/engine/updater/attack_matrix_test.go`.
- Fuzzing: `docs/fuzzing.md`, corpus replay in CI (`fuzz.yml`), journal
  fuzz tests.
- Go↔TypeScript differential parity: `scripts/run_differential.sh`.
- Release verification: `scripts/verify-release.sh` (SHA-256 manifest +
  minisign + sigstore/cosign bundle), exercised by
  `scripts/verify-release_test.sh` across happy-path and tamper vectors.

## 2. v2.0-specific risk notes

- **Streaming ZIP64** changed archive finalization on the browser and
  durable-receive paths. Boundary fixtures are extracted with independent
  tools (Info-ZIP, Python `zipfile`, Go `archive/zip`) and digests compared;
  rollback restores explicit ZIP32 limits rather than writing invalid
  archives.
- **Outbox/dispatch** never implies exactly-once delivery: the
  receiver-commit/sender-ack crash window is reconciled or reported as
  uncertain, never invented as guaranteed.
- **OS share entry points** prefill a composer only; they grant no permission
  to send or overwrite (single-instance forwarding into the existing consent
  flow).
- **Onboarding** (`sendbeam onboard`) creates identity only when none
  exists, reports `new_identity` honestly, and fails closed on corrupt
  identity state.

## 3. Stop-ship checklist (v2.0)

| Condition                   | Status                                                                  |
| --------------------------- | ----------------------------------------------------------------------- |
| Unresolved secret exposure  | None found; allowlisted DTOs + tests                                    |
| Authentication bypass       | None found; peer binding + SPAKE2 confirmation intact                   |
| Arbitrary write             | None found; containment enforced at finalization                        |
| Corrupted verified output   | None found; digest/byte-identity evidence in `docs/RELIABILITY-v2.0.md` |
| Destructive migration       | None; backup/rollback + quarantine tested                               |
| Silent security downgrade   | None; strict padding/incompatible-peer behavior unchanged               |
| Unsafe updater verification | None; minisign pre-verification + downgrade rejection                   |
| Fabricated evidence         | None; all claims cite runnable tests/workflows                          |

## 4. Limitations (not PASS)

- **Real mobile was never run.** Reliability evidence covers CLI/desktop/web
  paths; mobile remains a documented limitation
  (see `docs/RELIABILITY-v2.0.md`), not a pass.
- **No paid Apple notarization / Windows publisher signing.** Per the
  roadmap this is deferred until funded and approved; artifact signatures
  (minisign + sigstore) and OS publisher trust are separate claims.
- **Driver-level cutover** could not run in the sandbox (UDP loopback
  blocked); deterministic wire-level cutover evidence was supplied instead.
- This review did not re-audit the v1.9 cryptographic constructions; it
  verified that v2.0 did not change, bypass, or downgrade them.

## 5. Release-readiness statement

The v2.0 changes are confined to local state management, user workflows, and
packaging; the cryptographic core (key exchange, framing, resume
authorization) is untouched and its invariants are re-tested by this PR's
suites. Upgrade from v1.8/v1.9 state, clean installs, and downgrade safety
are covered by automated tests and by candidate-artifact smoke tests in CI.
Remaining gaps are the documented limitations above. Tagging and public
release remain maintainer-gated.
