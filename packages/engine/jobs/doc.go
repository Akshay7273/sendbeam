// Package jobs implements SendBeam's durable local job and recipient-attempt
// model (V20-PR01).
//
// A Job is scheduler metadata for one user-initiated handoff: the source file
// set it was created from (bound by manifest fingerprint), the list of
// recipient attempts, retry/backoff policy, expiry, and a dispatch lease.
//
// This layer is deliberately separate from the cryptographic resume journals
// (wire.DurableJournal, transfer.DurableStore, transfer.SenderRecord):
//
//   - Jobs never carry session keys, traffic keys, pair secrets, resume
//     secrets, or AEAD counters. A job ID alone never authorizes a resume;
//     the cryptographic journals remain the sole resume authority.
//   - A job survives process restarts, but a restart never marks work
//     delivered: attempts left active under a stale lease are re-queued as
//     interrupted, never completed.
//   - Cancelled jobs never dispatch. Changed sources are never silently
//     resent: a job whose source fingerprint no longer matches is stale and
//     must be explicitly re-queued.
//
// Layout:
//
//	<config>/sendbeam/jobs/
//	  <jobID>.json   # Job schema v1, mode 0600, atomic replace
//
// <config> is os.UserConfigDir(), overridable with SENDBEAM_JOBS_DIR for tests.
// Corrupt, torn, tampered, or unsupported-version job files fail closed: they
// are reported, never guessed, never deleted automatically. Only the explicit
// Discard operation removes jobs, idempotently.
package jobs
