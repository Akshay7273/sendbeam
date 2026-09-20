// Package transfercenter is the read model and retention layer for the
// local transfer center: it turns durable jobs (packages/engine/jobs) and
// the local outbox (packages/engine/outbox) into display-ready snapshots
// grouped by user-facing state — queued, active, interrupted, verified,
// completed, failed, cancelled — with per-target results and explicit
// history retention.
//
// It never dispatches and never touches cryptographic material: job metadata
// only. Scheduler metadata stays separate from the cryptographic resume
// journals in packages/engine/transfer. "Verified" is deliberately not
// "delivered": a digest-verified attempt whose receiver finalization is
// unconfirmed keeps the job out of the completed group, so the
// receiver-commit/sender-ack crash window is reported as uncertain, never
// invented as delivered.
package transfercenter
