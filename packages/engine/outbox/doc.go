// Package outbox implements SendBeam's explicit local outbox (V20-PR02): the
// durable offline-recipient queue built on the V20-PR01 job/recipient-attempt
// model.
//
// A local outbox means the payload stays on the sender. Dispatch requires the
// sender process to run and each recipient to become reachable; an offline
// recipient's attempt waits in the queue under bounded retries with
// exponential backoff, a hard expiry, and explicit cancellation. Failed
// targets are terminal until the operator explicitly re-queues them.
//
// Separation of concerns (enforced, not aspirational):
//
//   - The outbox is scheduler metadata. It never carries session keys,
//     traffic keys, pair secrets, resume secrets, or AEAD counters. The
//     production sender resolves trust credentials at dispatch time from the
//     trust store — a job ID or device label alone never authenticates a peer.
//   - Source paths are recorded in a sidecar (<jobID>.sources) next to
//     the job file, never inside the Job schema. Before every dispatch the
//     outbox re-expands and re-fingerprints the sources; changed sources are
//     never silently resent — the job fails closed and must be re-enqueued.
//   - Delivery honesty follows the job model: only a completed, digest-
//     verified transfer whose receiver finalized the output (Done received)
//     marks an attempt completed. Offline and transient failure outcomes
//     re-queue as interrupted with exponential backoff while attempt budget
//     remains; explicit refusals and fatal errors are terminal.
//
// The Outbox type is engine-level and sender-agnostic: production wiring
// injects a SendFunc (the CLI provides the real encrypted transfer). Browser
// dispatch is foreground/permission constrained by platform design and is not
// implemented here.
package outbox
