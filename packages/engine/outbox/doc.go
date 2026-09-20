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
//
// Network policy binding (V21-PR07): every job records the network policy
// it was enqueued under (Job.NetworkPolicy; empty means Online, the v2.0
// default). Each dispatch pass carries the dispatcher's current effective
// policy (DispatchOptions.EffectivePolicy) and an attempt is bound to the
// job's policy at dispatch time: a job is dispatched only when its bound
// policy is satisfiable under the effective policy
// (netpolicy.Policy.DispatchableUnder). Unsatisfiable jobs are held —
// skipped with a clear, secret-free reason, attempts untouched — never
// dispatched down a broader path. In particular a local-only job never
// becomes an online job: not while queued, not on resume, not when the
// global policy changes.
//
// Policy-change behavior (explicit, V21-PR07):
//
//   - A policy change takes effect at the next dispatch decision. The
//     dispatcher reads its effective policy fresh on every DispatchOnce;
//     there is no cached policy that could dispatch stale.
//   - In-flight attempts are lease-bound and run to completion or failure
//     under the policy they started with. They are not killed mid-transfer
//     by a policy change: their session keys, counters, and route were
//     already bound at dispatch, and aborting them would strand verified
//     partials without improving the posture. The next attempt of the same
//     job binds the new policy.
//   - Queued jobs whose bound policy is unsatisfiable under the new
//     effective policy wait (held). They resume automatically when the
//     policy allows again; no operator action and no re-enqueue is needed,
//     and their retry budget is not consumed by holds.
//   - Switching the global policy never rewrites a job's bound policy.
//     Changing from local-only to online does not release local-only jobs
//     onto online routes; changing from online to local-only does not
//     convert online jobs into local-only jobs — they are held until an
//     online route is permitted again.
//   - Restart safety comes from the shared transfer engine: resume across
//     sessions re-authenticates (resume preamble) and runs under a fresh
//     key epoch, so a restart never resets a nonce under the same key and
//     never reuses unauthorized progress. Changed sources fail the
//     pre-dispatch fingerprint check; revoked devices fail the
//     dispatch-time trust resolution; unknown newer job schemas are
//     quarantined by the strict store decoder. All fail closed.
package outbox
