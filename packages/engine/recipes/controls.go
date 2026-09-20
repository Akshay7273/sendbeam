package recipes

// Enable/disable controls for saved routines (V22-PR06).
//
// A routine is always in exactly one lifecycle state:
//   - "manual" (RecipeManual): the human at the keyboard may run it by
//     hand; automated dispatch needs a valid automation grant.
//   - "approval-required" (RecipeApprovalRequired): nothing dispatches,
//     not even a manual run, until a person approves it.
//   - "disabled" (RecipeDisabled): nothing dispatches for any trigger
//     reason, including manual, until it is enabled again.
//
// Disable and Enable mutate the recipe in memory; the caller persists
// with the store (the CLI and desktop adapters Save after mutating, the
// same pattern the grant/approve helpers use). Both are nil-safe no-ops
// so a missing record can never panic a control path.

// Disable switches the routine off: its status becomes "disabled", so
// every future dispatch — watch, schedule, retry, and manual alike — is
// refused, and the watcher's dynamic reload plus the scheduler's
// reconciliation drop it without touching in-flight work. A dispatch
// already admitted keeps running to completion: disable stops the NEXT
// send, never the one already moving bytes. The automation grant is left
// untouched; Enable will revoke it explicitly, so the two steps read
// honestly in the audit trail (a disabled routine still "holds" its
// grant, but the grant is inert until the routine is enabled and
// approved again).
func Disable(r *Recipe) {
	if r == nil {
		return
	}
	r.Status = RecipeDisabled
}

// Enable returns a disabled routine to life through the safe default:
// its status becomes "approval-required" and its automation consent is
// revoked, even though the user granted it before. The reasoning is
// deliberate — a routine that was switched off may have stale files,
// stale recipients, or stale intent, so nothing about it dispatches
// until a person re-reviews:
//   - manual runs are refused until `recipe approve <id>` (the human at
//     the keyboard re-confirms the current scope);
//   - automated watch/schedule dispatch additionally needs a fresh
//     `recipe grant <id>` after approval, because the grant was
//     revoked by the enable itself.
//
// Enabling an already-active routine is harmless: it re-states the same
// safe default (approval-required, no automation consent).
func Enable(r *Recipe) {
	if r == nil {
		return
	}
	r.Status = RecipeApprovalRequired
	RevokeAutomation(r)
}
