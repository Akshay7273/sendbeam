// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// EnqueueRecipient is one recipe recipient as passed to the job queue.
type EnqueueRecipient struct {
	DeviceID string
	Label    string
}

// Enqueuer is the single job-queue seam used by recipe runs. It is defined
// here (not in the CLI) so the engine never imports the CLI: the CLI
// adapts its real *outbox.Outbox to this interface, and tests inject a
// recording fake. One Run call enqueues exactly ONE job. The provenance is
// the routine origin label (V22-PR06): the dispatcher passes the routine's
// identity so the job and (at dispatch) the wire manifest can carry where
// the transfer came from.
type Enqueuer interface {
	Enqueue(ctx context.Context, paths []string, recipients []EnqueueRecipient, policy jobs.RetryPolicy, networkPolicy netpolicy.Policy, provenance *wire.Provenance) (jobs.Job, error)
}

// RunDeps are the recipe-run dependencies: the recipe store and the trust
// store used for point-in-time recipient revalidation.
type RunDeps struct {
	Store *RecipeStore
	Trust trust.Store
	// Now is the clock for time checks (expiry); tests inject a fixed one.
	Now func() time.Time
	// SenderLabel is this device's own label, stamped on the provenance
	// the dispatch carries. Empty is legal — the provenance label falls
	// back to the configured device name — but the CLI and desktop
	// adapters always set it.
	SenderLabel string
}

// Run executes an explicit one-shot recipe run. The human at the keyboard
// IS the authorization — one-shot manual runs never need an automation
// grant — so Run requires only that the recipe itself is runnable:
// status "manual", not expired, recipients still trusted, a non-empty
// resolved file set, and budgets respected. Everything is revalidated at
// enqueue time (files can change between preview and run; trust can
// change; budgets are enforced on the fresh resolution).
//
// The recipe status gate:
//
//   - "manual" proceeds;
//   - "disabled" refuses with "recipe is disabled";
//   - "approval-required" refuses with "recipe requires approval — run `recipe approve <id>` first".
//
// Dry-run paths (Resolve, PlanDTO, Preview) must NEVER enqueue: they do
// not take an Enqueuer at all, so a job cannot be created by accident.
//
// Run is RunWithTrigger with the manual reason; the routine runner calls
// RunWithTrigger directly for automated reasons.
func Run(ctx context.Context, deps RunDeps, eq Enqueuer, recipeID string) (jobs.Job, error) {
	return RunWithTrigger(ctx, deps, eq, recipeID, TriggerManual)
}

// RunWithTrigger dispatches one recipe run for the given trigger reason,
// running the same gates for every reason: status, expiry, recipient
// trust revalidation, fresh resolution, and budgets — then exactly one
// Enqueue. TriggerManual behaves exactly like Run: the human at the
// keyboard is the authorization, so no automation grant is needed. Every
// other reason (watch, schedule, retry) additionally requires a valid
// AutoSend grant at dispatch time; without one the attempt is refused
// with a CodeAuth error naming the recipe and the cause.
//
// Disabled recipes refuse for every trigger reason, including manual.
func RunWithTrigger(ctx context.Context, deps RunDeps, eq Enqueuer, recipeID string, reason TriggerReason) (jobs.Job, error) {
	if deps.Store == nil {
		return jobs.Job{}, wire.Errorf(wire.CodeInternal, "recipes: nil recipe store")
	}
	if deps.Trust == nil {
		return jobs.Job{}, wire.Errorf(wire.CodeInternal, "recipes: nil trust store")
	}
	if eq == nil {
		return jobs.Job{}, wire.Errorf(wire.CodeInternal, "recipes: nil enqueuer")
	}
	if !isLowerHex32(recipeID) {
		return jobs.Job{}, wire.Errorf(wire.CodeStorage, "recipes: invalid recipe id %q", recipeID)
	}
	switch reason {
	case TriggerManual, TriggerWatch, TriggerSchedule, TriggerRetry:
	default:
		return jobs.Job{}, wire.Errorf(wire.CodeStorage, "recipes: unknown trigger reason %q", string(reason))
	}
	now := time.Now().UTC
	if deps.Now != nil {
		now = deps.Now
	}

	r, ok, err := deps.Store.Load(recipeID)
	if err != nil {
		return jobs.Job{}, err
	}
	if !ok {
		return jobs.Job{}, wire.Errorf(wire.CodeStorage, "recipes: no recipe %q", recipeID)
	}

	switch r.Status {
	case RecipeManual:
		// Proceed.
	case RecipeDisabled:
		return jobs.Job{}, wire.Errorf(wire.CodeAuth, "recipes: recipe %q is disabled — run `recipe enable %s` first", r.Name, r.ID)
	case RecipeApprovalRequired:
		if reason == TriggerManual {
			return jobs.Job{}, wire.Errorf(wire.CodeAuth,
				"recipes: recipe %q requires approval — run `recipe approve %s` first", r.Name, r.ID)
		}
		if grantRevokedByMaterialChange(r) {
			return jobs.Job{}, wire.Errorf(wire.CodeAuth,
				"recipes: recipe %q automation grant revoked by material change — re-approve with `recipe approve %s`, then re-grant explicitly with `recipe grant %s`",
				r.Name, r.ID, r.ID)
		}
		return jobs.Job{}, wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q requires approval before automated %s dispatch — run `recipe approve %s` first (then `recipe grant %s` to allow automation)",
			r.Name, reason, r.ID, r.ID)
	default:
		return jobs.Job{}, wire.Errorf(wire.CodeStorage, "recipes: recipe %q has unknown status %q", r.Name, r.Status)
	}

	// Automated reasons need an explicit, still-valid AutoSend grant at
	// dispatch time. Manual never does: the human at the keyboard is the
	// authorization.
	if reason != TriggerManual && !r.GrantValid(now()) {
		return jobs.Job{}, grantRefusal(r, reason)
	}

	if !r.ExpiresAt.IsZero() && !now().UTC().Before(r.ExpiresAt.UTC()) {
		return jobs.Job{}, wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q expired at %s", r.Name, r.ExpiresAt.UTC().Format(time.RFC3339))
	}

	// Revalidate trust at dispatch: a device may have been revoked or
	// unpaired after the recipe was composed or previewed.
	if err := ValidateRecipients(ctx, deps.Trust, r); err != nil {
		return jobs.Job{}, err
	}

	// Resolve fresh: preview never locks content, so a file added (or
	// removed) after a preview changes what this run sends.
	plan, err := Resolve(r, ResolveOptions{})
	if err != nil {
		return jobs.Job{}, err
	}
	if len(plan.Files) == 0 {
		return jobs.Job{}, wire.Errorf(wire.CodeSourceIO,
			"recipes: no files matched recipe %q — nothing to send", r.Name)
	}
	if plan.TotalBytes > r.Budgets.MaxBytesPerRun {
		return jobs.Job{}, wire.Errorf(wire.CodeStorage,
			"recipes: recipe %q run would send %d bytes, exceeding the %d-byte per-run budget",
			r.Name, plan.TotalBytes, r.Budgets.MaxBytesPerRun)
	}
	if int64(len(plan.Files)) > r.Budgets.MaxFilesPerRun {
		return jobs.Job{}, wire.Errorf(wire.CodeStorage,
			"recipes: recipe %q run would send %d files, exceeding the %d-file per-run budget",
			r.Name, len(plan.Files), r.Budgets.MaxFilesPerRun)
	}

	np, err := netpolicy.Parse(r.NetworkPolicy)
	if err != nil {
		return jobs.Job{}, wire.Errorf(wire.CodeStorage, "recipes: invalid networkPolicy %q", r.NetworkPolicy)
	}
	paths := make([]string, len(plan.Files))
	for i, f := range plan.Files {
		paths[i] = f.Path
	}
	recipients := make([]EnqueueRecipient, len(plan.Recipients))
	for i, c := range plan.Recipients {
		recipients[i] = EnqueueRecipient(c)
	}
	// V22-PR06: attach the routine origin label to this dispatch. The
	// enqueuer stamps it on the job and, at dispatch time, on the wire
	// manifest so the receiver's consent surface can show where the
	// transfer came from. SenderLabel degrades to the recipe's origin
	// device only when the caller did not set one.
	provenance := Provenance{
		RoutineID:   r.ID,
		RoutineName: r.Name,
		SenderLabel: deps.SenderLabel,
		Trigger:     reason,
	}
	wireProv := provenance.Wire()
	job, err := eq.Enqueue(ctx, paths, recipients, jobs.DefaultRetryPolicy(), np, &wireProv)
	if err != nil {
		return jobs.Job{}, err
	}
	return job, nil
}

// grantRevokedByMaterialChange reports whether the recipe's automation
// grant was revoked by a material scope change: consent was given for the
// current scope (versioned, scope hash matches it) but is no longer
// active. ApplyUpdate leaves exactly this shape behind.
func grantRevokedByMaterialChange(r Recipe) bool {
	g := r.Grant
	return !g.AutoSend && g.ConsentVersion > 0 && g.ScopeHash != "" && g.ScopeHash == r.ScopeHash()
}

// grantRefusal builds the CodeAuth error for an automated dispatch attempt
// on a recipe whose automation grant is not currently valid. The message
// names the recipe and the specific cause so the user knows the fix is
// always an explicit re-grant — never silent, never automatic.
func grantRefusal(r Recipe, reason TriggerReason) error {
	g := r.Grant
	switch {
	case grantRevokedByMaterialChange(r):
		// Consent was given for the current scope but is no longer
		// active: a material change revoked it (ApplyUpdate clears
		// AutoSend while refreshing ScopeHash to the new scope).
		return wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q automation grant revoked by material change — re-grant explicitly with `recipe grant %s` before %s dispatch",
			r.Name, r.ID, reason)
	case g.AutoSend && (g.GrantedAt.IsZero() || g.ConsentVersion <= 0):
		return wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q automation grant is incomplete (missing timestamp or consent version) — re-grant explicitly with `recipe grant %s`",
			r.Name, r.ID)
	case g.AutoSend:
		// Scope drift or a future-dated grant: the stored consent no
		// longer matches what automated dispatch may use.
		return wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q automation grant does not match the current recipe scope — re-grant explicitly with `recipe grant %s` before %s dispatch",
			r.Name, r.ID, reason)
	default:
		return wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q has no automation grant for %s dispatch — run `recipe grant %s` to allow it (manual runs need no grant)",
			r.Name, reason, r.ID)
	}
}
