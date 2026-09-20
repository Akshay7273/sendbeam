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
// recording fake. One Run call enqueues exactly ONE job.
type Enqueuer interface {
	Enqueue(ctx context.Context, paths []string, recipients []EnqueueRecipient, policy jobs.RetryPolicy, networkPolicy netpolicy.Policy) (jobs.Job, error)
}

// RunDeps are the recipe-run dependencies: the recipe store and the trust
// store used for point-in-time recipient revalidation.
type RunDeps struct {
	Store *RecipeStore
	Trust trust.Store
	// Now is the clock for time checks (expiry); tests inject a fixed one.
	Now func() time.Time
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
func Run(ctx context.Context, deps RunDeps, eq Enqueuer, recipeID string) (jobs.Job, error) {
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
		return jobs.Job{}, wire.Errorf(wire.CodeAuth, "recipes: recipe %q is disabled — enable it before running", r.Name)
	case RecipeApprovalRequired:
		return jobs.Job{}, wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q requires approval — run `recipe approve %s` first", r.Name, r.ID)
	default:
		return jobs.Job{}, wire.Errorf(wire.CodeStorage, "recipes: recipe %q has unknown status %q", r.Name, r.Status)
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
	return eq.Enqueue(ctx, paths, recipients, jobs.DefaultRetryPolicy(), np)
}
