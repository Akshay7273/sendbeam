// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/wire"
)

// maxRunnerConcurrent caps RunnerOptions.MaxConcurrent: the runner is a
// small in-process host, never a thread pool.
const maxRunnerConcurrent = 4

// ErrAlreadyRunning is returned by Runner.Dispatch when the recipe already
// has a dispatch in flight. It is a deterministic skip signal, not a
// failure: check it with errors.Is and treat it as "nothing to do".
var ErrAlreadyRunning = errors.New("recipes: recipe already has a dispatch in flight — skipped")

// ErrRunnerBusy is returned by Runner.Dispatch when the runner is already
// at its MaxConcurrent dispatch limit. Callers should back off and retry
// later; the runner never queues unbounded work.
var ErrRunnerBusy = errors.New("recipes: routine runner at capacity — dispatch refused")

// RunnerOptions tunes the routine runner.
type RunnerOptions struct {
	// MaxConcurrent bounds how many dispatches may be in flight at once.
	// Values <= 0 mean 1 (the default); values above 4 are clamped to 4.
	MaxConcurrent int
	// Now is the clock for grant checks and the last-run ledger; tests
	// inject a fixed one. Defaults to time.Now.
	Now func() time.Time
}

// Runner is the user-scoped native routine runner (V22-PR03): the
// explicitly enabled, bounded host for automated recipe triggers. It only
// ever acts on the local user's own recipes — it has no remote authority,
// makes no network calls itself, and enqueues through the same Enqueuer
// seam as manual runs, so every dispatch becomes one ordinary outbox job.
//
// Concurrency is bounded twice: at most MaxConcurrent dispatches are in
// flight across all recipes, and a second Dispatch for a recipe that
// already has a dispatch in flight is skipped deterministically
// (ErrAlreadyRunning) instead of piling up. Overload returns ErrRunnerBusy
// immediately — never an unbounded goroutine, never a hidden queue.
//
// Dispatch honors context cancellation: a canceled context aborts the
// dispatch and is recorded in the last-run ledger as a failure. In-flight
// dispatches otherwise run to completion; the bound is on the dispatch
// path (load, gates, resolve, one enqueue), not on the transfer, which
// the outbox owns.
//
// Every dispatch attempt — success, refusal, failure, or skip — is
// recorded in the recipe's LastRun ledger via the store, so nothing is
// ever silent and the routine-management UI (V22-PR06) can show recent
// decisions.
type Runner struct {
	deps          RunDeps
	eq            Enqueuer
	now           func() time.Time
	maxConcurrent int

	mu       sync.Mutex
	inFlight map[string]struct{}
	running  int
	stopped  bool
}

// NewRunner builds a routine runner over deps (recipe store, trust store)
// and eq (the job-queue seam). A nil Enqueuer fails dispatch at call time
// with a clear error, like Run does.
func NewRunner(deps RunDeps, eq Enqueuer, opts RunnerOptions) *Runner {
	maxConcurrent := opts.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	if maxConcurrent > maxRunnerConcurrent {
		maxConcurrent = maxRunnerConcurrent
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if deps.Now == nil {
		deps.Now = now
	}
	return &Runner{
		deps:          deps,
		eq:            eq,
		now:           now,
		maxConcurrent: maxConcurrent,
		inFlight:      make(map[string]struct{}),
	}
}

// Stop prevents new dispatches: Dispatch after Stop refuses immediately.
// Dispatches already in flight are NOT interrupted — they run to
// completion, because the dispatch path is short (load, gates, resolve,
// one enqueue) and aborting mid-enqueue could not be honored safely.
// There is no restart: create a new Runner to dispatch again.
func (rn *Runner) Stop() {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	rn.stopped = true
}

// Dispatch runs one dispatch attempt for recipeID with the given trigger
// reason and returns the enqueued job.
//
//   - TriggerManual never needs an automation grant (the human at the
//     keyboard is the authorization) and behaves exactly like Run.
//   - TriggerWatch, TriggerSchedule and TriggerRetry require a valid
//     AutoSend grant at dispatch time; without one the attempt is refused
//     with a CodeAuth error naming the recipe and the cause.
//   - Disabled recipes refuse for every trigger reason.
//
// Admission control: if the recipe already has a dispatch in flight, the
// attempt is skipped deterministically — (jobs.Job{}, ErrAlreadyRunning)
// — and recorded as such. If the runner is at its MaxConcurrent limit, or
// has been stopped, the attempt is refused with ErrRunnerBusy (or a
// stopped error) and recorded as refused.
//
// Every attempt records the recipe's LastRun ledger entry (dispatched,
// refused, failed, or skipped) before returning, so failures are never
// silent. A canceled context aborts the dispatch: Dispatch returns the
// context error and records a failure.
func (rn *Runner) Dispatch(ctx context.Context, recipeID string, reason TriggerReason) (jobs.Job, error) {
	switch reason {
	case TriggerManual, TriggerWatch, TriggerSchedule, TriggerRetry:
	default:
		err := wire.Errorf(wire.CodeStorage, "recipes: unknown trigger reason %q", string(reason))
		rn.record(recipeID, reason, RunStatusRefused, "", err.Error())
		return jobs.Job{}, err
	}
	if err := ctx.Err(); err != nil {
		rn.record(recipeID, reason, RunStatusFailed, "", err.Error())
		return jobs.Job{}, err
	}

	rn.mu.Lock()
	if rn.stopped {
		rn.mu.Unlock()
		err := wire.Errorf(wire.CodeAuth, "recipes: routine runner is stopped — dispatch refused")
		rn.record(recipeID, reason, RunStatusRefused, "", err.Error())
		return jobs.Job{}, err
	}
	if _, ok := rn.inFlight[recipeID]; ok {
		rn.mu.Unlock()
		rn.record(recipeID, reason, RunStatusSkipped, "", "already running, skipped")
		return jobs.Job{}, ErrAlreadyRunning
	}
	if rn.running >= rn.maxConcurrent {
		rn.mu.Unlock()
		rn.record(recipeID, reason, RunStatusRefused, "",
			"runner at capacity ("+strconv.Itoa(rn.maxConcurrent)+" concurrent dispatch(es)) — refusing instead of queueing")
		return jobs.Job{}, ErrRunnerBusy
	}
	rn.inFlight[recipeID] = struct{}{}
	rn.running++
	rn.mu.Unlock()
	defer rn.release(recipeID)

	job, err := RunWithTrigger(ctx, rn.deps, rn.eq, recipeID, reason)
	if err != nil {
		rn.record(recipeID, reason, dispatchOutcome(err), "", err.Error())
		return jobs.Job{}, err
	}
	rn.record(recipeID, reason, RunStatusDispatched, job.JobID, "")
	return job, nil
}

// release drops one in-flight slot. It must run after every admitted
// dispatch, including panics in the dispatch path (none are expected, but
// a stuck slot would wedge the recipe forever).
func (rn *Runner) release(recipeID string) {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	delete(rn.inFlight, recipeID)
	if rn.running > 0 {
		rn.running--
	}
}

// record writes one last-run ledger entry through the store. It is
// best-effort: the dispatch outcome is already decided, and a ledger
// write failure must not mask or rewrite it, so the error is explicitly
// dropped. A nil store (misconfiguration) records nothing.
func (rn *Runner) record(recipeID string, reason TriggerReason, status RunStatus, jobID, detail string) {
	if rn.deps.Store == nil {
		return
	}
	info := RecipeRunInfo{
		At:      rn.now().UTC(),
		Trigger: reason,
		JobID:   jobID,
		Status:  status,
		Detail:  detail,
	}
	_ = rn.deps.Store.RecordRun(recipeID, info)
}

// dispatchOutcome classifies a RunWithTrigger error for the ledger:
// gate refusals (auth, storage, source IO) are "refused"; anything
// unexpected — enqueue errors, context cancellation — is "failed".
func dispatchOutcome(err error) RunStatus {
	switch wire.CodeOf(err) {
	case wire.CodeAuth, wire.CodeStorage, wire.CodeSourceIO:
		return RunStatusRefused
	default:
		return RunStatusFailed
	}
}
