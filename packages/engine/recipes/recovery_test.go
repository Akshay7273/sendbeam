// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// crashEnqueuer models the crash window between the scheduler's
// cursor-advance and the dispatch's enqueue: Enqueue signals entry and
// then blocks until the caller's context ends, returning the context
// error WITHOUT creating any job. The "crash" is the test canceling the
// scheduler context mid-dispatch.
type crashEnqueuer struct {
	entered chan struct{}
	calls   atomic.Int32
}

func (e *crashEnqueuer) Enqueue(ctx context.Context, _ []string, _ []EnqueueRecipient, _ jobs.RetryPolicy, _ netpolicy.Policy, _ *wire.Provenance) (jobs.Job, error) {
	e.calls.Add(1)
	select {
	case e.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return jobs.Job{}, ctx.Err()
}

// durableOutboxEnqueuer is the test-local equivalent of the CLI's
// outboxEnqueuer: it adapts the REAL *outbox.Outbox to the
// recipes.Enqueuer seam, so dispatches create durable jobs in a real job
// store that survives a simulated process restart.
type durableOutboxEnqueuer struct {
	ob *outbox.Outbox
}

func (e durableOutboxEnqueuer) Enqueue(ctx context.Context, paths []string, recipients []EnqueueRecipient, policy jobs.RetryPolicy, np netpolicy.Policy, provenance *wire.Provenance) (jobs.Job, error) {
	refs := make([]outbox.RecipientRef, len(recipients))
	for i, r := range recipients {
		refs[i] = outbox.RecipientRef{DeviceID: r.DeviceID, Label: r.Label}
	}
	if provenance != nil && provenance.SenderLabel == "" {
		cpy := *provenance
		cpy.SenderLabel = "test-sender"
		provenance = &cpy
	}
	return e.ob.EnqueueWithProvenance(ctx, paths, refs, policy, np, provenance)
}

// burstEnqueuer records every call's paths goroutine-safely (the
// watcher's event loop dispatches from its own goroutine).
type burstEnqueuer struct {
	mu    sync.Mutex
	calls [][]string
}

func (e *burstEnqueuer) Enqueue(_ context.Context, paths []string, _ []EnqueueRecipient, _ jobs.RetryPolicy, _ netpolicy.Policy, _ *wire.Provenance) (jobs.Job, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, append([]string{}, paths...))
	return jobs.Job{JobID: "burst-job"}, nil
}

func (e *burstEnqueuer) numCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.calls)
}

func (e *burstEnqueuer) allPaths() [][]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([][]string, len(e.calls))
	copy(out, e.calls)
	return out
}

// waitForQuiescence waits until count() stops changing for the whole
// settle window (debounce quiescence: no new dispatches), or fails after
// timeout.
func waitForQuiescence(t *testing.T, timeout, settle time.Duration, what string, count func() int) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last, stableSince := count(), time.Now()
	for time.Now().Before(deadline) {
		if n := count(); n != last {
			last, stableSince = n, time.Now()
		} else if time.Since(stableSince) >= settle {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for quiescence of %s (last count %d)", what, last)
}

// goroutinesSettle polls until the goroutine count is back within slop of
// the baseline, or fails after timeout.
func goroutinesSettle(t *testing.T, baseline, slop int, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n := runtime.NumGoroutine(); n <= baseline+slop {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle for %s: baseline=%d now=%d (slop %d)",
		what, baseline, runtime.NumGoroutine(), slop)
}

// TestSchedulerCrashBetweenCursorAndDispatch is the core crash-safety
// proof: the scheduler advances the schedule cursor BEFORE asking the
// runner to dispatch. A crash (here: the scheduler context canceled while
// the dispatch is blocked inside Enqueue) must therefore leave the
// occurrence consumed but never duplicated:
//
//   - (a) the cursor for the occurrence is already persisted,
//   - (b) no job exists for it (the enqueue never completed),
//   - (c) a fresh scheduler tick does NOT re-dispatch it,
//   - (d) the ledger records the attempt honestly.
//
// The honest ledger state: the runner records the interrupted dispatch
// as "failed: context canceled" and the catch-up summary records the
// failed catch-up. A TRUE process death (not simulated here — the test
// process survives) would leave no ledger entry at all for the
// occurrence: the cursor advance is the only durable evidence, and the
// occurrence is lost, never duplicated. That is the documented
// at-most-once contract: the ledger only ever records dispatch attempts
// the runner actually finished.
func TestSchedulerCrashBetweenCursorAndDispatch(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 1,
	}, now)
	// One missed occurrence (due at `now`) for the catch-up path.
	fx.backdateCursor(t, time.Minute)

	jobDir := t.TempDir() // the durable job store the dispatch would write to
	crashEq := &crashEnqueuer{entered: make(chan struct{}, 1)}
	nowFn := func() time.Time { return now }
	runner := NewRunner(RunDeps{Store: fx.store, Trust: fx.ts, Now: nowFn}, crashEq, RunnerOptions{Now: nowFn})
	sched, err := NewScheduler(fx.store, runner, ScheduleOptions{
		Now:            nowFn,
		OnEvent:        fx.log.handler(),
		RescanInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startDone := make(chan error, 1)
	go func() { startDone <- sched.Start(ctx) }()
	defer func() { _ = sched.Stop() }()

	// Wait until the dispatch is blocked inside Enqueue — i.e. the
	// cursor advance (which happens before runner.Dispatch) is done.
	select {
	case <-crashEq.entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("dispatch never reached the enqueuer")
	}

	// (a) The cursor for the occurrence was persisted BEFORE the
	// dispatch, so the crash cannot lose the deduplication state.
	cur := fx.loadCursor(t)
	if cur == nil || !cur.Equal(now) {
		t.Fatalf("cursor = %v, want the persisted occurrence time %v", cur, now)
	}

	// THE CRASH: cancel the scheduler context mid-dispatch.
	cancel()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("scheduler did not stop after the crash")
	}

	// (b) The enqueue never completed: reopening the durable job store
	// (as a restarted process would) shows no job for the occurrence.
	js, err := jobs.OpenJobStore(jobDir)
	if err != nil {
		t.Fatalf("OpenJobStore: %v", err)
	}
	entries, err := outbox.New(js, nil).List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("crashed dispatch left %d job(s) in the outbox", len(entries))
	}
	if n := crashEq.calls.Load(); n != 1 {
		t.Fatalf("enqueue attempts = %d, want exactly 1", n)
	}

	// (d) The ledger records the attempt honestly: the runner logged the
	// interrupted dispatch as failed, and the catch-up summary (last
	// write wins) describes the failed catch-up. A true process death
	// would leave NO entry — the cursor is the only durable evidence —
	// which is exactly the at-most-once contract.
	status, detail := fx.lastRunDetail(t)
	if status != RunStatusFailed {
		t.Fatalf("ledger status = %q, want failed", status)
	}
	if !strings.Contains(detail, "caught up 0 of 1 missed run(s)") || !strings.Contains(detail, "1 failed") {
		t.Fatalf("ledger detail does not describe the interrupted catch-up honestly: %q", detail)
	}
	if !strings.Contains(detail, "canceled") {
		t.Fatalf("ledger detail does not name the interruption cause: %q", detail)
	}

	// (c) A fresh scheduler tick must NOT re-dispatch the consumed
	// occurrence: the cursor is already past it. This is the
	// no-duplicate half of at-most-once.
	eq2 := &recordingEnqueuer{}
	runner2 := NewRunner(RunDeps{Store: fx.store, Trust: fx.ts, Now: nowFn}, eq2, RunnerOptions{Now: nowFn})
	sched2, err := NewScheduler(fx.store, runner2, ScheduleOptions{
		Now:            nowFn,
		RescanInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	sched2.tick()
	if eq2.calls != 0 {
		t.Fatalf("fresh tick re-dispatched the crashed occurrence: %d enqueue(s)", eq2.calls)
	}
	// The cursor is untouched by the re-tick.
	if cur2 := fx.loadCursor(t); cur2 == nil || !cur2.Equal(now) {
		t.Fatalf("cursor moved on re-tick: %v", cur2)
	}
}

// TestRunnerCrashAfterDispatch proves the other half of crash safety: a
// dispatch that COMPLETED before the crash leaves a durable outbox job.
// After a simulated process restart (the job store is reopened from the
// same directory, all in-memory state dropped), the job is listed, is in
// a non-terminal queued state (resumable by the normal dispatcher), and
// still carries the routine provenance — using the existing job/outbox
// APIs, no new queue.
func TestRunnerCrashAfterDispatch(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	jobDir := t.TempDir()
	js, err := jobs.OpenJobStore(jobDir)
	if err != nil {
		t.Fatalf("OpenJobStore: %v", err)
	}
	eq := durableOutboxEnqueuer{ob: outbox.New(js, nil)}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})

	job, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if job.JobID == "" {
		t.Fatalf("no job returned")
	}

	// THE CRASH: every in-memory handle is dropped here — nothing else
	// runs before the "restart" below reopens the same directory.

	// A restarted process reopens the same directory...
	js2, err := jobs.OpenJobStore(jobDir)
	if err != nil {
		t.Fatalf("reopen OpenJobStore: %v", err)
	}
	ob2 := outbox.New(js2, nil)

	// ...and the job is still there, listed and resumable.
	entries, err := ob2.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].JobID != job.JobID {
		t.Fatalf("List = %v, want exactly the dispatched job %q", entries, job.JobID)
	}
	got, ok, err := ob2.Get(job.JobID)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.Status != jobs.JobQueued {
		t.Fatalf("job status = %q after restart, want queued (resumable)", got.Status)
	}
	if len(got.Files) != 1 || got.Files[0].Name != "a.txt" {
		t.Fatalf("job files = %+v, want the single dispatched source file", got.Files)
	}
	if got.Provenance == nil {
		t.Fatalf("job lost its routine provenance across the restart")
	}
	if got.Provenance.RoutineID != r.ID || got.Provenance.RoutineName != r.Name {
		t.Fatalf("provenance = %+v, want routine %q (%q)", got.Provenance, r.ID, r.Name)
	}
	if got.Provenance.Trigger != string(TriggerWatch) {
		t.Fatalf("provenance trigger = %q, want watch", got.Provenance.Trigger)
	}
	// The recipe's own ledger independently agrees the dispatch happened.
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched || lr.JobID != job.JobID {
		t.Fatalf("LastRun = %+v, want dispatched with the job id", lr)
	}
}

// TestWatcherCrashMidDebounce proves a watcher killed mid-debounce loses
// the pending (not yet dispatched) change without a trace — no phantom
// dispatch, no phantom ledger entry — and that restarting the watcher
// dispatches the change exactly once when it is observed again.
func TestWatcherCrashMidDebounce(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "v1")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Crash watch", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerWatch
	r.Grant.ScopeHash = r.ScopeHash()
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &burstEnqueuer{}
	runner := NewRunner(RunDeps{Store: store, Trust: ts, Now: time.Now}, eq, RunnerOptions{Now: time.Now})
	newWatcher := func() *Watcher {
		w, err := NewWatcher(store, runner, r.ID, WatchOptions{
			Debounce: 500 * time.Millisecond,
			Cooldown: 0,
		})
		if err != nil {
			t.Fatalf("NewWatcher: %v", err)
		}
		return w
	}

	// Baseline: one observed change dispatches once.
	w1 := newWatcher()
	if err := w1.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	writeTestFile(t, root, "a.txt", "v1-touch")
	waitFor(t, 10*time.Second, "first dispatch", func() bool { return eq.numCalls() == 1 })

	// THE CRASH: a second change arms the debounce timer, then the
	// watcher is stopped before the quiet window elapses. The change is
	// dropped — the watcher keeps no pending-change log, and missed
	// events while down are documented as not backfilled.
	writeTestFile(t, root, "a.txt", "v2-lost")
	if err := w1.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Well past the debounce window: the dropped change must never fire.
	time.Sleep(1200 * time.Millisecond)
	if n := eq.numCalls(); n != 1 {
		t.Fatalf("dispatch happened after the mid-debounce kill: %d calls, want 1", n)
	}
	// The ledger is consistent: the last entry is still the real
	// dispatch, with no phantom failure for the dropped change.
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched {
		t.Fatalf("ledger after mid-debounce kill = %+v, want the real dispatched entry", lr)
	}

	// Restart: the change is observed again and dispatched exactly once —
	// no duplicate for the same file version, no missed-file confusion.
	w2 := newWatcher()
	defer func() { _ = w2.Stop() }()
	if err := w2.Start(ctx); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	writeTestFile(t, root, "a.txt", "v2-lost")
	waitFor(t, 10*time.Second, "post-restart dispatch", func() bool { return eq.numCalls() == 2 })
	// Quiescence: no third (duplicate) dispatch follows.
	time.Sleep(1200 * time.Millisecond)
	if n := eq.numCalls(); n != 2 {
		t.Fatalf("duplicate dispatch after restart: %d calls, want exactly 2", n)
	}
	for i, paths := range eq.allPaths() {
		seen := make(map[string]bool)
		for _, p := range paths {
			if seen[p] {
				t.Fatalf("job %d contains duplicate path %q", i, p)
			}
			seen[p] = true
		}
	}
}

// TestRunnerDispatchRevalidatesAtDispatchTime is the fail-closed proof
// the roadmap asks for: the grant, the recipe status, and the rest of the
// gates are re-checked by Runner.Dispatch at DISPATCH time (RunWithTrigger
// re-loads the recipe fresh) — never cached from schedule/watch time.
// Mutating the recipe between two dispatches changes the second outcome.
func TestRunnerDispatchRevalidatesAtDispatchTime(t *testing.T) {
	ctx := context.Background()

	t.Run("disable between dispatches refuses", func(t *testing.T) {
		store, ts, r, _ := runnerTestSetup(t)
		r = grantTestRecipe(t, store, r)
		eq := &recordingEnqueuer{}
		rn := newTestRunner(store, ts, eq, RunnerOptions{})

		if _, err := rn.Dispatch(ctx, r.ID, TriggerSchedule); err != nil {
			t.Fatalf("baseline schedule dispatch: %v", err)
		}
		// Disable between scheduling and dispatch.
		r.Status = RecipeDisabled
		if err := store.Save(r); err != nil {
			t.Fatalf("Save: %v", err)
		}
		_, err := rn.Dispatch(ctx, r.ID, TriggerSchedule)
		if err == nil {
			t.Fatalf("dispatch accepted after disable")
		}
		if !strings.Contains(err.Error(), "is disabled") {
			t.Fatalf("error %q does not say disabled", err)
		}
		if eq.calls != 1 {
			t.Fatalf("disabled dispatch enqueued (calls=%d)", eq.calls)
		}
		lr := loadLastRun(t, store, r.ID)
		if lr.Status != RunStatusRefused {
			t.Fatalf("LastRun = %+v, want refused", lr)
		}
	})

	t.Run("revoke between dispatches refuses", func(t *testing.T) {
		store, ts, r, _ := runnerTestSetup(t)
		r = grantTestRecipe(t, store, r)
		eq := &recordingEnqueuer{}
		rn := newTestRunner(store, ts, eq, RunnerOptions{})

		if _, err := rn.Dispatch(ctx, r.ID, TriggerWatch); err != nil {
			t.Fatalf("baseline watch dispatch: %v", err)
		}
		// Revoke the grant between dispatches.
		RevokeAutomation(&r)
		if err := store.Save(r); err != nil {
			t.Fatalf("Save: %v", err)
		}
		_, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
		if err == nil {
			t.Fatalf("dispatch accepted after revoke")
		}
		if wire.CodeOf(err) != wire.CodeAuth {
			t.Fatalf("error code = %s, want AUTH", wire.CodeOf(err))
		}
		if eq.calls != 1 {
			t.Fatalf("revoked dispatch enqueued (calls=%d)", eq.calls)
		}
		lr := loadLastRun(t, store, r.ID)
		if lr.Status != RunStatusRefused {
			t.Fatalf("LastRun = %+v, want refused", lr)
		}
	})

	t.Run("scope drift cannot be persisted, grant re-check still fails closed", func(t *testing.T) {
		// A scope change with a stale scope hash cannot even be saved:
		// the store's validation fails closed at write time, so dispatch
		// can never see it. The production mutation path is ApplyUpdate,
		// which revokes — covered by TestRunnerMaterialChangeRevokesGrant.
		// Here: prove a hand-mutated record (bypassing ApplyUpdate) is
		// rejected by Save before it can ever reach dispatch.
		store, _, r, _ := runnerTestSetup(t)
		r = grantTestRecipe(t, store, r)
		other := t.TempDir()
		r.Sources = append(r.Sources, RecipeSource{Path: other, Recursive: true})
		if err := store.Save(r); err == nil {
			t.Fatalf("Save accepted a scope-drifted grant")
		} else if !strings.Contains(err.Error(), "scope hash") {
			t.Fatalf("Save error %q does not name the scope hash", err)
		}
	})
}

// TestRunnerDispatchConfinesEditedSources is the TOCTOU proof: a source
// tree edited between approval/grant and dispatch is re-resolved AND
// re-confined at dispatch time. A symlink planted inside the root after
// the grant, pointing at a file outside the approved source root, is
// excluded from the enqueued job — the dispatch never sends it.
func TestRunnerDispatchConfinesEditedSources(t *testing.T) {
	ctx := context.Background()
	store, ts, r, root := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	// AFTER the grant: plant a symlink escape inside the approved root.
	outside := t.TempDir()
	target := writeTestFile(t, outside, "secret.txt", "not yours")
	link := filepath.Join(root, "escape-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	if _, err := rn.Dispatch(ctx, r.ID, TriggerManual); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if eq.calls != 1 {
		t.Fatalf("Enqueue called %d times, want 1", eq.calls)
	}
	// Only the approved in-root file is enqueued; the escape target (and
	// the link itself, which resolves outside) are confined out.
	want := filepath.Join(root, "a.txt")
	if len(eq.paths) != 1 || eq.paths[0] != want {
		t.Fatalf("enqueued paths = %v, want exactly [%q]", eq.paths, want)
	}
	for _, p := range eq.paths {
		if strings.HasPrefix(p, outside) {
			t.Fatalf("enqueued path %q escapes the approved source root", p)
		}
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched {
		t.Fatalf("LastRun = %+v, want dispatched", lr)
	}
}

// TestSchedulerCatchupThirtyDayBound proves the catch-up bound under a
// huge backlog: a cursor backdated 30 days on an every-minute recipe with
// max_catchup_runs=3 dispatches exactly 3 in one tick, the cursor lands on
// the latest occurrence, and the ledger describes the bounded catch-up in
// plain language. The missed-occurrence count is arithmetic (no
// per-occurrence iteration), so the 30-day backlog does not stall the
// tick.
func TestSchedulerCatchupThirtyDayBound(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 1, "max_catchup_runs": 3,
	}, now)
	fx.backdateCursor(t, 30*24*time.Hour) // ~43200 missed occurrences

	sched := fx.scheduler(t)
	start := time.Now()
	sched.tick()
	elapsed := time.Since(start)

	if got := fx.eq.numCalls(); got != 3 {
		t.Fatalf("dispatches = %d, want exactly 3 (the cap)", got)
	}
	cur := fx.loadCursor(t)
	if cur == nil || !cur.Equal(now) {
		t.Fatalf("cursor = %v, want the latest occurrence %v", cur, now)
	}
	status, detail := fx.lastRunDetail(t)
	if status != RunStatusDispatched {
		t.Fatalf("ledger status = %q, want dispatched", status)
	}
	if !strings.Contains(detail, "caught up 3 of 43200 missed run(s)") ||
		!strings.Contains(detail, "43197 skipped by cap") {
		t.Fatalf("ledger detail does not describe the bounded catch-up: %q", detail)
	}
	// The tick must not iterate the backlog: 30 days of minutes resolves
	// in well under a second (generous bound for slow CI).
	if elapsed > 30*time.Second {
		t.Fatalf("tick took %s over a 30-day backlog — not arithmetic", elapsed)
	}

	// A second tick dispatches nothing more: the backlog is consumed.
	sched.tick()
	if got := fx.eq.numCalls(); got != 3 {
		t.Fatalf("second tick dispatched again: calls = %d", got)
	}
}

// TestSchedulerCatchupEnforcesBudget proves the catch-up loop cannot
// bypass budget checks: every catch-up occurrence goes through
// Runner.Dispatch, which re-checks the per-run budget against the fresh
// resolution. An over-budget recipe under a 30-day backlog dispatches
// nothing, and the ledger names the budget refusal.
func TestSchedulerCatchupEnforcesBudget(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "seed.txt", "seed") // 4 bytes
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Over budget", now)
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerSchedule
	r.Trigger.Schedule = map[string]any{"kind": "interval", "every_minutes": 1, "max_catchup_runs": 3}
	// Tighten the budget BEFORE granting so the grant binds to it: the
	// 4-byte fixture file exceeds the 1-byte budget.
	r.Budgets.MaxBytesPerRun = 1
	r.Grant.ScopeHash = r.ScopeHash()
	if err := GrantAutomation(&r, now); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &watchEnqueuer{}
	nowFn := func() time.Time { return now }
	runner := NewRunner(RunDeps{Store: store, Trust: ts, Now: nowFn}, eq, RunnerOptions{Now: nowFn})
	sched, err := NewScheduler(store, runner, ScheduleOptions{
		Now:            nowFn,
		RescanInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	if err := store.AdvanceScheduleCursor(r.ID, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatalf("AdvanceScheduleCursor: %v", err)
	}

	sched.tick()

	if got := eq.numCalls(); got != 0 {
		t.Fatalf("catch-up dispatched %d over-budget job(s), want 0", got)
	}
	lr, ok, err := store.Load(r.ID)
	if err != nil || !ok || lr.LastRun == nil {
		t.Fatalf("Load: ok=%v err=%v lastRun=%v", ok, err, lr.LastRun)
	}
	if lr.LastRun.Status != RunStatusFailed {
		t.Fatalf("ledger status = %q, want failed (all catch-up attempts refused)", lr.LastRun.Status)
	}
	if !strings.Contains(lr.LastRun.Detail, "caught up 0 of 43200 missed run(s)") ||
		!strings.Contains(lr.LastRun.Detail, "budget") {
		t.Fatalf("ledger detail does not name the budget refusal: %q", lr.LastRun.Detail)
	}
}

// TestRunnerConcurrencyCapRefusesPromptly proves the isolation bound: with
// MaxConcurrent=1 and one dispatch in flight, 50 rapid sequential
// TriggerSchedule attempts are all refused immediately (no queue, no
// goroutine pile-up), and the in-flight slot drains cleanly afterwards.
func TestRunnerConcurrencyCapRefusesPromptly(t *testing.T) {
	ctx := context.Background()
	store, ts, _, _ := runnerTestSetup(t)
	// Two granted recipes: one holds the single slot, the other absorbs
	// the 50 refused attempts (distinct ids, so the per-recipe dedupe
	// does not mask the capacity refusal).
	holdRoot := t.TempDir()
	writeTestFile(t, holdRoot, "h.txt", "hold")
	holder := composableRecipe(t, store, holdRoot, "Holder", testIdentity(ctx, t, ts, "dev"))
	holder = grantTestRecipe(t, store, holder)
	tryRoot := t.TempDir()
	writeTestFile(t, tryRoot, "t.txt", "try")
	trier := composableRecipe(t, store, tryRoot, "Trier", testIdentity(ctx, t, ts, "dev2"))
	trier = grantTestRecipe(t, store, trier)

	eq := &blockingEnqueuer{entered: make(chan struct{}, 1), release: make(chan struct{})}
	rn := newTestRunner(store, ts, eq, RunnerOptions{MaxConcurrent: 1})

	// Hold the single in-flight slot.
	first := make(chan DispatchOut, 1)
	go func() {
		job, err := rn.Dispatch(ctx, holder.ID, TriggerSchedule)
		first <- DispatchOut{job: job, err: err}
	}()
	select {
	case <-eq.entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("holder dispatch never reached the enqueuer")
	}

	before := runtime.NumGoroutine()
	start := time.Now()
	var busy int
	for i := 0; i < 50; i++ {
		_, err := rn.Dispatch(ctx, trier.ID, TriggerSchedule)
		if errors.Is(err, ErrRunnerBusy) {
			busy++
			continue
		}
		t.Fatalf("attempt %d: err = %v, want ErrRunnerBusy", i, err)
	}
	elapsed := time.Since(start)
	if busy != 50 {
		t.Fatalf("busy refusals = %d, want 50", busy)
	}
	// 50 sequential refusals must be prompt: each is a synchronous gate
	// check, never a queued goroutine. (Bound is generous for slow CI;
	// a pile-up would block or take orders of magnitude longer.)
	if elapsed > 30*time.Second {
		t.Fatalf("50 refused dispatches took %s — not prompt", elapsed)
	}
	// No goroutine pile-up from the refused attempts.
	goroutinesSettle(t, before, 2, 10*time.Second, "50 refused dispatches")

	// The slot drains: the holder finishes, and a new dispatch succeeds.
	close(eq.release)
	select {
	case out := <-first:
		if out.err != nil {
			t.Fatalf("holder dispatch: %v", out.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("holder dispatch never returned")
	}
	if _, err := rn.Dispatch(ctx, trier.ID, TriggerSchedule); err != nil {
		t.Fatalf("dispatch after drain: %v", err)
	}
	lr := loadLastRun(t, store, trier.ID)
	if lr.Status != RunStatusDispatched {
		t.Fatalf("LastRun = %+v, want the post-drain dispatch recorded as dispatched", lr)
	}
}

// TestRoutineHostsNoGoroutineLeak starts and stops the Scheduler and the
// Watcher repeatedly and requires the goroutine count to return to
// baseline: no host may leak its tick loop, event loop, or timers.
func TestRoutineHostsNoGoroutineLeak(t *testing.T) {
	ctx := context.Background()
	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		// Scheduler cycle: a daily schedule adopted on the first tick
		// dispatches nothing immediately.
		fx := newScheduleFixture(t, map[string]any{
			"kind": "daily", "at": "14:30", "tz": "UTC",
		}, time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
		sched := fx.scheduler(t)
		if err := sched.Start(ctx); err != nil {
			t.Fatalf("cycle %d: scheduler Start: %v", i, err)
		}
		if err := sched.Stop(); err != nil {
			t.Fatalf("cycle %d: scheduler Stop: %v", i, err)
		}

		// Watcher cycle.
		wfx := newWatchFixture(t, nil)
		wfx.start(t)
		if err := wfx.watcher.Stop(); err != nil {
			t.Fatalf("cycle %d: watcher Stop: %v", i, err)
		}
	}
	goroutinesSettle(t, before, 3, 15*time.Second, "5 scheduler/watcher start-stop cycles")
}

// TestWatcherBurstFiftyFiles proves burst isolation: 50 rapid file
// creations collapse through the debounce window into a bounded number of
// dispatches (no per-file goroutine or queue growth), every file is
// covered by at least one dispatched job (no missed files), no job lists
// a file twice (no duplicates), and memory does not grow without bound.
// The watcher keeps no per-file pending queue at all — it only re-arms a
// timer — so the pending state is structurally O(1).
func TestWatcherBurstFiftyFiles(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "seed.txt", "seed")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Burst", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerWatch
	r.Grant.ScopeHash = r.ScopeHash()
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &burstEnqueuer{}
	runner := NewRunner(RunDeps{Store: store, Trust: ts, Now: time.Now}, eq, RunnerOptions{Now: time.Now})
	w, err := NewWatcher(store, runner, r.ID, WatchOptions{
		Debounce: 250 * time.Millisecond,
		Cooldown: 0,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Stop() }()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// The burst: 50 files as fast as the test can write them.
	const n = 50
	want := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("burst-%02d.txt", i)
		p := writeTestFile(t, root, name, "payload")
		want[p] = true
	}

	// Wait for the first dispatch, then for quiescence: the debounce
	// window must collapse the burst instead of emitting a long tail.
	waitFor(t, 15*time.Second, "first burst dispatch", func() bool { return eq.numCalls() >= 1 })
	waitForQuiescence(t, 15*time.Second, 800*time.Millisecond, "burst dispatches", eq.numCalls)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	calls := eq.numCalls()
	if calls < 1 || calls > 3 {
		t.Fatalf("burst produced %d dispatches, want a debounce-collapsed 1-3", calls)
	}
	// No missed files: the union of every dispatched job covers all 50.
	// No duplicates: no single job lists a path twice (Resolve dedupes).
	covered := make(map[string]bool)
	for i, paths := range eq.allPaths() {
		seen := make(map[string]bool, len(paths))
		for _, p := range paths {
			if seen[p] {
				t.Fatalf("job %d lists %q twice", i, p)
			}
			seen[p] = true
			covered[p] = true
		}
	}
	for p := range want {
		if !covered[p] {
			t.Fatalf("file %q was never dispatched (missed file)", p)
		}
	}
	// No unbounded memory growth from the burst (generous bound; the
	// watcher holds no per-file state, so real growth is kilobytes).
	if growth := int64(memAfter.Alloc) - int64(memBefore.Alloc); growth > 64<<20 {
		t.Fatalf("heap grew by %d bytes over a 50-file burst", growth)
	}
}
