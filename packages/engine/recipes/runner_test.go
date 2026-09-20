// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// runnerTestSetup builds one trusted device, one source tree with a file,
// and one saved manual-status recipe over it.
func runnerTestSetup(t *testing.T) (*RecipeStore, *trust.MemoryTrustStore, Recipe, string) {
	t.Helper()
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "alpha")
	store := openTestRecipeStore(t)
	r := composableRecipe(t, store, root, "Routine", id)
	return store, ts, r, root
}

// grantTestRecipe records explicit auto-send consent on r via the
// production helper and returns the saved record.
func grantTestRecipe(t *testing.T, store *RecipeStore, r Recipe) Recipe {
	t.Helper()
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	saved, ok, err := store.Load(r.ID)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", err, ok)
	}
	return saved
}

func newTestRunner(store *RecipeStore, ts *trust.MemoryTrustStore, eq Enqueuer, opts RunnerOptions) *Runner {
	if opts.Now == nil {
		opts.Now = func() time.Time { return testNow }
	}
	return NewRunner(RunDeps{Store: store, Trust: ts}, eq, opts)
}

func loadLastRun(t *testing.T, store *RecipeStore, id string) *RecipeRunInfo {
	t.Helper()
	r, ok, err := store.Load(id)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", err, ok)
	}
	if r.LastRun == nil {
		t.Fatalf("no LastRun recorded for recipe %q", id)
	}
	return r.LastRun
}

func TestRunnerManualDispatchNeedsNoGrant(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)

	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	job, err := rn.Dispatch(ctx, r.ID, TriggerManual)
	if err != nil {
		t.Fatalf("manual Dispatch without grant: %v", err)
	}
	if eq.calls != 1 {
		t.Fatalf("Enqueue called %d times, want exactly 1", eq.calls)
	}
	if job.JobID == "" {
		t.Fatalf("no job returned")
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched || lr.Trigger != TriggerManual || lr.JobID != job.JobID {
		t.Fatalf("LastRun = %+v, want dispatched/manual with job id", lr)
	}
	if lr.Detail != "" {
		t.Fatalf("dispatched LastRun should have empty detail, got %q", lr.Detail)
	}
}

func TestRunnerAutomatedRefusedWithoutGrant(t *testing.T) {
	ctx := context.Background()
	for _, reason := range []TriggerReason{TriggerWatch, TriggerSchedule, TriggerRetry} {
		t.Run(string(reason), func(t *testing.T) {
			store, ts, r, _ := runnerTestSetup(t)
			eq := &recordingEnqueuer{}
			rn := newTestRunner(store, ts, eq, RunnerOptions{})
			_, err := rn.Dispatch(ctx, r.ID, reason)
			if err == nil {
				t.Fatalf("%s dispatch without grant accepted", reason)
			}
			if wire.CodeOf(err) != wire.CodeAuth {
				t.Fatalf("error code = %s, want AUTH", wire.CodeOf(err))
			}
			if got := err.Error(); !strings.Contains(got, r.Name) || !strings.Contains(got, "no automation grant") {
				t.Fatalf("error %q does not name the recipe and the cause", got)
			}
			if eq.calls != 0 {
				t.Fatalf("refused dispatch enqueued")
			}
			lr := loadLastRun(t, store, r.ID)
			if lr.Status != RunStatusRefused || lr.Trigger != reason {
				t.Fatalf("LastRun = %+v, want refused/%s", lr, reason)
			}
			if lr.Detail == "" {
				t.Fatalf("refused LastRun must carry the refusal detail")
			}
		})
	}
}

func TestRunnerWatchWithGrantDispatchesOnce(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	job, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
	if err != nil {
		t.Fatalf("watch Dispatch with grant: %v", err)
	}
	if eq.calls != 1 {
		t.Fatalf("Enqueue called %d times, want exactly 1", eq.calls)
	}
	if job.JobID == "" {
		t.Fatalf("no job returned")
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched || lr.JobID != job.JobID {
		t.Fatalf("LastRun = %+v, want dispatched", lr)
	}
}

func TestRunnerMaterialChangeRevokesGrant(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)
	if !r.GrantValid(testNow) {
		t.Fatalf("grant should be valid before the material change")
	}

	// Material change through the production edit path.
	updated := r
	other := t.TempDir()
	writeTestFile(t, other, "b.txt", "bravo")
	updated.Sources = append(updated.Sources, RecipeSource{Path: other, Recursive: true})
	after, err := ApplyUpdate(store, updated)
	if err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if after.Grant.AutoSend {
		t.Fatalf("material change did not clear AutoSend")
	}
	if !after.Grant.GrantedAt.IsZero() {
		t.Fatalf("material change did not clear GrantedAt")
	}
	if after.Grant.ConsentVersion != r.Grant.ConsentVersion+1 {
		t.Fatalf("ConsentVersion = %d, want %d", after.Grant.ConsentVersion, r.Grant.ConsentVersion+1)
	}

	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	_, err = rn.Dispatch(ctx, after.ID, TriggerWatch)
	if err == nil {
		t.Fatalf("watch dispatch accepted after material change revoked the grant")
	}
	if wire.CodeOf(err) != wire.CodeAuth {
		t.Fatalf("error code = %s, want AUTH", wire.CodeOf(err))
	}
	if got := err.Error(); !strings.Contains(got, "revoked by material change") || !strings.Contains(got, after.Name) {
		t.Fatalf("error %q does not name the material-change cause", got)
	}
	if eq.calls != 0 {
		t.Fatalf("refused dispatch enqueued")
	}
	lr := loadLastRun(t, store, after.ID)
	if lr.Status != RunStatusRefused {
		t.Fatalf("LastRun = %+v, want refused", lr)
	}
}

func TestRunnerGrantThenRevoke(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	RevokeAutomation(&r)
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	saved, _, _ := store.Load(r.ID)
	if saved.Grant.AutoSend || !saved.Grant.GrantedAt.IsZero() {
		t.Fatalf("revoke did not clear the grant: %+v", saved.Grant)
	}

	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	_, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
	if err == nil {
		t.Fatalf("watch dispatch accepted after revoke")
	}
	if wire.CodeOf(err) != wire.CodeAuth {
		t.Fatalf("error code = %s, want AUTH", wire.CodeOf(err))
	}
	if eq.calls != 0 {
		t.Fatalf("refused dispatch enqueued")
	}
}

func TestRunnerDisabledRefusesEveryReason(t *testing.T) {
	ctx := context.Background()
	for _, reason := range []TriggerReason{TriggerManual, TriggerWatch, TriggerSchedule, TriggerRetry} {
		t.Run(string(reason), func(t *testing.T) {
			store, ts, r, _ := runnerTestSetup(t)
			r = grantTestRecipe(t, store, r)
			r.Status = RecipeDisabled
			if err := store.Save(r); err != nil {
				t.Fatalf("Save: %v", err)
			}
			eq := &recordingEnqueuer{}
			rn := newTestRunner(store, ts, eq, RunnerOptions{})
			_, err := rn.Dispatch(ctx, r.ID, reason)
			if err == nil {
				t.Fatalf("disabled recipe dispatched for reason %q", reason)
			}
			if !strings.Contains(err.Error(), "is disabled") {
				t.Fatalf("error %q does not say disabled", err)
			}
			if eq.calls != 0 {
				t.Fatalf("disabled dispatch enqueued")
			}
			lr := loadLastRun(t, store, r.ID)
			if lr.Status != RunStatusRefused {
				t.Fatalf("LastRun = %+v, want refused", lr)
			}
		})
	}
}

func TestRunnerExpiredRefusesAutomated(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	// Expire the recipe before granting: the grant binds to the scope,
	// and expiry is enforced at dispatch time.
	r.ExpiresAt = testNow.Add(-time.Hour)
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	r = grantTestRecipe(t, store, r)

	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	_, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
	if err == nil {
		t.Fatalf("expired recipe dispatched")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error %q does not say expired", err)
	}
	if eq.calls != 0 {
		t.Fatalf("expired dispatch enqueued")
	}
}

// blockingEnqueuer blocks inside Enqueue until release is closed (or the
// context ends), tracking the peak in-flight count for bound tests.
type blockingEnqueuer struct {
	mu      sync.Mutex
	cur     int
	peak    int
	entered chan struct{}
	release chan struct{}
	waitCtx bool
	jobs    int32
}

func (b *blockingEnqueuer) Enqueue(ctx context.Context, _ []string, _ []EnqueueRecipient, _ jobs.RetryPolicy, _ netpolicy.Policy, _ *wire.Provenance) (jobs.Job, error) {
	b.mu.Lock()
	b.cur++
	if b.cur > b.peak {
		b.peak = b.cur
	}
	b.mu.Unlock()
	select {
	case b.entered <- struct{}{}:
	default:
	}
	defer func() {
		b.mu.Lock()
		b.cur--
		b.mu.Unlock()
	}()
	if b.waitCtx {
		<-ctx.Done()
		return jobs.Job{}, ctx.Err()
	}
	select {
	case <-b.release:
		n := atomic.AddInt32(&b.jobs, 1)
		return jobs.Job{JobID: "job-" + strconv.Itoa(int(n))}, nil
	case <-ctx.Done():
		return jobs.Job{}, ctx.Err()
	}
}

func (b *blockingEnqueuer) peakInFlight() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}

func TestRunnerSameRecipeDedupes(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	eq := &blockingEnqueuer{entered: make(chan struct{}, 1), release: make(chan struct{})}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})

	first := make(chan DispatchOut, 1)
	go func() {
		job, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
		first <- DispatchOut{job: job, err: err}
	}()
	select {
	case <-eq.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("first dispatch never reached the enqueuer")
	}

	// The second dispatch for the same recipe must get the deterministic
	// skip signal, not a failure and not a second job.
	_, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second dispatch err = %v, want ErrAlreadyRunning", err)
	}

	close(eq.release)
	var out DispatchOut
	select {
	case out = <-first:
	case <-time.After(5 * time.Second):
		t.Fatalf("first dispatch never returned")
	}
	if out.err != nil {
		t.Fatalf("first dispatch: %v", out.err)
	}
	if out.job.JobID == "" {
		t.Fatalf("first dispatch returned no job")
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched {
		t.Fatalf("LastRun = %+v, want the winner recorded as dispatched", lr)
	}
}

// DispatchOut carries one Dispatch result across a goroutine boundary.
type DispatchOut struct {
	job jobs.Job
	err error
}

func TestRunnerMaxConcurrentBound(t *testing.T) {
	ctx := context.Background()
	store, ts, _, _ := runnerTestSetup(t)
	// Five distinct granted recipes; the runner allows two in flight.
	var ids []string
	for i := 0; i < 5; i++ {
		root := t.TempDir()
		writeTestFile(t, root, "f.txt", "data")
		r := composableRecipe(t, store, root, "R"+strconv.Itoa(i), testIdentity(ctx, t, ts, "dev"))
		r = grantTestRecipe(t, store, r)
		ids = append(ids, r.ID)
	}

	eq := &blockingEnqueuer{entered: make(chan struct{}, 5), release: make(chan struct{})}
	rn := newTestRunner(store, ts, eq, RunnerOptions{MaxConcurrent: 2})

	results := make(chan DispatchOut, len(ids))
	for _, id := range ids {
		go func(id string) {
			job, err := rn.Dispatch(ctx, id, TriggerWatch)
			results <- DispatchOut{job: job, err: err}
		}(id)
	}
	// Wait until every goroutine has observably attempted admission: each
	// one either entered the enqueuer or returned with the busy signal.
	// The admission mutex guarantees at most MaxConcurrent enter, so the
	// rest must be busy — no sleeps, no scheduling assumptions.
	deadline := time.After(10 * time.Second)
	for len(eq.entered)+len(results) < len(ids) {
		select {
		case <-deadline:
			t.Fatalf("not all dispatches attempted admission (entered=%d results=%d)",
				len(eq.entered), len(results))
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(eq.release)

	var dispatched, busy int
	for range ids {
		var out DispatchOut
		select {
		case out = <-results:
		case <-time.After(5 * time.Second):
			t.Fatalf("a dispatch never returned")
		}
		switch {
		case out.err == nil:
			dispatched++
		case errors.Is(out.err, ErrRunnerBusy):
			busy++
		default:
			t.Fatalf("unexpected dispatch error: %v", out.err)
		}
	}
	if dispatched != 2 || busy != 3 {
		t.Fatalf("dispatched=%d busy=%d, want 2 and 3", dispatched, busy)
	}
	if peak := eq.peakInFlight(); peak > 2 {
		t.Fatalf("peak in-flight %d exceeded MaxConcurrent 2", peak)
	}
}

func TestRunnerContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	eq := &blockingEnqueuer{entered: make(chan struct{}, 1), waitCtx: true}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})

	done := make(chan DispatchOut, 1)
	go func() {
		job, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
		done <- DispatchOut{job: job, err: err}
	}()
	select {
	case <-eq.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("dispatch never reached the enqueuer")
	}
	cancel()

	var out DispatchOut
	select {
	case out = <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("dispatch did not return after cancel")
	}
	if !errors.Is(out.err, context.Canceled) {
		t.Fatalf("dispatch err = %v, want context.Canceled", out.err)
	}
	// The cancellation must be recorded as a failure, not lost silently.
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusFailed {
		t.Fatalf("LastRun = %+v, want failed", lr)
	}
	if !strings.Contains(lr.Detail, "canceled") {
		t.Fatalf("LastRun detail %q does not mention cancellation", lr.Detail)
	}
}

func TestRunnerBudgetEnforcedAutomated(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	// Tighten the budget before granting so the grant binds to it; the
	// fixture file is 5 bytes, the budget allows 1.
	r.Budgets.MaxBytesPerRun = 1
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	r = grantTestRecipe(t, store, r)

	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	_, err := rn.Dispatch(ctx, r.ID, TriggerWatch)
	if err == nil {
		t.Fatalf("over-budget automated dispatch accepted")
	}
	if got := err.Error(); !strings.Contains(got, "budget") {
		t.Fatalf("error %q does not name the budget", got)
	}
	if eq.calls != 0 {
		t.Fatalf("over-budget dispatch enqueued")
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusRefused {
		t.Fatalf("LastRun = %+v, want refused", lr)
	}
}

func TestRunnerUnknownReasonRefused(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	_, err := rn.Dispatch(ctx, r.ID, TriggerReason("cron"))
	if err == nil {
		t.Fatalf("unknown trigger reason accepted")
	}
	if wire.CodeOf(err) != wire.CodeStorage {
		t.Fatalf("error code = %s, want STORAGE", wire.CodeOf(err))
	}
	if eq.calls != 0 {
		t.Fatalf("refused dispatch enqueued")
	}
}

func TestRunnerStopRefusesNewDispatches(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	eq := &recordingEnqueuer{}
	rn := newTestRunner(store, ts, eq, RunnerOptions{})
	rn.Stop()
	_, err := rn.Dispatch(ctx, r.ID, TriggerManual)
	if err == nil {
		t.Fatalf("dispatch accepted after Stop")
	}
	if !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("error %q does not say stopped", err)
	}
	if eq.calls != 0 {
		t.Fatalf("dispatch after Stop enqueued")
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusRefused {
		t.Fatalf("LastRun = %+v, want refused", lr)
	}
}

func TestRunnerOptionsClamp(t *testing.T) {
	store, ts, _, _ := runnerTestSetup(t)
	eq := &recordingEnqueuer{}
	if rn := newTestRunner(store, ts, eq, RunnerOptions{}); rn.maxConcurrent != 1 {
		t.Fatalf("default maxConcurrent = %d, want 1", rn.maxConcurrent)
	}
	if rn := newTestRunner(store, ts, eq, RunnerOptions{MaxConcurrent: 99}); rn.maxConcurrent != 4 {
		t.Fatalf("clamped maxConcurrent = %d, want 4", rn.maxConcurrent)
	}
	if rn := newTestRunner(store, ts, eq, RunnerOptions{MaxConcurrent: 3}); rn.maxConcurrent != 3 {
		t.Fatalf("maxConcurrent = %d, want 3", rn.maxConcurrent)
	}
}

func TestGrantValid(t *testing.T) {
	_, _, r, _ := runnerTestSetup(t)

	if r.GrantValid(testNow) {
		t.Fatalf("grant-less recipe validates")
	}
	g := r
	g.Grant = RecipeGrant{AutoSend: true, ConsentVersion: 1, GrantedAt: testNow, ScopeHash: g.ScopeHash()}
	if !g.GrantValid(testNow) {
		t.Fatalf("well-formed grant does not validate")
	}
	// Scope drift.
	drifted := g
	drifted.Sources = append(drifted.Sources, RecipeSource{Path: "/data/other", Recursive: false})
	if drifted.GrantValid(testNow) {
		t.Fatalf("scope-drifted grant validates")
	}
	// Missing timestamp / version.
	for _, mutate := range []struct {
		name string
		fn   func(*Recipe)
	}{
		{"zero GrantedAt", func(r *Recipe) { r.Grant.GrantedAt = time.Time{} }},
		{"zero ConsentVersion", func(r *Recipe) { r.Grant.ConsentVersion = 0 }},
		{"autoSend off", func(r *Recipe) { r.Grant.AutoSend = false }},
	} {
		m := g
		mutate.fn(&m)
		if m.GrantValid(testNow) {
			t.Fatalf("%s: invalid grant validates", mutate.name)
		}
	}
	// Future-dated grant (clock skew or hand-edited record).
	future := g
	future.Grant.GrantedAt = testNow.Add(time.Hour)
	if future.GrantValid(testNow) {
		t.Fatalf("future-dated grant validates")
	}
}

func TestGrantAutomationHelper(t *testing.T) {
	_, _, r, _ := runnerTestSetup(t)

	// approval-required cannot be granted: approve first.
	r.Status = RecipeApprovalRequired
	if err := GrantAutomation(&r, testNow); err == nil {
		t.Fatalf("grant on approval-required accepted")
	} else if !strings.Contains(err.Error(), "recipe approve") {
		t.Fatalf("error %q does not point at approval", err)
	}
	// Disabled cannot be granted either.
	r.Status = RecipeDisabled
	if err := GrantAutomation(&r, testNow); err == nil {
		t.Fatalf("grant on disabled accepted")
	}
	// Manual grants cleanly and validates afterwards.
	r.Status = RecipeManual
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if !r.Grant.AutoSend || r.Grant.GrantedAt.IsZero() || r.Grant.ConsentVersion <= 0 {
		t.Fatalf("grant fields not set: %+v", r.Grant)
	}
	if r.Grant.ScopeHash != r.ScopeHash() {
		t.Fatalf("grant scope hash not bound to current scope")
	}
	if !r.GrantValid(testNow) {
		t.Fatalf("freshly granted recipe does not validate")
	}
	if err := ValidateRecipe(r); err != nil {
		t.Fatalf("granted recipe fails validation: %v", err)
	}
	// Re-granting keeps the current consent version (grant == current).
	cv := r.Grant.ConsentVersion
	if err := GrantAutomation(&r, testNow.Add(time.Minute)); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if r.Grant.ConsentVersion != cv {
		t.Fatalf("re-grant changed consent version %d -> %d", cv, r.Grant.ConsentVersion)
	}
	// Revoking clears the active consent but keeps version and status.
	RevokeAutomation(&r)
	if r.Grant.AutoSend || !r.Grant.GrantedAt.IsZero() {
		t.Fatalf("revoke did not clear the grant: %+v", r.Grant)
	}
	if r.Grant.ConsentVersion != cv {
		t.Fatalf("revoke changed the consent version")
	}
	if r.Status != RecipeManual {
		t.Fatalf("revoke changed the status")
	}
	if r.GrantValid(testNow) {
		t.Fatalf("revoked grant still validates")
	}
}

func TestRecordRun(t *testing.T) {
	store, _, r, _ := runnerTestSetup(t)

	info := RecipeRunInfo{Trigger: TriggerWatch, Status: RunStatusDispatched, JobID: "job-1"}
	if err := store.RecordRun(r.ID, info); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched || lr.Trigger != TriggerWatch || lr.JobID != "job-1" {
		t.Fatalf("LastRun = %+v", lr)
	}
	if lr.At.IsZero() {
		t.Fatalf("zero At was not filled")
	}
	// The ledger survives the checksum round-trip and a second record
	// replaces the first.
	info2 := RecipeRunInfo{At: testNow, Trigger: TriggerRetry, Status: RunStatusFailed, Detail: "boom"}
	if err := store.RecordRun(r.ID, info2); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}
	lr = loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusFailed || lr.Detail != "boom" || !lr.At.Equal(testNow) {
		t.Fatalf("LastRun = %+v", lr)
	}
	// Unknown recipe fails closed.
	if err := store.RecordRun("00000000000000000000000000000000", info); err == nil {
		t.Fatalf("RecordRun on unknown recipe accepted")
	}
}

func TestNewRecipesCarryNoGrantOrLedger(t *testing.T) {
	r, err := NewRecipe("Fresh", testNow)
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	if r.Grant.AutoSend || !r.Grant.GrantedAt.IsZero() {
		t.Fatalf("new recipe carries a grant: %+v", r.Grant)
	}
	if r.LastRun != nil {
		t.Fatalf("new recipe carries a last-run entry")
	}

	// Import clears both the grant and any ledger the export carried.
	store, _, src, _ := runnerTestSetup(t)
	src = grantTestRecipe(t, store, src)
	if err := store.RecordRun(src.ID, RecipeRunInfo{Trigger: TriggerWatch, Status: RunStatusDispatched}); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}
	loaded, _, _ := store.Load(src.ID)
	data, err := Export(loaded)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	imp, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imp.Grant.AutoSend || !imp.Grant.GrantedAt.IsZero() {
		t.Fatalf("import restored a grant: %+v", imp.Grant)
	}
	if imp.LastRun != nil {
		t.Fatalf("import restored a last-run entry")
	}
	if imp.Status != RecipeDisabled {
		t.Fatalf("import status = %q, want disabled", imp.Status)
	}
}

func TestDryRunNeedsNoGrant(t *testing.T) {
	// Preview, Resolve and PlanDTO work on disabled, grant-less recipes:
	// dry-run paths never require (or create) automation consent.
	_, _, r, _ := runnerTestSetup(t)
	r.Status = RecipeDisabled
	_ = Preview(r)
	plan, err := Resolve(r, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Files) != 1 {
		t.Fatalf("plan has %d files", len(plan.Files))
	}
	_ = PlanDTO(plan)
}

func TestRunWithTriggerManualMatchesRun(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)

	// RunWithTrigger(manual) behaves exactly like Run, including the
	// status-gate messages.
	eq := &recordingEnqueuer{}
	if _, err := RunWithTrigger(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID, TriggerManual); err != nil {
		t.Fatalf("RunWithTrigger manual: %v", err)
	}
	if eq.calls != 1 {
		t.Fatalf("Enqueue called %d times, want 1", eq.calls)
	}

	r.Status = RecipeApprovalRequired
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, errRun := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID)
	_, errTrig := RunWithTrigger(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID, TriggerManual)
	if errRun == nil || errTrig == nil {
		t.Fatalf("approval-required run accepted")
	}
	if errRun.Error() != errTrig.Error() {
		t.Fatalf("Run %q != RunWithTrigger(manual) %q", errRun, errTrig)
	}
}
