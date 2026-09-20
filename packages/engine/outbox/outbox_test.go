package outbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/transfer"
)

// testClock is a mutable clock for deterministic backoff/expiry tests.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// writeTempFile creates a file with the given content under dir and returns its path.
func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newTestOutbox builds an Outbox backed by a temp jobs dir with the given sender.
func newTestOutbox(t *testing.T, clk *testClock, send SendFunc) *Outbox {
	t.Helper()
	dir := t.TempDir()
	store, err := jobs.OpenJobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &Outbox{store: store, send: send, now: clk.now}
}

func testRecipients() []RecipientRef {
	return []RecipientRef{
		{DeviceID: "dev-alice-0000000000000001", Label: "alice"},
		{DeviceID: "dev-bob-000000000000000002", Label: "bob"},
	}
}

func okSender(digest string) SendFunc {
	return func(_ context.Context, job jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		return SendOutcome{Status: transfer.StatusOk, Digest: digest, BytesTransferred: job.TotalSize}
	}
}

func TestEnqueue_QueuesJobWithAttempts(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)}
	ob := newTestOutbox(t, clk, nil)
	srcDir := t.TempDir()
	p := writeTempFile(t, srcDir, "hello.txt", "hello outbox")

	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if job.Status != jobs.JobQueued {
		t.Fatalf("job status = %q, want queued", job.Status)
	}
	if len(job.Attempts) != 1 || job.Attempts[0].DeviceID != "dev-alice-0000000000000001" {
		t.Fatalf("unexpected attempts: %+v", job.Attempts)
	}
	if job.Attempts[0].Status != jobs.AttemptQueued {
		t.Fatalf("attempt status = %q, want queued", job.Attempts[0].Status)
	}
	if len(job.Files) != 1 || job.Files[0].Name != "hello.txt" {
		t.Fatalf("unexpected files: %+v", job.Files)
	}
	// The job must survive a store reload (restart durability).
	loaded, ok, err := ob.store.Load(job.JobID)
	if err != nil || !ok {
		t.Fatalf("reload: ok=%v err=%v", ok, err)
	}
	if loaded.Status != jobs.JobQueued || len(loaded.Attempts) != 1 {
		t.Fatalf("reloaded job mismatch: %+v", loaded.Status)
	}
	// Sources sidecar must exist so dispatch can re-verify the files.
	sp, err := sourcesPath(ob.store.Dir(), job.JobID)
	if err != nil {
		t.Fatalf("sourcesPath: %v", err)
	}
	if _, err := os.Stat(sp); err != nil {
		t.Fatalf("sources sidecar missing: %v", err)
	}
}

func TestEnqueue_RejectsNoRecipients(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, nil)
	p := writeTempFile(t, t.TempDir(), "a.txt", "x")
	if _, err := ob.Enqueue(context.Background(), []string{p}, nil, jobs.DefaultRetryPolicy()); err == nil {
		t.Fatal("Enqueue with no recipients should fail")
	}
}

func TestDispatch_OfflineRecipientBackoff(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)}
	calls := 0
	offline := func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOffline, Error: "peer not found"}
	}
	ob := newTestOutbox(t, clk, offline)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	policy := jobs.DefaultRetryPolicy() // base 30s, max 5
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], policy)
	if err != nil {
		t.Fatal(err)
	}

	rep, err := ob.DispatchOnce(context.Background(), DispatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(rep.Results))
	}

	got, _, _ := ob.store.Load(job.JobID)
	a := got.Attempts[0]
	if a.Status != jobs.AttemptInterrupted {
		t.Fatalf("attempt status = %q, want interrupted", a.Status)
	}
	if a.Attempts != 1 {
		t.Fatalf("attempt count = %d, want 1", a.Attempts)
	}
	wantRetry := clk.t.Add(30 * time.Second)
	if !a.NextRetryAt.Equal(wantRetry) {
		t.Fatalf("NextRetryAt = %v, want %v", a.NextRetryAt, wantRetry)
	}
	if a.LastError == "" {
		t.Fatal("LastError should record the offline failure")
	}
	// Delivery honesty: an offline target must not complete or fail the job.
	if got.Status == jobs.JobCompleted || got.Status == jobs.JobFailed {
		t.Fatalf("job status = %q after offline attempt; must stay non-terminal", got.Status)
	}

	// Immediate re-dispatch must NOT call send again (backoff not elapsed).
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("send calls = %d after immediate re-dispatch, want 1 (backoff)", calls)
	}

	// After the backoff elapses, dispatch retries with doubled backoff.
	clk.advance(31 * time.Second)
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("send calls = %d after backoff elapsed, want 2", calls)
	}
	got, _, _ = ob.store.Load(job.JobID)
	a = got.Attempts[0]
	if a.Attempts != 2 {
		t.Fatalf("attempt count = %d, want 2", a.Attempts)
	}
	wantRetry2 := clk.t.Add(60 * time.Second)
	if !a.NextRetryAt.Equal(wantRetry2) {
		t.Fatalf("NextRetryAt = %v, want doubled %v", a.NextRetryAt, wantRetry2)
	}
}

func TestDispatch_OkCompletesJob(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	// 64-hex digest stand-in.
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ob := newTestOutbox(t, clk, okSender(digest))
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients(), jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ob.DispatchOnce(context.Background(), DispatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(rep.Results))
	}
	got, _, _ := ob.store.Load(job.JobID)
	for _, a := range got.Attempts {
		if a.Status != jobs.AttemptCompleted {
			t.Fatalf("device %s status = %q, want completed", a.DeviceID, a.Status)
		}
		if a.VerifiedDigest != digest {
			t.Fatalf("verified digest not recorded: %q", a.VerifiedDigest)
		}
	}
	if got.Status != jobs.JobCompleted {
		t.Fatalf("job status = %q, want completed", got.Status)
	}
	if got.Lease != nil {
		t.Fatal("terminal job must not hold a lease")
	}
}

func TestDispatch_RefusedIsTerminal(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	calls := 0
	refused := func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusRefused, Error: "peer declined"}
	}
	ob := newTestOutbox(t, clk, refused)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptFailed {
		t.Fatalf("attempt status = %q, want failed", got.Attempts[0].Status)
	}
	if got.Status != jobs.JobFailed {
		t.Fatalf("job status = %q, want failed", got.Status)
	}
	// A refused target must not be retried automatically.
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1 (refused is terminal)", calls)
	}
}

func TestDispatch_CancelStopsDispatch(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	calls := 0
	never := func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOk}
	}
	ob := newTestOutbox(t, clk, never)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients(), jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := ob.Cancel(job.JobID); err != nil {
		t.Fatal(err)
	}
	rep, err := ob.DispatchOnce(context.Background(), DispatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("send calls = %d after cancel, want 0", calls)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("results = %d after cancel, want 0", len(rep.Results))
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Status != jobs.JobCancelled {
		t.Fatalf("job status = %q, want cancelled", got.Status)
	}
}

func TestDispatch_ExpiredJobFailsAttempts(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)}
	calls := 0
	never := func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOk}
	}
	ob := newTestOutbox(t, clk, never)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	policy := jobs.DefaultRetryPolicy()
	policy.ExpiresAt = clk.t.Add(-time.Minute) // already expired
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("send calls = %d for expired job, want 0", calls)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptFailed {
		t.Fatalf("attempt status = %q, want failed", got.Attempts[0].Status)
	}
	if got.Status != jobs.JobFailed {
		t.Fatalf("job status = %q, want failed", got.Status)
	}
}

func TestDispatch_ChangedSourceFailsJob(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	calls := 0
	never := func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOk}
	}
	ob := newTestOutbox(t, clk, never)
	srcDir := t.TempDir()
	p := writeTempFile(t, srcDir, "a.txt", "original")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	// Change the source after enqueue: it must never be silently resent.
	if err := os.WriteFile(p, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("send calls = %d after source change, want 0 (never silently resent)", calls)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptFailed {
		t.Fatalf("attempt status = %q, want failed", got.Attempts[0].Status)
	}
	if got.Attempts[0].LastError == "" {
		t.Fatal("LastError should explain the stale source")
	}
}

func TestDispatch_RequiresSender(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, nil) // no production sender wired
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	if _, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err == nil {
		t.Fatal("DispatchOnce without a sender must fail closed")
	}
}

func TestDispatch_RestartRequeuesInterrupted(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	hang := func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		// Simulate a crash mid-dispatch: leave the attempt active in the store
		// and never report an outcome.
		return SendOutcome{Status: transfer.StatusOffline, Error: "simulated"}
	}
	_ = hang
	calls := 0
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOk, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	// Fake a crash: mark the attempt active under a stale lease directly in the store.
	loaded, _, _ := ob.store.Load(job.JobID)
	loaded.Attempts[0].Status = jobs.AttemptActive
	loaded.Attempts[0].Attempts = 1
	loaded.Lease = &jobs.Lease{Owner: "dead-host:9999", AcquiredAt: clk.t.Add(-time.Hour), ExpiresAt: clk.t.Add(-59 * time.Minute)}
	loaded.Status = jobs.JobDispatching
	if err := ob.store.Save(loaded); err != nil {
		t.Fatal(err)
	}
	// The next dispatch must adopt the stale lease and re-queue as
	// interrupted — never mark delivered.
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1 (interrupted work re-dispatched)", calls)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptCompleted {
		t.Fatalf("attempt status = %q, want completed after re-dispatch", got.Attempts[0].Status)
	}
}

func TestRetryFailed_RequeuesWithFreshBudget(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	calls := 0
	failOnce := func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		if calls == 1 {
			return SendOutcome{Status: transfer.StatusFailed, Error: "auth error"}
		}
		return SendOutcome{Status: transfer.StatusOk, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	}
	ob := newTestOutbox(t, clk, failOnce)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	policy := jobs.DefaultRetryPolicy()
	policy.MaxAttempts = 1 // exhaust the budget on the first failure
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptFailed {
		t.Fatalf("attempt status = %q, want failed", got.Attempts[0].Status)
	}
	// Explicit operator retry grants a fresh budget.
	requeued, err := ob.RetryFailed(job.JobID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requeued != 1 {
		t.Fatalf("requeued = %d, want 1", requeued)
	}
	got, _, _ = ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptQueued || got.Attempts[0].Attempts != 0 {
		t.Fatalf("after retry: status=%q attempts=%d, want queued/0",
			got.Attempts[0].Status, got.Attempts[0].Attempts)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("send calls = %d, want 2", calls)
	}
	got, _, _ = ob.store.Load(job.JobID)
	if got.Status != jobs.JobCompleted {
		t.Fatalf("job status = %q, want completed", got.Status)
	}
}

func TestRetryFailed_DeviceFilter(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		return SendOutcome{Status: transfer.StatusFailed, Error: "x"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	policy := jobs.DefaultRetryPolicy()
	policy.MaxAttempts = 1
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	// Retry only bob.
	n, err := ob.RetryFailed(job.JobID, []string{"dev-bob-000000000000000002"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("requeued = %d, want 1", n)
	}
	got, _, _ := ob.store.Load(job.JobID)
	for _, a := range got.Attempts {
		want := jobs.AttemptFailed
		if a.DeviceID == "dev-bob-000000000000000002" {
			want = jobs.AttemptQueued
		}
		if a.Status != want {
			t.Fatalf("device %s status = %q, want %q", a.DeviceID, a.Status, want)
		}
	}
}

func TestEnqueue_DuplicateRecipientsRejected(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, nil)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	recips := []RecipientRef{
		{DeviceID: "dev-alice-0000000000000001", Label: "alice"},
		{DeviceID: "dev-alice-0000000000000001", Label: "alice-again"},
	}
	if _, err := ob.Enqueue(context.Background(), []string{p}, recips, jobs.DefaultRetryPolicy()); err == nil {
		t.Fatal("expected duplicate recipient rejection")
	}
}

func TestDispatch_CorruptSidecarFailsJob(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	calls := 0
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOk, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecarPath(t, ob, job.JobID), []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("sender must not run with a corrupt sidecar, calls=%d", calls)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Status != jobs.JobFailed {
		t.Fatalf("job status = %q, want failed", got.Status)
	}
}

func TestDispatch_MissingSourceFailsJob(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	calls := 0
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOk, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("sender must not run with a missing source, calls=%d", calls)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Status != jobs.JobFailed {
		t.Fatalf("job status = %q, want failed", got.Status)
	}
}

func TestDispatch_AttemptExhaustionFailsJob(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		return SendOutcome{Status: transfer.StatusFailed, Error: "peer unreachable"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	policy := jobs.RetryPolicy{MaxAttempts: 2, BaseBackoff: time.Second, MaxBackoff: time.Minute}
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], policy)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
			t.Fatal(err)
		}
		clk.advance(2 * time.Second)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Status != jobs.JobFailed {
		t.Fatalf("job status = %q, want failed after exhausting attempts", got.Status)
	}
	if got.Attempts[0].Status != jobs.AttemptFailed {
		t.Fatalf("attempt status = %q, want failed", got.Attempts[0].Status)
	}
}

func TestDispatch_MixedOutcomes(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, attempt jobs.RecipientAttempt, _ []string) SendOutcome {
		if strings.HasSuffix(attempt.DeviceID, "0000000000000001") {
			return SendOutcome{Status: transfer.StatusOk, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
		}
		return SendOutcome{Status: transfer.StatusFailed, Error: "refused"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	policy := jobs.RetryPolicy{MaxAttempts: 1, BaseBackoff: time.Second, MaxBackoff: time.Minute}
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients(), policy)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ob.DispatchOnce(context.Background(), DispatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(rep.Results))
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptCompleted {
		t.Fatalf("attempt 0 = %q, want completed", got.Attempts[0].Status)
	}
	if got.Attempts[1].Status != jobs.AttemptFailed {
		t.Fatalf("attempt 1 = %q, want failed", got.Attempts[1].Status)
	}
	if got.Status != jobs.JobFailed {
		t.Fatalf("job status = %q, want failed (one recipient failed)", got.Status)
	}
}

func TestDispatch_OkWithoutDigestFails(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		return SendOutcome{Status: transfer.StatusOk, Digest: "not-hex"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	policy := jobs.RetryPolicy{MaxAttempts: 1, BaseBackoff: time.Second, MaxBackoff: time.Minute}
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.DispatchOnce(context.Background(), DispatchOptions{}); err != nil {
		t.Fatal(err)
	}
	got, _, _ := ob.store.Load(job.JobID)
	if got.Attempts[0].Status != jobs.AttemptFailed {
		t.Fatalf("attempt status = %q, want failed (ok without valid digest)", got.Attempts[0].Status)
	}
	if !strings.Contains(got.Attempts[0].LastError, "digest") {
		t.Fatalf("last error %q should mention the digest", got.Attempts[0].LastError)
	}
}

func TestDispatch_CancelDuringSendDropsResult(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ob := newTestOutbox(t, clk, func(_ context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		once.Do(func() { close(started) })
		<-release
		return SendOutcome{Status: transfer.StatusOk, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan DispatchReport, 1)
	go func() {
		rep, _ := ob.DispatchOnce(context.Background(), DispatchOptions{})
		done <- rep
	}()
	<-started
	if err := ob.Cancel(job.JobID); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	got, _, _ := ob.store.Load(job.JobID)
	if got.Status != jobs.JobCancelled {
		t.Fatalf("job status = %q, want cancelled (in-flight result must not resurrect it)", got.Status)
	}
	if got.Attempts[0].Status == jobs.AttemptCompleted {
		t.Fatal("attempt must not be completed after cancel")
	}
}

func TestDispatch_ParallelJobs(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	var mu sync.Mutex
	var seen []string
	ob := newTestOutbox(t, clk, func(_ context.Context, job jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		mu.Lock()
		seen = append(seen, job.JobID)
		mu.Unlock()
		return SendOutcome{Status: transfer.StatusOk, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	for i := 0; i < 4; i++ {
		if _, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := ob.DispatchOnce(context.Background(), DispatchOptions{Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	if rep.JobsDispatched != 4 {
		t.Fatalf("dispatched = %d, want 4", rep.JobsDispatched)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 4 {
		t.Fatalf("sender calls = %d, want 4", len(seen))
	}
}

func sidecarPath(t *testing.T, ob *Outbox, jobID string) string {
	t.Helper()
	p, err := sourcesPath(ob.store.Dir(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
