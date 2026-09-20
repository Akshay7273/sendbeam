package jobs

import (
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

const testDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func testFiles() []JobFile {
	return []JobFile{
		{Name: "a.txt", Size: 10, Digest: testDigest},
		{Name: "b.txt", Size: 20, Digest: testDigest},
	}
}

func testAttempts() []RecipientAttempt {
	return []RecipientAttempt{
		{DeviceID: "dev1", Label: "Laptop"},
		{DeviceID: "dev2", Label: "Phone"},
	}
}

func mustJob(t *testing.T) Job {
	t.Helper()
	j, err := NewJob(strings.Repeat("a", 32), testFiles(), testAttempts(), DefaultRetryPolicy(), testNow)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	return j
}

func TestNewJobValidation(t *testing.T) {
	j := mustJob(t)
	if j.Status != JobDraft {
		t.Fatalf("new job status = %q, want draft", j.Status)
	}
	if j.TotalSize != 30 {
		t.Fatalf("total size = %d, want 30", j.TotalSize)
	}
	if j.SourceFingerprint == "" {
		t.Fatal("empty source fingerprint")
	}
	for _, a := range j.Attempts {
		if a.Status != AttemptQueued {
			t.Fatalf("attempt status = %q, want queued", a.Status)
		}
	}

	if _, err := NewJob("short", testFiles(), testAttempts(), DefaultRetryPolicy(), testNow); err == nil {
		t.Fatal("short job id accepted")
	}
	if _, err := NewJob(strings.Repeat("A", 32), testFiles(), testAttempts(), DefaultRetryPolicy(), testNow); err == nil {
		t.Fatal("uppercase job id accepted")
	}
	if _, err := NewJob(strings.Repeat("a", 32), nil, testAttempts(), DefaultRetryPolicy(), testNow); err == nil {
		t.Fatal("empty files accepted")
	}
	if _, err := NewJob(strings.Repeat("a", 32), testFiles(), nil, DefaultRetryPolicy(), testNow); err == nil {
		t.Fatal("empty attempts accepted")
	}
	dup := testAttempts()
	dup = append(dup, RecipientAttempt{DeviceID: "dev1", Label: "Dupe"})
	if _, err := NewJob(strings.Repeat("a", 32), testFiles(), dup, DefaultRetryPolicy(), testNow); err == nil {
		t.Fatal("duplicate device id accepted")
	}
	badPolicy := DefaultRetryPolicy()
	badPolicy.MaxAttempts = 0
	if _, err := NewJob(strings.Repeat("a", 32), testFiles(), testAttempts(), badPolicy, testNow); err == nil {
		t.Fatal("maxAttempts=0 accepted")
	}
}

func TestSourceFingerprintDeterministic(t *testing.T) {
	f1 := testFiles()
	f2 := []JobFile{{Name: "b.txt", Size: 20, Digest: testDigest}, {Name: "a.txt", Size: 10, Digest: testDigest}}
	if SourceFingerprint(f1) != SourceFingerprint(f2) {
		t.Fatal("fingerprint depends on input order")
	}
	f3 := []JobFile{{Name: "a.txt", Size: 11, Digest: testDigest}, {Name: "b.txt", Size: 20, Digest: testDigest}}
	if SourceFingerprint(f1) == SourceFingerprint(f3) {
		t.Fatal("fingerprint ignores size change")
	}
	// Framing check: ("ab","c") vs ("a","bc") must differ.
	g1 := []JobFile{{Name: "ab", Size: 1, Digest: "c"}}
	g2 := []JobFile{{Name: "a", Size: 1, Digest: "bc"}}
	if SourceFingerprint(g1) == SourceFingerprint(g2) {
		t.Fatal("fingerprint framing collision")
	}
}

func TestFingerprintTamperFailsClosed(t *testing.T) {
	j := mustJob(t)
	j.SourceFingerprint = strings.Repeat("0", 64)
	if err := ValidateJob(j); err == nil {
		t.Fatal("tampered fingerprint accepted")
	}
}

func TestAttemptTransitions(t *testing.T) {
	a := RecipientAttempt{DeviceID: "d", Status: AttemptQueued, UpdatedAt: testNow}
	if err := TransitionAttempt(&a, AttemptActive, testNow); err != nil {
		t.Fatalf("queued->active: %v", err)
	}
	if a.Attempts != 0 {
		// TransitionAttempt does not bump the counter; dispatch does.
	}
	if err := TransitionAttempt(&a, AttemptCompleted, testNow); err == nil {
		t.Fatal("active->completed accepted (must go through verified)")
	}
	if err := TransitionAttempt(&a, AttemptVerified, testNow); err != nil {
		t.Fatalf("active->verified: %v", err)
	}
	if err := TransitionAttempt(&a, AttemptCompleted, testNow); err != nil {
		t.Fatalf("verified->completed: %v", err)
	}
	if err := TransitionAttempt(&a, AttemptQueued, testNow); err == nil {
		t.Fatal("completed->queued accepted")
	}

	b := RecipientAttempt{DeviceID: "d", Status: AttemptInterrupted, UpdatedAt: testNow}
	if err := TransitionAttempt(&b, AttemptQueued, testNow); err != nil {
		t.Fatalf("interrupted->queued: %v", err)
	}
}

func TestBackoff(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 5, BaseBackoff: 30 * time.Second, MaxBackoff: 4 * time.Minute}
	if got := BackoffForAttempt(p, 1); got != 30*time.Second {
		t.Fatalf("n=1: %v", got)
	}
	if got := BackoffForAttempt(p, 2); got != time.Minute {
		t.Fatalf("n=2: %v", got)
	}
	if got := BackoffForAttempt(p, 4); got != 4*time.Minute {
		t.Fatalf("n=4 capped: %v", got)
	}
	if got := BackoffForAttempt(p, 10); got != 4*time.Minute {
		t.Fatalf("n=10 capped: %v", got)
	}
}

func TestRetryable(t *testing.T) {
	p := DefaultRetryPolicy()
	now := testNow
	a := RecipientAttempt{DeviceID: "d", Status: AttemptQueued}
	if !a.Retryable(p, now) {
		t.Fatal("queued attempt not retryable")
	}
	a.Attempts = p.MaxAttempts
	if a.Retryable(p, now) {
		t.Fatal("exhausted attempt retryable")
	}
	a.Attempts = 1
	a.NextRetryAt = now.Add(time.Hour)
	if a.Retryable(p, now) {
		t.Fatal("backoff-pending attempt retryable")
	}
	a.NextRetryAt = now.Add(-time.Hour)
	if !a.Retryable(p, now) {
		t.Fatal("backoff-elapsed attempt not retryable")
	}
	a.Status = AttemptFailed
	if a.Retryable(p, now) {
		t.Fatal("failed attempt retryable")
	}
	exp := p
	exp.ExpiresAt = now.Add(-time.Second)
	a.Status = AttemptInterrupted
	if a.Retryable(exp, now) {
		t.Fatal("expired job attempt retryable")
	}
}

func TestCrashRequeueNeverDelivers(t *testing.T) {
	j := mustJob(t)
	j.Status = JobDispatching
	j.Attempts[0].Status = AttemptActive
	j.Attempts[0].Attempts = 2
	j.Attempts[1].Status = AttemptVerified
	n := MarkInterruptedAfterCrash(&j, testNow)
	if n != 1 {
		t.Fatalf("requeued %d, want 1", n)
	}
	if j.Attempts[0].Status != AttemptInterrupted {
		t.Fatalf("active became %q, want interrupted", j.Attempts[0].Status)
	}
	if j.Attempts[1].Status != AttemptVerified {
		t.Fatalf("verified changed to %q", j.Attempts[1].Status)
	}
	if j.Lease != nil {
		t.Fatal("lease not cleared after crash")
	}
	// Second call is a no-op.
	if n := MarkInterruptedAfterCrash(&j, testNow); n != 0 {
		t.Fatalf("second crash requeue = %d, want 0", n)
	}
}

func TestDeriveJobStatus(t *testing.T) {
	j := mustJob(t)
	j.Status = JobDispatching
	for i := range j.Attempts {
		j.Attempts[i].Status = AttemptCompleted
	}
	if got := DeriveJobStatus(&j); got != JobCompleted {
		t.Fatalf("got %q, want completed", got)
	}
	j.Attempts[0].Status = AttemptFailed
	if got := DeriveJobStatus(&j); got != JobFailed {
		t.Fatalf("got %q, want failed", got)
	}
	j.Attempts[0].Status = AttemptQueued
	if got := DeriveJobStatus(&j); got != JobDispatching {
		t.Fatalf("got %q, want dispatching", got)
	}
	// Verified-but-not-completed is NOT delivered: the job stays non-terminal.
	for i := range j.Attempts {
		j.Attempts[i].Status = AttemptVerified
	}
	if got := DeriveJobStatus(&j); got == JobCompleted || got == JobFailed {
		t.Fatalf("verified-only job reported terminal: %q", got)
	}
	// Cancelled is sticky.
	j.Status = JobCancelled
	if got := DeriveJobStatus(&j); got != JobCancelled {
		t.Fatalf("got %q, want cancelled", got)
	}
}
