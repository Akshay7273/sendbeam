package jobs

import (
	"strings"
	"testing"
	"time"
)

func TestAcquireRenewRelease(t *testing.T) {
	j := mustJob(t)
	j.Status = JobQueued

	if err := AcquireLease(&j, "host:1", 0, testNow); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if j.Lease == nil || j.Lease.Owner != "host:1" {
		t.Fatalf("lease not set: %+v", j.Lease)
	}
	if j.Status != JobDispatching {
		t.Fatalf("status = %q, want dispatching", j.Status)
	}
	wantExp := testNow.Add(DefaultLeaseTTL)
	if !j.Lease.ExpiresAt.Equal(wantExp) {
		t.Fatalf("expiry = %v, want %v", j.Lease.ExpiresAt, wantExp)
	}

	// Another owner cannot steal a live lease.
	if err := AcquireLease(&j, "host:2", 0, testNow); err == nil {
		t.Fatal("live lease stolen")
	}
	// Same owner can re-acquire (heartbeat path).
	if err := AcquireLease(&j, "host:1", 0, testNow); err != nil {
		t.Fatalf("re-acquire by owner: %v", err)
	}

	// Renew extends.
	later := testNow.Add(time.Minute)
	if err := RenewLease(&j, "host:1", 0, later); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !j.Lease.ExpiresAt.Equal(later.Add(DefaultLeaseTTL)) {
		t.Fatalf("renewed expiry = %v", j.Lease.ExpiresAt)
	}
	// Wrong owner cannot renew.
	if err := RenewLease(&j, "host:2", 0, later); err == nil {
		t.Fatal("renew by non-owner accepted")
	}

	// Release is idempotent and returns to queued.
	if err := ReleaseLease(&j, "host:1", later); err != nil {
		t.Fatalf("release: %v", err)
	}
	if j.Lease != nil {
		t.Fatal("lease not cleared")
	}
	if j.Status != JobQueued {
		t.Fatalf("status = %q, want queued", j.Status)
	}
	if err := ReleaseLease(&j, "host:1", later); err != nil {
		t.Fatalf("second release: %v", err)
	}
	// Wrong owner cannot release.
	if err := AcquireLease(&j, "host:1", 0, later); err != nil {
		t.Fatal(err)
	}
	if err := ReleaseLease(&j, "host:2", later); err == nil {
		t.Fatal("release by non-owner accepted")
	}
}

func TestAcquireRejectsTerminal(t *testing.T) {
	for _, st := range []JobStatus{JobDraft, JobCompleted, JobFailed, JobCancelled} {
		j := mustJob(t)
		j.Status = st
		if err := AcquireLease(&j, "host:1", 0, testNow); err == nil {
			t.Fatalf("acquire accepted for status %q", st)
		}
	}
}

func TestStaleLeaseAdoptionRequeues(t *testing.T) {
	j := mustJob(t)
	j.Status = JobDispatching
	j.Attempts[0].Status = AttemptActive
	j.Attempts[0].Attempts = 3
	if err := AcquireLease(&j, "host:1", time.Minute, testNow); err != nil {
		t.Fatal(err)
	}
	// Lease expires; a new owner adopts.
	after := testNow.Add(2 * time.Minute)
	if err := AcquireLease(&j, "host:2", 0, after); err != nil {
		t.Fatalf("adopt stale lease: %v", err)
	}
	if j.Lease.Owner != "host:2" {
		t.Fatalf("owner = %q", j.Lease.Owner)
	}
	if j.Attempts[0].Status != AttemptInterrupted {
		t.Fatalf("active attempt = %q, want interrupted", j.Attempts[0].Status)
	}
}

func TestRenewExpiredFails(t *testing.T) {
	j := mustJob(t)
	j.Status = JobQueued
	if err := AcquireLease(&j, "host:1", time.Minute, testNow); err != nil {
		t.Fatal(err)
	}
	after := testNow.Add(2 * time.Minute)
	if err := RenewLease(&j, "host:1", 0, after); err == nil {
		t.Fatal("renew of expired lease accepted")
	}
}

func TestCancelJob(t *testing.T) {
	j := mustJob(t)
	j.Status = JobDispatching
	j.Attempts[0].Status = AttemptActive
	j.Attempts[1].Status = AttemptQueued
	if err := AcquireLease(&j, "host:1", 0, testNow); err != nil {
		t.Fatal(err)
	}
	if err := CancelJob(&j, testNow); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if j.Status != JobCancelled || j.Lease != nil || j.CancelledAt.IsZero() {
		t.Fatalf("cancel state wrong: %+v", j)
	}
	for _, a := range j.Attempts {
		if a.Status == AttemptActive || a.Status == AttemptQueued {
			t.Fatalf("attempt left dispatchable: %q", a.Status)
		}
	}
	// Terminal jobs cannot be cancelled again; lease cannot be acquired.
	if err := CancelJob(&j, testNow); err == nil {
		t.Fatal("double cancel accepted")
	}
	if err := AcquireLease(&j, "host:1", 0, testNow); err == nil {
		t.Fatal("acquire on cancelled job accepted")
	}
}

func TestFinalizeJob(t *testing.T) {
	j := mustJob(t)
	j.Status = JobDispatching
	if err := AcquireLease(&j, "host:1", 0, testNow); err != nil {
		t.Fatal(err)
	}
	for i := range j.Attempts {
		j.Attempts[i].Status = AttemptCompleted
	}
	if got := FinalizeJob(&j, testNow); got != JobCompleted {
		t.Fatalf("got %q", got)
	}
	if j.Lease != nil {
		t.Fatal("lease kept on terminal job")
	}
	if err := ValidateJob(j); err != nil {
		t.Fatalf("finalized job invalid: %v", err)
	}

	// Non-terminal keeps lease.
	j2 := mustJob(t)
	j2.JobID = strings.Repeat("b", 32)
	j2.Status = JobDispatching
	if err := AcquireLease(&j2, "host:1", 0, testNow); err != nil {
		t.Fatal(err)
	}
	if got := FinalizeJob(&j2, testNow); got == JobCompleted || got == JobFailed {
		t.Fatalf("premature terminal: %q", got)
	}
	if j2.Lease == nil {
		t.Fatal("lease dropped on non-terminal job")
	}
}

func TestLeaseOwnerFormat(t *testing.T) {
	o := LeaseOwner()
	if !strings.Contains(o, ":") {
		t.Fatalf("owner %q missing pid separator", o)
	}
}
