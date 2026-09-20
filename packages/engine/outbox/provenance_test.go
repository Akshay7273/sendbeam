package outbox

import (
	"context"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/wire"
)

func testProvenance() *wire.Provenance {
	return &wire.Provenance{
		RoutineID:   "0123456789abcdef0123456789abcdef",
		RoutineName: "nightly backup",
		SenderLabel: "akshay-laptop",
		Trigger:     "watch",
	}
}

// A recipe dispatch stamps its origin on the job; the job survives a
// store reload with the provenance intact.
func TestEnqueueWithProvenance_StoresProvenance(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)}
	ob := newTestOutbox(t, clk, nil)
	p := writeTempFile(t, t.TempDir(), "hello.txt", "hello outbox")

	job, err := ob.EnqueueWithProvenance(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), netpolicy.Online, testProvenance())
	if err != nil {
		t.Fatalf("EnqueueWithProvenance: %v", err)
	}
	if job.Provenance == nil || *job.Provenance != *testProvenance() {
		t.Fatalf("job provenance = %+v, want %+v", job.Provenance, testProvenance())
	}
	loaded, ok, err := ob.store.Load(job.JobID)
	if err != nil || !ok {
		t.Fatalf("reload: ok=%v err=%v", ok, err)
	}
	if loaded.Provenance == nil || *loaded.Provenance != *testProvenance() {
		t.Fatalf("reloaded provenance = %+v, want %+v", loaded.Provenance, testProvenance())
	}
}

// The ordinary Enqueue path is a one-off send: no provenance.
func TestEnqueue_LeavesProvenanceNil(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, nil)
	p := writeTempFile(t, t.TempDir(), "a.txt", "x")

	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), netpolicy.Online)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if job.Provenance != nil {
		t.Fatalf("one-off job provenance = %+v, want nil", job.Provenance)
	}
	loaded, ok, err := ob.store.Load(job.JobID)
	if err != nil || !ok {
		t.Fatalf("reload: ok=%v err=%v", ok, err)
	}
	if loaded.Provenance != nil {
		t.Fatalf("reloaded one-off provenance = %+v, want nil", loaded.Provenance)
	}
}

// A malformed provenance fails closed before anything is persisted.
func TestEnqueueWithProvenance_RejectsMalformed(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	ob := newTestOutbox(t, clk, nil)
	p := writeTempFile(t, t.TempDir(), "a.txt", "x")

	bad := testProvenance()
	bad.Trigger = "cron"
	if _, err := ob.EnqueueWithProvenance(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), netpolicy.Online, bad); err == nil {
		t.Fatal("EnqueueWithProvenance accepted a malformed provenance")
	}
	entries, err := ob.store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("malformed provenance left %d job(s) in the store", len(entries))
	}
}
