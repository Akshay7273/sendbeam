package engine

import (
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
)

// seedCenterJob stores one minimal job directly in the jobs dir used by the
// transfer center under test.
func seedCenterJob(t *testing.T, dir, id string, status jobs.JobStatus, attempt jobs.AttemptStatus) {
	t.Helper()
	store, err := jobs.OpenJobStore(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	files := []jobs.JobFile{{Name: "a.bin", Size: 8, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}
	atts := []jobs.RecipientAttempt{{
		DeviceID:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Label:     "laptop",
		Status:    attempt,
		UpdatedAt: now,
	}}
	if attempt == jobs.AttemptActive {
		atts[0].Attempts = 1
	}
	j, err := jobs.NewJob(id, files, atts, jobs.DefaultRetryPolicy(), now)
	if err != nil {
		t.Fatalf("new job: %v", err)
	}
	j.Status = status
	j.UpdatedAt = now
	if status == jobs.JobCancelled {
		j.CancelledAt = now
	}
	if err := store.Save(j); err != nil {
		t.Fatalf("save job: %v", err)
	}
}

func TestTransferCenterListGroupsStates(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENDBEAM_JOBS_DIR", dir)
	seedCenterJob(t, dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobQueued, jobs.AttemptQueued)
	seedCenterJob(t, dir, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", jobs.JobCompleted, jobs.AttemptCompleted)

	svc := NewTransferService(nil, nil)
	snap, err := svc.TransferCenterList()
	if err != nil {
		t.Fatalf("TransferCenterList: %v", err)
	}
	if snap.Summary.Total != 2 {
		t.Fatalf("want 2 jobs, got %d", snap.Summary.Total)
	}
	if snap.Summary.ByState["queued"] != 1 || snap.Summary.ByState["completed"] != 1 {
		t.Fatalf("bad grouping: %+v", snap.Summary.ByState)
	}
}

func TestTransferCenterShowCancelForget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENDBEAM_JOBS_DIR", dir)
	seedCenterJob(t, dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobQueued, jobs.AttemptQueued)

	svc := NewTransferService(nil, nil)
	detail, err := svc.TransferCenterShow("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if detail.State != "queued" || len(detail.Attempts) != 1 || detail.Attempts[0].Label != "laptop" {
		t.Fatalf("bad detail: %+v", detail)
	}

	// Forgetting a live job is refused.
	if err := svc.TransferCenterForget("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatalf("Forget of a live job should fail")
	}
	// Cancel, then forget.
	if err := svc.TransferCenterCancel("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if err := svc.TransferCenterForget("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("Forget after cancel: %v", err)
	}
	if _, err := svc.TransferCenterShow("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatalf("Show of forgotten job should fail")
	}
}

func TestTransferCenterPruneDryRun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENDBEAM_JOBS_DIR", dir)
	seedCenterJob(t, dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobQueued, jobs.AttemptQueued)

	svc := NewTransferService(nil, nil)
	rep, err := svc.TransferCenterPrune(0, true)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if !rep.DryRun || len(rep.Pruned) != 0 {
		t.Fatalf("dry run should prune nothing, got %+v", rep)
	}
	if len(rep.Skipped) != 1 {
		t.Fatalf("live job should be skipped, got %+v", rep)
	}
}
