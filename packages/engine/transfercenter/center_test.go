// Baseline regression tests for the transfer center (V20-PR03).
//
// These tests fail until the transfercenter package exists: they pin the
// user-facing state derivation (queued, active, interrupted, verified,
// completed, failed, cancelled, paused, draft, broken), per-target results,
// and explicit history retention (prune/forget). Scheduler metadata only —
// no cryptographic material is ever surfaced.
package transfercenter

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/outbox"
)

// testStore opens an isolated job store for one test.
func testStore(t *testing.T) *jobs.JobStore {
	t.Helper()
	store, err := jobs.OpenJobStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return store
}

// seedJob builds a minimal valid job with the given status and attempt
// statuses, saves it, and returns it.
func seedJob(t *testing.T, store *jobs.JobStore, id string, status jobs.JobStatus, attempts ...jobs.AttemptStatus) jobs.Job {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	files := []jobs.JobFile{{Name: "a.bin", Size: 10, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}
	var atts []jobs.RecipientAttempt
	for i, st := range attempts {
		a := jobs.RecipientAttempt{
			DeviceID:  "0123456789abcdef0123456789abcdef0123456789abcd"[:32] + string(rune('a'+i)) + string(rune('0'+i)),
			Label:     "dev",
			Status:    st,
			UpdatedAt: now,
		}
		if st == jobs.AttemptActive {
			a.Attempts = 1 // ValidateJob requires a recorded try for active attempts
		}
		atts = append(atts, a)
	}
	job, err := jobs.NewJob(id, files, atts, jobs.DefaultRetryPolicy(), now)
	if err != nil {
		t.Fatalf("new job: %v", err)
	}
	job.Status = status
	job.UpdatedAt = now
	if status == jobs.JobCancelled {
		job.CancelledAt = now
	}
	if err := store.Save(job); err != nil {
		t.Fatalf("save job: %v", err)
	}
	return job
}

func jobIDs(group StateGroup) []string {
	var out []string
	for _, j := range group.Jobs {
		out = append(out, j.JobID)
	}
	return out
}

func groupBy(snap Snapshot, st DisplayState) StateGroup {
	for _, g := range snap.Groups {
		if g.State == st {
			return g
		}
	}
	return StateGroup{State: st}
}

func TestSnapshotGroupsByDisplayState(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))

	q := seedJob(t, store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobQueued, jobs.AttemptQueued)
	seedJob(t, store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", jobs.JobDispatching, jobs.AttemptActive)
	seedJob(t, store, "cccccccccccccccccccccccccccccccc", jobs.JobQueued, jobs.AttemptInterrupted)
	seedJob(t, store, "dddddddddddddddddddddddddddddddd", jobs.JobDispatching, jobs.AttemptVerified)
	done := seedJob(t, store, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", jobs.JobCompleted, jobs.AttemptCompleted)
	failed := seedJob(t, store, "ffffffffffffffffffffffffffffffff", jobs.JobFailed, jobs.AttemptFailed)
	cancelled := seedJob(t, store, "11111111111111111111111111111111", jobs.JobCancelled, jobs.AttemptQueued)

	snap, err := c.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	cases := map[DisplayState]string{
		StateQueued:      q.JobID,
		StateActive:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		StateInterrupted: "cccccccccccccccccccccccccccccccc",
		StateVerified:    "dddddddddddddddddddddddddddddddd",
		StateCompleted:   done.JobID,
		StateFailed:      failed.JobID,
		StateCancelled:   cancelled.JobID,
	}
	for st, want := range cases {
		got := jobIDs(groupBy(snap, st))
		found := false
		for _, id := range got {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Errorf("state %q: want job %q in group, got %v", st, want, got)
		}
	}
}

func TestSnapshotPerTargetResults(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	now := time.Now().UTC().Truncate(time.Second)
	files := []jobs.JobFile{{Name: "a.bin", Size: 10, Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}
	atts := []jobs.RecipientAttempt{
		{DeviceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Label: "laptop", Status: jobs.AttemptCompleted, Attempts: 1, UpdatedAt: now},
		{DeviceID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Label: "phone", Status: jobs.AttemptFailed, Attempts: 5, LastError: "recipient refused: no", UpdatedAt: now},
	}
	job, err := jobs.NewJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", files, atts, jobs.DefaultRetryPolicy(), now)
	if err != nil {
		t.Fatalf("new job: %v", err)
	}
	job.Status = jobs.JobFailed
	if err := store.Save(job); err != nil {
		t.Fatalf("save: %v", err)
	}
	detail, err := c.Get(job.JobID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(detail.Attempts) != 2 {
		t.Fatalf("want 2 attempt views, got %d", len(detail.Attempts))
	}
	if detail.Attempts[0].State != StateCompleted || detail.Attempts[0].Attempts != 1 {
		t.Errorf("attempt 0 = %+v, want completed/1", detail.Attempts[0])
	}
	if detail.Attempts[1].State != StateFailed || detail.Attempts[1].LastError != "recipient refused: no" {
		t.Errorf("attempt 1 = %+v, want failed with last error", detail.Attempts[1])
	}
}

// backdateJob rewrites a stored job's updatedAt in place, recomputing the
// checksum so the job stays valid. The store stamps UpdatedAt on every Save,
// so this byte-level surgery is the only way to fabricate age from outside
// the jobs package.
func backdateJob(t *testing.T, store *jobs.JobStore, jobID string, updatedAt time.Time) {
	t.Helper()
	path := store.Path(jobID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read job file: %v", err)
	}
	reUpdated := regexp.MustCompile(`"updatedAt":"[^"]*"`)
	if !reUpdated.Match(data) {
		t.Fatalf("job file has no updatedAt field")
	}
	data = reUpdated.ReplaceAll(data, []byte(`"updatedAt":"`+updatedAt.UTC().Format(time.RFC3339Nano)+`"`))
	reChecksum := regexp.MustCompile(`"checksum":"[0-9a-f]{64}"`)
	if !reChecksum.Match(data) {
		t.Fatalf("job file has no checksum field")
	}
	body := reChecksum.ReplaceAll(data, []byte(`"checksum":""`))
	sum := sha256.Sum256(body)
	data = reChecksum.ReplaceAll(data, []byte(`"checksum":"`+hex.EncodeToString(sum[:])+`"`))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write job file: %v", err)
	}
	// Sanity: the job must still load and validate.
	if _, ok, err := store.Load(jobID); err != nil || !ok {
		t.Fatalf("backdated job no longer loads: ok=%v err=%v", ok, err)
	}
}

func TestPruneKeepsRecentAndSkipsLive(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	old := time.Now().UTC().Add(-60 * 24 * time.Hour).Truncate(time.Second)

	oldJob := seedJob(t, store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobCompleted, jobs.AttemptCompleted)
	backdateJob(t, store, oldJob.JobID, old)
	seedJob(t, store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", jobs.JobQueued, jobs.AttemptQueued)

	// Dry run prunes nothing.
	rep, err := c.Prune(time.Now().UTC(), DefaultRetentionPolicy(), true)
	if err != nil {
		t.Fatalf("prune dry-run: %v", err)
	}
	if !rep.DryRun || len(rep.Pruned) != 1 {
		t.Errorf("dry-run: want 1 candidate, got %+v", rep)
	}
	if _, ok, _ := store.Load(oldJob.JobID); !ok {
		t.Errorf("dry-run deleted the job")
	}

	rep, err = c.Prune(time.Now().UTC(), DefaultRetentionPolicy(), false)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(rep.Pruned) != 1 || rep.Pruned[0] != oldJob.JobID {
		t.Errorf("prune: want [%s], got %+v", oldJob.JobID, rep)
	}
	if _, ok, _ := store.Load(oldJob.JobID); ok {
		t.Errorf("pruned job still loadable")
	}
	if _, ok, _ := store.Load("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !ok {
		t.Errorf("live job was pruned")
	}
}

func TestForgetRefusesLiveJob(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	live := seedJob(t, store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobQueued, jobs.AttemptQueued)
	if err := c.Forget(live.JobID); err == nil {
		t.Errorf("Forget on a live job should fail")
	}
	done := seedJob(t, store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", jobs.JobCompleted, jobs.AttemptCompleted)
	if err := c.Forget(done.JobID); err != nil {
		t.Errorf("Forget on a completed job: %v", err)
	}
	if _, ok, _ := store.Load(done.JobID); ok {
		t.Errorf("forgotten job still loadable")
	}
}

func TestForgetRefusesLiveJobs(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	job := seedJob(t, store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobQueued, jobs.AttemptQueued)

	if err := c.Forget(job.JobID); err == nil {
		t.Fatalf("Forget of a queued job should fail")
	}
	// The job file must still exist.
	if _, ok, err := store.Load(job.JobID); err != nil || !ok {
		t.Fatalf("live job was touched by refused Forget: ok=%v err=%v", ok, err)
	}
}

func TestForgetTerminalJob(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	job := seedJob(t, store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", jobs.JobCancelled, jobs.AttemptFailed)

	if err := c.Forget(job.JobID); err != nil {
		t.Fatalf("Forget of a cancelled job: %v", err)
	}
	if _, ok, _ := store.Load(job.JobID); ok {
		t.Fatalf("forgotten job still loads")
	}
	if err := c.Forget(job.JobID); err == nil {
		t.Fatalf("Forget of an unknown job should fail")
	}
}

func TestForgetCorruptFileIsCleared(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// A file that reads fine but does not decode: quarantined, not live.
	if err := os.WriteFile(store.Path(id), []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt job: %v", err)
	}
	if err := c.Forget(id); err != nil {
		t.Fatalf("Forget of a corrupt record: %v", err)
	}
	if _, err := os.Stat(store.Path(id)); !os.IsNotExist(err) {
		t.Fatalf("corrupt record was not cleared")
	}
}

func TestForgetFailsClosedOnStorageError(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	id := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// A directory at the job path: Load fails and the raw re-read fails
	// with an I/O error (not corruption). Forget must not delete.
	if err := os.Mkdir(store.Path(id), 0o700); err != nil {
		t.Fatalf("mkdir job path: %v", err)
	}
	if err := c.Forget(id); err == nil {
		t.Fatalf("Forget with an unreadable job path should fail closed")
	}
	if st, err := os.Stat(store.Path(id)); err != nil || !st.IsDir() {
		t.Fatalf("unreadable job path was touched by failed Forget")
	}
}

func TestForgetRejectsMalformedIDs(t *testing.T) {
	store := testStore(t)
	c := New(store, outbox.New(store, nil))
	for _, bad := range []string{"", "short", "../escape", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"} {
		if err := c.Forget(bad); err == nil {
			t.Fatalf("Forget(%q) should fail", bad)
		}
	}
}
