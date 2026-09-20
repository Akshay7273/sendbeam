package transfercenter

import (
	"errors"
	"os"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/wire"
)

// RetentionPolicy bounds how long terminal job history is kept. Each field
// is the maximum age (since last update) of a terminal job before Prune
// removes it. A non-positive duration keeps that class forever. Prune never
// touches non-terminal jobs, unreadable jobs, or jobs holding a lease —
// retention is history hygiene, never a way to make live work disappear.
type RetentionPolicy struct {
	CompletedFor time.Duration `json:"completedFor"`
	FailedFor    time.Duration `json:"failedFor"`
	CancelledFor time.Duration `json:"cancelledFor"`
}

// DefaultRetentionPolicy keeps completed and failed history for 30 days and
// cancelled jobs for 7 days.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		CompletedFor: 30 * 24 * time.Hour,
		FailedFor:    30 * 24 * time.Hour,
		CancelledFor: 7 * 24 * time.Hour,
	}
}

// PruneReport describes one retention pass.
type PruneReport struct {
	DryRun  bool     `json:"dryRun"`
	Pruned  []string `json:"pruned"`
	Kept    []string `json:"kept"`
	Skipped []string `json:"skipped"`
}

// retentionFor returns the retention duration for a terminal job status,
// and whether the status is terminal at all.
func retentionFor(status jobs.JobStatus, p RetentionPolicy) (time.Duration, bool) {
	switch status {
	case jobs.JobCompleted:
		return p.CompletedFor, true
	case jobs.JobFailed:
		return p.FailedFor, true
	case jobs.JobCancelled:
		return p.CancelledFor, true
	default:
		return 0, false
	}
}

// Prune deletes terminal jobs older than the retention policy. With dryRun,
// nothing is deleted and Pruned lists the candidates. Broken (unreadable)
// jobs are never pruned — quarantine needs an explicit operator decision —
// and neither are jobs holding a lease, defensively.
func (c *Center) Prune(now time.Time, p RetentionPolicy, dryRun bool) (PruneReport, error) {
	rep := PruneReport{DryRun: dryRun, Pruned: []string{}, Kept: []string{}, Skipped: []string{}}
	entries, err := c.store.List()
	if err != nil {
		return rep, err
	}
	for _, e := range entries {
		if !e.JobOK {
			rep.Skipped = append(rep.Skipped, e.JobID+": unreadable job file (quarantined, never auto-deleted)")
			continue
		}
		j, ok, err := c.store.Load(e.JobID)
		if err != nil || !ok {
			rep.Skipped = append(rep.Skipped, e.JobID+": reload failed after listing")
			continue
		}
		keep, terminal := retentionFor(j.Status, p)
		if !terminal {
			rep.Skipped = append(rep.Skipped, e.JobID+": not terminal ("+string(j.Status)+")")
			continue
		}
		if j.Lease != nil {
			rep.Skipped = append(rep.Skipped, e.JobID+": holds a lease")
			continue
		}
		if keep <= 0 || now.Sub(j.UpdatedAt) < keep {
			rep.Kept = append(rep.Kept, e.JobID+": within retention")
			continue
		}
		if !dryRun {
			// Only the job file goes: the transfer journals keep their own
			// lifecycle, and partial payload data is never deleted by
			// retention — the operator deletes partials explicitly.
			if err := c.store.Discard(j.JobID); err != nil {
				return rep, err
			}
		}
		rep.Pruned = append(rep.Pruned, j.JobID)
	}
	return rep, nil
}

// validJobID reports whether id has the only form that can name a job
// file: 32 lowercase hex characters. Checked before any raw filesystem
// access so a malformed id can never escape the jobs directory.
func validJobID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

// Forget discards one job's history explicitly. Only terminal jobs can be
// forgotten: live work is never deleted by Forget. Use Cancel first for a
// live job. When the job file exists and reads fine but does not decode,
// Forget clears that quarantined (corrupt/tampered/foreign-schema) record —
// an explicit per-job operator action, never bulk or automatic. A transient
// storage failure (missing file, I/O or permission error) never deletes:
// Forget fails closed and reports the error.
func (c *Center) Forget(jobID string) error {
	if !validJobID(jobID) {
		return wire.Errorf(wire.CodeStorage, "transfercenter: invalid job id %q", jobID)
	}
	j, ok, err := c.store.Load(jobID)
	if err == nil {
		if !ok {
			return wire.Errorf(wire.CodeStorage, "transfercenter: unknown job %q", jobID)
		}
		if _, terminal := retentionFor(j.Status, RetentionPolicy{}); !terminal {
			return wire.Errorf(wire.CodeStorage,
				"transfercenter: job %q is %s, not terminal; cancel it before forgetting", shortID(jobID), j.Status)
		}
		return c.store.Discard(jobID)
	}
	// Load failed. Re-read the raw file to tell an unreadable record apart
	// from a transient I/O failure: only positive proof of an unreadable
	// file may lead to deletion.
	if _, rerr := os.ReadFile(c.store.Path(jobID)); rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return wire.Errorf(wire.CodeStorage, "transfercenter: unknown job %q", jobID)
		}
		return wire.Errorf(wire.CodeStorage,
			"transfercenter: cannot forget %q: storage error, nothing deleted: %v", shortID(jobID), rerr)
	}
	return c.store.Discard(jobID)
}
