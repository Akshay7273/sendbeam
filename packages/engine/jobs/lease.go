package jobs

import (
	"fmt"
	"os"
	"time"

	"github.com/sendbeam/wire"
)

// DefaultLeaseTTL bounds how long a dispatcher may own a job without a
// heartbeat. After expiry another process may adopt the lease; attempts left
// active are re-queued as interrupted, never marked delivered.
const DefaultLeaseTTL = 2 * time.Minute

// LeaseOwner identifies the current process for lease ownership.
func LeaseOwner() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("%s:%d", host, os.Getpid())
}

// AcquireLease takes dispatch ownership of a job. It fails closed when:
//   - the job is terminal (completed/failed/cancelled) or a draft,
//   - a live lease is held by another owner,
//   - the job's source fingerprint no longer matches (checked by the caller
//     via VerifySources before dispatch; kept separate on purpose).
//
// A stale (expired) lease is adopted: active attempts are first re-queued as
// interrupted via MarkInterruptedAfterCrash so no work is falsely delivered.
func AcquireLease(j *Job, owner string, ttl time.Duration, now time.Time) error {
	now = now.UTC()
	switch j.Status {
	case JobQueued, JobDispatching, JobPaused:
	default:
		return wire.Errorf(wire.CodeStorage,
			"jobs: cannot acquire lease for job in status %q", j.Status)
	}
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	if j.Lease != nil {
		if now.Before(j.Lease.ExpiresAt) && j.Lease.Owner != owner {
			return wire.Errorf(wire.CodeStorage,
				"jobs: job %s is leased by %s until %s",
				j.JobID, j.Lease.Owner, j.Lease.ExpiresAt.Format(time.RFC3339))
		}
		// Same owner re-acquiring, or a stale lease: adopt cleanly.
		if now.After(j.Lease.ExpiresAt) || j.Lease.ExpiresAt.Equal(now) {
			MarkInterruptedAfterCrash(j, now)
		}
	}
	j.Lease = &Lease{
		Owner:      owner,
		AcquiredAt: now,
		ExpiresAt:  now.Add(ttl),
	}
	if j.Status == JobQueued || j.Status == JobPaused {
		j.Status = JobDispatching
	}
	j.UpdatedAt = now
	return nil
}

// RenewLease extends a live lease held by owner. It fails closed when the
// caller does not hold the lease or the lease already expired (adopt via
// AcquireLease instead, which re-queues interrupted work first).
func RenewLease(j *Job, owner string, ttl time.Duration, now time.Time) error {
	now = now.UTC()
	if j.Lease == nil {
		return wire.Errorf(wire.CodeStorage, "jobs: no lease to renew for job %s", j.JobID)
	}
	if j.Lease.Owner != owner {
		return wire.Errorf(wire.CodeStorage,
			"jobs: lease for job %s is owned by %s", j.JobID, j.Lease.Owner)
	}
	if !now.Before(j.Lease.ExpiresAt) {
		return wire.Errorf(wire.CodeStorage,
			"jobs: lease for job %s expired at %s; re-acquire instead",
			j.JobID, j.Lease.ExpiresAt.Format(time.RFC3339))
	}
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	j.Lease.ExpiresAt = now.Add(ttl)
	j.UpdatedAt = now
	return nil
}

// ReleaseLease gives up dispatch ownership. Active attempts are left to the
// next acquirer: ReleaseLease does not mark them anything — the next
// AcquireLease (or an explicit pause) decides via MarkInterruptedAfterCrash.
// Terminal bookkeeping is the caller's job (see FinalizeJob).
func ReleaseLease(j *Job, owner string, now time.Time) error {
	now = now.UTC()
	if j.Lease == nil {
		return nil // idempotent
	}
	if j.Lease.Owner != owner {
		return wire.Errorf(wire.CodeStorage,
			"jobs: cannot release lease for job %s owned by %s", j.JobID, j.Lease.Owner)
	}
	j.Lease = nil
	if j.Status == JobDispatching {
		j.Status = JobQueued
	}
	j.UpdatedAt = now
	return nil
}

// LeaseLive reports whether the job currently has an unexpired lease.
func LeaseLive(j *Job, now time.Time) bool {
	return j.Lease != nil && now.UTC().Before(j.Lease.ExpiresAt)
}

// CancelJob moves a job to cancelled. Cancelled jobs never dispatch: any held
// lease is dropped and active attempts become interrupted (their partial
// cryptographic state remains resumable under the transfer journals, but the
// scheduler will not touch them again).
func CancelJob(j *Job, now time.Time) error {
	now = now.UTC()
	switch j.Status {
	case JobCompleted, JobFailed, JobCancelled:
		return wire.Errorf(wire.CodeStorage,
			"jobs: cannot cancel job in terminal status %q", j.Status)
	}
	for i := range j.Attempts {
		a := &j.Attempts[i]
		if a.Status == AttemptActive || a.Status == AttemptQueued || a.Status == AttemptInterrupted {
			a.Status = AttemptInterrupted
			a.UpdatedAt = now
		}
	}
	j.Lease = nil
	j.Status = JobCancelled
	j.CancelledAt = now
	j.UpdatedAt = now
	return nil
}

// FinalizeJob recomputes the job status from its attempts and drops the lease
// when the job reached a terminal state. Non-terminal jobs keep their lease.
func FinalizeJob(j *Job, now time.Time) JobStatus {
	j.Status = DeriveJobStatus(j)
	switch j.Status {
	case JobCompleted, JobFailed:
		j.Lease = nil
	}
	j.UpdatedAt = now.UTC()
	return j.Status
}
