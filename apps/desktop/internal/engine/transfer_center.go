package engine

import (
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/transfercenter"
)

// This file exposes the local transfer center (V20-PR03) to the desktop
// frontend through the Wails-bound TransferService: the durable job/outbox
// read model with queued, active, interrupted, verified, completed, failed
// and cancelled states, per-target results, and explicit history retention.
//
// The center shares the jobs directory with the CLI (jobs.JobStoreDir), so
// `sendbeam outbox` and the desktop app see the same transfer center.
// Dispatch from the desktop UI is not wired here: retry re-queues failed
// attempts, and sending remains a CLI/dispatch-loop operation for now.

// transferCenter returns the lazily-initialized transfer center, opening the
// shared jobs store on first use.
func (s *TransferService) transferCenter() (*transfercenter.Center, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcCenter != nil {
		return s.tcCenter, nil
	}
	dir, err := jobs.JobStoreDir()
	if err != nil {
		return nil, err
	}
	store, err := jobs.OpenJobStore(dir)
	if err != nil {
		return nil, err
	}
	s.tcCenter = transfercenter.New(store, outbox.New(store, nil))
	return s.tcCenter, nil
}

// TransferCenterList renders the whole transfer center: jobs grouped by
// user-facing state with summary counts.
func (s *TransferService) TransferCenterList() (transfercenter.Snapshot, error) {
	c, err := s.transferCenter()
	if err != nil {
		return transfercenter.Snapshot{}, err
	}
	return c.Snapshot()
}

// TransferCenterShow returns the full detail of one job, including every
// per-target result.
func (s *TransferService) TransferCenterShow(jobID string) (transfercenter.JobDetail, error) {
	c, err := s.transferCenter()
	if err != nil {
		return transfercenter.JobDetail{}, err
	}
	return c.Get(jobID)
}

// TransferCenterCancel stops a job: it never dispatches again.
func (s *TransferService) TransferCenterCancel(jobID string) error {
	c, err := s.transferCenter()
	if err != nil {
		return err
	}
	return c.Cancel(jobID)
}

// TransferCenterRetry re-queues failed attempts of one job with a fresh
// retry budget. deviceIDs filters by device; empty retries every failed
// attempt.
func (s *TransferService) TransferCenterRetry(jobID string, deviceIDs []string) (int, error) {
	c, err := s.transferCenter()
	if err != nil {
		return 0, err
	}
	return c.RetryFailed(jobID, deviceIDs)
}

// TransferCenterPrune enforces history retention on terminal jobs.
// olderThanHours overrides the default retention for all terminal classes;
// 0 selects the default (30d completed/failed, 7d cancelled). With dryRun,
// nothing is deleted. Live, leased, and unreadable jobs are never pruned.
func (s *TransferService) TransferCenterPrune(olderThanHours float64, dryRun bool) (transfercenter.PruneReport, error) {
	c, err := s.transferCenter()
	if err != nil {
		return transfercenter.PruneReport{}, err
	}
	policy := transfercenter.DefaultRetentionPolicy()
	if olderThanHours > 0 {
		d := time.Duration(olderThanHours * float64(time.Hour))
		policy = transfercenter.RetentionPolicy{
			CompletedFor: d,
			FailedFor:    d,
			CancelledFor: d,
		}
	}
	return c.Prune(time.Now().UTC(), policy, dryRun)
}

// TransferCenterForget deletes one terminal job's history explicitly. Live
// jobs are refused; cancel first.
func (s *TransferService) TransferCenterForget(jobID string) error {
	c, err := s.transferCenter()
	if err != nil {
		return err
	}
	return c.Forget(jobID)
}
