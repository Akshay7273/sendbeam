// Package transfer wires a completed rendezvous into a direct-or-relayed file transfer.
package transfer

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sendbeam/wire"
)

// BroadcastStatus describes the outcome of an individual target in a broadcast send.
type BroadcastStatus string

const (
	// StatusOk indicates the transfer completed and the whole-file digest was verified.
	StatusOk BroadcastStatus = "ok"
	// StatusOffline indicates the target was unreachable, offline, or timed out.
	StatusOffline BroadcastStatus = "offline"
	// StatusRefused indicates the target explicitly declined or rejected the transfer.
	StatusRefused BroadcastStatus = "refused"
	// StatusFailed indicates the transfer encountered a fatal network, auth, or protocol error.
	StatusFailed BroadcastStatus = "failed"
)

// BroadcastTarget specifies one destination in a multi-device broadcast.
type BroadcastTarget struct {
	ID     string // Unique target identifier (e.g. DeviceID, label)
	Label  string // Human-readable label (e.g. "Work Laptop")
	Signal Signal // The adopted signaling connection for this target
	Spec   Spec   // Transfer specification for this target
}

// TargetResult holds the result of a single target's transfer in a broadcast.
type TargetResult struct {
	TargetID   string          `json:"target_id"`
	Label      string          `json:"label"`
	Status     BroadcastStatus `json:"status"` // "ok" | "offline" | "refused" | "failed"
	Digest     string          `json:"digest,omitempty"`
	Size       int64           `json:"size,omitempty"`
	DurationMs int64           `json:"duration_ms"`
	Error      string          `json:"error,omitempty"`
	Outcome    *Outcome        `json:"outcome,omitempty"`
}

// BroadcastResult aggregates the results of all target transfers.
type BroadcastResult struct {
	Results []TargetResult `json:"results"`
	AllOk   bool           `json:"all_ok"`
}

// BroadcastOptions configures concurrent execution and progress dispatching for broadcast sends.
type BroadcastOptions struct {
	// Concurrency limits the number of parallel target transfers. Default is 4.
	Concurrency int
	// OnTargetStart is called when a target's transfer begins.
	OnTargetStart func(target BroadcastTarget)
	// OnTargetProgress reports progress for a specific target.
	OnTargetProgress func(targetID string, bytes int64)
	// OnTargetFileProgress reports file-level progress for a specific target.
	OnTargetFileProgress func(targetID string, fileIdx int, fileBytes, ackBytes int64)
	// OnTargetComplete is called when a single target finishes (succeeded or failed).
	OnTargetComplete func(targetID string, res TargetResult)
}

// ClassifyBroadcastError categorizes a transfer error into a standard BroadcastStatus.
func ClassifyBroadcastError(err error) (BroadcastStatus, string) {
	if err == nil {
		return StatusOk, ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)

	// Explicit device/peer refusal or revocation
	if errors.Is(err, wire.ErrTrustedRejected) || errors.Is(err, wire.ErrTrustedPeerRevoked) ||
		strings.Contains(lower, "transfer refused") || strings.Contains(lower, "peer refused") ||
		strings.Contains(lower, "declined") || strings.Contains(lower, "rejected") {
		return StatusRefused, msg
	}

	// Network/connectivity/discovery offline
	if strings.Contains(lower, "offline") || strings.Contains(lower, "unreachable") ||
		strings.Contains(lower, "deadline exceeded") || strings.Contains(lower, "timeout") ||
		strings.Contains(lower, "connection refused") || strings.Contains(lower, "no route") ||
		strings.Contains(lower, "peer not found") || strings.Contains(lower, "closed network connection") {
		return StatusOffline, msg
	}

	if strings.Contains(lower, "refuse") {
		return StatusRefused, msg
	}

	return StatusFailed, msg
}

// RunBroadcast executes concurrent transfers to all specified targets with bounded concurrency
// and partial-failure isolation. A failure on one target never aborts or impacts other targets.
func RunBroadcast(ctx context.Context, targets []BroadcastTarget, opts BroadcastOptions) *BroadcastResult {
	if len(targets) == 0 {
		return &BroadcastResult{
			Results: []TargetResult{},
			AllOk:   true,
		}
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	results := make([]TargetResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt BroadcastTarget) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				dur := int64(0)
				results[idx] = TargetResult{
					TargetID:   tgt.ID,
					Label:      tgt.Label,
					Status:     StatusOffline,
					DurationMs: dur,
					Error:      ctx.Err().Error(),
				}
				if opts.OnTargetComplete != nil {
					opts.OnTargetComplete(tgt.ID, results[idx])
				}
				return
			}
			defer func() { <-sem }()

			if opts.OnTargetStart != nil {
				opts.OnTargetStart(tgt)
			}

			// Wrap callbacks for target-specific progress reporting
			specCopy := tgt.Spec
			if opts.OnTargetProgress != nil {
				origProgress := specCopy.OnProgress
				specCopy.OnProgress = func(b int64) {
					if origProgress != nil {
						origProgress(b)
					}
					opts.OnTargetProgress(tgt.ID, b)
				}
			}
			if opts.OnTargetFileProgress != nil {
				origFileProgress := specCopy.OnFileProgress
				specCopy.OnFileProgress = func(fileIdx int, fileBytes, ackBytes int64) {
					if origFileProgress != nil {
						origFileProgress(fileIdx, fileBytes, ackBytes)
					}
					opts.OnTargetFileProgress(tgt.ID, fileIdx, fileBytes, ackBytes)
				}
			}

			start := time.Now()
			out, err := Run(ctx, tgt.Signal, specCopy)
			dur := time.Since(start).Milliseconds()

			if err == nil && out != nil {
				results[idx] = TargetResult{
					TargetID:   tgt.ID,
					Label:      tgt.Label,
					Status:     StatusOk,
					Digest:     out.Digest,
					Size:       out.Size,
					DurationMs: dur,
					Outcome:    out,
				}
			} else {
				status, errMsg := ClassifyBroadcastError(err)
				results[idx] = TargetResult{
					TargetID:   tgt.ID,
					Label:      tgt.Label,
					Status:     status,
					DurationMs: dur,
					Error:      errMsg,
				}
			}

			if opts.OnTargetComplete != nil {
				opts.OnTargetComplete(tgt.ID, results[idx])
			}
		}(i, target)
	}

	wg.Wait()

	allOk := true
	for _, r := range results {
		if r.Status != StatusOk {
			allOk = false
			break
		}
	}

	return &BroadcastResult{
		Results: results,
		AllOk:   allOk,
	}
}
