// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package outbox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/transfer"
)

// TestSharedInFlightCancelStopsRunningSend proves the cross-instance cancel
// mechanism (SB-R08 fix): instance B (per-dispatch-pass) registers its
// in-flight cancel into the shared registry; instance A (persistent) must
// stop B's RUNNING send through Cancel.
func TestSharedInFlightCancelStopsRunningSend(t *testing.T) {
	store, err := jobs.OpenJobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	shared := NewInFlightCancels()

	// The real SendFunc records whether its ctx was cancelled.
	sendStarted := make(chan struct{})
	ctxCancelled := make(chan error, 1)
	sender := func(ctx context.Context, _ jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		close(sendStarted)
		select {
		case <-ctx.Done():
			ctxCancelled <- ctx.Err()
		case <-time.After(30 * time.Second):
			ctxCancelled <- nil
		}
		return SendOutcome{Status: transfer.StatusFailed, Error: "aborted"}
	}

	// Instance B: the per-pass outbox (registers the in-flight cancel).
	b := New(store, sender)
	b.SetInFlightCancels(shared)

	// Enqueue through A (a fresh instance, as the persistent service outbox
	// would be — send nil, it never dispatches).
	a := New(store, nil)
	a.SetInFlightCancels(shared)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := a.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), netpolicy.Online)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan DispatchReport, 1)
	go func() {
		rep, _ := b.DispatchOnce(context.Background(), DispatchOptions{EffectivePolicy: netpolicy.Online})
		done <- rep
	}()
	<-sendStarted

	// CANCEL through instance A — the cross-instance stop.
	if err := a.Cancel(job.JobID); err != nil {
		t.Fatalf("cancel through the other instance: %v", err)
	}

	select {
	case err := <-ctxCancelled:
		if err == nil {
			t.Fatal("the running send's context was never cancelled — the cross-instance stop failed")
		}
		if !strings.Contains(err.Error(), "cancel") {
			t.Fatalf("ctx error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("send did not react to the cancellation within 10s")
	}

	rep := <-done
	if rep.JobsDispatched != 1 {
		t.Fatalf("dispatch report: %+v", rep)
	}
	// The stored job must stay cancelled (the in-flight outcome dropped).
	got, _, _ := store.Load(job.JobID)
	if got.Status != jobs.JobCancelled {
		t.Fatalf("job status = %q, want cancelled", got.Status)
	}
}
