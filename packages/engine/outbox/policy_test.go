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

// TestDispatch_NetworkPolicyBinding verifies the V21-PR07 attempt-binding
// rule end to end at the dispatch gate: unsatisfiable jobs are held with a
// clear reason, their attempts are untouched, and the SendFunc is never
// invoked for them.
func TestDispatch_NetworkPolicyBinding(t *testing.T) {
	cases := []struct {
		name       string
		jobPolicy  netpolicy.Policy
		effective  netpolicy.Policy
		dispatched bool
	}{
		{"local-only held under online", netpolicy.LocalOnly, netpolicy.Online, false},
		{"local-only dispatched under local-only", netpolicy.LocalOnly, netpolicy.LocalOnly, true},
		{"local-only dispatched under prefer-local", netpolicy.LocalOnly, netpolicy.PreferLocal, true},
		{"online held under local-only", netpolicy.Online, netpolicy.LocalOnly, false},
		{"online dispatched under online", netpolicy.Online, netpolicy.Online, true},
		{"online dispatched under prefer-local", netpolicy.Online, netpolicy.PreferLocal, true},
		{"prefer-local dispatched under online", netpolicy.PreferLocal, netpolicy.Online, true},
		{"prefer-local dispatched under local-only", netpolicy.PreferLocal, netpolicy.LocalOnly, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clk := &testClock{t: time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)}
			var calls int
			sender := func(_ context.Context, job jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
				calls++
				// The SendFunc is the second line of defense: it must see
				// the job's bound policy and refuse a route the bound
				// policy forbids.
				if !job.EffectiveNetworkPolicy().DispatchableUnder(c.effective) {
					t.Errorf("SendFunc invoked for unsatisfiable job policy %q under effective %q",
						job.EffectiveNetworkPolicy(), c.effective)
				}
				return SendOutcome{Status: transfer.StatusOk, Digest: "dd", BytesTransferred: job.TotalSize}
			}
			ob := newTestOutbox(t, clk, sender)
			p := writeTempFile(t, t.TempDir(), "a.txt", "data")
			job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), c.jobPolicy)
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if got := job.EffectiveNetworkPolicy(); got != c.jobPolicy {
				t.Fatalf("enqueued job policy = %v, want %v", got, c.jobPolicy)
			}

			rep, err := ob.DispatchOnce(context.Background(), DispatchOptions{EffectivePolicy: c.effective})
			if err != nil {
				t.Fatalf("DispatchOnce: %v", err)
			}
			if c.dispatched {
				if calls != 1 {
					t.Errorf("expected SendFunc to be called once, got %d", calls)
				}
				if len(rep.Skipped) != 0 {
					t.Errorf("expected no skips, got %v", rep.Skipped)
				}
			} else {
				if calls != 0 {
					t.Errorf("SendFunc must not be invoked for held job (called %d times)", calls)
				}
				if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0], "network policy") {
					t.Errorf("expected a network-policy hold reason, got %v", rep.Skipped)
				}
				// The hold must not consume retry budget or mutate the attempt.
				stored, ok, err := ob.Get(job.JobID)
				if err != nil || !ok {
					t.Fatalf("Get: %v %v", err, ok)
				}
				if stored.Status != jobs.JobQueued {
					t.Errorf("held job status = %q, want queued", stored.Status)
				}
				if stored.Attempts[0].Status != jobs.AttemptQueued || stored.Attempts[0].Attempts != 0 {
					t.Errorf("held job attempt mutated: %+v", stored.Attempts[0])
				}
			}
		})
	}
}

// TestDispatch_PolicyChangeHoldsOnlineJobs proves the policy-change rule:
// flipping the effective policy to local-only holds already-queued online
// jobs instead of dispatching them down a local path, and flipping back
// releases them without re-enqueueing.
func TestDispatch_PolicyChangeHoldsOnlineJobs(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)}
	var calls int
	ob := newTestOutbox(t, clk, func(_ context.Context, job jobs.Job, _ jobs.RecipientAttempt, _ []string) SendOutcome {
		calls++
		return SendOutcome{Status: transfer.StatusOk, Digest: "dd", BytesTransferred: job.TotalSize}
	})
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), netpolicy.Online)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Policy flips to local-only: the online job is held.
	rep, err := ob.DispatchOnce(context.Background(), DispatchOptions{EffectivePolicy: netpolicy.LocalOnly})
	if err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	if calls != 0 || len(rep.Skipped) != 1 {
		t.Fatalf("expected hold under local-only, got calls=%d skipped=%v", calls, rep.Skipped)
	}

	// Policy flips back to online: the same job dispatches without any
	// re-enqueue or policy rewrite.
	rep, err = ob.DispatchOnce(context.Background(), DispatchOptions{EffectivePolicy: netpolicy.Online})
	if err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected dispatch after policy restored, got calls=%d skipped=%v", calls, rep.Skipped)
	}
	stored, _, _ := ob.Get(job.JobID)
	if stored.EffectiveNetworkPolicy() != netpolicy.Online {
		t.Errorf("job policy was rewritten by the policy change: %q", stored.NetworkPolicy)
	}
}

// TestEnqueue_OnlinePolicyStoredCanonically proves jobs enqueued under the
// default policy are byte-identical to v2.0 jobs (networkPolicy omitted),
// preserving checksum compatibility with older readers.
func TestEnqueue_OnlinePolicyStoredCanonically(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)}
	ob := newTestOutbox(t, clk, nil)
	p := writeTempFile(t, t.TempDir(), "a.txt", "data")
	job, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), netpolicy.Online)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if job.NetworkPolicy != "" {
		t.Errorf("online job stored networkPolicy %q, want empty (v2.0 canonical)", job.NetworkPolicy)
	}
	local, err := ob.Enqueue(context.Background(), []string{p}, testRecipients()[:1], jobs.DefaultRetryPolicy(), netpolicy.LocalOnly)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if local.NetworkPolicy != "local-only" {
		t.Errorf("local-only job stored networkPolicy %q, want %q", local.NetworkPolicy, "local-only")
	}
}
