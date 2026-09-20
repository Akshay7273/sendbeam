// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// testRunnerWithLabel builds a routine runner whose dispatches stamp the
// given sender label on their provenance.
func testRunnerWithLabel(store *RecipeStore, ts *trust.MemoryTrustStore, eq Enqueuer, label string) *Runner {
	return NewRunner(
		RunDeps{Store: store, Trust: ts, Now: func() time.Time { return testNow }, SenderLabel: label},
		eq,
		RunnerOptions{},
	)
}

// Every dispatch carries the routine origin label: the recipe's id and
// name, this device's label, and the trigger reason.
func TestDispatch_AttachesProvenance(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)

	for _, reason := range []TriggerReason{TriggerManual, TriggerWatch} {
		if reason != TriggerManual {
			r = grantTestRecipe(t, store, r)
		}
		eq := &recordingEnqueuer{}
		rn := testRunnerWithLabel(store, ts, eq, "test-device")
		if _, err := rn.Dispatch(ctx, r.ID, reason); err != nil {
			t.Fatalf("%s Dispatch: %v", reason, err)
		}
		if eq.calls != 1 {
			t.Fatalf("Enqueue called %d times, want exactly 1", eq.calls)
		}
		p := eq.provenance
		if p == nil {
			t.Fatalf("%s dispatch: no provenance attached", reason)
		}
		if p.RoutineID != r.ID {
			t.Fatalf("provenance routine id = %q, want recipe id %q", p.RoutineID, r.ID)
		}
		if p.RoutineName != r.Name {
			t.Fatalf("provenance routine name = %q, want %q", p.RoutineName, r.Name)
		}
		if p.SenderLabel != "test-device" {
			t.Fatalf("provenance sender label = %q, want test-device", p.SenderLabel)
		}
		if p.Trigger != string(reason) {
			t.Fatalf("provenance trigger = %q, want %q", p.Trigger, reason)
		}
		if err := wire.ValidateProvenance(p); err != nil {
			t.Fatalf("attached provenance fails wire validation: %v", err)
		}
	}
}

// A dispatched run records the actual queued bytes in the last-run
// ledger, so "recipe show" can print "last run sent X of Y bytes".
func TestDispatch_RecordsBytesSent(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)

	eq := &recordingEnqueuer{}
	// "alpha" is 5 bytes; the fake returns this job verbatim.
	eq.job = jobs.Job{JobID: "test-job-1", TotalSize: 5}
	rn := testRunnerWithLabel(store, ts, eq, "test-device")
	if _, err := rn.Dispatch(ctx, r.ID, TriggerManual); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	lr := loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusDispatched {
		t.Fatalf("LastRun status = %q, want dispatched", lr.Status)
	}
	if lr.BytesSent != 5 {
		t.Fatalf("LastRun bytes = %d, want 5", lr.BytesSent)
	}
	// A refused run records no bytes.
	eq2 := &recordingEnqueuer{}
	rn2 := testRunnerWithLabel(store, ts, eq2, "test-device")
	if _, err := rn2.Dispatch(ctx, r.ID, TriggerWatch); err == nil {
		t.Fatal("watch dispatch without grant should be refused")
	}
	lr = loadLastRun(t, store, r.ID)
	if lr.Status != RunStatusRefused || lr.BytesSent != 0 {
		t.Fatalf("refused LastRun = %+v, want refused with zero bytes", lr)
	}
}

// Disable switches the routine off for every trigger reason, including
// manual; a dispatch already admitted is untouched (documented runner
// behavior — Stop prevents new dispatches, never an in-progress one).
func TestDisable_StopsAllDispatch(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	Disable(&r)
	if r.Status != RecipeDisabled {
		t.Fatalf("status = %q, want disabled", r.Status)
	}
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []TriggerReason{TriggerManual, TriggerWatch, TriggerSchedule, TriggerRetry} {
		eq := &recordingEnqueuer{}
		rn := testRunnerWithLabel(store, ts, eq, "test-device")
		_, err := rn.Dispatch(ctx, r.ID, reason)
		if err == nil {
			t.Fatalf("%s dispatch on disabled recipe accepted", reason)
		}
		if wire.CodeOf(err) != wire.CodeAuth {
			t.Fatalf("%s dispatch error code = %s, want AUTH", reason, wire.CodeOf(err))
		}
		if eq.calls != 0 {
			t.Fatalf("%s dispatch on disabled recipe enqueued", reason)
		}
	}
	// The grant survives disable (inert): the audit trail distinguishes
	// "switched off" from "consent withdrawn".
	saved, _, err := store.Load(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Grant.AutoSend {
		t.Fatal("disable should not revoke the automation grant")
	}
}

// Enable returns a disabled routine to approval-required AND revokes its
// automation consent: nothing dispatches until a person re-reviews —
// manual runs need approve first, automation needs a fresh grant after.
func TestEnable_RequiresReApprovalAndReGrant(t *testing.T) {
	ctx := context.Background()
	store, ts, r, _ := runnerTestSetup(t)
	r = grantTestRecipe(t, store, r)

	Disable(&r)
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}
	Enable(&r)
	if r.Status != RecipeApprovalRequired {
		t.Fatalf("status = %q, want approval-required", r.Status)
	}
	if r.Grant.AutoSend {
		t.Fatal("enable must revoke the automation consent")
	}
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}

	// Manual runs are refused until approve.
	eq := &recordingEnqueuer{}
	rn := testRunnerWithLabel(store, ts, eq, "test-device")
	if _, err := rn.Dispatch(ctx, r.ID, TriggerManual); err == nil {
		t.Fatal("manual dispatch on approval-required recipe accepted")
	}
	// Approve re-arms manual runs only.
	r.Status = RecipeManual
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}
	if _, err := rn.Dispatch(ctx, r.ID, TriggerManual); err != nil {
		t.Fatalf("manual dispatch after approve: %v", err)
	}
	// Automation still needs a fresh grant.
	if _, err := rn.Dispatch(ctx, r.ID, TriggerWatch); err == nil {
		t.Fatal("watch dispatch without a fresh grant accepted")
	}
	r, _, err := store.Load(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("re-grant after enable: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}
	if _, err := rn.Dispatch(ctx, r.ID, TriggerWatch); err != nil {
		t.Fatalf("watch dispatch after re-grant: %v", err)
	}
}

// Disable and Enable are nil-safe: a missing record never panics a
// control path.
func TestControls_NilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Disable/Enable panicked on nil: %v", r)
		}
	}()
	Disable(nil)
	Enable(nil)
}

// Provenance display renders the consent-surface line the receiver
// shows; it never renders blank.
func TestProvenance_Display(t *testing.T) {
	p := Provenance{RoutineID: "id", RoutineName: "nightly", SenderLabel: "laptop", Trigger: TriggerWatch}
	if got := p.Display(); got != "Routine: nightly (trigger: watch) from laptop" {
		t.Fatalf("display = %q", got)
	}
}
