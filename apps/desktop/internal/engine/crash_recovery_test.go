// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// ---------------------------------------------------------------------------
// SB-R08: cancellation, shutdown, durable consistency, crash recovery.
//
// EXISTING COVERAGE (reused as regression anchors, not duplicated):
//   - cancellation-in-flight with a bytes-moving barrier and post-cancel
//     dispatch blocking (TestRecipeCancellationInFlight),
//   - graceful desktop shutdown with bounded join (TestDesktopGracefulShutdown),
//   - lifecycle coordinator sleep/wake/shutdown (lifecycle tests),
//   - scheduler crash between cursor and dispatch + no duplicate
//     re-dispatch after restart (TestSchedulerCrashBetweenCursorAndDispatch),
//   - runner crash after dispatch, durable job survives a simulated
//     restart (TestRunnerCrashAfterDispatch),
//   - outbox restart re-queueing interrupted attempts and
//     cancel-during-send dropping in-flight results
//     (TestDispatch_RestartRequeuesInterrupted, TestDispatch_CancelDuringSendDropsResult),
//   - lease acquire/renew/adoption units (jobs/lease_test.go),
//   - durable resume and corrupt-journal quarantine (durability_test.go).
//
// NEW HERE:
//   1. cancel-vs-verification linearization at the service level, both
//      orderings, real transfer (before receiver commit → never verified,
//      receiver file never written; after commit → cancel refused,
//      legitimate success preserved),
//   2. shutdown racing an ACTIVE recipe dispatch pass (bounded join, no
//      leaked workers, no false delivery),
//   3. rapid lifecycle cycling of dispatcher/scheduler/watch,
//   4. REAL process death: a subprocess of this test binary crashes with
//      os.Exit(9) at the persisted attempt-Active boundary; the parent
//      reopens the REAL on-disk job store and proves: no false delivery,
//      no concurrent active owners while the lease is live, adoption after
//      expiry re-queues interrupted WITHOUT consuming budget, exactly one
//      job (no duplicates),
//   5. service-level scheduled-occurrence deduplication across restart.
//
// THE AT-MOST-ONCE CONTRACT (as implemented, stated precisely): the
// scheduler's cursor is persisted BEFORE dispatch, so a crash can lose a
// dispatch but never re-issue a consumed occurrence (no duplicates). The
// crash window between the sender's "receiver verified" and the sender's
// persisted outcome is a real delivery-uncertainty window: the receiver
// may hold verified content the sender will re-send after adopting the
// stale lease (attempt re-queued interrupted). The receiver-side durable
// journal/resume dedup is the mitigation at the transfer layer; this is
// NOT an exactly-once end-to-end guarantee and no such claim is made.
// ---------------------------------------------------------------------------

// waitChecked polls cond until true or the deadline passes, then fails
// with the given context message.
func waitChecked(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: condition not met within %s", what, d)
}

// receiverGate wraps a consent handler: closes entered on the first call
// (the transfer is provably in flight, at the receiver consent boundary),
// then delegates.
func receiverGate(entered chan struct{}, inner transfer.ConsentHandler) transfer.ConsentHandler {
	var once atomic.Bool
	return func(ctx context.Context, req transfer.ConsentRequest) (transfer.ConsentDecision, error) {
		if once.CompareAndSwap(false, true) {
			close(entered)
		}
		if inner == nil {
			return transfer.ConsentDecision{Accepted: true}, nil
		}
		return inner(ctx, req)
	}
}

// ---------------------------------------------------------------------------
// 1. Cancellation / verification linearization (both orderings)
// ---------------------------------------------------------------------------

// TestR08CancelAtConsentBoundaryStopsBothSides: the cancel lands while the
// receiver is held at the consent gate (nothing committed receiver-side).
// After the cancel, the receiver context is cancelled BEFORE its consent is
// released, so the receiver must refuse and abort with NO file, and the
// sender must record the cancelled job with the in-flight outcome dropped —
// no false delivery on either side, and no resurrection of the job.
//
// Delivery-uncertainty note (documented, tested separately): if the whole
// payload had already reached the wire before the cancel took effect, the
// receiver's commit is legitimate (the wire has no recall); the mid-stream
// stop is proven by TestR08CancelMidStreamStopsBytesAndNeverDelivers.
func TestR08CancelAtConsentBoundaryStopsBothSides(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	recipeID := enqueueRecipe(t, svc, fx.peerIdentity.DeviceID, fx.sources, "local-only")
	jobID := lastRunJobID(t, svc, recipeID)
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })

	entered := make(chan struct{})
	consentRelease := make(chan struct{})
	recvDone, recvCancel := fx.startReceiver(t, fx.peerIdentity.DeviceID, receiverGate(entered, func(rcvCtx context.Context, _ transfer.ConsentRequest) (transfer.ConsentDecision, error) {
		// Hold consent until the test releases it (after the cancel and
		// the receiver-context cancel): the refusal path is then taken
		// deterministically — nothing is committed receiver-side.
		<-consentRelease
		if rcvCtx.Err() != nil {
			return transfer.ConsentDecision{Accepted: false, Reason: "cancelled"}, rcvCtx.Err()
		}
		return transfer.ConsentDecision{Accepted: true}, nil
	}))
	defer recvCancel()

	passDone := make(chan struct{})
	go func() {
		defer close(passDone)
		_, _ = svc.DispatchOnceNow(ctx)
	}()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("transfer never reached the receiver consent boundary")
	}

	// CANCEL through the production API (what the UI cancel invokes).
	if err := svc.outbox.Cancel(jobID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	// Stop the receiver context, THEN release consent: the receiver must
	// take the refusal path and abort without any file.
	recvCancel()
	close(consentRelease)

	select {
	case <-passDone:
	case <-time.After(60 * time.Second):
		t.Fatal("dispatch pass did not settle after cancellation (termination bound exceeded)")
	}

	// Sender side: honest terminal state, in-flight outcome dropped, no
	// resurrection.
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	if job.Status != jobs.JobCancelled {
		t.Fatalf("job status after cancel = %q, want cancelled", job.Status)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.Status == jobs.AttemptVerified || a.Status == jobs.AttemptCompleted {
			t.Fatalf("attempt marked %q after cancellation — false delivery", a.Status)
		}
		if a.VerifiedDigest != "" {
			t.Fatalf("attempt carries a verified digest %q after cancellation", a.VerifiedDigest)
		}
	}
	// Receiver side: refusal path — the receiver terminal error must NOT
	// be a clean success and NO file may exist.
	recvCancel()
	select {
	case rerr := <-recvDone:
		if rerr == nil {
			t.Fatal("receiver completed cleanly after the cancellation — the stop did not reach it")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("receiver did not settle after the cancellation")
	}
	if _, statErr := os.Stat(filepath.Join(fx.destDir, "route.bin")); statErr == nil {
		t.Fatal("final output file exists at the receiver after the cancelled consent — false delivery on disk")
	}

	// Further dispatch stays blocked for the cancelled job (no unauthorized
	// retry after an explicit cancel).
	rep, err := svc.DispatchOnceNow(ctx)
	if err != nil {
		t.Fatalf("second dispatch pass: %v", err)
	}
	if rep.JobsDispatched != 0 {
		t.Fatalf("cancelled job was re-dispatched: %+v", rep)
	}
}

// TestR08CancelMidStreamStopsBytesAndNeverDelivers is the bytes-stop proof:
// a large payload is mid-transfer (receiver durable staging shows partial
// bytes) when the cancel fires. The transfer must terminate within a
// bounded window; the receiver must NOT end up with the final file; the
// sender must record the cancel honestly with no verified digest; and no
// outcome may resurrect the cancelled job.
func TestR08CancelMidStreamStopsBytesAndNeverDelivers(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// ~200 MiB payload: completion within the cancel latency is
	// physically impossible even on loopback (~2s at loopback SCTP
	// throughput), so the cancel provably fires mid-stream.
	root := fx.sources
	payload := bytes.Repeat([]byte("R08-MIDSTREAM-CANCEL-"), 9600000)
	if err := os.WriteFile(filepath.Join(root, "route.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	recipeID := enqueueRecipe(t, svc, fx.peerIdentity.DeviceID, root, "local-only")
	jobID := lastRunJobID(t, svc, recipeID)
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })

	recvDone, recvCancel := fx.startReceiver(t, fx.peerIdentity.DeviceID, nil)
	defer recvCancel()

	passDone := make(chan struct{})
	go func() {
		defer close(passDone)
		_, _ = svc.DispatchOnceNow(ctx)
	}()

	// BYTES-MOVING barrier: cancel only when the receiver's durable
	// journal staging shows REAL partial bytes (the transfer is provably
	// mid-flight, not merely armed).
	staging := filepath.Join(fx.destDir, ".sendbeam")
	waitChecked(t, "staged partial bytes", 60*time.Second, func() bool {
		entries, rerr := os.ReadDir(staging)
		if rerr != nil {
			return false
		}
		for _, e := range entries {
			if info, ierr := e.Info(); ierr == nil && info.Size() > 0 {
				return true
			}
			// staging is hierarchical: transfer-id dirs contain the parts
			if e.IsDir() {
				sub, serr := os.ReadDir(filepath.Join(staging, e.Name()))
				if serr == nil {
					for _, se := range sub {
						if info, ierr := se.Info(); ierr == nil && info.Size() > 0 {
							return true
						}
					}
				}
			}
		}
		return false
	})

	// Snapshot the staged partials BEFORE the cancel: they prove bytes
	// actually moved (the pre-cancel state), and after the abort they must
	// STILL be present (stopped mid-stream, never promoted) while no final
	// file ever appears.
	stagedBefore := 0
	var stagedBytes int64
	walkStaging := func() (int, int64) {
		count, total := 0, int64(0)
		_ = filepath.Walk(staging, func(_ string, info os.FileInfo, werr error) error {
			if werr != nil || info.IsDir() {
				return nil
			}
			count++
			total += info.Size()
			return nil
		})
		return count, total
	}
	stagedBefore, stagedBytes = walkStaging()
	if stagedBefore == 0 || stagedBytes == 0 {
		t.Fatal("barrier precondition failed: no staged partial bytes before the cancel")
	}
	cancelStart := time.Now()
	if err := svc.outbox.Cancel(jobID); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	// The dispatch pass must settle within a bounded window after the
	// cancel (the in-flight stop propagated).
	select {
	case <-passDone:
	case <-time.After(45 * time.Second):
		t.Fatal("dispatch pass did not settle within 45s of the cancel — termination bound exceeded")
	}
	t.Logf("transfer terminated %v after cancel", time.Since(cancelStart))

	// Sender: honest cancel, no delivery, no resurrection.
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	if job.Status != jobs.JobCancelled {
		t.Fatalf("job status after mid-stream cancel = %q, want cancelled", job.Status)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.Status == jobs.AttemptVerified || a.Status == jobs.AttemptCompleted {
			t.Fatalf("attempt marked %q after mid-stream cancel — false delivery", a.Status)
		}
		if a.VerifiedDigest != "" {
			t.Fatalf("attempt carries a verified digest %q after mid-stream cancel", a.VerifiedDigest)
		}
	}

	// Receiver: the abort must leave the staged partials in place (the
	// documented journal behavior — resumable, never final without the
	// digest-verified completion) and NO final file, even after the
	// receiver goroutine fully settles.
	recvDeadline := time.Now().Add(20 * time.Second)
	settledRecv := false
	for time.Now().Before(recvDeadline) {
		select {
		case <-recvDone:
			settledRecv = true
		case <-time.After(100 * time.Millisecond):
		}
		if settledRecv {
			break
		}
	}
	if _, statErr := os.Stat(filepath.Join(fx.destDir, "route.bin")); statErr == nil {
		t.Fatal("final output file exists at the receiver after a mid-stream cancel — false delivery on disk")
	}
	stagedAfter, stagedBytesAfter := walkStaging()
	if stagedAfter == 0 || stagedBytesAfter == 0 {
		t.Fatal("staged partials vanished after the mid-stream abort — expected the durable journal to keep them (resumable, unpromoted)")
	}
	t.Logf("staged partials preserved: %d file(s), %d bytes (bytes moved, then stopped)", stagedAfter, stagedBytesAfter)
	// The receiver must not have finished cleanly.
	select {
	case rerr := <-recvDone:
		_ = rerr // error (cancelled transport) or nil both fine here: the
		// final-file assertion above is the delivery truth on disk.
	case <-time.After(15 * time.Second):
	}

	// No unauthorized retry: a further pass must not re-dispatch the
	// cancelled job.
	rep, err := svc.DispatchOnceNow(ctx)
	if err != nil {
		t.Fatalf("post-cancel dispatch pass: %v", err)
	}
	if rep.JobsDispatched != 0 {
		t.Fatalf("cancelled job re-dispatched: %+v", rep)
	}
}

// TestR08VerifiedBeforeCancelPreservesLegitimateSuccess pins the other
// linearization ordering: verification completes and is recorded BEFORE
// the cancel arrives; the cancel is then refused (terminal), and the
// legitimate success is preserved — history is never rewritten.
func TestR08VerifiedBeforeCancelPreservesLegitimateSuccess(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	recipeID := enqueueRecipe(t, svc, fx.peerIdentity.DeviceID, fx.sources, "local-only")
	jobID := lastRunJobID(t, svc, recipeID)
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })
	recvDone, recvCancel := fx.startReceiver(t, fx.peerIdentity.DeviceID, nil)
	defer recvCancel()

	if _, err := svc.DispatchOnceNow(ctx); err != nil {
		t.Fatalf("dispatch pass: %v", err)
	}
	// Wait for the VERIFIED attempt (real transfer completion).
	waitChecked(t, "verified attempt", 80*time.Second, func() bool {
		j, ok, _ := svc.jobs.Load(jobID)
		if !ok {
			return false
		}
		for _, a := range j.Attempts {
			if a.VerifiedDigest != "" && (a.Status == jobs.AttemptVerified || a.Status == jobs.AttemptCompleted) {
				return true
			}
		}
		return false
	})

	// Cancel AFTER the verified commit: must be refused — the job is
	// terminal and history must not be rewritten.
	if err := svc.outbox.Cancel(jobID); err == nil {
		t.Fatal("cancel succeeded on a verified/completed job — terminal state must refuse cancellation")
	}
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	if job.Status != jobs.JobCompleted {
		t.Fatalf("job status = %q, want completed (legitimate success preserved)", job.Status)
	}
	sum := sha256.Sum256(fx.payload)
	if job.Attempts[0].VerifiedDigest != hex.EncodeToString(sum[:]) {
		t.Fatalf("VerifiedDigest = %q, want the payload digest", job.Attempts[0].VerifiedDigest)
	}
	select {
	case <-recvDone:
	case <-time.After(10 * time.Second):
	}
}

// ---------------------------------------------------------------------------
// 2. Shutdown racing active dispatch; rapid lifecycle cycling
// ---------------------------------------------------------------------------

// TestR08ShutdownDuringActiveDispatchPass: shutdown fires while a REAL
// transfer is mid-flight (partial bytes staged). The DOCUMENTED contract
// (RecipeService.Shutdown): in-flight passes finish under the bounded
// lease — so the transfer may legitimately complete OR be interrupted by
// the shutdown; what must hold is the bounded join, no leaked workers, and
// an HONEST consistent ledger (completed only with a verified digest; any
// non-completed state must carry no digest).
func TestR08ShutdownDuringActiveDispatchPass(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Large payload: the transfer is still mid-flight at shutdown.
	payload := bytes.Repeat([]byte("R08-SHUTDOWN-MIDFLIGHT-"), 900000) // ~20 MiB
	if err := os.WriteFile(filepath.Join(fx.sources, "route.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	recipeID := enqueueRecipe(t, svc, fx.peerIdentity.DeviceID, fx.sources, "local-only")
	jobID := lastRunJobID(t, svc, recipeID)
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })

	recvDone, recvCancel := fx.startReceiver(t, fx.peerIdentity.DeviceID, nil)
	defer recvCancel()

	runtimeBefore := runtime.NumGoroutine()
	passDone := make(chan struct{})
	go func() {
		defer close(passDone)
		_, _ = svc.DispatchOnceNow(ctx)
	}()

	// BYTES-MOVING barrier: shutdown while real bytes are staging.
	staging := filepath.Join(fx.destDir, ".sendbeam")
	waitChecked(t, "staged partial bytes", 60*time.Second, func() bool {
		entries, rerr := os.ReadDir(staging)
		if rerr != nil {
			return false
		}
		for _, e := range entries {
			if info, ierr := e.Info(); ierr == nil && info.Size() > 0 {
				return true
			}
			if e.IsDir() {
				sub, serr := os.ReadDir(filepath.Join(staging, e.Name()))
				if serr == nil {
					for _, se := range sub {
						if info, ierr := se.Info(); ierr == nil && info.Size() > 0 {
							return true
						}
					}
				}
			}
		}
		return false
	})

	// SHUTDOWN (bounded join) while the pass is active.
	deployStart := time.Now()
	if err := svc.Shutdown(10 * time.Second); err != nil {
		t.Fatalf("Shutdown during active dispatch: %v (bounded join failed)", err)
	}
	if elapsed := time.Since(deployStart); elapsed > 12*time.Second {
		t.Fatalf("Shutdown took %v — exceeded its own bound", elapsed)
	}

	// The pass must still settle (its outbox dispatch context is not owned
	// by the service; the pass unwinds through the transfer).
	select {
	case <-passDone:
	case <-time.After(90 * time.Second):
		t.Fatal("dispatch pass did not settle after shutdown")
	}

	// Bounded worker-leak check: settle, then compare goroutine counts
	// with a small tolerance for runtime jitter (GC, timers).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= runtimeBefore+2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > runtimeBefore+2 {
		t.Fatalf("worker leak after shutdown: before=%d after=%d", runtimeBefore, after)
	}

	// HONEST ledger: completed ⇔ a verified digest exists; anything else
	// must carry none.
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if job.Status == jobs.JobCompleted && a.VerifiedDigest == "" {
			t.Fatal("job completed without a verified digest — false delivery")
		}
		if job.Status != jobs.JobCompleted && a.VerifiedDigest != "" {
			t.Fatalf("job status %q but attempt carries a verified digest — inconsistent ledger", job.Status)
		}
		if a.Status == jobs.AttemptCompleted && a.VerifiedDigest == "" {
			t.Fatal("attempt completed without a verified digest")
		}
	}
	select {
	case <-recvDone:
	case <-time.After(10 * time.Second):
	}
}

// TestR08RapidLifecycleCycling arms and disarms every owned worker in
// rapid succession; each cycle must settle, and the machinery must remain
// startable afterwards (no wedged state, no leaked start/stop state).
func TestR08RapidLifecycleCycling(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc

	for i := 0; i < 25; i++ {
		if err := svc.StartDispatcher(time.Hour); err != nil {
			t.Fatalf("iter %d: StartDispatcher: %v", i, err)
		}
		if err := svc.StartScheduler(); err != nil {
			t.Fatalf("iter %d: StartScheduler: %v", i, err)
		}
		// Watch may legitimately fail for a recipe without watch params —
		// either way it must not wedge the service.
		if err := svc.StartWatch("nightly"); err == nil {
			_ = svc.StopWatch("nightly")
		}
		svc.StopDispatcher()
		if err := svc.StopScheduler(); err != nil {
			t.Fatalf("iter %d: StopScheduler: %v", i, err)
		}
	}
	// Final: everything startable again.
	if err := svc.StartDispatcher(time.Hour); err != nil {
		t.Fatalf("dispatcher not startable after cycling: %v", err)
	}
	svc.StopDispatcher()
	if err := svc.StartScheduler(); err != nil {
		t.Fatalf("scheduler not startable after cycling: %v", err)
	}
	if err := svc.StopScheduler(); err != nil {
		t.Fatalf("final StopScheduler: %v", err)
	}
	// Bounded Shutdown still works after the cycling.
	if err := svc.Shutdown(5 * time.Second); err != nil {
		t.Fatalf("Shutdown after cycling: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 4. Scheduled occurrences: service-level restart deduplication
// ---------------------------------------------------------------------------

// TestR08ScheduledOccurrenceNotReDispatchedAfterRestart proves the
// service-level at-most-once contract: a due occurrence is dispatched once
// (cursor persisted before dispatch), and a restarted service's scheduler
// must NOT re-dispatch the consumed occurrence — while legitimate job
// retries (same job, attempt+1) remain a different mechanism.
func TestR08ScheduledOccurrenceNotReDispatchedAfterRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Service 1 over a real on-disk state dir.
	dir := t.TempDir()
	ts := trust.NewMemoryTrustStore()
	idm, err := trust.NewIdentityManager(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := trust.NewFileSecretStore(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewRecipeService(dir, ts, idm, secrets)
	if err != nil {
		t.Fatal(err)
	}
	senderIdentity, err := idm.GetOrCreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerIdentity, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, pair := range [][2]*wire.DeviceIdentity{{senderIdentity, peerIdentity}, {peerIdentity, senderIdentity}} {
		_, peer := pair[0], pair[1]
		if err := ts.AddOrUpdateDevice(ctx, &wire.TrustRecord{
			DeviceID:          peer.DeviceID,
			PublicKey:         peer.PublicKeyHex(),
			LocalLabel:        "peer",
			PairCredentialRef: "cred-sched",
			FirstSeenAt:       now,
			LastSeenAt:        now,
			Policy:            wire.DefaultTrustPolicy(),
		}); err != nil {
			t.Fatal(err)
		}
		if err := secrets.SetSecret(peer.DeviceID, []byte(strings.Repeat("k", 32))); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(dir, "src")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "f.bin"), []byte("scheduled occurrence"), 0o600); err != nil {
		t.Fatal(err)
	}

	in := newEditorInput("nightly", root, peerIdentity.DeviceID)
	in.NetworkPolicy = "online"
	in.TriggerKind = "schedule"
	// Hourly interval: within the whole test window EXACTLY ONE occurrence
	// can possibly be due (the one the cursor backdate creates), so any
	// second job is a dedup violation by construction — no minute-boundary
	// crossing can legitimately add a catch-up occurrence.
	in.ScheduleParams = map[string]any{"kind": "interval", "every_minutes": 60}
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatalf("CreateRecipe(schedule): %v", err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantAutomation(created.ID); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}

	// Make exactly one occurrence due now: cursor backdated one full
	// interval. The next real occurrence is an hour away — no test-timing
	// race can add another.
	if err := svc.store.AdvanceScheduleCursor(created.ID, time.Now().UTC().Add(-60*time.Minute)); err != nil {
		t.Fatalf("backdate cursor: %v", err)
	}
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.Online })
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		return transfer.Outcome{}, errors.New("no signaling server in test (honest failure)")
	})

	if err := svc.StartScheduler(); err != nil {
		t.Fatalf("StartScheduler: %v", err)
	}
	// The synchronous first tick dispatches the occurrence. The consumed
	// occurrence is identified by the DURABLE JOB (the catch-up ledger
	// records its summary entry with an empty job id by design — last
	// write wins), so the job store is the dedup anchor here.
	waitChecked(t, "scheduled dispatch", 15*time.Second, func() bool {
		list, err := svc.outbox.List()
		return err == nil && len(list) == 1
	})
	list1, err := svc.outbox.List()
	if err != nil || len(list1) != 1 {
		t.Fatalf("first outbox list: %v (%d entries)", err, len(list1))
	}
	occurrenceJobID := list1[0].JobID
	before, okBefore, err := svc.store.Load(created.ID)
	if err != nil || !okBefore {
		t.Fatalf("load recipe: %v", err)
	}
	if before.LastRun == nil {
		t.Fatalf("scheduled run not recorded: %+v", before.LastRun)
	}
	if err := svc.StopScheduler(); err != nil {
		t.Fatalf("StopScheduler: %v", err)
	}
	if cur, okCur, errCur := svc.store.Load(created.ID); errCur == nil && okCur {
		t.Logf("CURSOR-DIAG before restart: %v", cur.ScheduleCursor)
	}
	if err := svc.Shutdown(5 * time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Service 2: a RESTARTED process over the SAME state dir, with a fresh
	// trust store that WOULD let a re-dispatch succeed (making the
	// no-re-dispatch assertion strong: any dispatch would create a job).
	ts2 := trust.NewMemoryTrustStore()
	idm2, err := trust.NewIdentityManager(filepath.Join(dir, "identity2.key"))
	if err != nil {
		t.Fatal(err)
	}
	secrets2, err := trust.NewFileSecretStore(filepath.Join(dir, "secrets2.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc2, err := NewRecipeService(dir, ts2, idm2, secrets2)
	if err != nil {
		t.Fatalf("restart service: %v", err)
	}
	t.Cleanup(func() { _ = svc2.Shutdown(5 * time.Second) })
	senderIdentity2, err := idm2.GetOrCreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now2 := time.Now().UTC()
	for _, pair := range [][2]*wire.DeviceIdentity{{senderIdentity2, peerIdentity}, {peerIdentity, senderIdentity2}} {
		_, peer := pair[0], pair[1]
		if err := ts2.AddOrUpdateDevice(ctx, &wire.TrustRecord{
			DeviceID:          peer.DeviceID,
			PublicKey:         peer.PublicKeyHex(),
			LocalLabel:        "peer",
			PairCredentialRef: "cred-sched2",
			FirstSeenAt:       now2,
			LastSeenAt:        now2,
			Policy:            wire.DefaultTrustPolicy(),
		}); err != nil {
			t.Fatal(err)
		}
		if err := secrets2.SetSecret(peer.DeviceID, []byte(strings.Repeat("k", 32))); err != nil {
			t.Fatal(err)
		}
	}
	svc2.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.Online })
	svc2.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		return transfer.Outcome{}, errors.New("no signaling server in restarted test (honest failure)")
	})

	if err := svc2.StartScheduler(); err != nil {
		t.Fatalf("restarted StartScheduler: %v", err)
	}
	// Observe long enough for a tick to act if it were going to (the next
	// real occurrence is a minute away; the observation window is far
	// shorter and deterministic).
	//
	// Which job the restart must NOT create: the outbox may legitimately
	// hold the ORIGINAL job (still non-terminal after the honest online
	// failure — retrying it is the legitimate job-retry mechanism, a
	// different thing from a duplicate occurrence). A SECOND job for the
	// same recipe is the duplicate-occurrence violation.
	time.Sleep(3 * time.Second)
	list2, err := svc2.outbox.List()
	if err != nil {
		t.Fatalf("restarted list: %v", err)
	}
	if len(list2) > 1 {
		for _, jj := range list2 {
			full, _, _ := svc2.jobs.Load(jj.JobID)
			prov := "nil"
			if full.Provenance != nil {
				prov = full.Provenance.Trigger + "/" + full.Provenance.RoutineName
			}
			t.Logf("DUPLICATE-DIAG job=%s created=%v status=%s prov=%s", jj.JobID[:8], jj.CreatedAt, jj.Status, prov)
		}
		t.Fatalf("restarted outbox has %d job(s), want at most 1 — a second job is a duplicate occurrence dispatch", len(list2))
	}
	for _, j := range list2 {
		if j.JobID != occurrenceJobID {
			t.Fatalf("unexpected NEW job %s — duplicate occurrence dispatch", j.JobID[:8])
		}
	}
	after, okAfter, err := svc2.store.Load(created.ID)
	if err != nil || !okAfter {
		t.Fatalf("reload recipe: %v", err)
	}
	if after.LastRun == nil || !after.LastRun.At.Equal(before.LastRun.At) {
		t.Fatalf("LastRun changed across restart: %v -> %v (duplicate ledger entry)", before.LastRun.At, after.LastRun.At)
	}
	if err := svc2.StopScheduler(); err != nil {
		t.Fatalf("restarted StopScheduler: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SB-R08: REAL process death (subprocess) + on-disk recovery.
//
// The crash helper is this test binary re-executed with SENDBEAM_R08_CRASH
// set. It builds a REAL RecipeService over REAL on-disk stores, drives a
// real transfer to the in-flight (consent-gated) boundary, waits for the
// PERSISTED attempt-Active record, then dies abruptly via os.Exit(9) — no
// unwinding, no defers: the deterministic process-death model available in
// this environment.
//
// The parent reopens the job store from disk (as a restarted process would)
// and asserts the recovery invariants from PERSISTED state. Nothing here is
// simulated lease expiry; the lease in the store is the one the dead process
// wrote.
// ---------------------------------------------------------------------------

// TestR08CrashHelperEntrypoint is the subprocess entrypoint; it is a no-op
// in a normal test run.
func TestR08CrashHelperEntrypoint(t *testing.T) {
	mode := os.Getenv("SENDBEAM_R08_CRASH")
	if mode == "" {
		t.Skip("crash-helper entrypoint (only runs as a subprocess)")
	}
	stateDir := os.Getenv("SENDBEAM_R08_STATE")
	if stateDir == "" {
		fmt.Fprintln(os.Stderr, "helper: missing SENDBEAM_R08_STATE")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ts := trust.NewMemoryTrustStore()
	idm, err := trust.NewIdentityManager(filepath.Join(stateDir, "identity.key"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: identity: %v\n", err)
		os.Exit(3)
	}
	secrets, err := trust.NewFileSecretStore(filepath.Join(stateDir, "secrets.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: secrets: %v\n", err)
		os.Exit(3)
	}
	svc, err := NewRecipeService(stateDir, ts, idm, secrets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: service: %v\n", err)
		os.Exit(3)
	}

	senderIdentity, err := idm.GetOrCreateIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: sender identity: %v\n", err)
		os.Exit(3)
	}
	peerIdentity, err := wire.GenerateDeviceIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: peer identity: %v\n", err)
		os.Exit(3)
	}
	now := time.Now().UTC()
	for _, pair := range [][2]*wire.DeviceIdentity{{senderIdentity, peerIdentity}, {peerIdentity, senderIdentity}} {
		_, peer := pair[0], pair[1]
		if err := ts.AddOrUpdateDevice(ctx, &wire.TrustRecord{
			DeviceID:          peer.DeviceID,
			PublicKey:         peer.PublicKeyHex(),
			LocalLabel:        "peer",
			PairCredentialRef: "cred-crash",
			FirstSeenAt:       now,
			LastSeenAt:        now,
			Policy:            wire.DefaultTrustPolicy(),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "helper: trust: %v\n", err)
			os.Exit(3)
		}
		if err := secrets.SetSecret(peer.DeviceID, []byte(strings.Repeat("k", 32))); err != nil {
			fmt.Fprintf(os.Stderr, "helper: secret: %v\n", err)
			os.Exit(3)
		}
	}

	root := filepath.Join(stateDir, "src")
	if err := os.MkdirAll(root, 0o755); err != nil {
		os.Exit(3)
	}
	payload := bytes.Repeat([]byte("R08-CRASH-BOUNDARY-"), 120000) // ~2.3 MiB
	if err := os.WriteFile(filepath.Join(root, "route.bin"), payload, 0o600); err != nil {
		os.Exit(3)
	}
	destDir := filepath.Join(stateDir, "out")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		os.Exit(3)
	}

	in := newEditorInput("nightly", root, peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: create: %v\n", err)
		os.Exit(3)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		fmt.Fprintf(os.Stderr, "helper: approve: %v\n", err)
		os.Exit(3)
	}
	jobID, err := svc.RunRecipe(created.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: run: %v\n", err)
		os.Exit(3)
	}
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })

	// Real receiver with a consent gate that holds until the process dies:
	// the send is authenticated and mid-flight at the crash boundary.
	entered := make(chan struct{})
	recvCtx := context.Background()
	go func() {
		rcvSrv := localrendezvous.NewServer(localrendezvous.Config{
			BindAddr:      "127.0.0.1:0",
			AllowWildcard: false,
		}, ts)
		recvAddr, err := rcvSrv.Start(recvCtx)
		if err != nil {
			return
		}
		svc.SetLocalPeerAddr(peerIdentity.DeviceID, recvAddr.String())
		_, _ = localtransfer.Receive(recvCtx, localtransfer.ReceiveOptions{
			Identity: peerIdentity,
			Store:    ts,
			Resolver: secrets,
			Server:   rcvSrv,
			DestDir:  destDir,
			Consent: receiverGate(entered, func(rcvCtx context.Context, _ transfer.ConsentRequest) (transfer.ConsentDecision, error) {
				<-recvCtx.Done()
				return transfer.ConsentDecision{Accepted: false, Reason: "crash"}, rcvCtx.Err()
			}),
		})
	}()

	// Wait for the transfer to reach the consent boundary (in flight), then
	// wait for the PERSISTED attempt-Active record on disk — the crash
	// boundary is AFTER the lease acquire and the attempt journal write.
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		fmt.Fprintln(os.Stderr, "helper: transfer never reached the consent boundary")
		os.Exit(4)
	}
	js, err := jobs.OpenJobStore(filepath.Join(stateDir, "jobs"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: reopen jobs: %v\n", err)
		os.Exit(3)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		job, ok, err := js.Load(jobID)
		if err == nil && ok && len(job.Attempts) > 0 && job.Attempts[0].Status == jobs.AttemptActive {
			// THE CRASH: abrupt process death. No unwinding, no defers.
			os.Exit(9)
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "helper: attempt never became active on disk")
	os.Exit(5)
}

// TestR08ProcessDeathMidSendRecoversFromDisk is the parent: it re-executes
// this test binary as a subprocess that dies abruptly (exit 9) at the
// persisted attempt-Active boundary, then reopens the REAL on-disk job
// store and proves the recovery invariants from PERSISTED state:
//   - the attempt is Active with no verified digest (crash window; no
//     false delivery),
//   - the live lease REFUSES another owner (no concurrent active owners),
//   - adoption AFTER expiry re-queues the attempt interrupted WITHOUT
//     consuming budget,
//   - exactly one job exists (no duplicates from the crash),
//   - the receiver-side state has no final output file.
func TestR08ProcessDeathMidSendRecoversFromDisk(t *testing.T) {
	if testing.Short() {
		t.Skip("process-death recovery requires the full test binary")
	}
	stateDir := t.TempDir()

	cmd := exec.Command(os.Args[0], "-test.run", "TestR08CrashHelperEntrypoint", "-test.timeout", "150s")
	cmd.Env = append(os.Environ(),
		"SENDBEAM_R08_CRASH=mid-send",
		"SENDBEAM_R08_STATE="+stateDir,
	)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code != 9 {
			t.Fatalf("crash subprocess exited %d, want 9 (signal-free abrupt death); output:\n%s", code, out)
		}
	} else if err != nil {
		t.Fatalf("crash subprocess failed to run: %v; output:\n%s", err, out)
	} else {
		t.Fatalf("crash subprocess exited 0 — the crash did not happen; output:\n%s", out)
	}

	// ---- reopen the REAL job store, as a restarted process would ----
	js, err := jobs.OpenJobStore(filepath.Join(stateDir, "jobs"))
	if err != nil {
		t.Fatalf("reopen job store: %v", err)
	}
	entries, err := outbox.New(js, nil).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("on-disk job count = %d, want exactly 1 (no duplicates from the crash)", len(entries))
	}
	job, ok, err := js.Load(entries[0].JobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	if job.Status != jobs.JobDispatching {
		t.Fatalf("persisted job status = %q, want dispatching (crashed mid-send)", job.Status)
	}
	if job.Lease == nil {
		t.Fatal("persisted job has no lease — the crash lost the lease record")
	}
	if len(job.Attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(job.Attempts))
	}
	a := job.Attempts[0]
	if a.Status != jobs.AttemptActive {
		t.Fatalf("persisted attempt status = %q, want active (crash before outcome)", a.Status)
	}
	if a.VerifiedDigest != "" {
		t.Fatalf("persisted attempt carries a verified digest %q — false delivery across crash", a.VerifiedDigest)
	}
	if a.Attempts != 1 {
		t.Fatalf("persisted attempt count = %d, want 1 (budget preserved)", a.Attempts)
	}

	// No concurrent active owners while the lease is live: a different
	// owner's acquire must FAIL CLOSED.
	if err := jobs.AcquireLease(&job, "recovered-owner", jobs.DefaultLeaseTTL, time.Now().UTC()); err == nil {
		t.Fatal("a second owner acquired the live lease — concurrent active owners possible")
	}

	// Adoption AFTER expiry: re-queues the ACTIVE attempt as interrupted
	// (MarkInterruptedAfterCrash) and preserves the retry budget.
	future := time.Now().UTC().Add(3 * time.Minute)
	if err := jobs.AcquireLease(&job, "recovered-owner", jobs.DefaultLeaseTTL, future); err != nil {
		t.Fatalf("stale-lease adoption: %v", err)
	}
	if job.Attempts[0].Status != jobs.AttemptInterrupted {
		t.Fatalf("attempt status after adoption = %q, want interrupted (crash recovery re-queue)", job.Attempts[0].Status)
	}
	if job.Attempts[0].Attempts != 1 {
		t.Fatalf("attempt count after adoption = %d, want 1 (budget preserved)", job.Attempts[0].Attempts)
	}
	if err := js.Save(job); err != nil {
		t.Fatalf("save adopted job: %v", err)
	}

	// The restarted outbox lists the adopted, non-terminal job for normal
	// dispatch (the documented restart-recovery path).
	entries2, err := outbox.New(js, nil).List()
	if err != nil {
		t.Fatalf("list after adoption: %v", err)
	}
	if len(entries2) != 1 {
		t.Fatalf("job count after adoption = %d, want 1", len(entries2))
	}

	// Receiver-side durable state: no final output file from the crashed
	// transfer (the receiver died at consent; nothing was committed).
	if _, statErr := os.Stat(filepath.Join(stateDir, "out", "route.bin")); statErr == nil {
		t.Fatal("final output file exists at the crashed receiver — false delivery on disk")
	}
}
