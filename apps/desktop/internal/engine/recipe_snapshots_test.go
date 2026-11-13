// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/transfer"
)

// ---------------------------------------------------------------------------
// SB-R04: synchronized dispatcher snapshots.
//
// Proves (a) the pass runs on a coherent endpoint snapshot — endpoint edits
// during a pass never race and never alter the in-flight pass; (b) the
// policy lookup is never executed while the service lock is held; (c) churn
// under the race detector leaves consistent attempt states; (d) the copy
// semantics are isolated from the live map.
// ---------------------------------------------------------------------------

// TestDispatchPassUsesEndpointSnapshot proves both SB-R04 properties with
// one deterministic discriminator. The policy lookup stalls the pass (after
// the endpoint snapshot was taken); while it is stalled, another goroutine
// DELETES the endpoint. Then:
//
//   - The edit must complete — impossible under the old code, which invoked
//     the lookup while holding the service lock, so SetLocalPeerAddr
//     deadlocked (lock-scope property).
//   - The in-flight pass must still attempt the OLD endpoint — the pass
//     runs on the coherent snapshot, not the live map (snapshot property).
//     Under the old aliasing behavior the mid-pass delete was visible to
//     the running pass: the endpoint gate/sender observed the missing
//     endpoint and HELD the job with no attempt at all.
func TestDispatchPassUsesEndpointSnapshot(t *testing.T) {
	svc, deviceID := newDispatchableRecipeService(t)
	root := t.TempDir()
	if err := writeFile(t, filepath.Join(root, "f.bin"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recipeID := enqueueRecipe(t, svc, deviceID, root, "local-only")
	svc.SetLocalPeerAddr(deviceID, "127.0.0.1:1")

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	svc.SetPolicyLookup(func() netpolicy.Policy {
		once.Do(func() { close(entered) })
		<-release // stall the pass AFTER the endpoint snapshot was taken
		return netpolicy.LocalOnly
	})
	// The mid-pass delete races with the stalled pass.
	go func() {
		<-entered
		svc.SetLocalPeerAddr(deviceID, "") // delete the endpoint mid-pass
		close(release)
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := svc.DispatchOnceNow(context.Background()); err != nil {
			t.Errorf("dispatch pass error: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("dispatch deadlocked or stalled: the policy lookup must not run while the service lock is held")
	}

	// Snapshot property: the pass attempted the OLD endpoint (:1) and
	// recorded an honest failure. Under the aliasing defect the delete was
	// visible mid-pass and the job was held with NO attempt recorded.
	jobID := lastRunJobID(t, svc, recipeID)
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	found := false
	for _, a := range job.Attempts {
		if a.DeviceID != deviceID {
			continue
		}
		found = true
		if a.Status != jobs.AttemptFailed && a.Status != jobs.AttemptInterrupted {
			t.Fatalf("attempt status = %q, want failed/interrupted (the pass must attempt the snapshot endpoint)", a.Status)
		}
		if a.LastError == "" {
			t.Fatal("expected an honest local-send error")
		}
	}
	if !found {
		t.Fatal("no attempt recorded — the pass observed the mid-pass endpoint deletion, i.e. it read the LIVE map instead of its snapshot")
	}
}

// TestPolicyLookupNeverHoldsServiceLock isolates the lock-scope rule: a
// lookup that re-enters the service (SetLocalPeerAddr takes the lock) must
// complete instead of deadlocking the pass.
func TestPolicyLookupNeverHoldsServiceLock(t *testing.T) {
	svc, deviceID := newDispatchableRecipeService(t)
	root := t.TempDir()
	if err := writeFile(t, filepath.Join(root, "f.bin"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	enqueueRecipe(t, svc, deviceID, root, "online")

	svc.SetPolicyLookup(func() netpolicy.Policy {
		svc.SetLocalPeerAddr("probe-device", "127.0.0.1:7777")
		return netpolicy.Online
	})
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		return transfer.Outcome{}, errors.New("must not run: trust resolution fails for this probe")
	})

	done := make(chan struct{})
	go func() {
		_, _ = svc.DispatchOnceNow(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dispatch deadlocked: policy lookup ran while the service lock was held")
	}
}

// TestEndpointEditChurnUnderRaceDetector is the churn proof. The
// choreography makes the race detector a DETERMINISTIC detector of the
// aliasing defect this test guards against: the first policy-lookup call
// (which happens after the pass's endpoint snapshot) releases the endpoint
// writers and waits until the first write landed. The sender's endpoint
// access is therefore ordered after a writer's write with NO mutex edge on
// the map itself — exactly what the race detector reports when the pass
// aliases the live map. With the snapshot copy (the fix), the pass reads a
// private map and no race exists. Concurrent endpoint edits (including
// deletes), policy flips and dispatch passes must leave consistent states.
func TestEndpointEditChurnUnderRaceDetector(t *testing.T) {
	svc, deviceID := newDispatchableRecipeService(t)
	root := t.TempDir()
	if err := writeFile(t, filepath.Join(root, "f.bin"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recipeID := enqueueRecipe(t, svc, deviceID, root, "prefer-local")
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		return transfer.Outcome{}, errors.New("no online egress in this test")
	})

	startCh := make(chan struct{})
	writtenCh := make(chan struct{})
	var writtenOnce sync.Once
	// The service's lookup is wired EXACTLY ONCE, and the choreography
	// lives in that stable wrapper — never in a swappable closure — so the
	// policy churn below cannot lose it. The first invocation happens after
	// the pass's endpoint snapshot: it releases the endpoint writers and
	// waits for the first write to land. Any live-map alias in the pass is
	// then ordered-after a writer's write with no HB edge on the map —
	// exactly what the race detector reports for the old aliasing defect.
	var firstLookup atomic.Bool
	var inner func() netpolicy.Policy
	var innerMu sync.Mutex
	svc.SetPolicyLookup(func() netpolicy.Policy {
		if firstLookup.CompareAndSwap(false, true) {
			close(startCh)
			select {
			case <-writtenCh:
			case <-time.After(10 * time.Second):
				// Writers never ran; the settle check below reports it.
			}
		}
		innerMu.Lock()
		f := inner
		innerMu.Unlock()
		if f == nil {
			return netpolicy.LocalOnly
		}
		return f()
	})

	var wg sync.WaitGroup
	done := make(chan struct{})
	// endpoint churn
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-startCh
			for j := 0; j < 50; j++ {
				if j%3 == 0 {
					svc.SetLocalPeerAddr(deviceID, "") // delete path
				} else {
					svc.SetLocalPeerAddr(deviceID, fmt.Sprintf("127.0.0.1:%d", 40000+n*1000+j))
				}
				if j%7 == 0 {
					// cover the lazily re-created nil-map path
					svc.SetLocalPeerAddr(fmt.Sprintf("extra-%d-%d", n, j), "127.0.0.1:2")
				}
				writtenOnce.Do(func() { close(writtenCh) })
			}
		}(i)
	}
	// policy churn via the atomic inner swap
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				innerMu.Lock()
				if (n+j)%2 == 0 {
					inner = func() netpolicy.Policy { return netpolicy.PreferLocal }
				} else {
					inner = func() netpolicy.Policy { return netpolicy.LocalOnly }
				}
				innerMu.Unlock()
			}
		}(i)
	}
	// dispatch churn
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_, _ = svc.DispatchOnceNow(context.Background())
			}
		}()
	}
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("churn did not settle")
	}
	if !firstLookup.Load() {
		t.Fatal("choreography never ran: no dispatch pass invoked the policy lookup")
	}

	// Post-churn consistency: legal attempt states only; nothing can be
	// delivered/completed because no sender ever succeeded.
	jobID := lastRunJobID(t, svc, recipeID)
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		switch a.Status {
		case jobs.AttemptQueued, jobs.AttemptFailed, jobs.AttemptInterrupted, jobs.AttemptActive:
		default:
			t.Fatalf("illegal attempt state %q after churn", a.Status)
		}
	}
}

// TestSnapshotCopyIsIsolatedFromLiveMap is the direct unit proof of the
// copy semantics: mutating a snapshot must not affect the live map, and a
// fresh snapshot reflects the current service state.
func TestSnapshotCopyIsIsolatedFromLiveMap(t *testing.T) {
	svc, deviceID := newDispatchableRecipeService(t)
	svc.SetLocalPeerAddr(deviceID, "127.0.0.1:1")

	svc.mu.Lock()
	snap := svc.copyLocalPeerAddrsLocked()
	svc.mu.Unlock()
	if snap[deviceID] != "127.0.0.1:1" {
		t.Fatalf("snapshot = %q", snap[deviceID])
	}
	// Mutate the COPY — the service must be unaffected.
	snap[deviceID] = "9.9.9.9:9"
	svc.mu.Lock()
	got := svc.localPeerAddrs[deviceID]
	svc.mu.Unlock()
	if got != "127.0.0.1:1" {
		t.Fatalf("live map mutated through snapshot copy: %q", got)
	}
	// And a fresh snapshot reflects the service state, not the old copy.
	svc.SetLocalPeerAddr(deviceID, "127.0.0.1:2")
	svc.mu.Lock()
	snap2 := svc.copyLocalPeerAddrsLocked()
	svc.mu.Unlock()
	if snap2[deviceID] != "127.0.0.1:2" {
		t.Fatalf("fresh snapshot = %q, want :2", snap2[deviceID])
	}
}
