package signal

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestReaperUnderChurn simulates a create/abandon storm across many concurrent clients,
// verifying that room creation, failed joins, vacating, and reaping function reliably
// without deadlocks, state corruption, or memory leaks.
func TestReaperUnderChurn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IdleTimeout = 50 * time.Millisecond
	cfg.RateLimitEnabled = false // allow massive concurrent traffic in test
	cfg.MaxRooms = 1000

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := NewHub(ctx, cfg, nil)

	var wg sync.WaitGroup
	workers := 10
	iterations := 25

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.0.2.%d", workerID+1)
			for i := 0; i < iterations; i++ {
				p := newTestPeer()
				room, code := h.createRoom(p, ip)
				if code != "" {
					continue
				}

				// Sometimes vacate immediately, sometimes join then vacate, sometimes leave idle
				switch (workerID + i) % 3 {
				case 0:
					h.vacate(p)
				case 1:
					joiner := newTestPeer()
					other, jcode := h.join(joiner, room, ip)
					if jcode == "" && other != nil {
						h.vacate(joiner)
					}
					h.vacate(p)
				case 2:
					// Leave abandoned and unvacated; wait for reaper
				}
			}
		}(w)
	}

	wg.Wait()

	// Run multiple reap cycles after idle timeout elapses
	time.Sleep(100 * time.Millisecond)
	h.reapOnce(time.Now().Add(time.Second))

	if count := h.roomCount(); count != 0 {
		t.Fatalf("expected 0 rooms after churn reap, got %d", count)
	}

	m := h.Metrics()
	if m.RoomsReapedTotal == 0 && m.RoomsCreatedTotal > 0 {
		t.Fatalf("expected rooms to have been reaped: created=%d, reaped=%d", m.RoomsCreatedTotal, m.RoomsReapedTotal)
	}
}

// TestDrainGracefulShutdown tests the drain lifecycle: new connections are refused
// while existing paired rooms are given time to complete.
func TestDrainGracefulShutdown(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DrainTimeout = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := NewHub(ctx, cfg, nil)

	// Create an unpaired room (should be immediately reaped on drain)
	unpaired := newTestPeer()
	_, _ = h.createRoom(unpaired, "127.0.0.1")

	// Create a paired room
	offerer := newTestPeer()
	room, _ := h.createRoom(offerer, "127.0.0.1")
	joiner := newTestPeer()
	_, _ = h.join(joiner, room, "127.0.0.1")

	// Drain in background
	drainDone := make(chan error, 1)
	go func() {
		drainDone <- h.Drain(context.Background())
	}()

	for !h.IsDraining() {
		time.Sleep(time.Millisecond)
	}

	// Verify new connection is rejected with draining error
	ok, _, errCode := h.acquireConnection("127.0.0.1")
	if ok || errCode != errDraining {
		t.Fatalf("new connection during drain should be rejected with draining, got ok=%v errCode=%s", ok, errCode)
	}

	// Verify new room creation is rejected
	newOfferer := newTestPeer()
	_, rcode := h.createRoom(newOfferer, "127.0.0.1")
	if rcode != errDraining {
		t.Fatalf("new room during drain should be rejected with draining, got %s", rcode)
	}

	// Verify unpaired room was closed immediately
	select {
	case <-unpaired.done:
	default:
		t.Fatal("unpaired room was not closed on drain")
	}

	// Finish the paired transfer by discarding
	h.discard(offerer)

	select {
	case err := <-drainDone:
		if err != nil {
			t.Fatalf("drain returned error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("drain timed out")
	}
}
