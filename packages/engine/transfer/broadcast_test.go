package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

func TestBroadcast_AllSucceed(t *testing.T) {
	payload := []byte("broadcast-test-payload-1234567890")
	meta := wire.FileMeta{Name: "doc.txt", Size: int64(len(payload)), Mime: "text/plain"}
	numTargets := 3

	targets := make([]BroadcastTarget, numTargets)
	receiverDones := make([]chan struct{}, numTargets)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < numTargets; i++ {
		hub := newRelay()
		words := fmt.Sprintf("target-bravo-%d", i+1)
		code := fmt.Sprintf("7-target-bravo-%d", i+1)
		targetID := fmt.Sprintf("device-%d", i+1)
		targetLabel := fmt.Sprintf("Laptop %d", i+1)

		destDir := t.TempDir()
		receiverDone := make(chan struct{})
		receiverDones[i] = receiverDone

		// Launch receiver
		go func(h *relay, c string, dir string, done chan struct{}) {
			defer close(done)
			out, err := Run(ctx, h.join, Spec{
				Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: c},
				DestDir:    dir,
				ICEServers: []webrtc.ICEServer{},
			})
			if err != nil {
				t.Errorf("receiver %s failed: %v", c, err)
				return
			}
			got, err := os.ReadFile(out.Path)
			if err != nil {
				t.Errorf("read received file: %v", err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload mismatch on receiver %s", c)
			}
		}(hub, code, destDir, receiverDone)

		targets[i] = BroadcastTarget{
			ID:     targetID,
			Label:  targetLabel,
			Signal: hub.off,
			Spec: Spec{
				Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: words},
				Source:     wire.BytesSource(payload, meta, 64*1024),
				ICEServers: []webrtc.ICEServer{},
			},
		}
	}

	progressCalls := atomic.Int64{}
	completedCalls := atomic.Int64{}

	result := RunBroadcast(ctx, targets, BroadcastOptions{
		Concurrency: 3,
		OnTargetProgress: func(_ string, _ int64) {
			progressCalls.Add(1)
		},
		OnTargetComplete: func(_ string, _ TargetResult) {
			completedCalls.Add(1)
		},
	})

	if !result.AllOk {
		t.Fatalf("expected AllOk=true, got false: %+v", result.Results)
	}
	if len(result.Results) != numTargets {
		t.Fatalf("expected %d results, got %d", numTargets, len(result.Results))
	}
	for i, r := range result.Results {
		if r.Status != StatusOk {
			t.Errorf("target %d (%s) status = %s, want %s (err: %s)", i, r.TargetID, r.Status, StatusOk, r.Error)
		}
		if r.Digest == "" {
			t.Errorf("target %d digest is empty", i)
		}
	}

	for _, done := range receiverDones {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for receiver")
		}
	}

	if completedCalls.Load() != int64(numTargets) {
		t.Fatalf("expected %d completed callbacks, got %d", numTargets, completedCalls.Load())
	}
}

func TestBroadcast_MixedStatuses(t *testing.T) {
	payload := []byte("broadcast-mixed-payload")
	meta := wire.FileMeta{Name: "data.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Target 1: Happy path
	hub1 := newRelay()
	destDir1 := t.TempDir()
	recvDone1 := make(chan struct{})
	go func() {
		defer close(recvDone1)
		_, _ = Run(ctx, hub1.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha"},
			DestDir:    destDir1,
			ICEServers: []webrtc.ICEServer{},
		})
	}()

	target1 := BroadcastTarget{
		ID:     "dev-1-ok",
		Label:  "Device 1",
		Signal: hub1.off,
		Spec: Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha"},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		},
	}

	// Target 2: Offline (signaling immediately closed / unreachable)
	closedSignal := &mockClosedSignal{}
	target2 := BroadcastTarget{
		ID:     "dev-2-offline",
		Label:  "Device 2",
		Signal: closedSignal,
		Spec: Spec{
			Session: rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "beta"},
			Source:  wire.BytesSource(payload, meta, 64*1024),
		},
	}

	// Target 3: Refused (trusted peer revoked or refused error)
	refusedSignal := &mockErrorSignal{err: wire.ErrTrustedRejected}
	target3 := BroadcastTarget{
		ID:     "dev-3-refused",
		Label:  "Device 3",
		Signal: refusedSignal,
		Spec: Spec{
			Session: rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "gamma"},
			Source:  wire.BytesSource(payload, meta, 64*1024),
		},
	}

	targets := []BroadcastTarget{target1, target2, target3}
	res := RunBroadcast(ctx, targets, BroadcastOptions{
		Concurrency: 3,
	})

	if res.AllOk {
		t.Fatal("expected AllOk=false when some targets fail")
	}
	if len(res.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(res.Results))
	}

	// Check partial-failure isolation: Target 1 MUST succeed despite targets 2 and 3 failing
	if res.Results[0].Status != StatusOk {
		t.Errorf("target 1 status = %s, want %s (err: %s)", res.Results[0].Status, StatusOk, res.Results[0].Error)
	}
	if res.Results[1].Status != StatusOffline && res.Results[1].Status != StatusFailed {
		t.Errorf("target 2 status = %s, want offline/failed", res.Results[1].Status)
	}
	if res.Results[2].Status != StatusRefused {
		t.Errorf("target 3 status = %s, want %s", res.Results[2].Status, StatusRefused)
	}

	<-recvDone1
}

func TestBroadcast_ConcurrencyLimiting(t *testing.T) {
	numTargets := 6
	concurrencyLimit := 2

	var running atomic.Int64
	var maxObserved atomic.Int64
	var mu sync.Mutex

	targets := make([]BroadcastTarget, numTargets)
	for i := 0; i < numTargets; i++ {
		idx := i
		targets[i] = BroadcastTarget{
			ID:    fmt.Sprintf("dev-%d", idx),
			Label: fmt.Sprintf("Dev %d", idx),
			Signal: &mockCustomSignal{
				onRun: func(_ context.Context) error {
					cur := running.Add(1)
					mu.Lock()
					if cur > maxObserved.Load() {
						maxObserved.Store(cur)
					}
					mu.Unlock()

					time.Sleep(50 * time.Millisecond)
					running.Add(-1)
					return errors.New("peer offline: connection refused")
				},
			},
			Spec: Spec{
				Session: rendezvous.Options{Role: rendezvous.RoleOfferer, Words: fmt.Sprintf("w-%d", idx)},
			},
		}
	}

	ctx := context.Background()
	_ = RunBroadcast(ctx, targets, BroadcastOptions{
		Concurrency: concurrencyLimit,
		OnTargetStart: func(_ BroadcastTarget) {
			cur := running.Add(1)
			mu.Lock()
			if cur > maxObserved.Load() {
				maxObserved.Store(cur)
			}
			mu.Unlock()
			time.Sleep(40 * time.Millisecond)
			running.Add(-1)
		},
	})

	if maxObserved.Load() > int64(concurrencyLimit) {
		t.Fatalf("observed concurrency %d exceeded limit %d", maxObserved.Load(), concurrencyLimit)
	}
}

func TestBroadcast_EmptyTargets(t *testing.T) {
	ctx := context.Background()
	res := RunBroadcast(ctx, nil, BroadcastOptions{})
	if !res.AllOk {
		t.Fatal("expected AllOk=true for empty targets")
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

// --- Mocks for broadcast tests ---

type mockClosedSignal struct{}

func (m *mockClosedSignal) Send(rendezvous.Message) error     { return errors.New("peer offline: connection refused") }
func (m *mockClosedSignal) SendBinary([]byte) error           { return errors.New("peer offline: connection refused") }
func (m *mockClosedSignal) Run(context.Context, func(rendezvous.Message), func([]byte)) error {
	return errors.New("peer offline: connection refused")
}
func (m *mockClosedSignal) Close() {}

type mockErrorSignal struct {
	err error
}

func (m *mockErrorSignal) Send(rendezvous.Message) error     { return m.err }
func (m *mockErrorSignal) SendBinary([]byte) error           { return m.err }
func (m *mockErrorSignal) Run(context.Context, func(rendezvous.Message), func([]byte)) error {
	return m.err
}
func (m *mockErrorSignal) Close() {}

type mockCustomSignal struct {
	onRun func(ctx context.Context) error
}

func (m *mockCustomSignal) Send(rendezvous.Message) error     { return errors.New("simulated socket error") }
func (m *mockCustomSignal) SendBinary([]byte) error           { return errors.New("simulated socket error") }
func (m *mockCustomSignal) Run(ctx context.Context, _ func(rendezvous.Message), _ func([]byte)) error {
	if m.onRun != nil {
		return m.onRun(ctx)
	}
	return errors.New("simulated socket error")
}
func (m *mockCustomSignal) Close() {}
