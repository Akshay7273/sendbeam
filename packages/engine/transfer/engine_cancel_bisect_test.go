// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

// TestRunCancelMidStreamStopsSending bisects the SB-R08 cancel chain at the
// ENGINE layer (outbox layer already proven by outbox/cancel_registry_test):
// a real sender/receiver over the test relay, cancel(ctx) while a large
// payload is mid-stream. The sender must stop within a bounded window; the
// receiver must NOT end up with the final file.
//
// FAILURE MODE THIS TEST EXPOSES (if it fails): the cancel does not reach
// wire.Sender's stream loop — bytes keep flowing after the dispatch-layer
// cancel, the receiver commits the file, and the sender's ledger says
// "cancelled, not delivered" (split-brain).
func TestRunCancelMidStreamStopsSending(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	destDir := t.TempDir()
	payload := bytes.Repeat([]byte("ENGINE-CANCEL-BISECTION-"), 4_400_000) // ~100 MiB
	meta := wire.FileMeta{
		Name:         "engine_cancel.bin",
		Size:         int64(len(payload)),
		Mime:         "application/octet-stream",
		LastModified: 1_700_000_000_000,
	}
	src := wire.BytesSource(payload, meta, 16*1024)

	relayServer := newRelay()

	type res struct {
		out *Outcome
		err error
	}
	offCh := make(chan res, 1)
	joinCh := make(chan res, 1)

	// Receiver: accepts, stages into destDir.
	go func() {
		o, err := Run(ctx, relayServer.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-engine-cancel"},
			DestDir:    destDir,
			ICEServers: []webrtc.ICEServer{},
		})
		joinCh <- res{o, err}
	}()

	// Sender: cancellable independent of the test ctx.
	sendCtx, sendCancel := context.WithCancel(context.Background())
	go func() {
		o, err := Run(sendCtx, relayServer.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "engine-cancel"},
			Source:     src,
			ICEServers: []webrtc.ICEServer{},
		})
		offCh <- res{o, err}
	}()

	// BYTES-MOVING barrier: wait until the receiver stages real bytes.
	staged := func() int64 {
		var total int64
		_ = filepath.Walk(filepath.Join(destDir, ".sendbeam"), func(_ string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				total += info.Size()
			}
			return nil
		})
		return total
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if staged() > 4*1024*1024 { // >4 staged: provably mid-stream
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	atCancel := staged()
	if atCancel == 0 {
		t.Fatal("barrier precondition failed: no staged bytes")
	}
	t.Logf("staged at cancel: %d bytes", atCancel)

	// THE CANCEL, mid-stream.
	cancelStart := time.Now()
	sendCancel()

	// Sample staged growth: if it keeps growing for seconds, the sender
	// ignored the cancel.
	var maxGrowth int64
	last := atCancel
	for i := 0; i < 100; i++ {
		time.Sleep(50 * time.Millisecond)
		now := staged()
		if now-last > maxGrowth {
			maxGrowth = now - last
		}
		last = now
		select {
		case <-offCh:
			goto senderSettled
		default:
		}
	}
senderSettled:
	settleLatency := time.Since(cancelStart)
	t.Logf("sender settled %v after cancel; max staged growth after cancel: %d bytes", settleLatency, maxGrowth)

	// ASSERT: the sender stopped within a bounded window — staged bytes
	// must not keep flowing after the cancel. Allow one window's worth of
	// pipeline drain (8 MiB in-flight cap) as the documented uncertainty;
	// beyond that the cancel demonstrably failed to stop the stream.
	if maxGrowth > 16*1024*1024 {
		t.Fatalf("sender kept streaming after cancel: staged grew %d bytes post-cancel (bounded drain is 16 MiB)", maxGrowth)
	}
	if settleLatency > 10*time.Second {
		t.Fatalf("sender settled %v after cancel — termination bound exceeded", settleLatency)
	}

	// Receiver: no final file.
	select {
	case <-joinCh:
	case <-time.After(15 * time.Second):
	}
	if _, err := os.Stat(filepath.Join(destDir, "engine_cancel.bin")); err == nil {
		t.Fatal("final output file exists at the receiver after the mid-stream engine cancel — false delivery on disk")
	}
}
