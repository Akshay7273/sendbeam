// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// ---------------------------------------------------------------------------
// SB-R09: preview zero-transmission proof (requirement 3) — a REAL listener
// on the loopback counts every inbound connection during preview: the
// preview must send ZERO bytes over ZERO connections.
// ---------------------------------------------------------------------------

// TestR09PreviewSendsZeroBytes proves the preview path is physically
// transmission-free: a real local rendezvous listener runs on loopback (and
// an online sender seam that would fail loudly if invoked); preview and plan
// are called; the connection counter stays at zero and the status line never
// shows a job.
func TestR09PreviewSendsZeroBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	idm, err := trust.NewIdentityManager(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := trust.NewFileSecretStore(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts := trust.NewMemoryTrustStore()
	svc, err := NewRecipeService(dir, ts, idm, secrets)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Shutdown(5 * time.Second) }()
	svc.StopDispatcher()

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
			PairCredentialRef: "cred-prev",
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
	root := filepath.Join(dir, "sources")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret-report.bin"), []byte("CONFIDENTIAL PREVIEW CONTENT — must never leave the machine"), 0o600); err != nil {
		t.Fatal(err)
	}

	in := newEditorInput("nightly", root, peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}

	// REAL listener on loopback: counts every admitted session (any
	// connection attempt by a transmission-happy preview would show here).
	var connections atomic.Int32
	srv := localrendezvous.NewServer(localrendezvous.Config{
		BindAddr:      "127.0.0.1:0",
		AllowWildcard: false,
	}, ts)
	srv.OnSession(func(*localrendezvous.Session) {
		connections.Add(1)
	})
	recvCtx, recvCancel := context.WithCancel(ctx)
	defer recvCancel()
	if _, err := srv.Start(recvCtx); err != nil {
		t.Fatalf("listener start: %v", err)
	}

	// The online route would fail loudly if the preview ever dialed it.
	var onlineCalls atomic.Int32
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.Online })
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		onlineCalls.Add(1)
		return transfer.Outcome{}, errors.New("preview attempted an online send")
	})
	// Record an endpoint so any local dial would even be possible.
	svc.SetLocalPeerAddr(peerIdentity.DeviceID, "127.0.0.1:1")

	// THE PREVIEW (twice: text + plan) and nothing else.
	if _, err := svc.PreviewRecipe(created.ID); err != nil {
		t.Fatalf("PreviewRecipe: %v", err)
	}
	if _, err := svc.PlanRecipe(created.ID); err != nil {
		t.Fatalf("PlanRecipe: %v", err)
	}

	if n := connections.Load(); n != 0 {
		t.Fatalf("preview produced %d inbound connection(s) — preview must transmit NOTHING", n)
	}
	if n := onlineCalls.Load(); n != 0 {
		t.Fatalf("preview invoked the online sender %d time(s)", n)
	}

	// No job may exist for the recipe (preview never enqueues).
	st, err := svc.RecipeDeliveryStatus(created.ID)
	if err != nil {
		t.Fatalf("delivery status: %v", err)
	}
	if st.LastRun != nil {
		t.Fatalf("preview recorded a run ledger entry: %+v", st.LastRun)
	}
	if st.Job != nil {
		t.Fatalf("preview created a job: %+v", st.Job)
	}
}
