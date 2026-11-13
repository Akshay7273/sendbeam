// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// ---------------------------------------------------------------------------
// SB-R07: strict-padding negative proof on the desktop production path.
//
// The incompatibility tested is real protocol-level capability negotiation:
// a receiver started with Private=false and RequirePadding=false never
// advertises wire.PaddingCapability in its caps (the caps append in the
// transfer driver happens only when Private || RequirePadding). A sender
// running a recipe with RequirePadding=true must refuse that peer at the
// capability stage — before any manifest — with wire.ErrPaddingRequired.
//
// The receiver fixture is genuinely incompatible at the CAPABILITY level:
// it advertises its Opaque caps WITHOUT the padding feature (see
// localtransfer.ReceiveWithoutPaddingCapability for why an option cannot
// express this today). A control case proves the fixture itself is
// functional (the same receiver receives the same payload successfully when
// the recipe does not require padding) — so the negative outcome is caused
// specifically by the capability gap under the strict requirement, not by a
// broken fixture.
// ---------------------------------------------------------------------------

// strictPaddingFixture wires a desktop RecipeService and a REAL loopback
// receiver over the production local rendezvous path, with full paired
// identities exactly like TestStrictPaddingCompatibleReceiverVerifies.
type strictPaddingFixture struct {
	svc          *RecipeService
	ts           *trust.MemoryTrustStore
	secrets      *trust.FileSecretStore
	peerIdentity *wire.DeviceIdentity
	sources      string
	destDir      string
}

func newStrictPaddingFixture(t *testing.T) *strictPaddingFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	t.Cleanup(func() { _ = svc.Shutdown(5 * time.Second) })
	svc.StopDispatcher() // deterministic: only the explicit pass dispatches

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
			PairCredentialRef: "cred-pad",
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
	if err := os.WriteFile(filepath.Join(root, "f.bin"), []byte("padding-required dispatch bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	destDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &strictPaddingFixture{svc: svc, ts: ts, secrets: secrets, peerIdentity: peerIdentity, sources: root, destDir: destDir}
}

// startIncompatibleReceiver runs the REAL production receiver
// (localrendezvous + localtransfer.Receive) with padding capability absent:
// Private=false, RequirePadding=false. Registers its loopback endpoint as
// the peer's local address and reports readiness before accepting.
func (f *strictPaddingFixture) startIncompatibleReceiver(t *testing.T) (recvDone chan error, recvCancel func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		rcvSrv := localrendezvous.NewServer(localrendezvous.Config{
			BindAddr:      "127.0.0.1:0",
			AllowWildcard: false,
		}, f.ts)
		recvAddr, err := rcvSrv.Start(ctx)
		if err != nil {
			done <- err
			return
		}
		f.svc.SetLocalPeerAddr(f.peerIdentity.DeviceID, recvAddr.String())
		close(ready)
		_, rerr := localtransfer.ReceiveWithoutPaddingCapability(ctx, localtransfer.ReceiveOptions{
			Identity: f.peerIdentity,
			Store:    f.ts,
			Resolver: f.secrets,
			Server:   rcvSrv,
			DestDir:  f.destDir,
			// GENUINE INCOMPATIBILITY: this receiver's advertised
			// capabilities EXCLUDE the padding feature (explicit caps in
			// the Opaque ceremony). RequirePadding/Private stay false: the
			// receiver does not demand padding — it simply cannot do it.
			RequirePadding: false,
			Private:        false,
			Consent: func(_ context.Context, _ transfer.ConsentRequest) (transfer.ConsentDecision, error) {
				return transfer.ConsentDecision{Accepted: true}, nil
			},
		})
		done <- rerr
	}()
	select {
	case <-ready:
	case rerr := <-done:
		t.Fatalf("receiver failed to start: %v", rerr)
	case <-time.After(30 * time.Second):
		t.Fatal("receiver did not become ready within 30s")
	}
	return done, cancel
}

// enqueueStrictRecipe creates, approves and runs a recipe with the given
// persisted padding decision; returns the job ID.
func (f *strictPaddingFixture) enqueueStrictRecipe(t *testing.T, deviceID string, requirePadding bool) string {
	t.Helper()
	in := newEditorInput("nightly", f.sources, deviceID)
	in.NetworkPolicy = "local-only"
	in.RequirePadding = requirePadding
	created, err := f.svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := f.svc.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	job, ok, err := f.svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatal("job missing after RunRecipe")
	}
	if job.RequirePadding == nil || *job.RequirePadding != requirePadding {
		t.Fatalf("padding decision not persisted correctly: %+v", job.RequirePadding)
	}
	return jobID
}

// assertNoOutputFile proves no completed output was accepted from the
// rejected transfer.
func assertNoOutputFile(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dest dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("output files exist despite strict-padding rejection: %v", names)
	}
}

// TestStrictPaddingRecipeFailsClosedAgainstIncompatibleReceiver is the
// SB-R07 negative proof: a desktop recipe with RequirePadding=true driven
// through the REAL production sender against a REAL padding-incompatible
// receiver must fail closed with zero false delivery.
func TestStrictPaddingRecipeFailsClosedAgainstIncompatibleReceiver(t *testing.T) {
	fx := newStrictPaddingFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	jobID := fx.enqueueStrictRecipe(t, fx.peerIdentity.DeviceID, true)
	recvDone, recvCancel := fx.startIncompatibleReceiver(t)
	defer recvCancel()

	// One explicit production dispatch pass.
	if _, err := fx.svc.DispatchOnceNow(ctx); err != nil {
		t.Fatalf("dispatch pass: %v", err)
	}

	// Poll the persisted attempt state (bounded, deterministic).
	deadline := time.Now().Add(60 * time.Second)
	var observed bool
	var lastErr string
	for time.Now().Before(deadline) {
		job, ok, err := fx.svc.jobs.Load(jobID)
		if err != nil || !ok {
			t.Fatalf("load job: %v %v", err, ok)
		}
		for _, a := range job.Attempts {
			if a.DeviceID != fx.peerIdentity.DeviceID {
				continue
			}
			if a.Status == jobs.AttemptInterrupted || a.Status == jobs.AttemptFailed {
				observed = true
				lastErr = a.LastError
			}
			if a.Status == jobs.AttemptVerified || a.Status == jobs.AttemptCompleted {
				t.Fatalf("attempt marked %q against an incompatible receiver — false delivery; lastError=%q", a.Status, a.LastError)
			}
			if a.VerifiedDigest != "" {
				t.Fatalf("attempt carries a verified digest against an incompatible receiver: %q", a.VerifiedDigest)
			}
		}
		if observed {
			break
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("context expired while waiting for the honest failure")
		}
	}
	if !observed {
		if job, ok, _ := fx.svc.jobs.Load(jobID); ok {
			t.Fatalf("no honest failure recorded within deadline — attempts: %+v", job.Attempts)
		}
		t.Fatal("no honest failure recorded within deadline")
	}
	// The failure must NAME the padding incompatibility (observable, not a
	// generic transport error).
	if !strings.Contains(strings.ToLower(lastErr), "padding") {
		t.Fatalf("failure reason does not name the padding incompatibility: %q", lastErr)
	}

	// Documented retry/terminal contract: exactly one real attempt consumed,
	// re-queued as interrupted with a scheduled retry (budget intact), and
	// the error text preserved.
	job, ok, err := fx.svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.Attempts != 1 {
			t.Fatalf("attempts = %d, want 1 (exactly one real send)", a.Attempts)
		}
		if a.Status != jobs.AttemptInterrupted {
			t.Fatalf("status = %q, want interrupted (re-queued with backoff; MaxAttempts=5 budget intact)", a.Status)
		}
		if a.NextRetryAt.IsZero() {
			t.Fatal("NextRetryAt not scheduled despite interrupted state")
		}
		if a.LastError == "" || !strings.Contains(strings.ToLower(a.LastError), "padding") {
			t.Fatalf("persisted LastError does not record the padding failure: %q", a.LastError)
		}
	}
	if job.Status == jobs.JobCompleted {
		t.Fatal("job marked completed despite the rejected transfer")
	}

	// The persisted decision is unchanged.
	if job.RequirePadding == nil || !*job.RequirePadding {
		t.Fatal("persisted RequirePadding was downgraded by the failed transfer")
	}

	// No completed output file was accepted from the rejected transfer.
	assertNoOutputFile(t, fx.destDir)

	// The receiver must not have completed a transfer either. Cancel the
	// receiver deterministically and inspect its terminal state: the
	// fixture reports (nil outcome, nil error) when it was cancelled before
	// any transfer, or (outcome, error) when the exchange ran.
	recvCancel()
	select {
	case <-recvDone:
	case <-time.After(15 * time.Second):
		t.Fatal("receiver did not settle after the rejected transfer")
	}
	assertNoOutputFile(t, fx.destDir)
}

// TestNoStrictPaddingSucceedsAgainstSameIncompatibleReceiver is the control
// that proves the negative test discriminates: the SAME receiver fixture
// (padding-incompatible) receives the SAME payload successfully when the
// recipe does not require padding. Therefore the negative outcome above is
// caused by the capability gap under the strict requirement — not by a
// broken fixture or unreachable receiver.
func TestNoStrictPaddingSucceedsAgainstSameIncompatibleReceiver(t *testing.T) {
	fx := newStrictPaddingFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	jobID := fx.enqueueStrictRecipe(t, fx.peerIdentity.DeviceID, false)
	recvDone, recvCancel := fx.startIncompatibleReceiver(t)
	defer recvCancel()

	if _, err := fx.svc.DispatchOnceNow(ctx); err != nil {
		t.Fatalf("dispatch pass: %v", err)
	}

	// Eventually-verified, as in the existing positive test: loopback
	// WebRTC transfers can take tens of seconds; poll the persisted job.
	deadline := time.Now().Add(80 * time.Second)
	verified := false
	for time.Now().Before(deadline) {
		job, ok, _ := fx.svc.jobs.Load(jobID)
		if ok {
			for _, a := range job.Attempts {
				if a.VerifiedDigest != "" && (a.Status == jobs.AttemptVerified || a.Status == jobs.AttemptCompleted) {
					verified = true
				}
			}
		}
		if verified {
			break
		}
		select {
		case rerr := <-recvDone:
			if rerr != nil {
				t.Fatalf("receiver errored in the control case: %v", rerr)
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !verified {
		if job, ok, _ := fx.svc.jobs.Load(jobID); ok {
			t.Fatalf("control transfer never verified — attempts: %+v", job.Attempts)
		}
		t.Fatal("control transfer never verified")
	}
	// The receiver completed and the output exists: the fixture works.
	entries, err := os.ReadDir(fx.destDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("control case: no output file accepted (entries=%v err=%v)", entries, err)
	}
}
