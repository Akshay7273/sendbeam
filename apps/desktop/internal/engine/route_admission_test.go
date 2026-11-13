// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// ---------------------------------------------------------------------------
// SB-R06: route admission & real transfer-policy contract.
//
// Gap analysis drove this file. ALREADY PROVEN elsewhere (not duplicated):
//   - online recipes admitted without a LAN endpoint
//     (TestOnlineRecipeNeedsNoEndpoint),
//   - prefer-local fallback refused under LocalOnly, including a mid-pass
//     policy flip (TestPreferLocalNeverOnlineUnderLocalOnlyPolicy),
//   - revoked-recipient dispatch-time rejection
//     (TestRecipeDispatchRevokedRecipientFailsClosed),
//   - coherent per-pass snapshots and lock-scope safety (R04),
//   - fail-closed live-policy retrieval (R05),
//   - strict-padding capability refusal with a real receiver (R07).
//
// NEW here: dispatch-time recipient authentication for UNKNOWN devices (a
// recorded endpoint must never substitute for identity), identity MISMATCH
// between the trusted target and the endpoint's owner, the no-endpoint HOLD
// for a local-only job with its budget untouched, consent refusal at a real
// receiver, source-mutation staleness failing the job without consuming
// budget, and a full real-transfer VERIFIED case with byte-for-byte and
// digest validation.
// ---------------------------------------------------------------------------

// routeFixture is the real-receiver fixture: full paired identities on both
// sides (the production admission/Opaque path), a source tree, and a
// receiver destination directory.
type routeFixture struct {
	svc          *RecipeService
	ts           *trust.MemoryTrustStore
	secrets      *trust.FileSecretStore
	peerIdentity *wire.DeviceIdentity
	sources      string
	destDir      string
	payload      []byte

	// recvErr captures the receiver's terminal error text (the protocol
	// keeps consent-refusal detail receiver-local: wire.Fail carries only
	// a reason code, so the sender legitimately sees "canceled" without
	// the human reason).
	mu      sync.Mutex
	recvErr string
}

func (f *routeFixture) setRecvErr(s string) {
	f.mu.Lock()
	f.recvErr = s
	f.mu.Unlock()
}

func (f *routeFixture) getRecvErr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recvErr
}

func newRouteFixture(t *testing.T) *routeFixture {
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
	svc.StopDispatcher() // deterministic: only explicit passes dispatch

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
			PairCredentialRef: "cred-route",
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
	payload := []byte("SB-R06 route-admission evidence: bytes must arrive intact or not at all")
	if err := os.WriteFile(filepath.Join(root, "route.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	destDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &routeFixture{svc: svc, ts: ts, secrets: secrets, peerIdentity: peerIdentity, sources: root, destDir: destDir, payload: payload}
}

// startReceiver runs the REAL production receiver with the given consent
// handler and registers its loopback endpoint for deviceID.
func (f *routeFixture) startReceiver(t *testing.T, deviceID string, consent func(context.Context, transfer.ConsentRequest) (transfer.ConsentDecision, error)) (recvDone chan error, recvCancel func()) {
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
		f.svc.SetLocalPeerAddr(deviceID, recvAddr.String())
		close(ready)
		_, rerr := localtransfer.Receive(ctx, localtransfer.ReceiveOptions{
			Identity: f.peerIdentity,
			Store:    f.ts,
			Resolver: f.secrets,
			Server:   rcvSrv,
			DestDir:  f.destDir,
			Consent:  consent,
		})
		if rerr != nil {
			f.setRecvErr(rerr.Error())
		}
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

// -----------------------------------------------------------------------
// G2: dispatch-time recipient authentication
// -----------------------------------------------------------------------

// TestRecipeDispatchRejectsDeviceUnpairedAfterEnqueue proves dispatch-time
// recipient authentication: the job is created while the device is trusted,
// but the pairing is REMOVED before dispatch. A recorded LAN endpoint is
// present — exactly the condition that must never substitute for identity —
// and dispatch must still fail at the trust-resolution seam (before any
// dial) with the resolver's own error. (CreateRecipe additionally rejects
// never-trusted recipients at authoring time; this test covers the
// dispatch-time half of the same invariant.)
func TestRecipeDispatchRejectsDeviceUnpairedAfterEnqueue(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	in := newEditorInput("nightly", fx.sources, fx.peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatalf("CreateRecipe: %v", err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := svc.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The device leaves the trust store AFTER enqueue (unpaired/removed).
	if err := svc.trust.UnpairDevice(ctx, fx.peerIdentity.DeviceID); err != nil {
		t.Fatalf("UnpairDevice: %v", err)
	}
	// A DISCOVERED/RECORDED endpoint remains — the bypass that must not work.
	svc.SetLocalPeerAddr(fx.peerIdentity.DeviceID, "127.0.0.1:1")
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		t.Error("online sender invoked for an unpaired-device job")
		return transfer.Outcome{}, fmt.Errorf("online must never run here")
	})

	if _, err := svc.DispatchOnceNow(context.Background()); err != nil {
		t.Fatalf("dispatch pass error: %v", err)
	}

	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	found := false
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		found = true
		if a.Status != jobs.AttemptFailed && a.Status != jobs.AttemptInterrupted {
			t.Fatalf("attempt status = %q, want failed/interrupted", a.Status)
		}
		if a.VerifiedDigest != "" {
			t.Fatalf("unpaired-device attempt carries a verified digest: %q", a.VerifiedDigest)
		}
		// The rejection must come from the DISPATCH-TIME trust lookup
		// itself (the "resolve recipient" seam, before any dial) and must
		// name the trust failure. This is deliberate discrimination, not
		// seam-name matching: a mutation that accepts an unauthenticated
		// target (nil record replaced by a stub) proceeds one seam deeper
		// (pair-secret resolution) and produces a DIFFERENT error family —
		// which this assertion refuses.
		lower := strings.ToLower(a.LastError)
		if !strings.Contains(a.LastError, "resolve recipient") ||
			(!strings.Contains(lower, "trust lookup") &&
				!strings.Contains(lower, "not a trusted paired device") &&
				!strings.Contains(lower, "revoked")) {
			t.Fatalf("expected the dispatch-time trust lookup to reject the unpaired device, got: %q", a.LastError)
		}
	}
	if !found {
		t.Fatal("no attempt recorded for the unpaired device")
	}
	if job.Status == jobs.JobCompleted {
		t.Fatal("unpaired-device job marked completed")
	}
}

// TestRecipeDispatchRejectsEndpointOwnerMismatch proves the endpoint's
// owner is not the recipient: the job targets the TRUSTED peer, but the
// recorded endpoint is operated by an UNPAIRED device with its own real
// identity. The rendezvous server refuses admission (unknown device), so no
// authentication ceremony, no transfer, and no bytes can occur — a
// discovered endpoint never substitutes for the authenticated identity.
func TestRecipeDispatchRejectsEndpointOwnerMismatch(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc

	in := newEditorInput("nightly", fx.sources, fx.peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := svc.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}

	// A server operated by the STRANGER, registered as the trusted peer's
	// endpoint. Admission is trust-bound: the stranger's server refuses
	// the sender because the sender is not paired with the stranger —
	// mirroring the production situation of a spoofed/hostile endpoint.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		srv := localrendezvous.NewServer(localrendezvous.Config{
			BindAddr:      "127.0.0.1:0",
			AllowWildcard: false,
		}, trust.NewMemoryTrustStore()) // the STRANGER's trust store: our sender is not paired
		addr, err := srv.Start(ctx)
		if err != nil {
			done <- err
			return
		}
		svc.SetLocalPeerAddr(fx.peerIdentity.DeviceID, addr.String())
		// Pump one dispatch pass once the endpoint is registered.
		_, _ = svc.DispatchOnceNow(context.Background())
		done <- nil
	}()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatal("mismatch scenario did not settle within 45s")
	}

	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.Status != jobs.AttemptFailed && a.Status != jobs.AttemptInterrupted {
			t.Fatalf("attempt status = %q, want failed/interrupted after refused admission", a.Status)
		}
		if a.VerifiedDigest != "" {
			t.Fatalf("mismatch attempt carries a verified digest: %q", a.VerifiedDigest)
		}
		if a.LastError == "" {
			t.Fatal("attempt should record the honest refusal")
		}
	}
	if job.Status == jobs.JobCompleted {
		t.Fatal("endpoint-owner-mismatch job marked completed")
	}
	// Nothing was received anywhere: the receiver destination belongs to
	// the fixture and was never contacted (the stranger's server refused
	// admission).
	entries, err := os.ReadDir(fx.destDir)
	if err != nil {
		t.Fatalf("read dest dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("output files exist despite refused admission: %v", names)
	}
}

// switchableTrustStore embeds the real store and can be flipped to report
// devices as absent via the (nil, nil) shape some store implementations may
// produce — exercising the nil-record guard in resolveSendTarget that
// MemoryTrustStore's (record, error) behavior cannot reach.
type switchableTrustStore struct {
	trust.Store
	nilRecords atomic.Bool
}

func (n *switchableTrustStore) GetDevice(ctx context.Context, deviceID string) (*wire.TrustRecord, error) {
	if n.nilRecords.Load() {
		return nil, nil
	}
	return n.Store.GetDevice(ctx, deviceID)
}

// TestRecipeDispatchRejectsNilTrustRecord drives the dispatch-time nil-
// record guard: the recipe is authored while the device resolves normally,
// then the store starts reporting the (nil, nil) shape BEFORE dispatch. The
// guard must reject the target with the not-trusted error — before any dial
// and with no delivery. (Mutation-relevant: fabricating a record on the nil
// branch changes the failure family and is refused by the assertion.)
func TestRecipeDispatchRejectsNilTrustRecord(t *testing.T) {
	fx := newRouteFixture(t)

	dir := t.TempDir()
	idm, err := trust.NewIdentityManager(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := trust.NewFileSecretStore(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	// NOTE: the peer's pair secret must resolve from the service's own
	// secret store for the guard-discrimination to be meaningful (a stub
	// record must die at the TRUST seam, not merely at a missing secret).
	store := &switchableTrustStore{Store: trust.NewMemoryTrustStore()}
	svc2, err := NewRecipeService(dir, store, idm, secrets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc2.Shutdown(5 * time.Second) })
	svc2.StopDispatcher()

	// Author against the healthy store (peer record present), then flip.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	now := time.Now().UTC()
	if err := store.AddOrUpdateDevice(ctx2, &wire.TrustRecord{
		DeviceID:          fx.peerIdentity.DeviceID,
		PublicKey:         fx.peerIdentity.PublicKeyHex(),
		LocalLabel:        "peer",
		PairCredentialRef: "cred-route",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	}); err != nil {
		t.Fatalf("AddOrUpdateDevice: %v", err)
	}
	if err := secrets.SetSecret(fx.peerIdentity.DeviceID, []byte(strings.Repeat("k", 32))); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	in := newEditorInput("nightly", fx.sources, fx.peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc2.CreateRecipe(in)
	if err != nil {
		t.Fatalf("CreateRecipe: %v", err)
	}
	if _, err := svc2.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := svc2.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	store.nilRecords.Store(true) // the (nil, nil) shape appears after enqueue

	svc2.SetLocalPeerAddr(fx.peerIdentity.DeviceID, "127.0.0.1:1")
	svc2.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })
	svc2.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		t.Error("online sender invoked for a nil-record device")
		return transfer.Outcome{}, fmt.Errorf("online must never run here")
	})

	if _, err := svc2.DispatchOnceNow(context.Background()); err != nil {
		t.Fatalf("dispatch pass error: %v", err)
	}
	job, ok, err := svc2.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	found := false
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		found = true
		if a.Status != jobs.AttemptFailed && a.Status != jobs.AttemptInterrupted {
			t.Fatalf("attempt status = %q, want failed/interrupted", a.Status)
		}
		if a.VerifiedDigest != "" {
			t.Fatalf("nil-record attempt carries a verified digest: %q", a.VerifiedDigest)
		}
		// The NIL-RECORD GUARD is the discriminated seam: its error text is
		// the not-trusted error. A mutation fabricating a record on this
		// branch proceeds one seam deeper (pair-secret resolution) and
		// produces a different error family — refused here.
		if !strings.Contains(a.LastError, "not a trusted paired device") {
			t.Fatalf("expected the nil-record guard to reject with the not-trusted error, got: %q", a.LastError)
		}
	}
	if !found {
		t.Fatal("no attempt recorded for the nil-record device")
	}
}

// -----------------------------------------------------------------------
// G4: local-only job without an endpoint is HELD, budget untouched
// -----------------------------------------------------------------------

// TestLocalOnlyJobWithoutEndpointHeldEvenUnderOnlinePolicy proves the
// attempt-binding hold for the case the earlier tests do not cover: a
// LOCAL-ONLY recipe with no endpoint, dispatched under a live ONLINE policy.
// The job must be HELD (skipped with a policy reason) — never silently
// broadened to the online route — with zero attempt consumption and zero
// online egress.
func TestLocalOnlyJobWithoutEndpointHeldEvenUnderOnlinePolicy(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc

	in := newEditorInput("nightly", fx.sources, fx.peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := svc.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	// NO endpoint recorded; live policy is the most permissive one.
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.Online })
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		t.Error("online sender invoked for a held local-only job")
		return transfer.Outcome{}, fmt.Errorf("online must never run for a local-only job")
	})

	rep, err := svc.DispatchOnceNow(context.Background())
	if err != nil {
		t.Fatalf("dispatch pass error: %v", err)
	}

	held := false
	for _, skip := range rep.Skipped {
		lower := strings.ToLower(skip)
		if strings.Contains(lower, "policy") || strings.Contains(lower, "endpoint") {
			held = true
		}
	}
	if !held {
		t.Fatalf("expected the local-only job to be HELD without an endpoint; skipped=%v results=%v", rep.Skipped, rep.Results)
	}

	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.Attempts != 0 {
			t.Fatalf("held job consumed %d attempt(s); budget must be untouched", a.Attempts)
		}
		if a.Status != jobs.AttemptQueued {
			t.Fatalf("held attempt status = %q, want queued", a.Status)
		}
		if a.LastError != "" {
			t.Fatalf("held attempt recorded an error: %q", a.LastError)
		}
		if !a.NextRetryAt.IsZero() {
			t.Fatalf("held job scheduled a retry: %v — holds must not consume the retry budget", a.NextRetryAt)
		}
	}
	if job.Status == jobs.JobCompleted || job.Status == jobs.JobFailed {
		t.Fatalf("held job became %s — holds are not terminal", job.Status)
	}

	// Phase 2: the ENDPOINT gate's own hold. The live policy flips to
	// local-only, so the JOB-policy gate now passes (local-only is
	// dispatchable under local-only) — the only remaining barrier is the
	// missing endpoint. The job must STILL be held with the budget
	// untouched. This phase is the discriminator for the endpoint gate:
	// a bypass there dispatches the job, the sender's local-only backstop
	// fails it, and the attempt budget moves — which the assertions below
	// refuse.
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })
	rep2, err := svc.DispatchOnceNow(context.Background())
	if err != nil {
		t.Fatalf("phase-2 dispatch pass error: %v", err)
	}
	held2 := false
	for _, skip := range rep2.Skipped {
		lower := strings.ToLower(skip)
		if strings.Contains(lower, "endpoint") || strings.Contains(lower, "policy") {
			held2 = true
		}
	}
	if !held2 {
		t.Fatalf("phase 2: expected the local-only job to be HELD without an endpoint; skipped=%v results=%v", rep2.Skipped, rep2.Results)
	}
	job2, ok2, err2 := svc.jobs.Load(jobID)
	if err2 != nil || !ok2 {
		t.Fatalf("load job (phase 2): %v %v", err2, ok2)
	}
	for _, a := range job2.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.Attempts != 0 {
			t.Fatalf("phase 2: endpoint-gate bypass consumed %d attempt(s); the hold must be pre-attempt", a.Attempts)
		}
		if a.Status != jobs.AttemptQueued {
			t.Fatalf("phase 2: held attempt status = %q, want queued", a.Status)
		}
	}
}

// -----------------------------------------------------------------------
// G5: real verified delivery with byte + digest validation
// -----------------------------------------------------------------------

// TestPreferLocalRecipeVerifiesBytesAndDigest drives the full production
// path to a VERIFIED delivery against the real receiver and validates the
// actual bytes on disk and the persisted cryptographic digest — not merely
// a success counter.
func TestPreferLocalRecipeVerifiesBytesAndDigest(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	in := newEditorInput("nightly", fx.sources, fx.peerIdentity.DeviceID)
	in.NetworkPolicy = "prefer-local"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := svc.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.PreferLocal })
	recvDone, recvCancel := fx.startReceiver(t, fx.peerIdentity.DeviceID, func(_ context.Context, _ transfer.ConsentRequest) (transfer.ConsentDecision, error) {
		return transfer.ConsentDecision{Accepted: true}, nil
	})
	defer recvCancel()

	if _, err := svc.DispatchOnceNow(ctx); err != nil {
		t.Fatalf("dispatch pass: %v", err)
	}

	// Bounded poll for the verified attempt.
	deadline := time.Now().Add(80 * time.Second)
	verified := false
	for time.Now().Before(deadline) {
		if j, ok, _ := svc.jobs.Load(jobID); ok {
			for _, a := range j.Attempts {
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
				t.Fatalf("receiver errored during the verified case: %v", rerr)
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !verified {
		if j, ok, _ := svc.jobs.Load(jobID); ok {
			t.Fatalf("transfer never verified — attempts: %+v", j.Attempts)
		}
		t.Fatal("transfer never verified")
	}

	// The persisted attempt carries the whole-content digest, and it is the
	// real SHA-256 of the payload bytes.
	sum := sha256.Sum256(fx.payload)
	wantDigest := hex.EncodeToString(sum[:])
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	var attempt jobs.RecipientAttempt
	for _, a := range job.Attempts {
		if a.DeviceID == fx.peerIdentity.DeviceID {
			attempt = a
		}
	}
	if attempt.VerifiedDigest != wantDigest {
		t.Fatalf("VerifiedDigest = %q, want the payload SHA-256 %q", attempt.VerifiedDigest, wantDigest)
	}

	// The receiver's disk holds the actual bytes, unchanged.
	got, err := os.ReadFile(filepath.Join(fx.destDir, "route.bin"))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if string(got) != string(fx.payload) {
		t.Fatalf("received bytes differ: got %d bytes, want %d", len(got), len(fx.payload))
	}
}

// -----------------------------------------------------------------------
// G7: rejected endpoint (consent refusal at a real receiver)
// -----------------------------------------------------------------------

// TestRecipeConsentRefusalRecordsHonestFailure: the receiver is reached,
// authenticated — and refuses at the consent gate. The sender must record
// the refusal honestly (no verified digest, no output file, no completed
// job), and the retry contract applies as documented for a failed send.
func TestRecipeConsentRefusalRecordsHonestFailure(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	in := newEditorInput("nightly", fx.sources, fx.peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := svc.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })
	recvDone, recvCancel := fx.startReceiver(t, fx.peerIdentity.DeviceID, func(_ context.Context, _ transfer.ConsentRequest) (transfer.ConsentDecision, error) {
		return transfer.ConsentDecision{Accepted: false, Reason: "route-admission test refusal"}, nil
	})
	defer recvCancel()

	if _, err := svc.DispatchOnceNow(ctx); err != nil {
		t.Fatalf("dispatch pass: %v", err)
	}

	// Bounded poll for the honest refusal to land in the attempt record.
	// recvSettled tracks whether the receiver goroutine already finished
	// during the poll (its buffered done signal would otherwise be
	// consumed here without the assertion below noticing).
	deadline := time.Now().Add(80 * time.Second)
	refused := false
	recvSettled := false
	for time.Now().Before(deadline) {
		if j, ok, _ := svc.jobs.Load(jobID); ok {
			for _, a := range j.Attempts {
				if a.Status == jobs.AttemptFailed || a.Status == jobs.AttemptInterrupted {
					refused = true
				}
			}
		}
		if refused {
			break
		}
		select {
		case <-recvDone:
			// receiver finished (refusal) — one more poll picks up the job
			recvSettled = true
			time.Sleep(200 * time.Millisecond)
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !refused {
		if j, ok, _ := svc.jobs.Load(jobID); ok {
			t.Fatalf("refusal never recorded — attempts: %+v", j.Attempts)
		}
		t.Fatal("refusal never recorded")
	}
	// The refusal flows to BOTH sides asynchronously; the receiver's
	// terminal error must be read only after its goroutine settled (CI
	// caught this ordering assumption the hard way).
	if !recvSettled {
		select {
		case <-recvDone:
		case <-time.After(15 * time.Second):
			t.Fatal("receiver did not settle after the refusal")
		}
	}

	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.VerifiedDigest != "" {
			t.Fatalf("refused attempt carries a verified digest: %q", a.VerifiedDigest)
		}
		if a.Status == jobs.AttemptCompleted || a.Status == jobs.AttemptVerified {
			t.Fatalf("refused attempt marked %q — false delivery", a.Status)
		}
		if a.LastError == "" {
			t.Fatal("refusal not recorded honestly: empty LastError")
		}
		// wire.Fail carries only a reason code across the protocol, so the
		// sender-side text legitimately ends at the canceled-code hop; the
		// human refusal reason stays receiver-local by design (asserted
		// below against the receiver's terminal error).
		lower := strings.ToLower(a.LastError)
		if !strings.Contains(lower, "canceled") && !strings.Contains(lower, "receiver") {
			t.Fatalf("refusal error does not reflect the receiver-side cancellation: %q", a.LastError)
		}
		if a.Attempts != 1 {
			t.Fatalf("attempts = %d, want exactly 1 real send", a.Attempts)
		}
	}
	if job.Status == jobs.JobCompleted {
		t.Fatal("refused job marked completed")
	}
	// The RECEIVER must have recorded the refusal with its human reason —
	// the protocol keeps consent-refusal detail receiver-local, and it must
	// actually surface there.
	if err := fx.getRecvErr(); !strings.Contains(err, "route-admission test refusal") {
		t.Fatalf("receiver terminal error does not carry the consent refusal reason: %q", err)
	}
	// No output was accepted.
	entries, err := os.ReadDir(fx.destDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("output files exist despite consent refusal: %v (err=%v)", entries, err)
	}
}

// -----------------------------------------------------------------------
// G7: source mutation → job fails stale, budget untouched
// -----------------------------------------------------------------------

// TestRecipeSourceMutationFailsJobWithoutConsumingBudget: after enqueue,
// the source bytes change. The next dispatch must FAIL THE JOB as stale
// (fingerprint mismatch) — never resend mutated content, never consume a
// send attempt, never contact any receiver.
func TestRecipeSourceMutationFailsJobWithoutConsumingBudget(t *testing.T) {
	fx := newRouteFixture(t)
	svc := fx.svc

	in := newEditorInput("nightly", fx.sources, fx.peerIdentity.DeviceID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	jobID, err := svc.RunRecipe(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetLocalPeerAddr(fx.peerIdentity.DeviceID, "127.0.0.1:1") // endpoint present: gate passes
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		t.Error("online sender invoked during stale-source pass")
		return transfer.Outcome{}, fmt.Errorf("no online egress in this test")
	})

	// MUTATE the source bytes after enqueue.
	if err := os.WriteFile(filepath.Join(fx.sources, "route.bin"), []byte("TAMPERED CONTENT — must never be sent"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.DispatchOnceNow(context.Background()); err != nil {
		t.Fatalf("dispatch pass error: %v", err)
	}

	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	if job.Status != jobs.JobFailed {
		t.Fatalf("mutated-source job status = %q, want failed (stale)", job.Status)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != fx.peerIdentity.DeviceID {
			continue
		}
		if a.Attempts != 0 {
			t.Fatalf("stale job consumed %d attempt(s); budget must be untouched", a.Attempts)
		}
		if a.VerifiedDigest != "" {
			t.Fatalf("stale job carries a verified digest: %q", a.VerifiedDigest)
		}
	}
	// The staleness reason must be visible in the job's attempt records.
	foundReason := false
	for _, a := range job.Attempts {
		if strings.Contains(strings.ToLower(a.LastError), "changed") ||
			strings.Contains(strings.ToLower(a.LastError), "fingerprint") {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("stale reason not recorded in attempts: %+v", job.Attempts)
	}
	// No receiver was ever contacted (none was started): nothing to assert
	// on disk beyond the dest dir staying empty.
	entries, err := os.ReadDir(fx.destDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("output files exist despite stale-source failure: %v (err=%v)", entries, err)
	}
}
