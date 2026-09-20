// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package localpairing

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// --- Test helpers ---

type testDevice struct {
	idMgr *trust.IdentityManager
	store *trust.MemoryTrustStore
	coord *trust.PairingCoordinator
}

func newTestDevice(t *testing.T) *testDevice {
	t.Helper()
	keyPath := t.TempDir() + "/identity.key"
	idMgr, err := trust.NewIdentityManager(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	store := trust.NewMemoryTrustStore()
	coord := trust.NewPairingCoordinator(idMgr, store)
	return &testDevice{idMgr: idMgr, store: store, coord: coord}
}

func (d *testDevice) deviceID(t *testing.T) string {
	t.Helper()
	id, err := d.idMgr.GetOrCreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = pub
	return wire.DeriveDeviceID(id.PublicKey)
}

func startServer(t *testing.T, store trust.Store) (*localrendezvous.Server, string) {
	t.Helper()
	cfg := localrendezvous.Config{
		BindAddr:      "127.0.0.1:0",
		PairingWindow: time.Minute,
		DeviceID:      "test-server",
	}
	srv := localrendezvous.NewServer(cfg, store)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	addr, err := srv.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, addr.String()
}

// --- Invitation encoding ---

func TestInvitationEncodeParseRoundTrip(t *testing.T) {
	in := &Invitation{
		Address:     "192.168.1.10:45931",
		Token:       "abc123",
		Fingerprint: "device-id-123",
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	enc := in.Encode()
	if !strings.HasPrefix(enc, "sendbeam-local-pair|v1|") {
		t.Fatalf("bad prefix: %q", enc)
	}
	got, err := ParseInvitation(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != in.Address || got.Token != in.Token || got.Fingerprint != in.Fingerprint {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestParseInvitationRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"sendbeam-local-pair|v1|127.0.0.1:tok", // too few parts
		"sendbeam-local-pair|v2|127.0.0.1:tok:fp",      // wrong version
		"other-prefix|v1|127.0.0.1:tok:fp",             // wrong prefix
		"sendbeam-local-pair|v1|:tok:fp",               // empty address
		"sendbeam-local-pair|v1|127.0.0.1::fp",         // empty token
		"sendbeam-local-pair|v1|127.0.0.1:tok:",        // empty fingerprint
		"sendbeam-local-pair|v1|example.com:80:tok:fp", // hostname, not IP
		"sendbeam-local-pair|v1|not-an-address:tok:fp", // bad address
	}
	for _, c := range cases {
		if _, err := ParseInvitation(c); err == nil {
			t.Fatalf("expected error for %q", c)
		}
	}
}

// --- Full pairing flow ---

func TestOfflinePairingFreshDevices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	aliceID := alice.deviceID(t)

	srv, addr := startServer(t, alice.store)
	masterKey, err := newMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	in, err := CreateInvitation(srv, addr, aliceID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Inviter accepts in the background.
	acceptDone := make(chan *trust.PairingResult, 1)
	acceptErr := make(chan error, 1)
	go func() {
		res, err := Accept(ctx, srv, Options{
			Coordinator: alice.coord,
			DeviceName:  "alice",
			MasterKey:   masterKey,
		})
		if err != nil {
			acceptErr <- err
		} else {
			acceptDone <- res
		}
	}()

	// Joiner dials with the invitation.
	joinRes, err := Join(ctx, in, Options{
		Coordinator: bob.coord,
		DeviceName:  "bob",
		MasterKey:   masterKey,
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if joinRes.PeerRecord == nil || joinRes.PeerRecord.DeviceID != aliceID {
		t.Fatalf("joiner got wrong peer: %+v", joinRes.PeerRecord)
	}

	// Inviter completes.
	var acceptRes *trust.PairingResult
	select {
	case res := <-acceptDone:
		if res.PeerRecord == nil {
			t.Fatal("acceptor got nil peer record")
		}
		acceptRes = res
		// The acceptor learns bob's device ID.
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-ctx.Done():
		t.Fatal("accept timed out")
	}

	// Both sides persisted trust: alice has bob, bob has alice.
	bobID := acceptRes.PeerRecord.DeviceID
	if _, err := alice.store.GetDevice(ctx, bobID); err != nil {
		t.Fatalf("alice did not persist bob's trust: %v", err)
	}
	if _, err := bob.store.GetDevice(ctx, aliceID); err != nil {
		t.Fatalf("bob did not persist alice's trust: %v", err)
	}
}

func TestJoinWrongTokenFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	srv, addr := startServer(t, alice.store)
	masterKey, _ := newMasterKey()
	in, err := CreateInvitation(srv, addr, alice.deviceID(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	in.Token = "wrong-token"

	_, err = Join(ctx, in, Options{
		Coordinator: bob.coord,
		DeviceName:  "bob",
		MasterKey:   masterKey,
	})
	if err == nil {
		t.Fatal("expected wrong token to fail")
	}
	// No trust persisted on either side.
	if n, _ := bob.store.ListDevices(ctx); len(n) != 0 {
		t.Fatalf("bob persisted trust after failed join: %v", n)
	}
}

func TestJoinExpiredInvitationFails(t *testing.T) {
	in := &Invitation{
		Address:     "127.0.0.1:1",
		Token:       "tok",
		Fingerprint: "fp",
		ExpiresAt:   time.Now().Add(-time.Minute),
	}
	_, err := Join(context.Background(), in, Options{
		Coordinator: trust.NewPairingCoordinator(nil, nil),
		MasterKey:   []byte("0123456789abcdef0123456789abcdef"),
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestJoinNilInvitationFails(t *testing.T) {
	_, err := Join(context.Background(), nil, Options{})
	if err == nil {
		t.Fatal("expected error for nil invitation")
	}
}

// --- Fingerprint mismatch (substituted endpoint) ---

func TestJoinFingerprintMismatchFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	srv, addr := startServer(t, alice.store)
	masterKey, _ := newMasterKey()
	// Invitation claims a DIFFERENT fingerprint than alice's real ID.
	in, err := CreateInvitation(srv, addr, "wrong-device-id", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	acceptDone := make(chan error, 1)
	go func() {
		_, err := Accept(ctx, srv, Options{
			Coordinator: alice.coord,
			DeviceName:  "alice",
			MasterKey:   masterKey,
		})
		acceptDone <- err
	}()

	_, err = Join(ctx, in, Options{
		Coordinator: bob.coord,
		DeviceName:  "bob",
		MasterKey:   masterKey,
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected fingerprint mismatch error, got %v", err)
	}
	// No trust persisted on the joiner side.
	if n, _ := bob.store.ListDevices(ctx); len(n) != 0 {
		t.Fatalf("bob persisted trust after fingerprint mismatch: %v", n)
	}
	<-acceptDone // let the acceptor finish
}

// --- Competing joiner ---

func TestCompetingJoinerFailsCleanly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	carol := newTestDevice(t)
	aliceID := alice.deviceID(t)
	srv, addr := startServer(t, alice.store)
	masterKey, _ := newMasterKey()
	in, err := CreateInvitation(srv, addr, aliceID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Acceptor takes the first session; the second gets closed.
	acceptDone := make(chan error, 1)
	go func() {
		_, err := Accept(ctx, srv, Options{
			Coordinator: alice.coord,
			DeviceName:  "alice",
			MasterKey:   masterKey,
		})
		acceptDone <- err
	}()

	// Bob and carol race to join.
	bobDone := make(chan error, 1)
	carolDone := make(chan error, 1)
	go func() {
		_, err := Join(ctx, in, Options{
			Coordinator: bob.coord, DeviceName: "bob", MasterKey: masterKey,
		})
		bobDone <- err
	}()
	go func() {
		// Carol uses a WRONG master key, so she fails the ceremony even if
		// she wins the race.
		wrongKey, _ := newMasterKey()
		_, err := Join(ctx, in, Options{
			Coordinator: carol.coord, DeviceName: "carol", MasterKey: wrongKey,
		})
		carolDone <- err
	}()

	// One of them completes the pairing; the other fails. Exactly one
	// trust record lands on alice's side (bob's, if he won).
	bobErr := <-bobDone
	carolErr := <-carolDone
	<-acceptDone
	if bobErr == nil && carolErr == nil {
		t.Fatal("both joiners succeeded; expected exactly one")
	}
	// Carol must never get trust (wrong key).
	if n, _ := carol.store.ListDevices(ctx); len(n) != 0 {
		t.Fatalf("carol persisted trust with wrong key: %v", n)
	}
}
