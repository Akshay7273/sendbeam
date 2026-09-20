// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package localtransfer

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

// loopbackUDPAvailable probes whether this environment can pass UDP on
// loopback — the transport WebRTC host candidates need. Sandboxes that block
// UDP cannot run the full byte-transfer test; callers skip with a clear
// message instead of failing (the transfer itself is exercised in CI).
func loopbackUDPAvailable() bool {
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer a.Close()
	b, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer b.Close()
	if _, err := a.WriteTo([]byte("ping"), b.LocalAddr()); err != nil {
		return false
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	n, _, err := b.ReadFrom(buf)
	return err == nil && n == 4 && string(buf[:n]) == "ping"
}

// TestReceiveEndToEnd runs a real local-only transfer between two paired
// devices on loopback: bob's Receive accepts alice's Transfer dial and the
// shared engine moves verified bytes with no public service involved.
func TestReceiveEndToEnd(t *testing.T) {
	if !loopbackUDPAvailable() {
		t.Skip("sandbox blocks loopback UDP, so WebRTC host candidates cannot connect; full transfer runs in CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	kPair := []byte(strings.Repeat("k", 32))
	pair(t, alice, bob, kPair, "cred-e2e")

	// Bob listens on loopback (same-host test setup).
	srv := localrendezvous.NewServer(localrendezvous.Config{
		BindAddr:      "127.0.0.1:0",
		AllowWildcard: false,
	}, bob.store)
	addr, err := srv.Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	destDir := t.TempDir()
	recvDone := make(chan error, 1)
	var recvOut string
	go func() {
		out, err := Receive(ctx, ReceiveOptions{
			Identity:    bob.identity,
			Store:       bob.store,
			Resolver:    bob.resolver,
			Server:      srv,
			DestDir:     destDir,
			Consent:     acceptAll,
			OnTransport: func(tr string) { recvOut = tr },
		})
		if err != nil {
			recvDone <- err
			return
		}
		recvDone <- nil
		_ = out
	}()

	// Give the receiver a moment to arm its session handler.
	time.Sleep(200 * time.Millisecond)

	payload := []byte("offline receive path moves real bytes")
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	if _, err := tab.AddManual(bob.identity.DeviceID, addr.String()); err != nil {
		t.Fatalf("add manual candidate: %v", err)
	}
	src := wire.BytesSource(payload, wire.FileMeta{
		Name: "recv.txt", Size: int64(len(payload)), Mime: "text/plain", LastModified: 1_700_000_000_000,
	}, 64*1024)
	var sentTransport string
	_, err = Transfer(ctx, Options{
		Identity:     alice.identity,
		Store:        alice.store,
		Resolver:     alice.resolver,
		Table:        tab,
		PeerDeviceID: bob.identity.DeviceID,
		PeerLabel:    "bob",
		Role:         rendezvous.RoleOfferer,
		Source:       src,
		OnTransport:  func(tr string) { sentTransport = tr },
	})
	if err != nil {
		t.Fatalf("offerer transfer: %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("joiner receive: %v", err)
	}

	// Verify the bytes landed intact.
	got, err := os.ReadFile(filepath.Join(destDir, "recv.txt"))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("received %q, want %q", got, payload)
	}
	if sentTransport == "" || recvOut == "" {
		t.Fatal("expected transport reports on both sides")
	}
}

// TestReceiveValidation rejects incomplete options before any network.
func TestReceiveValidation(t *testing.T) {
	ctx := context.Background()
	base := ReceiveOptions{
		Identity: &wire.DeviceIdentity{DeviceID: "d"},
		Store:    newTestDevice(t).store,
		Resolver: newTestDevice(t).resolver,
		Server:   localrendezvous.NewServer(localrendezvous.Config{}, newTestDevice(t).store),
		DestDir:  t.TempDir(),
	}
	cases := []struct {
		name string
		mut  func(*ReceiveOptions)
	}{
		{"nil identity", func(o *ReceiveOptions) { o.Identity = nil }},
		{"nil store", func(o *ReceiveOptions) { o.Store = nil }},
		{"nil resolver", func(o *ReceiveOptions) { o.Resolver = nil }},
		{"nil server", func(o *ReceiveOptions) { o.Server = nil }},
		{"empty destdir", func(o *ReceiveOptions) { o.DestDir = "" }},
	}
	for _, c := range cases {
		o := base
		c.mut(&o)
		if _, err := Receive(ctx, o); err == nil {
			t.Fatalf("%s: expected validation error", c.name)
		}
	}
}

// TestReceiveRevokedPeerFailsClosed ensures a revoked device cannot receive
// even though the rendezvous server admitted the session.
func TestReceiveRevokedPeerFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	kPair := []byte(strings.Repeat("k", 32))
	pair(t, alice, bob, kPair, "cred-revoke")

	// Revoke alice on bob's store after pairing.
	rec, err := bob.store.GetDevice(ctx, alice.identity.DeviceID)
	if err != nil || rec == nil {
		t.Fatalf("get device: %v", err)
	}
	rec.Revoked = true
	if err := bob.store.AddOrUpdateDevice(ctx, rec); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	srv := localrendezvous.NewServer(localrendezvous.Config{BindAddr: "127.0.0.1:0"}, bob.store)
	addr, err := srv.Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	recvDone := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, ReceiveOptions{
			Identity: bob.identity,
			Store:    bob.store,
			Resolver: bob.resolver,
			Server:   srv,
			DestDir:  t.TempDir(),
			Consent:  acceptAll,
		})
		recvDone <- err
	}()
	time.Sleep(200 * time.Millisecond)

	// Alice dials; admission may refuse the revoked device, or the joiner
	// fails closed on the revoked trust record. Either way, no transfer.
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	_, _ = tab.AddManual(bob.identity.DeviceID, addr.String())
	payload := []byte("x")
	src := wire.BytesSource(payload, wire.FileMeta{Name: "x", Size: 1, LastModified: 1}, 64*1024)
	_, _ = Transfer(ctx, Options{
		Identity:     alice.identity,
		Store:        alice.store,
		Resolver:     alice.resolver,
		Table:        tab,
		PeerDeviceID: bob.identity.DeviceID,
		Role:         rendezvous.RoleOfferer,
		Source:       src,
	})

	select {
	case err := <-recvDone:
		if err == nil {
			t.Fatal("revoked peer must not complete a receive")
		}
	case <-time.After(15 * time.Second):
		// No session arrived because the server refused the revoked
		// dialer: also a fail-closed outcome. Cancel to release Receive.
		cancel()
		if err := <-recvDone; err == nil {
			t.Fatal("expected an error after cancel")
		}
	}
}

// TestServeSessionValidation verifies the session-serving core fails closed
// on missing inputs before any network or crypto work happens.
func TestServeSessionValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := ServeSession(ctx, nil, ServeOptions{}); err == nil {
		t.Fatal("nil session should fail")
	}
	if _, err := ServeSession(ctx, &localrendezvous.Session{}, ServeOptions{}); err == nil {
		t.Fatal("missing identity should fail")
	}
}
