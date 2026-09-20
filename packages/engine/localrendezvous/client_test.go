package localrendezvous

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startPairedServer starts a server whose trust store pairs testDeviceID and
// returns its dial address.
func startPairedServer(t *testing.T, cfg Config) (string, *Server) {
	t.Helper()
	st := testStore(t)
	srv := NewServer(cfg, st)
	ctx := context.Background()
	if _, err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv.Addr().String(), srv
}

func TestDialPairedRoundTrip(t *testing.T) {
	addr, _ := startPairedServer(t, Config{BindAddr: "127.0.0.1:0", DeviceID: "server-dev"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := Dial(ctx, addr, DialConfig{DeviceID: testDeviceID})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if sess.Kind != PeerPaired {
		t.Fatalf("kind = %v, want paired", sess.Kind)
	}
	if sess.DeviceID != "server-dev" {
		t.Fatalf("server device id = %q, want %q", sess.DeviceID, "server-dev")
	}
	// Frames flow on the admitted session.
	if err := sess.WriteFrame(ctx, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestDialRefused(t *testing.T) {
	addr, _ := startPairedServer(t, Config{BindAddr: "127.0.0.1:0"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Dial(ctx, addr, DialConfig{DeviceID: "unknown-device"})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

func TestDialPairingToken(t *testing.T) {
	st := testStore(t)
	srv := NewServer(Config{BindAddr: "127.0.0.1:0"}, st)
	ctx := context.Background()
	if _, err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	token := srv.OpenPairingWindow(0)
	addr := srv.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := Dial(ctx, addr, DialConfig{DeviceID: "new-device", PairToken: token})
	if err != nil {
		t.Fatalf("dial with pairing token: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if sess.Kind != PeerPairing {
		t.Fatalf("kind = %v, want pairing", sess.Kind)
	}
}

func TestDialRefusesHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, "localhost:12345", DialConfig{DeviceID: testDeviceID})
	if err == nil || !strings.Contains(err.Error(), "literal IP") {
		t.Fatalf("err = %v, want literal-IP refusal", err)
	}
}

func TestDialRefusesUnspecified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, "0.0.0.0:12345", DialConfig{DeviceID: testDeviceID})
	if err == nil || !strings.Contains(err.Error(), "unspecified") {
		t.Fatalf("err = %v, want unspecified refusal", err)
	}
}

func TestDialClosedPortFailsCleanly(t *testing.T) {
	// Reserve then release a port so nothing listens there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, addr, DialConfig{DeviceID: testDeviceID})
	if err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want a clear dial failure (not refusal)", err)
	}
}

// TestDialEgressHookSeesEveryDial proves every outbound connection flows
// through DialConfig.DialContext, so a host can deny and monitor egress.
func TestDialEgressHookSeesEveryDial(t *testing.T) {
	addr, _ := startPairedServer(t, Config{BindAddr: "127.0.0.1:0"})

	var dials int64
	deny := func(ctx context.Context, network, address string) (net.Conn, error) {
		atomic.AddInt64(&dials, 1)
		host, _, _ := net.SplitHostPort(address)
		if host != "127.0.0.1" {
			return nil, errors.New("egress policy: non-loopback dial denied")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := Dial(ctx, addr, DialConfig{DeviceID: testDeviceID, DialContext: deny})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = sess.Close()
	if got := atomic.LoadInt64(&dials); got != 1 {
		t.Fatalf("dials seen = %d, want exactly 1", got)
	}

	// A hook that denies everything fails the dial cleanly.
	denyAll := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("egress policy: all dials denied")
	}
	if _, err := Dial(ctx, addr, DialConfig{DeviceID: testDeviceID, DialContext: denyAll}); err == nil {
		t.Fatal("expected dial failure when egress is denied")
	}
}

func TestDialMalformedAcceptFailsClosed(t *testing.T) {
	// A fake server that sends garbage instead of the accept frame.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = readFrame(conn, maxHelloBytes) // consume hello
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = writeFrame(conn, []byte("not-json{"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, ln.Addr().String(), DialConfig{DeviceID: testDeviceID})
	if err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want a malformed-accept failure", err)
	}
}
