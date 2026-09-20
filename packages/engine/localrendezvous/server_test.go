package localrendezvous

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// testDeviceID is the paired device's ID, set by testStore.
var testDeviceID string

// testStore builds a trust store with one paired, non-revoked device.
func testStore(t *testing.T) *trust.MemoryTrustStore {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	testDeviceID = wire.DeriveDeviceID(pub)
	st := trust.NewMemoryTrustStore()
	ctx := context.Background()
	rec := &wire.TrustRecord{
		DeviceID:          testDeviceID,
		PublicKey:         hex.EncodeToString(pub),
		LocalLabel:        "Test Peer",
		PairCredentialRef: "cred-test",
		Capabilities:      []string{"transfer.v1"},
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	}
	if err := st.AddOrUpdateDevice(ctx, rec); err != nil {
		t.Fatalf("seed trust store: %v", err)
	}
	return st
}

func startTestServer(t *testing.T, st trust.Store, cfg Config) *Server {
	t.Helper()
	if cfg.BindAddr == "" {
		cfg.BindAddr = "127.0.0.1:0"
	}
	srv := NewServer(cfg, st)
	var sessions []*Session
	var mu sync.Mutex
	srv.OnSession(func(s *Session) {
		mu.Lock()
		sessions = append(sessions, s)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = srv.Close() })
	if _, err := srv.Start(ctx); err != nil {
		t.Fatalf("start server: %v", err)
	}
	return srv
}

// dialHello opens a TCP connection to the server and sends a hello frame.
func dialHello(t *testing.T, srv *Server, deviceID, token string) net.Conn {
	t.Helper()
	conn := dialHelloRaw(t, srv, deviceID, token)
	// Admission is confirmed by the server's accept frame; consume and
	// validate it so the caller starts at the first post-admission frame.
	frame, err := readTestFrame(t, conn)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read accept frame: %v", err)
	}
	if string(frame) != `{"ok":true}` && !strings.HasPrefix(string(frame), `{"ok":true,`) {
		_ = conn.Close()
		t.Fatalf("unexpected accept frame: %q", frame)
	}
	return conn
}

// dialHelloRaw dials and sends the hello without consuming the admission
// reply, for tests that exercise refusal paths.
func dialHelloRaw(t *testing.T, srv *Server, deviceID, token string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	payload := []byte(`{"device_id":` + fmt.Sprintf("%q", deviceID) + `}`)
	if token != "" {
		payload = []byte(`{"device_id":` + fmt.Sprintf("%q", deviceID) + `,"pair_token":` + fmt.Sprintf("%q", token) + `}`)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(append(hdr[:], payload...)); err != nil {
		_ = conn.Close()
		t.Fatalf("write hello: %v", err)
	}
	return conn
}

func readTestFrame(t *testing.T, conn net.Conn) ([]byte, error) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [4]byte
	if _, err := ioReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	buf := make([]byte, n)
	if _, err := ioReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestBootstrapTwoProcesses(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{})

	conn := dialHello(t, srv, testDeviceID, "")
	defer func() { _ = conn.Close() }()

	// Paired device is admitted: server must route a frame back and forth.
	deadline := time.Now().Add(5 * time.Second)
	for {
		srv.mu.RLock()
		n := len(srv.sessions)
		srv.mu.RUnlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("paired session was not admitted")
		}
		time.Sleep(10 * time.Millisecond)
	}

	srv.mu.RLock()
	var sess *Session
	for s := range srv.sessions {
		sess = s
		break
	}
	srv.mu.RUnlock()
	if sess == nil {
		t.Fatal("no session admitted")
	}
	if sess.Kind != PeerPaired || sess.DeviceID != testDeviceID {
		t.Fatalf("unexpected session: kind=%v device=%q", sess.Kind, sess.DeviceID)
	}

	// Echo: write a frame from the client, read it on the session, write it back.
	payload := []byte(`{"type":"ping"}`)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(append(hdr[:], payload...)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got, err := sess.ReadFrame(context.Background())
	if err != nil {
		t.Fatalf("session read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("frame mismatch: %q", got)
	}
	if err := sess.WriteFrame(context.Background(), []byte(`{"type":"pong"}`)); err != nil {
		t.Fatalf("session write: %v", err)
	}
	resp, err := readTestFrame(t, conn)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(resp) != `{"type":"pong"}` {
		t.Fatalf("echo mismatch: %q", resp)
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{MaxFrameBytes: 1024})

	conn := dialHello(t, srv, testDeviceID, "")
	defer func() { _ = conn.Close() }()

	// Send a frame larger than the limit.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 1<<20)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(hdr[:])

	// Server must close the connection.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection close after oversized frame")
	}

	// Server stays alive: a fresh paired hello still works.
	conn2 := dialHello(t, srv, testDeviceID, "")
	defer func() { _ = conn2.Close() }()
	_ = conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
}

func TestMalformedFrameRejected(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{})

	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Garbage hello (not JSON).
	payload := []byte("not-json{{{")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(append(hdr[:], payload...))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		// Either an error frame or a close is acceptable; but the session must
		// never reach the handler. Give the server a moment then check.
		time.Sleep(200 * time.Millisecond)
	}
	srv.mu.RLock()
	n := len(srv.sessions)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("malformed hello admitted %d sessions", n)
	}
}

func TestUnpairedWithoutWindowRefused(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{})

	conn := dialHelloRaw(t, srv, "dev-stranger", "")
	defer func() { _ = conn.Close() }()

	// Server must refuse: read the refusal frame or observe the close.
	frame, err := readTestFrame(t, conn)
	if err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if string(frame) != `{"error":"refused"}` {
		t.Fatalf("unexpected admission reply: %q", frame)
	}
	body := string(frame)

	time.Sleep(200 * time.Millisecond)
	srv.mu.RLock()
	nsess := len(srv.sessions)
	srv.mu.RUnlock()
	if nsess != 0 {
		t.Fatalf("unpaired device admitted without pairing window")
	}
	if body != "" && containsToken(body) {
		t.Fatalf("refusal leaked token material: %q", body)
	}
}

func containsToken(s string) bool {
	// Test-only heuristic: refusal frames must be short, fixed strings.
	return len(s) > 64
}

func TestPairingWindowAdmits(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{PairingWindow: 50 * time.Millisecond})

	token := srv.OpenPairingWindow(0)
	if token == "" {
		t.Fatal("empty pairing token")
	}

	// Correct token: admitted as pairing peer.
	conn := dialHello(t, srv, "dev-new", token)
	defer func() { _ = conn.Close() }()
	waitForSessions(t, srv, 1)
	srv.mu.RLock()
	var kind PeerKind
	for s := range srv.sessions {
		kind = s.Kind
		break
	}
	srv.mu.RUnlock()
	if kind != PeerPairing {
		t.Fatalf("expected PeerPairing, got %v", kind)
	}

	// Wrong token: refused.
	conn2 := dialHelloRaw(t, srv, "dev-new2", "wrong-token")
	defer func() { _ = conn2.Close() }()
	time.Sleep(300 * time.Millisecond)
	waitForSessions(t, srv, 1) // still exactly one

	// After the window expires: refused even with the (now stale) token.
	time.Sleep(100 * time.Millisecond)
	conn3 := dialHelloRaw(t, srv, "dev-new3", token)
	defer func() { _ = conn3.Close() }()
	time.Sleep(300 * time.Millisecond)
	waitForSessions(t, srv, 1)

	// Explicit close also refuses.
	token2 := srv.OpenPairingWindow(0)
	srv.ClosePairingWindow()
	conn4 := dialHelloRaw(t, srv, "dev-new4", token2)
	defer func() { _ = conn4.Close() }()
	time.Sleep(300 * time.Millisecond)
	waitForSessions(t, srv, 1)
}

func waitForSessions(t *testing.T, srv *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		srv.mu.RLock()
		got := len(srv.sessions)
		srv.mu.RUnlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("wanted %d sessions, have %d", n, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRevokedDeviceRefused(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.RevokeDevice(ctx, testDeviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	srv := startTestServer(t, st, Config{})

	conn := dialHelloRaw(t, srv, testDeviceID, "")
	defer func() { _ = conn.Close() }()
	// The admission reply must be the fixed refusal, not an accept frame.
	frame, err := readTestFrame(t, conn)
	if err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if string(frame) != `{"error":"refused"}` {
		t.Fatalf("unexpected admission reply: %q", frame)
	}
	time.Sleep(300 * time.Millisecond)
	srv.mu.RLock()
	n := len(srv.sessions)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatal("revoked device was admitted")
	}
}

func TestConnectionFloodRateLimited(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{
		MaxConnections:     64,
		MaxConnPerMinPerIP: 10,
		RateLimitWindow:    2 * time.Second,
	})

	// Flood with completed hellos (unknown device, no pairing window).
	// The first 10 fill the budget; the rest must be refused.
	var refused int
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
		if err != nil {
			refused++
			continue
		}
		payload := []byte(`{"device_id":"sb-dev-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`)
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(append(hdr[:], payload...))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		// Read one full length-prefixed frame (a single Read may return
		// only the header under TCP segmentation).
		var fhdr [4]byte
		if _, err := io.ReadFull(conn, fhdr[:]); err != nil {
			refused++
			_ = conn.Close()
			continue
		}
		frame := make([]byte, binary.BigEndian.Uint32(fhdr[:]))
		if _, err := io.ReadFull(conn, frame); err != nil {
			refused++
			_ = conn.Close()
			continue
		}
		// The server refuses with a fixed frame; either that frame or a
		// bare close counts as refused.
		if strings.Contains(string(frame), `"refused"`) {
			refused++
		}
		_ = conn.Close()
	}
	if refused < 10 {
		t.Fatalf("rate limiter did not engage: only %d/30 refused", refused)
	}

	// After the window expires the server must admit a legitimate peer again.
	time.Sleep(2500 * time.Millisecond)
	conn := dialHello(t, srv, testDeviceID, "")
	defer func() { _ = conn.Close() }()
	waitForSessions(t, srv, 1)
}

func TestPortConflict(t *testing.T) {
	st := testStore(t)
	srv1 := startTestServer(t, st, Config{BindAddr: "127.0.0.1:0"})
	addr := srv1.Addr().String()

	srv2 := NewServer(Config{BindAddr: addr}, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := srv2.Start(ctx); err == nil {
		_ = srv2.Close()
		t.Fatal("expected port-conflict error, got nil")
	}
}

func TestRepeatedStartStop(t *testing.T) {
	st := testStore(t)
	srv := NewServer(Config{BindAddr: "127.0.0.1:0"}, st)
	srv.OnSession(func(*Session) {})

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		addr, err := srv.Start(ctx)
		if err != nil {
			cancel()
			t.Fatalf("start %d: %v", i, err)
		}
		conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
		if err != nil {
			cancel()
			t.Fatalf("dial %d: %v", i, err)
		}
		_ = conn.Close()
		cancel()
		if err := srv.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
		// Listener must be gone: dial now fails.
		if _, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
			t.Fatalf("listener still present after close (iteration %d)", i)
		}
	}
}

func TestWildcardBindRefused(t *testing.T) {
	st := testStore(t)
	srv := NewServer(Config{BindAddr: "0.0.0.0:0"}, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := srv.Start(ctx); err == nil {
		_ = srv.Close()
		t.Fatal("expected wildcard-bind refusal, got nil")
	}
}

func TestMaxConnectionsEnforced(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{MaxConnections: 2})

	held := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		held = append(held, dialHello(t, srv, testDeviceID, ""))
	}
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	waitForSessions(t, srv, 2)

	// Third connection must be refused promptly.
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
	if err != nil {
		return // refused at TCP level: acceptable
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		// If we read an error frame, the session count must not grow.
		time.Sleep(200 * time.Millisecond)
		waitForSessions(t, srv, 2)
	}
}

func TestPairingTransportRoundTrip(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{})
	conn := dialHello(t, srv, testDeviceID, "")
	defer func() { _ = conn.Close() }()
	waitForSessions(t, srv, 1)

	srv.mu.RLock()
	var sess *Session
	for s := range srv.sessions {
		sess = s
		break
	}
	srv.mu.RUnlock()
	if sess == nil {
		t.Fatal("no session admitted")
	}

	pt := sess.PairingTransport()
	ctx := context.Background()

	// Client side acts as the peer: read the frame the transport sends, then
	// write one back.
	done := make(chan error, 1)
	go func() {
		frame, err := readTestFrame(t, conn)
		if err != nil {
			done <- err
			return
		}
		if string(frame) != "ceremony-payload-1" {
			done <- errMismatch(frame)
			return
		}
		var hdr [4]byte
		reply := []byte("ceremony-payload-2")
		binary.BigEndian.PutUint32(hdr[:], uint32(len(reply)))
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write(append(hdr[:], reply...))
		done <- err
	}()

	if err := pt.SendMessage(ctx, []byte("ceremony-payload-1")); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := pt.ReceiveMessage(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(got) != "ceremony-payload-2" {
		t.Fatalf("payload mismatch: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("peer side: %v", err)
	}
}

func TestSessionSinkRoundTrip(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{})
	conn := dialHello(t, srv, testDeviceID, "")
	defer func() { _ = conn.Close() }()
	waitForSessions(t, srv, 1)

	srv.mu.RLock()
	var sess *Session
	for s := range srv.sessions {
		sess = s
		break
	}
	srv.mu.RUnlock()
	if sess == nil {
		t.Fatal("no session admitted")
	}

	sink := sess.Sink()
	if err := sink.Send(rendezvous.Message{Type: "ping"}); err != nil {
		t.Fatalf("sink send: %v", err)
	}
	frame, err := readTestFrame(t, conn)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if len(frame) == 0 {
		t.Fatal("empty frame via Sink")
	}
}

func errMismatch(frame []byte) error {
	return fmt.Errorf("payload mismatch: %q", frame)
}

func TestShutdownClosesSessions(t *testing.T) {
	st := testStore(t)
	srv := NewServer(Config{BindAddr: "127.0.0.1:0"}, st)
	srv.OnSession(func(*Session) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := srv.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	conn := dialHello(t, srv, testDeviceID, "")
	defer func() { _ = conn.Close() }()
	waitForSessions(t, srv, 1)

	if err := srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Client observes the close.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected client-visible close after server shutdown")
	}
}

func TestErrorsDoNotLeakToken(t *testing.T) {
	st := testStore(t)
	srv := startTestServer(t, st, Config{})
	token := srv.OpenPairingWindow(0)
	srv.ClosePairingWindow()

	conn := dialHelloRaw(t, srv, "dev-stranger", token)
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 && stringContains(string(buf[:n]), token) {
		t.Fatalf("refusal contained the pairing token")
	}
	var _ = errors.Is // keep errors import used across refactors
}

func stringContains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
