package signal

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// newTestPeer builds a peer without a socket, for hub-logic tests that never write.
func newTestPeer() *peer {
	return &peer{
		room:             -1,
		clientIP:         "127.0.0.1",
		send:             make(chan outboundFrame, sendBuffer),
		relayRate:        newTokenBucket(1<<20, 1<<20),
		relayControlRate: newTokenBucket(128, 64),
		done:             make(chan struct{}),
		closed:           make(chan struct{}),
	}
}

func testHub(t *testing.T) *Hub {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return NewHub(ctx, DefaultConfig(), nil)
}

func TestCreateRoomAllocatesSmallestFree(t *testing.T) {
	h := testHub(t)

	a, b, c := newTestPeer(), newTestPeer(), newTestPeer()
	if n, code := h.createRoom(a, "127.0.0.1"); code != "" || n != 0 {
		t.Fatalf("first room = %d (code=%s), want 0", n, code)
	}
	if n, code := h.createRoom(b, "127.0.0.1"); code != "" || n != 1 {
		t.Fatalf("second room = %d (code=%s), want 1", n, code)
	}
	if n, code := h.createRoom(c, "127.0.0.1"); code != "" || n != 2 {
		t.Fatalf("third room = %d (code=%s), want 2", n, code)
	}

	// Freeing room 1 makes it the smallest free slot again. b is the lone peer, so
	// vacate deletes the room outright.
	h.vacate(b)
	d := newTestPeer()
	if n, code := h.createRoom(d, "127.0.0.1"); code != "" || n != 1 {
		t.Fatalf("reused room = %d (code=%s), want 1", n, code)
	}
}

func TestJoinPairsAndIsOneToOne(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room, code := h.createRoom(off, "127.0.0.1")
	if code != "" {
		t.Fatalf("createRoom failed: %s", code)
	}

	join := newTestPeer()
	other, code := h.join(join, room, "127.0.0.1")
	if code != "" {
		t.Fatalf("join failed: %s", code)
	}
	if other != off {
		t.Fatal("join did not return the offerer")
	}
	if off.role != roleOfferer || join.role != roleJoiner {
		t.Fatalf("roles = %q/%q", off.role, join.role)
	}

	// A second join for the same room is refused: strict 1:1.
	third := newTestPeer()
	if _, code := h.join(third, room, "127.0.0.1"); code != errRoomFull {
		t.Fatalf("third join code = %q, want %q", code, errRoomFull)
	}
}

func TestJoinUnknownRoom(t *testing.T) {
	h := testHub(t)
	if _, code := h.join(newTestPeer(), 999, "127.0.0.1"); code != errUnknownRoom {
		t.Fatalf("code = %q, want %q", code, errUnknownRoom)
	}
}

func TestPartnerLookup(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room, _ := h.createRoom(off, "127.0.0.1")
	join := newTestPeer()
	if _, code := h.join(join, room, "127.0.0.1"); code != "" {
		t.Fatalf("join: %s", code)
	}

	if h.partner(off) != join || h.partner(join) != off {
		t.Fatal("partner lookup wrong")
	}
}

// A partnered peer that drops leaves the room lingering with its slot vacated, so the
// dropped peer can reload and re-attach. The room is only deleted when the last peer goes.
func TestVacateLingersThenDeletes(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room, _ := h.createRoom(off, "127.0.0.1")
	join := newTestPeer()
	if _, code := h.join(join, room, "127.0.0.1"); code != "" {
		t.Fatalf("join: %s", code)
	}

	// The offerer drops: its slot is vacated, the joiner surfaces, and the room lingers.
	if other := h.vacate(off); other != join {
		t.Fatal("vacate did not surface the surviving partner")
	}
	if h.roomCount() != 1 {
		t.Fatalf("room count after one drop = %d, want 1 (lingering)", h.roomCount())
	}
	if h.partner(join) != nil {
		t.Fatal("partner of a vacated slot should be nil until a peer re-attaches")
	}

	// The joiner drops too: now the room is empty and deleted.
	if other := h.vacate(join); other != nil {
		t.Fatalf("vacating the last peer should return nil, got %v", other)
	}
	if h.roomCount() != 0 {
		t.Fatalf("room count after last drop = %d, want 0", h.roomCount())
	}
}

// resume re-attaches a reloaded peer to its vacated slot and surfaces the waiting partner.
func TestResumeReattachesVacatedSlot(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room, _ := h.createRoom(off, "127.0.0.1")
	join := newTestPeer()
	if _, code := h.join(join, room, "127.0.0.1"); code != "" {
		t.Fatalf("join: %s", code)
	}

	// The offerer drops; the room lingers with the offerer slot empty.
	h.vacate(off)

	// A reloaded offerer resumes into the vacated slot and gets the waiting joiner back.
	reoff := newTestPeer()
	other, code := h.resume(reoff, room, roleOfferer, "127.0.0.1")
	if code != "" {
		t.Fatalf("resume failed: %s", code)
	}
	if other != join {
		t.Fatal("resume did not surface the waiting partner")
	}
	if reoff.room != room || reoff.role != roleOfferer {
		t.Fatalf("resumed peer state = room %d role %q", reoff.room, reoff.role)
	}
	if h.partner(join) != reoff || h.partner(reoff) != join {
		t.Fatal("pairing not restored after resume")
	}
}

// resume is refused when the target slot is still occupied or the room is unknown.
func TestResumeRefusesOccupiedOrUnknown(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room, _ := h.createRoom(off, "127.0.0.1")
	join := newTestPeer()
	if _, code := h.join(join, room, "127.0.0.1"); code != "" {
		t.Fatalf("join: %s", code)
	}

	// Both slots are occupied: claiming the offerer role is refused.
	if _, code := h.resume(newTestPeer(), room, roleOfferer, "127.0.0.1"); code != errRoomFull {
		t.Fatalf("resume into occupied slot code = %q, want %q", code, errRoomFull)
	}
	// An unknown room is refused.
	if _, code := h.resume(newTestPeer(), 999, roleJoiner, "127.0.0.1"); code != errUnknownRoom {
		t.Fatalf("resume into unknown room code = %q, want %q", code, errUnknownRoom)
	}
	// A bad role is rejected before any room lookup.
	if _, code := h.resume(newTestPeer(), room, "bogus", "127.0.0.1"); code != errBadMessage {
		t.Fatalf("resume with bad role code = %q, want %q", code, errBadMessage)
	}
}

// discard tears down the whole room on a graceful bye and surfaces the partner to close.
func TestDiscardTearsDownRoom(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room, _ := h.createRoom(off, "127.0.0.1")
	join := newTestPeer()
	if _, code := h.join(join, room, "127.0.0.1"); code != "" {
		t.Fatalf("join: %s", code)
	}

	if other := h.discard(off); other != join {
		t.Fatal("discard did not surface the partner")
	}
	if h.roomCount() != 0 {
		t.Fatalf("room count after discard = %d, want 0", h.roomCount())
	}
}

// A lingering half-empty room is still bounded by the idle reaper: a peer that drops and
// never returns cannot pin server memory beyond the idle timeout.
func TestReapClosesLingeringRoom(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room, _ := h.createRoom(off, "127.0.0.1")
	join := newTestPeer()
	if _, code := h.join(join, room, "127.0.0.1"); code != "" {
		t.Fatalf("join: %s", code)
	}
	h.vacate(off) // room now lingers with only the joiner attached

	h.mu.Lock()
	for _, r := range h.rooms {
		r.lastSeen = time.Now().Add(-2 * h.cfg.IdleTimeout)
	}
	h.mu.Unlock()

	h.reapOnce(time.Now())
	if h.roomCount() != 0 {
		t.Fatalf("room count after reap = %d, want 0", h.roomCount())
	}
	select {
	case <-join.done:
		// the surviving peer was closed as expected
	default:
		t.Fatal("reaped lingering room did not close its surviving peer")
	}
}

func TestReapClosesIdleRooms(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	_, _ = h.createRoom(off, "127.0.0.1")

	// Backdate the room past the idle timeout, then reap.
	h.mu.Lock()
	for _, r := range h.rooms {
		r.lastSeen = time.Now().Add(-2 * h.cfg.IdleTimeout)
	}
	h.mu.Unlock()

	h.reapOnce(time.Now())
	if h.roomCount() != 0 {
		t.Fatalf("room count after reap = %d, want 0", h.roomCount())
	}
	select {
	case <-off.done:
		// closed as expected
	default:
		t.Fatal("reaped peer was not closed")
	}
}

func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(2, 1) // burst 2, 1 token/sec
	t0 := time.Now()

	if !b.allowAt(t0) {
		t.Fatal("first call should be allowed by burst")
	}
	if !b.allowAt(t0) {
		t.Fatal("second call should be allowed by burst")
	}
	if b.allowAt(t0) {
		t.Fatal("third call in the same instant should be denied")
	}
	if !b.allowAt(t0.Add(time.Second)) {
		t.Fatal("one token should have refilled after a second")
	}
	if b.allowAt(t0.Add(time.Second)) {
		t.Fatal("only one token should refill per second")
	}
}

func TestTokenBucketWeightedBytes(t *testing.T) {
	b := newTokenBucket(10, 10)
	t0 := time.Now()
	if !b.allowNAt(7, t0) || b.allowNAt(4, t0) {
		t.Fatal("weighted burst accounting did not enforce the byte ceiling")
	}
	if !b.allowNAt(4, t0.Add(100*time.Millisecond)) {
		t.Fatal("weighted bucket did not refill one byte")
	}
}

func TestPeerRelayQueueIsByteBounded(t *testing.T) {
	h := testHub(t)
	h.cfg.RelayQueueBytes = 32
	p := newTestPeer()
	p.hub = h
	if !p.tryEnqueue(websocket.MessageBinary, make([]byte, 24)) {
		t.Fatal("first bounded relay frame was refused")
	}
	if p.tryEnqueue(websocket.MessageBinary, make([]byte, 9)) {
		t.Fatal("queue accepted bytes above its configured ceiling")
	}
	p.queueMu.Lock()
	queued := p.queuedBytes
	p.queueMu.Unlock()
	if queued != 24 {
		t.Fatalf("queued bytes = %d, want 24", queued)
	}
}

func TestPeerRelayQueueBackpressuresAtMessageCapacity(t *testing.T) {
	h := testHub(t)
	p := newTestPeer()
	p.hub = h
	for i := 0; i < cap(p.send); i++ {
		if !p.tryEnqueue(websocket.MessageBinary, []byte{byte(i)}) {
			t.Fatalf("frame %d was refused before the channel reached capacity", i)
		}
	}
	result := make(chan bool, 1)
	go func() { result <- p.tryEnqueue(websocket.MessageBinary, []byte("next")) }()
	select {
	case <-result:
		t.Fatal("enqueue did not apply backpressure to a momentarily full channel")
	case <-time.After(10 * time.Millisecond):
	}
	frame := <-p.send
	p.releaseQueued(int64(len(frame.data)))
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("enqueue was refused after the writer made room")
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue did not resume after the writer made room")
	}
}

func TestReapPrunesIdleIPTrackers(t *testing.T) {
	h := testHub(t)
	sweepAt := time.Now().Add(2 * h.cfg.IdleTimeout)

	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		ok, release, _ := h.acquireConnection(ip)
		if !ok {
			t.Fatalf("first connection from %s refused", ip)
		}
		release()
	}
	h.reapOnce(sweepAt)
	h.ipMu.Lock()
	n := len(h.ipTrackers)
	h.ipMu.Unlock()
	if n != 0 {
		t.Fatalf("idle trackers not pruned: %d remain", n)
	}

	// A tracker with an active connection survives
	ok, _, _ := h.acquireConnection("203.0.113.3")
	if !ok {
		t.Fatal("connection refused")
	}
	h.reapOnce(sweepAt)
	h.ipMu.Lock()
	_, found := h.ipTrackers["203.0.113.3"]
	h.ipMu.Unlock()
	if !found {
		t.Fatal("active tracker was pruned")
	}
}

func TestRateLimitingAndQuotas(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConnections = 3
	cfg.MaxConnsPerIP = 2
	cfg.MaxRooms = 2
	cfg.RoomCreateBurst = 2
	cfg.JoinFailBurst = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := NewHub(ctx, cfg, nil)

	// Test MaxConnsPerIP
	ok1, rel1, _ := h.acquireConnection("198.51.100.1")
	if !ok1 {
		t.Fatal("first conn failed")
	}
	ok2, rel2, _ := h.acquireConnection("198.51.100.1")
	if !ok2 {
		t.Fatal("second conn failed")
	}
	ok3, _, _ := h.acquireConnection("198.51.100.1")
	if ok3 {
		t.Fatal("third conn from same IP should be rejected by MaxConnsPerIP")
	}

	// Another IP can connect
	okOther, relOther, _ := h.acquireConnection("198.51.100.2")
	if !okOther {
		t.Fatal("conn from second IP failed")
	}

	// Global MaxConnections (now at 3: 2 + 1 = 3)
	okGlobalExceeded, _, _ := h.acquireConnection("198.51.100.3")
	if okGlobalExceeded {
		t.Fatal("conn should exceed global MaxConnections")
	}

	rel1()
	rel2()
	relOther()

	// Test MaxRooms
	p1, p2, p3 := newTestPeer(), newTestPeer(), newTestPeer()
	_, code1 := h.createRoom(p1, "198.51.100.1")
	if code1 != "" {
		t.Fatalf("first room failed: %s", code1)
	}
	_, code2 := h.createRoom(p2, "198.51.100.2")
	if code2 != "" {
		t.Fatalf("second room failed: %s", code2)
	}
	_, code3 := h.createRoom(p3, "198.51.100.3")
	if code3 != errRoomLimit {
		t.Fatalf("third room code = %q, want %q", code3, errRoomLimit)
	}

	// Test Anti-Brute-Force Failed Join Limiting
	joiner := newTestPeer()
	_, jcode1 := h.join(joiner, 9999, "198.51.100.99")
	if jcode1 != errUnknownRoom {
		t.Fatalf("expected unknown room, got %s", jcode1)
	}
	_, jcode2 := h.join(joiner, 9998, "198.51.100.99")
	if jcode2 != errUnknownRoom {
		t.Fatalf("expected unknown room, got %s", jcode2)
	}
	// Burst exhausted: further attempts rejected immediately with errRateLimited
	_, jcode3 := h.join(joiner, 9997, "198.51.100.99")
	if jcode3 != errRateLimited {
		t.Fatalf("expected rate limited on exhausted join fail tokens, got %s", jcode3)
	}
}

func TestRateLimitDisabledSwitch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimitEnabled = false
	cfg.MaxConnsPerIP = 1
	cfg.RoomCreateBurst = 1

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := NewHub(ctx, cfg, nil)

	// Able to exceed configured limits because rate limiting is disabled
	ok1, _, _ := h.acquireConnection("198.51.100.1")
	ok2, _, _ := h.acquireConnection("198.51.100.1")
	if !ok1 || !ok2 {
		t.Fatal("connections should succeed when rate limiting is disabled")
	}

	p1, p2 := newTestPeer(), newTestPeer()
	_, code1 := h.createRoom(p1, "198.51.100.1")
	_, code2 := h.createRoom(p2, "198.51.100.1")
	if code1 != "" || code2 != "" {
		t.Fatalf("room creations should succeed when rate limiting is disabled: %s, %s", code1, code2)
	}
}
