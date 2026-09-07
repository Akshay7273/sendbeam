package signal

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/sendbeam/wire"
)

// Hub owns every room and the goroutine that reaps idle ones. A room holds at most
// two peers — the offerer that created it and the joiner that paired in.
type Hub struct {
	cfg            Config
	logger         *slog.Logger
	trustedProxies []*net.IPNet

	mu                sync.Mutex
	rooms             map[int]*room
	handleRooms       map[string]*room
	draining          bool
	drainCh           chan struct{}
	activeConns       int
	connsTotal        int64
	roomsCreatedTotal int64
	roomsPairedTotal  int64
	roomsReapedTotal  int64
	relayBytes        int64
	errors            map[string]int64
	messages          map[string]int64

	ipMu       sync.Mutex
	ipTrackers map[string]*ipTracker
}

type room struct {
	number     int
	handle     string
	offerer    *peer
	joiner     *peer
	lastSeen   time.Time
	relayBytes int64
}

// NewHub builds a Hub and starts its reaper. The reaper stops when ctx is canceled.
func NewHub(ctx context.Context, cfg Config, logger *slog.Logger) *Hub {
	trusted, err := ParseTrustedProxies(stringsJoin(cfg.TrustedProxies, ","))
	if err != nil && logger != nil {
		logger.Warn("signal: failed to parse trusted proxies", "err", err)
	}

	h := &Hub{
		cfg:            cfg,
		logger:         orDiscard(logger),
		trustedProxies: trusted,
		rooms:          make(map[int]*room),
		handleRooms:    make(map[string]*room),
		drainCh:        make(chan struct{}),
		errors:         make(map[string]int64),
		messages:       make(map[string]int64),
		ipTrackers:     make(map[string]*ipTracker),
	}
	go h.reap(ctx)
	return h
}

func (h *Hub) getRoomLocked(p *peer) *room {
	if p.handle != "" {
		return h.handleRooms[p.handle]
	}
	if p.room >= 0 {
		return h.rooms[p.room]
	}
	return nil
}

func stringsJoin(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	res := ""
	for i, s := range elems {
		if i > 0 {
			res += sep
		}
		res += s
	}
	return res
}

// IsDraining reports whether the hub is currently draining active connections for shutdown.
func (h *Hub) IsDraining() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.draining
}

// Drain initiates graceful shutdown: it refuses new connections/rooms, reaps unpaired rooms
// immediately, and waits up to the provided context or cfg.DrainTimeout for active transfers to finish.
func (h *Hub) Drain(ctx context.Context) error {
	h.mu.Lock()
	if h.draining {
		h.mu.Unlock()
		return nil
	}
	h.draining = true
	close(h.drainCh)

	// Clean up unpaired rooms immediately.
	var unpairedPeers []*peer
	for n, r := range h.rooms {
		if r.offerer == nil || r.joiner == nil {
			if r.offerer != nil {
				unpairedPeers = append(unpairedPeers, r.offerer)
			}
			if r.joiner != nil {
				unpairedPeers = append(unpairedPeers, r.joiner)
			}
			delete(h.rooms, n)
		}
	}
	for handle, r := range h.handleRooms {
		if r.offerer == nil || r.joiner == nil {
			if r.offerer != nil {
				unpairedPeers = append(unpairedPeers, r.offerer)
			}
			if r.joiner != nil {
				unpairedPeers = append(unpairedPeers, r.joiner)
			}
			delete(h.handleRooms, handle)
		}
	}
	h.mu.Unlock()

	for _, p := range unpairedPeers {
		p.close(byeFrame("server shutting down"))
	}

	timeout := h.cfg.DrainTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	drainCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pollInterval := min(20*time.Millisecond, timeout/5)
	if pollInterval < 5*time.Millisecond {
		pollInterval = 5 * time.Millisecond
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		h.mu.Lock()
		count := len(h.rooms) + len(h.handleRooms)
		h.mu.Unlock()
		if count == 0 {
			return nil
		}

		select {
		case <-drainCtx.Done():
			// Timeout reached: force close remaining peers.
			h.mu.Lock()
			var remaining []*peer
			for n, r := range h.rooms {
				if r.offerer != nil {
					remaining = append(remaining, r.offerer)
				}
				if r.joiner != nil {
					remaining = append(remaining, r.joiner)
				}
				delete(h.rooms, n)
			}
			for handle, r := range h.handleRooms {
				if r.offerer != nil {
					remaining = append(remaining, r.offerer)
				}
				if r.joiner != nil {
					remaining = append(remaining, r.joiner)
				}
				delete(h.handleRooms, handle)
			}
			h.mu.Unlock()

			for _, p := range remaining {
				p.close(byeFrame("drain timeout expired"))
			}
			return drainCtx.Err()
		case <-ticker.C:
		}
	}
}

// getOrCreateIPTracker returns the tracker for ip, allocating it if needed.
func (h *Hub) getOrCreateIPTracker(ip string) *ipTracker {
	h.ipMu.Lock()
	defer h.ipMu.Unlock()
	t, ok := h.ipTrackers[ip]
	if !ok {
		t = newIPTracker(h.cfg)
		h.ipTrackers[ip] = t
	}
	return t
}

// acquireConnection checks global and per-IP connection limits and reserves one active connection slot.
func (h *Hub) acquireConnection(ip string) (allowed bool, release func(), errCode string) {
	h.mu.Lock()
	if h.draining {
		h.mu.Unlock()
		return false, nil, errDraining
	}
	if h.cfg.RateLimitEnabled && h.cfg.MaxConnections > 0 && h.activeConns >= h.cfg.MaxConnections {
		h.mu.Unlock()
		return false, nil, errRateLimited
	}
	h.activeConns++
	h.connsTotal++
	h.mu.Unlock()

	tracker := h.getOrCreateIPTracker(ip)
	ok, ipRelease := tracker.acquireConn(h.cfg.MaxConnsPerIP, h.cfg.RateLimitEnabled)
	if !ok {
		h.mu.Lock()
		h.activeConns--
		h.mu.Unlock()
		return false, nil, errRateLimited
	}

	var once sync.Once
	release = func() {
		once.Do(func() {
			ipRelease()
			h.mu.Lock()
			if h.activeConns > 0 {
				h.activeConns--
			}
			h.mu.Unlock()
		})
	}
	return true, release, ""
}

// createRoom allocates the smallest free room number, seats p as its offerer, and
// returns the room number.
func (h *Hub) createRoom(p *peer, ip string) (int, string) {
	tracker := h.getOrCreateIPTracker(ip)
	if !tracker.allowRoomCreate(h.cfg.RateLimitEnabled) {
		return -1, errRateLimited
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.draining {
		return -1, errDraining
	}
	if h.cfg.RateLimitEnabled && h.cfg.MaxRooms > 0 && (len(h.rooms)+len(h.handleRooms)) >= h.cfg.MaxRooms {
		return -1, errRoomLimit
	}

	n := 0
	for {
		if _, taken := h.rooms[n]; !taken {
			break
		}
		n++
	}
	h.rooms[n] = &room{number: n, offerer: p, lastSeen: time.Now()}
	p.room = n
	p.role = roleOfferer
	h.roomsCreatedTotal++
	return n, ""
}

// rendezvous seats p into an opaque handle room. If the handle room does not exist,
// it is created with p as the first peer (default roleOfferer unless roleJoiner is requested).
// If the handle room exists with one peer, p is seated as the complementary peer.
// If the room is full, it is refused with errRoomFull.
func (h *Hub) rendezvous(p *peer, handle string, role string, ip string) (*peer, string) {
	if !wire.ValidateRendezvousHandle(handle) {
		return nil, errInvalidHandle
	}

	tracker := h.getOrCreateIPTracker(ip)
	if !tracker.allowJoin(h.cfg.RateLimitEnabled) {
		return nil, errRateLimited
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.draining {
		return nil, errDraining
	}

	if r, ok := h.handleRooms[handle]; ok {
		if r.offerer != nil && r.joiner != nil {
			tracker.recordFailedJoin(h.cfg.RateLimitEnabled)
			return nil, errRoomFull
		}

		if r.offerer == nil {
			r.offerer = p
			p.role = roleOfferer
			p.handle = handle
			r.lastSeen = time.Now()
			h.roomsPairedTotal++
			return r.joiner, ""
		}

		r.joiner = p
		p.role = roleJoiner
		p.handle = handle
		r.lastSeen = time.Now()
		h.roomsPairedTotal++
		return r.offerer, ""
	}

	if !tracker.allowRoomCreate(h.cfg.RateLimitEnabled) {
		return nil, errRateLimited
	}

	if h.cfg.RateLimitEnabled && h.cfg.MaxRooms > 0 && (len(h.rooms)+len(h.handleRooms)) >= h.cfg.MaxRooms {
		return nil, errRoomLimit
	}

	r := &room{
		number:   -1,
		handle:   handle,
		lastSeen: time.Now(),
	}
	if role == roleJoiner {
		r.joiner = p
		p.role = roleJoiner
	} else {
		r.offerer = p
		p.role = roleOfferer
	}
	p.handle = handle
	h.handleRooms[handle] = r
	h.roomsCreatedTotal++
	return nil, ""
}

// join seats p as the joiner of an existing room and returns the offerer it paired
// with. It enforces strict 1:1 pairing: an unknown or already-full room is refused.
func (h *Hub) join(p *peer, number int, ip string) (*peer, string) {
	tracker := h.getOrCreateIPTracker(ip)
	if !tracker.allowJoin(h.cfg.RateLimitEnabled) {
		return nil, errRateLimited
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.draining {
		return nil, errDraining
	}

	r, ok := h.rooms[number]
	if !ok {
		tracker.recordFailedJoin(h.cfg.RateLimitEnabled)
		return nil, errUnknownRoom
	}
	if r.joiner != nil || r.offerer == nil {
		tracker.recordFailedJoin(h.cfg.RateLimitEnabled)
		return nil, errRoomFull
	}
	r.joiner = p
	r.lastSeen = time.Now()
	p.room = number
	p.role = roleJoiner
	h.roomsPairedTotal++
	return r.offerer, ""
}

// resume re-attaches p to a vacated slot of an existing (lingering) room after the peer
// reloaded and lost its ephemeral session. Only the slot for the claimed role may be
// filled, and only if empty; the room and its number are unchanged.
func (h *Hub) resume(p *peer, number int, role string, ip string) (*peer, string) {
	return h.resumeInternal(p, number, "", role, ip)
}

// resumeHandle re-attaches p to a vacated slot of an existing (lingering) handle room.
func (h *Hub) resumeHandle(p *peer, handle string, role string, ip string) (*peer, string) {
	return h.resumeInternal(p, -1, handle, role, ip)
}

func (h *Hub) resumeInternal(p *peer, number int, handle string, role string, ip string) (*peer, string) {
	if role != roleOfferer && role != roleJoiner {
		return nil, errBadMessage
	}
	tracker := h.getOrCreateIPTracker(ip)
	if !tracker.allowJoin(h.cfg.RateLimitEnabled) {
		return nil, errRateLimited
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.draining {
		return nil, errDraining
	}

	var r *room
	var ok bool
	if handle != "" {
		if !wire.ValidateRendezvousHandle(handle) {
			return nil, errInvalidHandle
		}
		r, ok = h.handleRooms[handle]
	} else {
		r, ok = h.rooms[number]
	}

	if !ok {
		tracker.recordFailedJoin(h.cfg.RateLimitEnabled)
		return nil, errUnknownRoom
	}
	switch role {
	case roleOfferer:
		if r.offerer != nil {
			tracker.recordFailedJoin(h.cfg.RateLimitEnabled)
			return nil, errRoomFull
		}
		r.offerer = p
	case roleJoiner:
		if r.joiner != nil {
			tracker.recordFailedJoin(h.cfg.RateLimitEnabled)
			return nil, errRoomFull
		}
		r.joiner = p
	}
	p.room = r.number
	p.handle = r.handle
	p.role = role
	r.lastSeen = time.Now()
	return roomPartner(r, p), ""
}

// openRelay opts p into the binary path and coordinates a room-wide cutover.
func (h *Hub) openRelay(p *peer) (other *peer, ready bool, code string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.getRoomLocked(p)
	if r == nil {
		return nil, false, errNotPaired
	}
	other = roomPartner(r, p)
	if other == nil {
		return nil, false, errNotPaired
	}
	p.relayOpen = true
	r.lastSeen = time.Now()
	return other, other.relayOpen, ""
}

// grantRelayCredit caps a receiver's grant to one configured window and returns the actual grant.
func (h *Hub) grantRelayCredit(receiver *peer, requested int64) (*peer, int64, string) {
	if requested <= 0 {
		return nil, 0, errRelayCredit
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.getRoomLocked(receiver)
	if r == nil {
		return nil, 0, errNotPaired
	}
	sender := roomPartner(r, receiver)
	if sender == nil || !receiver.relayOpen || !sender.relayOpen {
		return nil, 0, errRelayNotReady
	}
	grant := min(requested, h.cfg.RelayWindowBytes, h.cfg.RelayWindowBytes-sender.relayCredit)
	if grant <= 0 {
		return sender, 0, ""
	}
	sender.relayCredit += grant
	r.lastSeen = time.Now()
	return sender, grant, ""
}

// forwardRelay reserves sender credit and room byte budget before handing one opaque frame to the partner.
func (h *Hub) forwardRelay(sender *peer, data []byte) string {
	size := int64(len(data))
	if size <= 0 || size > h.cfg.MaxRelayFrameBytes {
		return errRelayLimit
	}
	if !sender.relayRate.allowN(float64(size)) {
		return errRelayLimit
	}

	h.mu.Lock()
	r := h.getRoomLocked(sender)
	if r == nil {
		h.mu.Unlock()
		return errNotPaired
	}
	other := roomPartner(r, sender)
	if other == nil || !sender.relayOpen || !other.relayOpen {
		h.mu.Unlock()
		return errRelayNotReady
	}
	if sender.relayCredit < size {
		h.mu.Unlock()
		return errRelayCredit
	}
	if size > h.cfg.RelayMaxSessionBytes-r.relayBytes {
		h.mu.Unlock()
		return errRelayLimit
	}
	h.mu.Unlock()

	if !other.tryEnqueue(websocket.MessageBinary, append([]byte(nil), data...)) {
		other.fail(errRelayLimit, "receiver relay queue full")
		return errRelayLimit
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	r = h.getRoomLocked(sender)
	if r == nil || roomPartner(r, sender) != other {
		return ""
	}
	sender.relayCredit -= size
	r.relayBytes += size
	h.relayBytes += size
	r.lastSeen = time.Now()
	return ""
}

func roomPartner(r *room, p *peer) *peer {
	if p == r.offerer {
		return r.joiner
	}
	if p == r.joiner {
		return r.offerer
	}
	return nil
}

// partner returns the other peer in p's room, or nil if the room is gone or p is not yet paired.
func (h *Hub) partner(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.getRoomLocked(p)
	if r == nil {
		return nil
	}
	r.lastSeen = time.Now()
	switch p {
	case r.offerer:
		return r.joiner
	case r.joiner:
		return r.offerer
	default:
		return nil
	}
}

// vacate frees p's slot after an unexpected socket drop.
func (h *Hub) vacate(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.getRoomLocked(p)
	if r == nil {
		return nil
	}
	var other *peer
	switch p {
	case r.offerer:
		other = r.joiner
		r.offerer = nil
	case r.joiner:
		other = r.offerer
		r.joiner = nil
	default:
		return nil
	}
	if other == nil {
		if r.handle != "" {
			delete(h.handleRooms, r.handle)
		} else {
			delete(h.rooms, r.number)
		}
		return nil
	}
	r.lastSeen = time.Now()
	return other
}

// discard tears down p's whole room after a graceful bye.
func (h *Hub) discard(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.getRoomLocked(p)
	if r == nil {
		return nil
	}
	other := roomPartner(r, p)
	if r.handle != "" {
		delete(h.handleRooms, r.handle)
	} else {
		delete(h.rooms, r.number)
	}
	return other
}

// reap periodically frees rooms whose last activity is older than the idle timeout.
func (h *Hub) reap(ctx context.Context) {
	interval := h.cfg.IdleTimeout / 2
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.reapOnce(now)
		}
	}
}

func (h *Hub) reapOnce(now time.Time) {
	h.mu.Lock()
	var stale []*room
	for n, r := range h.rooms {
		if now.Sub(r.lastSeen) > h.cfg.IdleTimeout {
			stale = append(stale, r)
			delete(h.rooms, n)
		}
	}
	for handle, r := range h.handleRooms {
		timeout := h.cfg.IdleTimeout
		if (r.offerer == nil || r.joiner == nil) && h.cfg.UnpairedTimeout > 0 {
			timeout = h.cfg.UnpairedTimeout
		}
		if now.Sub(r.lastSeen) > timeout {
			stale = append(stale, r)
			delete(h.handleRooms, handle)
		}
	}
	h.roomsReapedTotal += int64(len(stale))
	h.mu.Unlock()

	// Prune per-IP trackers that have no active connections, fully refilled, and idle.
	h.ipMu.Lock()
	for ip, t := range h.ipTrackers {
		if t.refilledAndIdle(now, h.cfg.IdleTimeout) {
			delete(h.ipTrackers, ip)
		}
	}
	h.ipMu.Unlock()

	for _, r := range stale {
		if r.handle != "" {
			h.logger.Info("signal: reaping idle handle room", "handle", r.handle)
		} else {
			h.logger.Info("signal: reaping idle room", "room", r.number)
		}
		for _, p := range []*peer{r.offerer, r.joiner} {
			if p != nil {
				p.close(byeFrame("idle timeout"))
			}
		}
	}
}

// roomCount reports the number of live rooms (used by tests).
func (h *Hub) roomCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.rooms) + len(h.handleRooms)
}
