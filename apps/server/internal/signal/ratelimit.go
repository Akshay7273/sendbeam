package signal

import (
	"sync"
	"time"
)

// tokenBucket is a minimal token-bucket rate limiter. It refills continuously at a
// fixed rate up to a burst capacity; allow reports whether one token is available
// and, if so, spends it. It is safe for concurrent use.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	rate   float64 // tokens per second
	last   time.Time
}

func newTokenBucket(burst int, perSec float64) *tokenBucket {
	return &tokenBucket{
		tokens: float64(burst),
		burst:  float64(burst),
		rate:   perSec,
		last:   time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	return b.allowNAt(1, time.Now())
}

func (b *tokenBucket) allowN(tokens float64) bool { return b.allowNAt(tokens, time.Now()) }

// allowAt is the time-injectable core, kept separate so tests can drive it
// deterministically.
func (b *tokenBucket) allowAt(now time.Time) bool {
	return b.allowNAt(1, now)
}

func (b *tokenBucket) hasToken() bool {
	return b.hasTokenAt(time.Now())
}

func (b *tokenBucket) hasTokenAt(now time.Time) bool {
	if b == nil || b.burst <= 0 || b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
		b.last = now
	}
	return b.tokens >= 1.0
}

func (b *tokenBucket) allowNAt(tokens float64, now time.Time) bool {
	if b == nil || b.burst <= 0 || b.rate <= 0 {
		return true // unlimited
	}
	if tokens <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
		b.last = now
	}
	if b.tokens < tokens {
		return false
	}
	b.tokens -= tokens
	return true
}

// refilledAndIdle reports whether the bucket has fully refilled and seen no use for at
// least idle. It refills before checking and refreshes last, so it is safe to call from a
// periodic sweeper that keeps non-idle buckets alive.
func (b *tokenBucket) refilledAndIdle(now time.Time, idle time.Duration) bool {
	if b == nil || b.burst <= 0 || b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed.Seconds()*b.rate)
		b.last = now
	}
	return b.tokens >= b.burst && elapsed >= idle
}

// ipTracker tracks active connections and multi-dimensional rate limiters for a single client IP.
type ipTracker struct {
	mu           sync.Mutex
	activeConns  int
	connLimiter  *tokenBucket
	roomLimiter  *tokenBucket
	joinLimiter  *tokenBucket
	lastActivity time.Time
}

func newIPTracker(cfg Config) *ipTracker {
	return &ipTracker{
		connLimiter:  newTokenBucket(cfg.ConnBurst, cfg.ConnPerSec),
		roomLimiter:  newTokenBucket(cfg.RoomCreateBurst, cfg.RoomCreatePerSec),
		joinLimiter:  newTokenBucket(cfg.JoinFailBurst, cfg.JoinFailPerSec),
		lastActivity: time.Now(),
	}
}

func (t *ipTracker) acquireConn(maxPerIP int, rateLimitEnabled bool) (allowed bool, release func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastActivity = time.Now()

	if rateLimitEnabled {
		if maxPerIP > 0 && t.activeConns >= maxPerIP {
			return false, nil
		}
		if !t.connLimiter.allow() {
			return false, nil
		}
	}

	t.activeConns++
	var once sync.Once
	release = func() {
		once.Do(func() {
			t.mu.Lock()
			if t.activeConns > 0 {
				t.activeConns--
			}
			t.lastActivity = time.Now()
			t.mu.Unlock()
		})
	}
	return true, release
}

func (t *ipTracker) allowRoomCreate(rateLimitEnabled bool) bool {
	if !rateLimitEnabled {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastActivity = time.Now()
	return t.roomLimiter.allow()
}

func (t *ipTracker) allowJoin(rateLimitEnabled bool) bool {
	if !rateLimitEnabled {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastActivity = time.Now()
	return t.joinLimiter.hasToken()
}

func (t *ipTracker) recordFailedJoin(rateLimitEnabled bool) {
	if !rateLimitEnabled {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastActivity = time.Now()
	_ = t.joinLimiter.allow() // spend 1 failure token
}

func (t *ipTracker) refilledAndIdle(now time.Time, idle time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.activeConns > 0 {
		return false
	}
	if now.Sub(t.lastActivity) < idle {
		return false
	}
	return t.connLimiter.refilledAndIdle(now, idle) &&
		t.roomLimiter.refilledAndIdle(now, idle) &&
		t.joinLimiter.refilledAndIdle(now, idle)
}
