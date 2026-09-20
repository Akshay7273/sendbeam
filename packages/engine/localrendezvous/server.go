// Package localrendezvous implements the bounded native local rendezvous
// service for SendBeam v2.1 "Nearby & Offline" (ADR 0011).
//
// It gives native clients a bootstrap/signaling endpoint that does not
// require the public rendezvous server: a TCP listener on explicitly
// selected local interfaces routes length-prefixed protocol envelopes
// between two local peers. The service is deliberately dumb about
// cryptography: admission gates who may connect (paired device, or an
// unpaired device presenting the current pairing-window token), while all
// authentication runs in the existing reviewed ceremonies
// (trust.PairingCoordinator, ADR 0010 trusted session auth) over the
// Session's framed transport.
//
// Security properties enforced here:
//   - explicit interface binding (wildcard binds refused by default)
//   - bounded connections, message sizes, per-IP rate limits, deadlines
//   - unpaired sessions admitted only through a user-opened short-lived
//     pairing window
//   - refusal frames are fixed strings; they never leak tokens or roster
//     information (no paired/unpaired oracle)
//   - clean shutdown removes the listener and closes pending sessions
package localrendezvous

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/trust"
)

const (
	defaultMaxConnections   = 16
	defaultMaxFrameBytes    = 1 << 20 // 1 MiB: signaling envelopes are tiny; SDP is the largest
	defaultMaxConnPerMinIP  = 30
	defaultHandshakeTimeout = 60 * time.Second
	defaultReadTimeout      = 30 * time.Second
	defaultWriteTimeout     = 10 * time.Second
	defaultHelloTimeout     = 10 * time.Second
	defaultPairingWindow    = 5 * time.Minute
	maxHelloBytes           = 4096

	// refusalFrame is the only wire-visible refusal. It is a fixed string so
	// a prober cannot distinguish "unknown device" from "window closed" and
	// can never extract token material.
	refusalFrame = `{"error":"refused"}`
)

// PeerKind distinguishes how a session was admitted.
type PeerKind int

const (
	// PeerPaired is a device present in the trust store and not revoked.
	PeerPaired PeerKind = iota
	// PeerPairing is an unpaired device admitted via an open pairing window.
	PeerPairing
)

func (k PeerKind) String() string {
	if k == PeerPairing {
		return "pairing"
	}
	return "paired"
}

// Config tunes the local rendezvous service.
type Config struct {
	// BindAddr is the explicit "ip:port" to listen on. Empty defaults to
	// "127.0.0.1:0". Wildcard addresses are refused unless AllowWildcard.
	BindAddr string
	// AllowWildcard permits binding 0.0.0.0/::. Default false.
	AllowWildcard bool
	// MaxConnections caps concurrent sessions. Default 16.
	MaxConnections int
	// MaxFrameBytes caps one length-prefixed frame. Default 1 MiB.
	MaxFrameBytes int
	// MaxConnPerMinPerIP caps new connections per source IP per window. Default 30.
	MaxConnPerMinPerIP int
	// RateLimitWindow is the window for MaxConnPerMinPerIP. Default 1 minute.
	RateLimitWindow time.Duration
	// HandshakeTimeout bounds admission (hello read + decision). Default 60s.
	HandshakeTimeout time.Duration
	// ReadTimeout bounds one frame read. Default 30s.
	ReadTimeout time.Duration
	// WriteTimeout bounds one frame write. Default 10s.
	WriteTimeout time.Duration
	// PairingWindow is the default lifetime of OpenPairingWindow(0). Default 5m.
	PairingWindow time.Duration
}

// hello is the first frame a connector must send.
type hello struct {
	DeviceID  string `json:"device_id"`
	PairToken string `json:"pair_token,omitempty"`
}

// Server is the bounded local rendezvous service.
type Server struct {
	cfg   Config
	store trust.Store

	mu       sync.RWMutex
	listener net.Listener
	addr     net.Addr
	sessions map[*Session]struct{}
	handler  func(*Session)
	started  bool
	closed   bool
	acceptWg sync.WaitGroup

	// pairing window state
	winMu     sync.Mutex
	winToken  string
	winExpiry time.Time

	// admission bounds
	sem    chan struct{}
	ipMu   sync.Mutex
	ipHits map[string]*ipBucket
}

type ipBucket struct {
	count int
	start time.Time
}

// NewServer creates the service. It does not listen until Start.
func NewServer(cfg Config, store trust.Store) *Server {
	if cfg.BindAddr == "" {
		cfg.BindAddr = "127.0.0.1:0"
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConnections
	}
	if cfg.MaxFrameBytes <= 0 {
		cfg.MaxFrameBytes = defaultMaxFrameBytes
	}
	if cfg.MaxConnPerMinPerIP <= 0 {
		cfg.MaxConnPerMinPerIP = defaultMaxConnPerMinIP
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = defaultReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
	if cfg.PairingWindow <= 0 {
		cfg.PairingWindow = defaultPairingWindow
	}
	if cfg.RateLimitWindow <= 0 {
		cfg.RateLimitWindow = time.Minute
	}
	return &Server{
		cfg:      cfg,
		store:    store,
		sessions: make(map[*Session]struct{}),
		sem:      make(chan struct{}, cfg.MaxConnections),
		ipHits:   make(map[string]*ipBucket),
	}
}

// OnSession registers the host callback invoked for each admitted session.
// The callback runs on its own goroutine and owns the session lifetime.
func (s *Server) OnSession(h func(*Session)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

// Addr returns the bound address after Start.
func (s *Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

// Start binds the listener and begins accepting. It refuses wildcard binds
// unless AllowWildcard, and fails cleanly on port conflicts.
func (s *Server) Start(ctx context.Context) (net.Addr, error) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil, errors.New("localrendezvous: already started")
	}
	host, port, err := net.SplitHostPort(s.cfg.BindAddr)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("localrendezvous: invalid bind address: %w", err)
	}
	if !s.cfg.AllowWildcard {
		ip := net.ParseIP(host)
		if ip != nil && ip.IsUnspecified() {
			s.mu.Unlock()
			return nil, errors.New("localrendezvous: wildcard bind refused; set an explicit interface address or AllowWildcard")
		}
	}
	ln, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("localrendezvous: listen: %w", err)
	}
	s.listener = ln
	s.addr = ln.Addr()
	s.started = true
	s.closed = false
	_ = port
	s.mu.Unlock()

	s.acceptWg.Add(1)
	go s.acceptLoop(ctx)
	return s.addr, nil
}

// OpenPairingWindow opens a short-lived window admitting unpaired devices.
// It returns the token to share out-of-band (QR/code). A zero duration
// uses Config.PairingWindow. Only one window is open at a time.
func (s *Server) OpenPairingWindow(d time.Duration) string {
	if d <= 0 {
		d = s.cfg.PairingWindow
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	token := hex.EncodeToString(raw[:])
	s.winMu.Lock()
	s.winToken = token
	s.winExpiry = time.Now().Add(d)
	s.winMu.Unlock()
	return token
}

// ClosePairingWindow closes the pairing window immediately.
func (s *Server) ClosePairingWindow() {
	s.winMu.Lock()
	s.winToken = ""
	s.winExpiry = time.Time{}
	s.winMu.Unlock()
}

// pairingTokenValid reports whether the window is open and the token matches,
// in constant time.
func (s *Server) pairingTokenValid(token string) bool {
	s.winMu.Lock()
	defer s.winMu.Unlock()
	if s.winToken == "" || time.Now().After(s.winExpiry) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.winToken)) == 1
}

// Close shuts the service down: the listener is removed and every pending
// session is closed. It is idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	if !s.started || s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.listener
	sessions := make([]*Session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, sess := range sessions {
		_ = sess.Close()
	}
	s.acceptWg.Wait()

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
	return nil
}

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.acceptWg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed
		}
		select {
		case s.sem <- struct{}{}:
		default:
			// At capacity: refuse promptly without reading.
			_ = conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer func() { <-s.sem }()
			s.handleConn(ctx, c)
		}(conn)
	}
}

// rateLimited reports whether the source IP exceeded its budget.
func (s *Server) rateLimited(ip string) bool {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	now := time.Now()
	window := s.cfg.RateLimitWindow
	// Reap expired buckets so the map stays bounded.
	for k, b := range s.ipHits {
		if now.Sub(b.start) > window {
			delete(s.ipHits, k)
		}
	}
	b, ok := s.ipHits[ip]
	if !ok || now.Sub(b.start) > window {
		s.ipHits[ip] = &ipBucket{count: 1, start: now}
		return false
	}
	b.count++
	return b.count > s.cfg.MaxConnPerMinPerIP
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	hsCtx, cancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	defer cancel()

	_ = conn.SetReadDeadline(time.Now().Add(defaultHelloTimeout))
	raw, err := readFrame(conn, maxHelloBytes)
	if err != nil {
		_ = conn.Close()
		return
	}
	var h hello
	if err := json.Unmarshal(raw, &h); err != nil || h.DeviceID == "" {
		writeRefusal(conn, s.cfg.WriteTimeout)
		_ = conn.Close()
		return
	}

	// Rate-limit completed hellos per source IP, not bare TCP accepts: an
	// attacker opening idle connections must not crowd out a legitimate
	// peer's hello. Idle connections are bounded by the connection
	// semaphore and the hello read deadline instead.
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if s.rateLimited(remoteIP) {
		writeRefusal(conn, s.cfg.WriteTimeout)
		_ = conn.Close()
		return
	}

	kind, ok := s.admit(hsCtx, h)
	if !ok {
		writeRefusal(conn, s.cfg.WriteTimeout)
		_ = conn.Close()
		return
	}

	sess := &Session{
		server:   s,
		conn:     conn,
		DeviceID: h.DeviceID,
		Kind:     kind,
		done:     make(chan struct{}),
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.sessions[sess] = struct{}{}
	handler := s.handler
	s.mu.Unlock()

	if handler != nil {
		go handler(sess)
	} else {
		// No host handler: hold the session until it closes.
		go func() {
			<-sess.done
		}()
	}
}

// admit decides whether the hello may connect. Paired, non-revoked devices
// are admitted directly; anyone else needs an open pairing window and the
// current token. The decision never leaks which case failed.
func (s *Server) admit(ctx context.Context, h hello) (PeerKind, bool) {
	if s.store != nil && h.DeviceID != "" {
		rec, err := s.store.GetDevice(ctx, h.DeviceID)
		if err == nil && rec != nil && !rec.Revoked {
			return PeerPaired, true
		}
	}
	if h.PairToken != "" && s.pairingTokenValid(h.PairToken) {
		return PeerPairing, true
	}
	return PeerPaired, false
}

func (s *Server) removeSession(sess *Session) {
	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
}

// Session is one admitted local rendezvous connection. Frames are
// length-prefixed envelopes; the session layer above decides their meaning.
type Session struct {
	server   *Server
	conn     net.Conn
	DeviceID string
	Kind     PeerKind

	closeOnce sync.Once
	done      chan struct{}
}

// RemoteAddr returns the peer's network address.
func (sess *Session) RemoteAddr() net.Addr { return sess.conn.RemoteAddr() }

// ReadFrame reads one length-prefixed frame, bounded by MaxFrameBytes.
func (sess *Session) ReadFrame(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = sess.conn.SetReadDeadline(time.Now().Add(sess.server.cfg.ReadTimeout))
	return readFrame(sess.conn, sess.server.cfg.MaxFrameBytes)
}

// WriteFrame writes one length-prefixed frame.
func (sess *Session) WriteFrame(ctx context.Context, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(payload) > sess.server.cfg.MaxFrameBytes {
		return fmt.Errorf("localrendezvous: frame too large: %d", len(payload))
	}
	_ = sess.conn.SetWriteDeadline(time.Now().Add(sess.server.cfg.WriteTimeout))
	return writeFrame(sess.conn, payload)
}

// Close terminates the session and unregisters it from the server.
func (sess *Session) Close() error {
	sess.closeOnce.Do(func() { close(sess.done) })
	sess.server.removeSession(sess)
	return sess.conn.Close()
}

// PairingTransport adapts the session to trust.PairingTransport so the
// reviewed pairing ceremony can run over the local rendezvous connection.
func (sess *Session) PairingTransport() trust.PairingTransport {
	return &sessionPairingTransport{sess: sess}
}

type sessionPairingTransport struct {
	sess *Session
}

// SendMessage implements trust.PairingTransport.
func (t *sessionPairingTransport) SendMessage(ctx context.Context, data []byte) error {
	return t.sess.WriteFrame(ctx, data)
}

// ReceiveMessage implements trust.PairingTransport.
func (t *sessionPairingTransport) ReceiveMessage(ctx context.Context) ([]byte, error) {
	return t.sess.ReadFrame(ctx)
}

// Sink adapts the session to rendezvous.Sink: outbound signaling envelopes
// are JSON-marshaled and framed.
func (sess *Session) Sink() rendezvous.Sink {
	return &sessionSink{sess: sess}
}

type sessionSink struct {
	sess *Session
}

// Send implements rendezvous.Sink.
func (sn *sessionSink) Send(m rendezvous.Message) error {
	data, err := rendezvous.MarshalMessage(m)
	if err != nil {
		return err
	}
	return sn.sess.WriteFrame(context.Background(), data)
}

// readFrame reads a 4-byte big-endian length prefix followed by the payload,
// enforcing maxBytes on the declared length before allocating.
func readFrame(conn net.Conn, maxBytes int) ([]byte, error) {
	var hdr [4]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > uint32(maxBytes) {
		return nil, fmt.Errorf("localrendezvous: frame length %d exceeds %d", n, maxBytes)
	}
	if n == 0 {
		return nil, errors.New("localrendezvous: empty frame")
	}
	buf := make([]byte, n)
	if _, err := readFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(conn net.Conn, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func readFull(conn net.Conn, buf []byte) (int, error) {
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

// writeRefusal sends the fixed refusal frame on a best-effort basis.
func writeRefusal(conn net.Conn, timeout time.Duration) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_ = writeFrame(conn, []byte(refusalFrame))
}
