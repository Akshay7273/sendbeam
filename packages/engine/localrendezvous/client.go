package localrendezvous

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrRefused is returned by Dial when the server denies admission.
var ErrRefused = errors.New("localrendezvous: admission refused")

// DialConfig configures Dial.
type DialConfig struct {
	// DeviceID is the dialer's own device ID, sent in the hello frame.
	DeviceID string
	// PairToken, when non-empty, is presented for pairing-window admission.
	// Paired dialers leave it empty and are admitted via the trust store.
	PairToken string
	// Timeout bounds the whole dial plus admission handshake. Zero selects
	// the 10s default.
	Timeout time.Duration
	// DialContext performs the TCP dial. When nil, a default dialer is used.
	// Tests use this hook to enforce and monitor the egress policy: every
	// outbound connection the local path makes flows through it.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// MaxFrameBytes caps one length-prefixed frame on the resulting session.
	// Zero selects the 1 MiB default.
	MaxFrameBytes int
	// ReadTimeout bounds one frame read on the session. Zero selects 30s.
	ReadTimeout time.Duration
	// WriteTimeout bounds one frame write on the session. Zero selects 10s.
	WriteTimeout time.Duration
}

// Dial connects to a local rendezvous server at addr ("ip:port"), performs the
// admission handshake, and returns the admitted session. The caller must close
// the session.
//
// The address must be a literal IP: dialers pass the pinned IPs returned by
// discovery's validated route candidates. Hostnames are refused: resolving a
// hostname at dial time would re-open DNS-rebinding, so callers resolve once,
// policy-check every result, and pin an approved IP (see discovery).
func Dial(ctx context.Context, addr string, cfg DialConfig) (*Session, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("localrendezvous: invalid dial address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("localrendezvous: dial requires a literal IP, got %q (resolve and policy-check hostnames via discovery)", host)
	}
	if ip.IsUnspecified() {
		return nil, fmt.Errorf("localrendezvous: refusing to dial unspecified address %q", host)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultHelloTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialFn := cfg.DialContext
	if dialFn == nil {
		dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	conn, err := dialFn(dialCtx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, fmt.Errorf("localrendezvous: dial %s: %w", addr, err)
	}
	fail := func(format string, args ...interface{}) (*Session, error) {
		_ = conn.Close()
		return nil, fmt.Errorf(format, args...)
	}

	raw, err := json.Marshal(hello{DeviceID: cfg.DeviceID, PairToken: cfg.PairToken})
	if err != nil {
		return fail("localrendezvous: encode hello: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := writeFrame(conn, raw); err != nil {
		return fail("localrendezvous: send hello: %v", err)
	}

	// The first server frame is either the accept frame or the fixed
	// refusal. Anything else is a protocol error: fail closed.
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	resp, err := readFrame(conn, maxHelloBytes)
	if err != nil {
		return fail("localrendezvous: read admission reply: %v", err)
	}
	if string(resp) == refusalFrame {
		_ = conn.Close()
		return nil, ErrRefused
	}
	var acc acceptFrame
	if err := json.Unmarshal(resp, &acc); err != nil || !acc.OK {
		return fail("localrendezvous: malformed admission reply")
	}

	maxFrame := cfg.MaxFrameBytes
	if maxFrame <= 0 {
		maxFrame = defaultMaxFrameBytes
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}
	kind := PeerPaired
	if cfg.PairToken != "" {
		kind = PeerPairing
	}
	return &Session{
		cfg: Config{
			MaxFrameBytes: maxFrame,
			ReadTimeout:   readTimeout,
			WriteTimeout:  writeTimeout,
		},
		conn:     conn,
		DeviceID: acc.ServerDeviceID,
		Kind:     kind,
		done:     make(chan struct{}),
	}, nil
}
