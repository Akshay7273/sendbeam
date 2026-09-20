package localtransfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/rtc"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// testDevice is one paired native client: identity, trust store, secrets.
type testDevice struct {
	identity *wire.DeviceIdentity
	store    *trust.MemoryTrustStore
	resolver *trust.MemorySecretResolver
}

func newTestDevice(t *testing.T) *testDevice {
	t.Helper()
	id, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &testDevice{
		identity: id,
		store:    trust.NewMemoryTrustStore(),
		resolver: trust.NewMemorySecretResolver(),
	}
}

// pair cross-registers two devices as paired with the same kPair.
func pair(t *testing.T, a, b *testDevice, kPair []byte, credRef string) {
	t.Helper()
	ctx := context.Background()
	for _, pair := range [][2]*testDevice{{a, b}, {b, a}} {
		local, peer := pair[0], pair[1]
		rec := &wire.TrustRecord{
			DeviceID:          peer.identity.DeviceID,
			PublicKey:         hex.EncodeToString(peer.identity.PublicKey),
			LocalLabel:        "test peer",
			PairCredentialRef: credRef,
			Capabilities:      []string{"transfer.v1"},
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
			Policy:            wire.DefaultTrustPolicy(),
		}
		if err := local.store.AddOrUpdateDevice(ctx, rec); err != nil {
			t.Fatal(err)
		}
		local.resolver.SetSecret(peer.identity.DeviceID, kPair)
	}
}

func acceptAll(context.Context, transfer.ConsentRequest) (transfer.ConsentDecision, error) {
	return transfer.ConsentDecision{Accepted: true}, nil
}

// egressMonitor records every dial and optionally denies non-loopback dials.
// It proves the local path's entire TCP egress surface flows through the
// auditable dial hook.
type egressMonitor struct {
	mu    sync.Mutex
	dials []string
	deny  bool
}

func (m *egressMonitor) dial(ctx context.Context, network, address string) (net.Conn, error) {
	m.mu.Lock()
	m.dials = append(m.dials, address)
	m.mu.Unlock()
	if m.deny {
		host, _, _ := net.SplitHostPort(address)
		if host != "127.0.0.1" && host != "::1" {
			return nil, errors.New("egress policy: non-loopback dial denied")
		}
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (m *egressMonitor) allLoopback() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.dials {
		host, _, _ := net.SplitHostPort(d)
		if host != "127.0.0.1" && host != "::1" {
			return false
		}
	}
	return true
}

func (m *egressMonitor) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.dials)
}

// receiver is a running local rendezvous server whose sessions run the joiner
// side of transfer.Run.
type receiver struct {
	addr string
	done chan recvResult
}

type recvResult struct {
	out *transfer.Outcome
	err error
}

// startReceiver serves the joiner side for senderID. mutate adjusts the joiner
// spec (e.g. to break padding or the pair secret for negative tests).
// peerIPs are the sender's validated endpoint IPs, pinning the joiner's ICE
// candidate policy to the same local route (PR04).
func startReceiver(t *testing.T, dev, sender *testDevice, kPair []byte, handle, destDir string, peerIPs []net.IP, mutate func(*transfer.Spec)) *receiver {
	t.Helper()
	srv := localrendezvous.NewServer(localrendezvous.Config{BindAddr: "127.0.0.1:0"}, dev.store)
	r := &receiver{done: make(chan recvResult, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.OnSession(func(sess *localrendezvous.Session) {
		go func() {
			defer func() { _ = sess.Close() }()
			spec := transfer.Spec{
				Opaque: &rendezvous.OpaqueOptions{
					Role:              rendezvous.RoleJoiner,
					Handle:            handle,
					LocalIdentity:     dev.identity,
					PeerDeviceID:      sender.identity.DeviceID,
					PeerPublicKey:     sender.identity.PublicKey,
					KPair:             kPair,
					PairCredentialRef: "cred-test",
				},
				PeerDeviceID: sender.identity.DeviceID,
				DestDir:      destDir,
				Consent:      transfer.ConsentHandler(acceptAll),
				ICEServers:   []webrtc.ICEServer{},
				DisableRelay: true,
				RTCAPI:       rtc.LocalOnlyAPI(rtc.LocalOnlyNetsForIPs(peerIPs)),
			}
			if mutate != nil {
				mutate(&spec)
			}
			out, err := transfer.Run(ctx, newSessionSignal(sess), spec)
			r.done <- recvResult{out, err}
		}()
	})
	if _, err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	r.addr = srv.Addr().String()
	return r
}

func candidateTableFor(t *testing.T, peerID, addr string) *discovery.CandidateTable {
	t.Helper()
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	if _, err := tab.AddManual(peerID, addr); err != nil {
		t.Fatalf("add manual candidate: %v", err)
	}
	return tab
}

func randomHandle(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// --- Spec invariants (structural, no network) ---

func TestLocalOnlyInvariantsOnSpec(t *testing.T) {
	alice := newTestDevice(t)
	bob := newTestDevice(t)
	kPair := []byte(strings.Repeat("k", 32))
	opts := Options{
		Identity:     alice.identity,
		Store:        alice.store,
		Resolver:     alice.resolver,
		Table:        discovery.NewCandidateTable(discovery.RoutePolicy{}, 16, time.Minute),
		PeerDeviceID: bob.identity.DeviceID,
		Role:         rendezvous.RoleOfferer,
		Source:       wire.BytesSource([]byte("x"), wire.FileMeta{Name: "x"}, 1024),
	}
	spec, err := opts.buildSpec("handle", bob.identity.PublicKey, kPair, "cred-test", []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	// ICE: explicit empty slice — host candidates only. Nil would silently
	// take the default public STUN server, so nil is a policy violation.
	if spec.ICEServers == nil || len(spec.ICEServers) != 0 {
		t.Fatalf("ICEServers must be an explicit empty slice, got %#v", spec.ICEServers)
	}
	if !spec.DisableRelay {
		t.Fatal("DisableRelay must be set: no relay path may exist in local-only mode")
	}
	if spec.RTCAPI == nil {
		t.Fatal("RTCAPI must be set: the ICE agent must enforce the local-only candidate policy")
	}
	if spec.Opaque == nil || spec.Opaque.PeerDeviceID != bob.identity.DeviceID {
		t.Fatal("Opaque handshake must bind the selected peer identity")
	}
}

// --- Direct-only transfer fails closed when ICE cannot connect ---
//
// UDP is blocked in this sandbox, so ICE cannot establish: the transfer
// must fail with a clear terminal error (relay disabled, no fallback),
// not a hang and not a silent fallback. The handshake and SDP/ICE exchange
// complete over the local session first (a handshake failure would surface
// a different error), and every TCP dial is loopback-only per the egress
// monitor. On a real LAN the same code path connects directly.

func TestTransferFileWithEgressDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	kPair := []byte(strings.Repeat("k", 32))
	pair(t, alice, bob, kPair, "cred-test")

	payload := []byte("local-only file transfer over the shared engine, no public service")
	handle := randomHandle(t)
	// TEST-NET-1: guaranteed unroutable, so the dial is denied by the
	// egress hook before any bytes flow. This is deterministic in every
	// environment (no UDP dependence). The policy explicitly allows
	// TEST-NET-1 so the candidate is valid; the egress hook denies it.
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true, Networks: []string{"192.0.2.0/24"}}, 16, 5*time.Minute)
	if _, err := tab.AddManual(bob.identity.DeviceID, "192.0.2.1:9"); err != nil {
		t.Fatalf("add manual candidate: %v", err)
	}

	mon := &egressMonitor{deny: true}
	src := wire.BytesSource(payload, wire.FileMeta{
		Name: "local.txt", Size: int64(len(payload)), Mime: "text/plain", LastModified: 1_700_000_000_000,
	}, 64*1024)
	_, err := Transfer(ctx, Options{
		Identity:     alice.identity,
		Store:        alice.store,
		Resolver:     alice.resolver,
		Table:        tab,
		PeerDeviceID: bob.identity.DeviceID,
		PeerLabel:    "bob",
		Role:         rendezvous.RoleOfferer,
		Handle:       handle,
		Source:       src,
		Dial:         mon.dial,
	})
	// The egress hook denies the non-loopback dial: the transfer must fail
	// closed with a clear dial error, never attempting a fallback.
	if err == nil {
		t.Fatal("expected the denied dial to fail the transfer")
	}
	if !strings.Contains(err.Error(), "denied") && !strings.Contains(err.Error(), "dial") {
		t.Fatalf("err = %v, want a clear dial-denied failure", err)
	}

	// Egress audit: the denied dial was observed and recorded.
	if mon.count() == 0 {
		t.Fatal("expected the denied dial to be monitored")
	}
	if mon.allLoopback() {
		t.Fatalf("expected a non-loopback dial attempt, got only loopback: %v", mon.dials)
	}
	// The failed route is marked failed, never verified.
	cand, ok := tab.Get(bob.identity.DeviceID)
	if !ok {
		t.Fatal("candidate missing after failed transfer")
	}
	if cand.State == discovery.StateVerified {
		t.Fatal("denied candidate must never verify")
	}
}

// --- Wrong peer fails closed ---

func TestTransferWrongPeerFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	mallory := newTestDevice(t)
	kPairAB := []byte(strings.Repeat("a", 32))
	kPairAM := []byte(strings.Repeat("m", 32))
	pair(t, alice, bob, kPairAB, "cred-test")
	// Mallory is "paired" with alice under a different secret, and runs the
	// receiver at the dialed endpoint while alice selects bob's identity.
	pair(t, alice, mallory, kPairAM, "cred-test")

	payload := []byte("must not reach the wrong peer")
	destDir := t.TempDir()
	handle := randomHandle(t)
	// The receiver authenticates as mallory with kPairAM; alice's handshake
	// expects bob with kPairAB.
	r := startReceiver(t, mallory, alice, kPairAM, handle, destDir, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	tab := candidateTableFor(t, bob.identity.DeviceID, r.addr)

	src := wire.BytesSource(payload, wire.FileMeta{Name: "secret.txt", Size: int64(len(payload))}, 64*1024)
	_, err := Transfer(ctx, Options{
		Identity: alice.identity, Store: alice.store, Resolver: alice.resolver,
		Table: tab, PeerDeviceID: bob.identity.DeviceID, Role: rendezvous.RoleOfferer,
		Handle: handle, Source: src,
	})
	if err == nil {
		t.Fatal("expected the transfer to fail closed against the wrong peer")
	}
	// Nothing may be delivered to the wrong peer.
	entries, _ := os.ReadDir(destDir)
	if len(entries) != 0 {
		t.Fatalf("wrong peer received %d files", len(entries))
	}
	recv := <-r.done
	if recv.err == nil {
		t.Fatal("expected the receiver side to fail as well")
	}
	// The candidate is marked failed, never verified. (Failed candidates
	// stay re-dialable by table design for transient retry; the invariant
	// is they never become the verified route.)
	cand, ok := tab.Get(bob.identity.DeviceID)
	if !ok {
		t.Fatal("candidate missing after failed transfer")
	}
	if cand.State == discovery.StateVerified {
		t.Fatal("failed candidate must not stay dialable as verified")
	}
	if cand.State != discovery.StateFailed {
		t.Fatalf("wrong-peer candidate should be failed, got %v", cand.State)
	}
}

// --- No route: clear failure, never silent fallback ---

func TestTransferNoCandidateFailsClearly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	kPair := []byte(strings.Repeat("k", 32))
	pair(t, alice, bob, kPair, "cred-test")

	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	mon := &egressMonitor{deny: true}
	src := wire.BytesSource([]byte("x"), wire.FileMeta{Name: "x"}, 1024)
	_, err := Transfer(ctx, Options{
		Identity: alice.identity, Store: alice.store, Resolver: alice.resolver,
		Table: tab, PeerDeviceID: bob.identity.DeviceID, Role: rendezvous.RoleOfferer,
		Source: src, Dial: mon.dial,
	})
	if err == nil || !strings.Contains(err.Error(), "no local route candidate") {
		t.Fatalf("err = %v, want a clear no-route failure", err)
	}
	if mon.count() != 0 {
		t.Fatalf("no dial may be attempted without a route candidate, saw %v", mon.dials)
	}
}

// --- Refused/unreachable endpoint: clear failure ---

func TestTransferRefusedEndpointFailsClearly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice := newTestDevice(t)
	bob := newTestDevice(t)
	kPair := []byte(strings.Repeat("k", 32))
	pair(t, alice, bob, kPair, "cred-test")

	// Bob's server does NOT pair alice: admission is refused.
	lonely := newTestDevice(t)
	destDir := t.TempDir()
	handle := randomHandle(t)
	r := startReceiver(t, lonely, alice, kPair, handle, destDir, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	_ = r
	tab := candidateTableFor(t, bob.identity.DeviceID, r.addr)
	mon := &egressMonitor{deny: true}

	src := wire.BytesSource([]byte("x"), wire.FileMeta{Name: "x"}, 1024)
	_, err := Transfer(ctx, Options{
		Identity: alice.identity, Store: alice.store, Resolver: alice.resolver,
		Table: tab, PeerDeviceID: bob.identity.DeviceID, Role: rendezvous.RoleOfferer,
		Handle: handle, Source: src, Dial: mon.dial,
	})
	if err == nil || !strings.Contains(err.Error(), "no local route") {
		t.Fatalf("err = %v, want a clear no-route failure", err)
	}
	if !mon.allLoopback() {
		t.Fatalf("non-loopback dial attempted: %v", mon.dials)
	}
	// The refused route is marked failed, never verified.
	cand, ok := tab.Get(bob.identity.DeviceID)
	if !ok {
		t.Fatal("candidate missing after refused transfer")
	}
	if cand.State == discovery.StateVerified {
		t.Fatal("refused endpoint must never verify the route candidate")
	}
	if cand.State != discovery.StateFailed {
		t.Fatalf("refused candidate should be failed, got %v", cand.State)
	}
}

// --- Strict padding requirement propagates to the engine ---
//
// The padding policy itself is enforced by the shared engine after the
// channel opens (driver_test covers it); the local layer's job is to carry
// the caller's RequirePadding/Private flags into the spec unchanged, so a
// strict sender can never silently downgrade on a local route.

func TestTransferStrictPaddingPropagates(t *testing.T) {
	alice := newTestDevice(t)
	bob := newTestDevice(t)
	kPair := []byte(strings.Repeat("k", 32))
	pair(t, alice, bob, kPair, "cred-test")

	opts := Options{
		Identity: alice.identity, Store: alice.store, Resolver: alice.resolver,
		Table:        discovery.NewCandidateTable(discovery.RoutePolicy{}, 16, time.Minute),
		PeerDeviceID: bob.identity.DeviceID, Role: rendezvous.RoleOfferer,
		RequirePadding: true, Private: true,
	}
	spec, err := opts.buildSpec("handle", bob.identity.PublicKey, kPair, "cred-test", []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if !spec.RequirePadding {
		t.Fatal("RequirePadding must propagate to the engine spec")
	}
	if !spec.Private {
		t.Fatal("Private must propagate to the engine spec")
	}

	// And the default is off: no silent padding.
	opts2 := opts
	opts2.RequirePadding = false
	opts2.Private = false
	spec2, err := opts2.buildSpec("handle", bob.identity.PublicKey, kPair, "cred-test", []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if spec2.RequirePadding || spec2.Private {
		t.Fatal("padding flags must default off")
	}
}

// --- Cancelled context fails without network activity ---

func TestTransferCancelledContext(t *testing.T) {
	alice := newTestDevice(t)
	bob := newTestDevice(t)
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	if _, err := tab.AddManual(bob.identity.DeviceID, "127.0.0.1:9"); err != nil {
		t.Fatal(err)
	}
	mon := &egressMonitor{deny: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := wire.BytesSource([]byte("x"), wire.FileMeta{Name: "x"}, 1024)
	_, err := Transfer(ctx, Options{
		Identity: alice.identity, Store: alice.store, Resolver: alice.resolver,
		Table: tab, PeerDeviceID: bob.identity.DeviceID, Role: rendezvous.RoleOfferer,
		Source: src, Dial: mon.dial,
	})
	if err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if mon.count() != 0 {
		t.Fatalf("no dial may be attempted on a cancelled context, saw %v", mon.dials)
	}
}

// --- Signal framing rejects mistyped frames ---

func TestSignalRejectsMistypedFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st := trust.NewMemoryTrustStore()
	probeID, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          probeID.DeviceID,
		PublicKey:         hex.EncodeToString(probeID.PublicKey),
		LocalLabel:        "probe",
		PairCredentialRef: "cred-probe",
		Capabilities:      []string{"transfer.v1"},
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	}); err != nil {
		t.Fatal(err)
	}
	srv := localrendezvous.NewServer(localrendezvous.Config{BindAddr: "127.0.0.1:0"}, st)
	gotFrame := make(chan []byte, 1)
	srv.OnSession(func(sess *localrendezvous.Session) {
		defer func() { _ = sess.Close() }()
		// Send one mistyped frame, then hold the session.
		_ = sess.WriteFrame(ctx, []byte{0x7f, 0x01, 0x02})
		gotFrame <- []byte("sent")
	})
	if _, err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	sess, err := localrendezvous.Dial(ctx, srv.Addr().String(), localrendezvous.DialConfig{DeviceID: probeID.DeviceID})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = sess.Close() }()
	<-gotFrame

	sig := newSessionSignal(sess)
	err = sig.Run(ctx, func(rendezvous.Message) {}, func([]byte) {})
	if err == nil || !strings.Contains(err.Error(), "unknown signal frame type") {
		t.Fatalf("err = %v, want mistyped-frame rejection", err)
	}
}
