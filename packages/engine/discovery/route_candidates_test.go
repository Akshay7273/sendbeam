// Package discovery route-candidate tests for V21-PR03: nearby discovery
// becomes validated route candidates; a beacon is never authentication.
package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// policyForTest approves 192.168.1.0/24 and fd00::/8, loopback/link-local
// denied by default.
func policyForTest() RoutePolicy {
	return RoutePolicy{
		Networks: []string{"192.168.1.0/24", "fd00::/8"},
	}
}

func TestBeaconBecomesDiscoveredCandidate(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	peer := DiscoveredPeer{
		DeviceID: "sb-dev-" + repeatHex("a1", 32),
		IP:       net.ParseIP("192.168.1.20"),
		Port:     53317,
		LastSeen: time.Now().UTC(),
	}
	c, err := tab.UpsertBeacon(peer)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if c.State != StateDiscovered {
		t.Fatalf("want StateDiscovered, have %v", c.State)
	}
	if c.Source != SourceBeacon {
		t.Fatalf("want SourceBeacon, have %v", c.Source)
	}
	if c.Endpoint.Port != 53317 {
		t.Fatalf("want port 53317, have %d", c.Endpoint.Port)
	}
	if got := c.Endpoint.HostPort; got != "192.168.1.20:53317" {
		t.Fatalf("want 192.168.1.20:53317, have %s", got)
	}
}

func TestStaleBeaconRejected(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	peer := DiscoveredPeer{
		DeviceID: "sb-dev-" + repeatHex("a1", 32),
		IP:       net.ParseIP("192.168.1.20"),
		Port:     53317,
		LastSeen: time.Now().UTC().Add(-10 * time.Minute),
	}
	if _, err := tab.UpsertBeacon(peer); err != ErrStaleBeacon {
		t.Fatalf("want ErrStaleBeacon, have %v", err)
	}
	if n := len(tab.All()); n != 0 {
		t.Fatalf("stale beacon must not create a candidate, have %d", n)
	}
}

func TestEndpointSubstitutionResetsState(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	id := "sb-dev-" + repeatHex("a1", 32)
	mk := func(ip string) DiscoveredPeer {
		return DiscoveredPeer{DeviceID: id, IP: net.ParseIP(ip), Port: 53317, LastSeen: time.Now().UTC()}
	}
	if _, err := tab.UpsertBeacon(mk("192.168.1.20")); err != nil {
		t.Fatal(err)
	}
	if _, ok := tab.TakeForDial(id); !ok {
		t.Fatal("TakeForDial should succeed")
	}
	if !tab.MarkVerified(id, id) {
		t.Fatal("verify should succeed")
	}
	// Same claimed identity now seen at a different endpoint: the candidate
	// must drop back to Discovered — the new endpoint is not authenticated.
	c, err := tab.UpsertBeacon(mk("192.168.1.21"))
	if err != nil {
		t.Fatal(err)
	}
	if c.State != StateDiscovered {
		t.Fatalf("endpoint substitution must reset to Discovered, have %v", c.State)
	}
	if got := c.Endpoint.HostPort; got != "192.168.1.21:53317" {
		t.Fatalf("endpoint not updated, have %s", got)
	}
}

func TestLoopbackRejectedByDefault(t *testing.T) {
	p := policyForTest()
	if _, err := p.ValidateEndpoint(context.Background(), "127.0.0.1:53317"); err != ErrEndpointNotPermitted {
		t.Fatalf("loopback should be rejected, have %v", err)
	}
	p.AllowLoopback = true
	ep, err := p.ValidateEndpoint(context.Background(), "127.0.0.1:53317")
	if err != nil {
		t.Fatalf("loopback should be allowed with flag: %v", err)
	}
	if ep.HostPort != "127.0.0.1:53317" {
		t.Fatalf("bad canonical form: %s", ep.HostPort)
	}
}

func TestLinkLocalRejectedByDefault(t *testing.T) {
	p := policyForTest()
	if _, err := p.ValidateEndpoint(context.Background(), "[fe80::1]:53317"); err != ErrEndpointNotPermitted {
		t.Fatalf("link-local should be rejected, have %v", err)
	}
}

func TestUnspecifiedAndMulticastRejected(t *testing.T) {
	p := policyForTest()
	for _, hp := range []string{"0.0.0.0:53317", "[::]:53317", "224.0.0.1:53317"} {
		if _, err := p.ValidateEndpoint(context.Background(), hp); err != ErrEndpointNotPermitted {
			t.Fatalf("%s: want ErrEndpointNotPermitted, have %v", hp, err)
		}
	}
}

func TestOutsidePolicyNetworkRejected(t *testing.T) {
	p := policyForTest()
	if _, err := p.ValidateEndpoint(context.Background(), "10.9.9.9:53317"); err != ErrEndpointOutsidePolicy {
		t.Fatalf("want ErrEndpointOutsidePolicy, have %v", err)
	}
}

func TestDNSRebindingGuard(t *testing.T) {
	p := policyForTest()
	p.Resolve = func(_ context.Context, _ string) ([]net.IP, error) {
		// Attacker-controlled name flips between an approved and a
		// non-approved address.
		return []net.IP{net.ParseIP("192.168.1.50"), net.ParseIP("10.9.9.9")}, nil
	}
	if _, err := p.ValidateEndpoint(context.Background(), "evil.example:53317"); err != ErrDNSRebinding {
		t.Fatalf("mixed resolution must be rejected, have %v", err)
	}
}

func TestDNSAllApprovedPasses(t *testing.T) {
	p := policyForTest()
	p.Resolve = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.168.1.50"), net.ParseIP("192.168.1.51")}, nil
	}
	ep, err := p.ValidateEndpoint(context.Background(), "peer.example:53317")
	if err != nil {
		t.Fatalf("all-approved resolution should pass: %v", err)
	}
	if len(ep.IPs) != 2 {
		t.Fatalf("want 2 validated IPs, have %d", len(ep.IPs))
	}
}

func TestIPv6Formatting(t *testing.T) {
	p := policyForTest()
	ep, err := p.ValidateEndpoint(context.Background(), "[fd00::42]:53317")
	if err != nil {
		t.Fatalf("ULA IPv6 should validate: %v", err)
	}
	if ep.HostPort != "[fd00::42]:53317" {
		t.Fatalf("bad IPv6 canonical form: %s", ep.HostPort)
	}
}

func TestManualCandidateWithoutMulticast(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	c, err := tab.AddManual("sb-dev-"+repeatHex("b2", 32), "192.168.1.99:53317")
	if err != nil {
		t.Fatalf("manual entry should work without any beacon: %v", err)
	}
	if c.Source != SourceManual || c.State != StateDiscovered {
		t.Fatalf("bad source/state: %v/%v", c.Source, c.State)
	}
}

func TestManualCandidateBadEndpoint(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	if _, err := tab.AddManual("sb-dev-"+repeatHex("b2", 32), "10.9.9.9:53317"); err != ErrEndpointOutsidePolicy {
		t.Fatalf("manual entry outside policy must fail, have %v", err)
	}
	if _, err := tab.AddManual("sb-dev-"+repeatHex("b2", 32), "not a hostport"); err != ErrEndpointUnparsable {
		t.Fatalf("unparsable manual entry must fail cleanly, have %v", err)
	}
}

func TestCandidatesExpire(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 50*time.Millisecond)
	if _, err := tab.AddManual("sb-dev-"+repeatHex("b2", 32), "192.168.1.99:53317"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	if removed := tab.Sweep(time.Now()); removed != 1 {
		t.Fatalf("want 1 expired, have %d", removed)
	}
	if n := len(tab.All()); n != 0 {
		t.Fatalf("table should be empty after sweep, have %d", n)
	}
}

func TestTableBounded(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 4, 5*time.Minute)
	for i := 0; i < 10; i++ {
		id := "sb-dev-" + repeatHex("c3", 31) + hexByte(i)
		if _, err := tab.AddManual(id, "192.168.1.99:53317"); err != nil {
			t.Fatal(err)
		}
	}
	tab.Sweep(time.Now())
	if n := len(tab.All()); n > 4 {
		t.Fatalf("table must stay bounded, have %d", n)
	}
}

func TestInterfaceChangeRevalidates(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	if _, err := tab.AddManual("sb-dev-"+repeatHex("b2", 32), "192.168.1.99:53317"); err != nil {
		t.Fatal(err)
	}
	// The host roams to a new network: 192.168.1.0/24 is gone.
	newPolicy := RoutePolicy{Networks: []string{"192.168.7.0/24"}}
	if removed := tab.Revalidate(newPolicy); removed != 1 {
		t.Fatalf("roamed-away candidate must be dropped, removed=%d", removed)
	}
	if n := len(tab.All()); n != 0 {
		t.Fatalf("table should be empty after roam, have %d", n)
	}
}

func TestAuthFlowOnlySelectedIdentityVerifies(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	id := "sb-dev-" + repeatHex("a1", 32)
	if _, err := tab.AddManual(id, "192.168.1.99:53317"); err != nil {
		t.Fatal(err)
	}
	ep, ok := tab.TakeForDial(id)
	if !ok {
		t.Fatal("TakeForDial should succeed")
	}
	if ep.HostPort != "192.168.1.99:53317" {
		t.Fatalf("bad dial target: %s", ep.HostPort)
	}
	c, _ := tab.Get(id)
	if c.State != StateAuthenticating {
		t.Fatalf("want StateAuthenticating, have %v", c.State)
	}
	// The authenticated identity differs from the selected one: must fail.
	if tab.MarkVerified(id, "sb-dev-"+repeatHex("d4", 32)) {
		t.Fatal("mismatched identity must not verify")
	}
	c, _ = tab.Get(id)
	if c.State != StateFailed {
		t.Fatalf("want StateFailed after identity mismatch, have %v", c.State)
	}
	// Correct identity verifies.
	if _, err := tab.AddManual(id, "192.168.1.99:53317"); err != nil {
		t.Fatal(err)
	}
	if _, ok := tab.TakeForDial(id); !ok {
		t.Fatal("re-dial should succeed")
	}
	if !tab.MarkVerified(id, id) {
		t.Fatal("matching identity should verify")
	}
	c, _ = tab.Get(id)
	if c.State != StateVerified {
		t.Fatalf("want StateVerified, have %v", c.State)
	}
}

func TestBeaconNeverAuthenticates(t *testing.T) {
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	peer := DiscoveredPeer{
		DeviceID: "sb-dev-" + repeatHex("a1", 32),
		IP:       net.ParseIP("192.168.1.20"),
		Port:     53317,
		LastSeen: time.Now().UTC(),
	}
	c, err := tab.UpsertBeacon(peer)
	if err != nil {
		t.Fatal(err)
	}
	// A beacon alone must never reach Verified: only TakeForDial +
	// MarkVerified with the authenticated identity can do that.
	if c.State == StateVerified {
		t.Fatal("beacon must never authenticate a candidate")
	}
	if tab.MarkVerified(c.DeviceID, c.DeviceID) {
		t.Fatal("MarkVerified without TakeForDial must fail")
	}
}

func TestBlockedMulticastNoInternetFallback(t *testing.T) {
	// With no beacons received and no manual entry, there is simply no
	// candidate: the table never invents an internet fallback.
	tab := NewCandidateTable(policyForTest(), 16, 5*time.Minute)
	if n := len(tab.All()); n != 0 {
		t.Fatalf("empty table expected, have %d", n)
	}
	if _, ok := tab.TakeForDial("sb-dev-" + repeatHex("a1", 32)); ok {
		t.Fatal("no candidate must mean no dial target")
	}
}

func TestDiscoveryPeerTableExpiresAndBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	store, _ := trust.NewFileTrustStore(filepath.Join(tmpDir, "trust.json"))
	resolver := trust.NewMemorySecretResolver()

	now := time.Now().UTC()
	mkDevice := func(label string) (string, []byte) {
		pub, _, _ := ed25519.GenerateKey(nil)
		id := wire.DeriveDeviceID(pub)
		kPair := sha256.Sum256([]byte("k-pair-" + label))
		hCred := sha256.Sum256(kPair[:])
		credRef := "cred-" + hex.EncodeToString(hCred[:])
		if err := store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
			DeviceID:          id,
			PublicKey:         hex.EncodeToString(pub),
			LocalLabel:        label,
			PairCredentialRef: credRef,
			FirstSeenAt:       now,
			LastSeenAt:        now,
			Policy:            wire.DefaultTrustPolicy(),
		}); err != nil {
			t.Fatal(err)
		}
		resolver.SetSecret(id, kPair[:])
		return id, kPair[:]
	}
	id1, kPair1 := mkDevice("peer-one")
	id2, kPair2 := mkDevice("peer-two")

	svc := NewLanDiscoveryService(Config{
		BeaconInterval: time.Hour, // no advertising; we inject beacons directly
		PeerTTL:        120 * time.Millisecond,
		MaxPeers:       1,
	}, store, resolver)

	inject := func(kPair []byte, ip string) {
		b, err := wire.NewLanBeacon(53317, [][]byte{kPair}, time.Now().UTC(), 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		svc.processBeacon(ctx, b, net.ParseIP(ip))
	}
	inject(kPair1, "192.168.1.21")
	inject(kPair2, "192.168.1.22")

	peers := svc.GetDiscoveredPeers()
	if len(peers) != 1 {
		t.Fatalf("peer table must be bounded to MaxPeers=1, have %d", len(peers))
	}
	_ = id1
	_ = id2

	// Expiry: after the TTL passes with no fresh beacons, the table drains.
	time.Sleep(300 * time.Millisecond)
	svc.SweepPeers(time.Now())
	if peers := svc.GetDiscoveredPeers(); len(peers) != 0 {
		t.Fatalf("expired peers must be swept, have %d", len(peers))
	}
}

// repeatHex repeats a two-char hex byte n times.
func repeatHex(b string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += b
	}
	return out
}

func hexByte(b int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(b>>4)&15], digits[b&15]})
}
