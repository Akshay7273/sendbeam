package discovery

// Route candidates for SendBeam v2.1 "Nearby & Offline" (V21-PR03).
//
// Discovery finds nearby peers; it never authenticates them. This file turns
// blinded-beacon sightings and explicit manual entries into validated route
// candidates: endpoints checked against the approved network/interface
// policy, with an explicit lifecycle (discovered -> authenticating ->
// verified) so that only the selected identity becomes the connected peer
// after the real authentication ceremony runs.
//
// Security properties:
//   - A beacon match only proves the peer knows a pair secret for a claimed
//     device ID; the candidate stays in StateDiscovered until the trust
//     ceremony authenticates it (see localrendezvous + trust packages).
//   - Endpoints are validated before they enter the table: loopback,
//     link-local, unspecified and multicast addresses are rejected unless
//     explicitly allowed; every address must sit inside an approved
//     network. Hostnames are resolved once and every resolved IP must be
//     approved (DNS-rebinding guard); the dial path must use the returned
//     IPs, never re-resolve the hostname.
//   - Endpoint substitution (same claimed ID, new address) resets the
//     candidate to StateDiscovered: the new endpoint is not authenticated.
//   - The table is bounded and expiring; interface/roaming changes drop
//     candidates that no longer validate.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

var (
	// ErrEndpointUnparsable means the endpoint is not a valid host:port.
	ErrEndpointUnparsable = errors.New("discovery: endpoint is not a valid host:port")
	// ErrEndpointNotPermitted covers loopback, link-local, unspecified and
	// multicast addresses when they are not explicitly allowed.
	ErrEndpointNotPermitted = errors.New("discovery: endpoint address class not permitted")
	// ErrEndpointOutsidePolicy means the address is outside every approved network.
	ErrEndpointOutsidePolicy = errors.New("discovery: endpoint outside approved networks")
	// ErrDNSRebinding means a hostname resolved to a mix of approved and
	// non-approved addresses (or resolution failed).
	ErrDNSRebinding = errors.New("discovery: hostname resolution is not uniformly policy-approved")
	// ErrStaleBeacon means the sighting is older than the beacon max age.
	ErrStaleBeacon = errors.New("discovery: stale beacon sighting")
	// ErrUnknownCandidate means no candidate exists for the device ID.
	ErrUnknownCandidate = errors.New("discovery: unknown candidate")
)

const (
	// defaultBeaconMaxAge bounds how old a beacon sighting may be to enter
	// the table.
	defaultBeaconMaxAge = 60 * time.Second
	// defaultCandidateTTL bounds candidate lifetime without refresh.
	defaultCandidateTTL = 5 * time.Minute
	// defaultMaxCandidates bounds the table.
	defaultMaxCandidates = 64
)

// CandidateSource records how a candidate entered the table.
type CandidateSource int

const (
	// SourceBeacon entered via a blinded-beacon sighting.
	SourceBeacon CandidateSource = iota + 1
	// SourceManual was entered explicitly by the user (blocked-multicast
	// networks, direct IP entry).
	SourceManual
)

func (s CandidateSource) String() string {
	if s == SourceManual {
		return "manual"
	}
	return "beacon"
}

// CandidateState is the validation lifecycle of a route candidate. A beacon
// sighting alone can only ever reach StateDiscovered.
type CandidateState int

const (
	// StateDiscovered means the endpoint validated; the identity is NOT authenticated.
	StateDiscovered CandidateState = iota + 1
	// StateAuthenticating means a dial/auth ceremony is in flight for this candidate.
	StateAuthenticating
	// StateVerified means the authentication ceremony confirmed the claimed identity.
	StateVerified
	// StateFailed means authentication failed or the endpoint stopped validating.
	StateFailed
)

func (s CandidateState) String() string {
	switch s {
	case StateAuthenticating:
		return "authenticating"
	case StateVerified:
		return "verified"
	case StateFailed:
		return "failed"
	default:
		return "discovered"
	}
}

// RoutePolicy decides which endpoints may become route candidates.
type RoutePolicy struct {
	// Networks is the approved set of CIDRs. When empty, it is derived
	// from the host's up interfaces (see NetworksFromInterfaces).
	Networks []string
	// Interfaces, when non-empty, restricts network derivation to these
	// interface names.
	Interfaces []string
	// AllowLoopback permits 127.0.0.0/8 and ::1 (tests, same-host setups).
	AllowLoopback bool
	// AllowLinkLocal permits fe80::/10.
	AllowLinkLocal bool
	// Resolve maps a hostname to IPs. Nil uses net.DefaultResolver.
	// Injectable for tests.
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
}

// ValidatedEndpoint is a policy-checked dial target. IPs holds every
// resolved-and-approved address; the dial path must use these rather than
// re-resolving the original hostname (DNS-rebinding guard).
type ValidatedEndpoint struct {
	HostPort string
	IPs      []net.IP
	Port     uint16
}

// approvedNets parses p.Networks, or derives them from interfaces.
func (p RoutePolicy) approvedNets() ([]*net.IPNet, error) {
	if len(p.Networks) > 0 {
		nets := make([]*net.IPNet, 0, len(p.Networks))
		for _, c := range p.Networks {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("discovery: bad approved network %q: %w", c, err)
			}
			nets = append(nets, n)
		}
		return nets, nil
	}
	return NetworksFromInterfaces(p.Interfaces)
}

// NetworksFromInterfaces returns the CIDRs of up, non-loopback interfaces,
// optionally restricted to names. Loopback addresses are excluded here;
// loopback endpoints are governed by AllowLoopback instead.
func NetworksFromInterfaces(names []string) ([]*net.IPNet, error) {
	only := make(map[string]bool, len(names))
	for _, n := range names {
		only[n] = true
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("discovery: list interfaces: %w", err)
	}
	var nets []*net.IPNet
	for _, ifi := range ifs {
		if len(names) > 0 && !only[ifi.Name] {
			continue
		}
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ipnet *net.IPNet
			switch v := a.(type) {
			case *net.IPNet:
				ipnet = v
			case *net.IPAddr:
				ipnet = &net.IPNet{IP: v.IP, Mask: net.CIDRMask(128, 128)}
				if v.IP.To4() != nil {
					ipnet.Mask = net.CIDRMask(32, 32)
				}
			default:
				continue
			}
			if ipnet.IP.IsLoopback() {
				continue
			}
			nets = append(nets, ipnet)
		}
	}
	return nets, nil
}

// ValidateEndpoint parses host:port and enforces the route policy.
func (p RoutePolicy) ValidateEndpoint(ctx context.Context, hostport string) (ValidatedEndpoint, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || portStr == "" {
		return ValidatedEndpoint{}, ErrEndpointUnparsable
	}
	port64, err := parsePort(portStr)
	if err != nil {
		return ValidatedEndpoint{}, ErrEndpointUnparsable
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = p.resolve(ctx, host)
		if err != nil {
			return ValidatedEndpoint{}, err
		}
	}

	nets, err := p.approvedNets()
	if err != nil {
		return ValidatedEndpoint{}, err
	}
	for _, ip := range ips {
		if err := p.checkIP(ip, nets); err != nil {
			return ValidatedEndpoint{}, err
		}
	}

	// Canonical form: net.JoinHostPort handles IPv6 bracketing.
	canonical := net.JoinHostPort(ips[0].String(), portStr)
	return ValidatedEndpoint{HostPort: canonical, IPs: ips, Port: uint16(port64)}, nil
}

func (p RoutePolicy) resolve(ctx context.Context, host string) ([]net.IP, error) {
	resolve := p.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, ErrDNSRebinding
	}
	nets, err := p.approvedNets()
	if err != nil {
		return nil, err
	}
	// DNS-rebinding guard: EVERY resolved address must be policy-approved.
	for _, ip := range ips {
		if err := p.checkIP(ip, nets); err != nil {
			return nil, ErrDNSRebinding
		}
	}
	return ips, nil
}

// checkIP enforces address-class rules and network membership.
func (p RoutePolicy) checkIP(ip net.IP, nets []*net.IPNet) error {
	if ip.IsUnspecified() || ip.IsMulticast() {
		return ErrEndpointNotPermitted
	}
	if ip.IsLoopback() && !p.AllowLoopback {
		return ErrEndpointNotPermitted
	}
	if ip.IsLinkLocalUnicast() && !p.AllowLinkLocal {
		return ErrEndpointNotPermitted
	}
	// Loopback/link-local explicitly allowed still count as inside policy.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return nil
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return nil
		}
	}
	return ErrEndpointOutsidePolicy
}

func parsePort(s string) (uint64, error) {
	var n uint64
	if s == "" {
		return 0, errors.New("empty port")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("bad port")
		}
		n = n*10 + uint64(c-'0')
		if n > 65535 {
			return 0, errors.New("bad port")
		}
	}
	if n == 0 {
		return 0, errors.New("bad port")
	}
	return n, nil
}

// RouteCandidate is one validated way to reach a claimed device identity.
// The DeviceID is claimed until State == StateVerified.
type RouteCandidate struct {
	DeviceID  string
	Endpoint  ValidatedEndpoint
	Source    CandidateSource
	State     CandidateState
	FirstSeen time.Time
	LastSeen  time.Time
	Failures  int
}

// CandidateTable is a bounded, expiring table of route candidates.
type CandidateTable struct {
	policy       RoutePolicy
	max          int
	ttl          time.Duration
	beaconMaxAge time.Duration

	mu   sync.Mutex
	byID map[string]*RouteCandidate
}

// NewCandidateTable creates a table. Non-positive max/ttl select defaults.
func NewCandidateTable(policy RoutePolicy, maxCandidates int, ttl time.Duration) *CandidateTable {
	if maxCandidates <= 0 {
		maxCandidates = defaultMaxCandidates
	}
	if ttl <= 0 {
		ttl = defaultCandidateTTL
	}
	return &CandidateTable{
		policy:       policy,
		max:          maxCandidates,
		ttl:          ttl,
		beaconMaxAge: defaultBeaconMaxAge,
		byID:         make(map[string]*RouteCandidate),
	}
}

// UpsertBeacon records a blinded-beacon sighting. The beacon match only
// proves knowledge of a pair secret; the candidate enters (or returns to)
// StateDiscovered — never further.
func (t *CandidateTable) UpsertBeacon(peer DiscoveredPeer) (*RouteCandidate, error) {
	now := time.Now().UTC()
	if now.Sub(peer.LastSeen) > t.beaconMaxAge {
		return nil, ErrStaleBeacon
	}
	ep, err := t.policy.ValidateEndpoint(context.Background(), net.JoinHostPort(peer.IP.String(), itoa(peer.Port)))
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.byID[peer.DeviceID]
	if !ok {
		c = &RouteCandidate{
			DeviceID:  peer.DeviceID,
			Source:    SourceBeacon,
			State:     StateDiscovered,
			FirstSeen: now,
		}
		t.byID[peer.DeviceID] = c
	} else if c.Endpoint.HostPort != ep.HostPort {
		// Endpoint substitution: same claimed identity, new address. The
		// new endpoint is not authenticated; drop back to Discovered.
		c.State = StateDiscovered
		c.Failures = 0
	}
	c.Endpoint = ep
	c.LastSeen = now
	// A beacon sighting corroborates a manual entry but never changes its
	// source; the Source field already records manual origin.
	t.enforceBoundLocked()
	return copyCandidate(c), nil
}

// AddManual adds an explicitly user-entered endpoint (for networks where
// multicast discovery is blocked). The endpoint is validated exactly like
// a discovered one; manual entry still never authenticates the identity.
func (t *CandidateTable) AddManual(deviceID, hostport string) (*RouteCandidate, error) {
	ep, err := t.policy.ValidateEndpoint(context.Background(), hostport)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.byID[deviceID]
	if !ok {
		c = &RouteCandidate{
			DeviceID:  deviceID,
			Source:    SourceManual,
			State:     StateDiscovered,
			FirstSeen: now,
		}
		t.byID[deviceID] = c
	} else if c.Endpoint.HostPort != ep.HostPort {
		c.State = StateDiscovered
		c.Failures = 0
	}
	c.Endpoint = ep
	c.Source = SourceManual
	c.LastSeen = now
	if c.State == StateFailed {
		c.State = StateDiscovered
	}
	t.enforceBoundLocked()
	return copyCandidate(c), nil
}

// TakeForDial returns the validated dial target and moves the candidate to
// StateAuthenticating. Only discovered/manual candidates may start a dial.
func (t *CandidateTable) TakeForDial(deviceID string) (ValidatedEndpoint, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.byID[deviceID]
	if !ok {
		return ValidatedEndpoint{}, false
	}
	if c.State != StateDiscovered && c.State != StateFailed {
		return ValidatedEndpoint{}, false
	}
	c.State = StateAuthenticating
	return c.Endpoint, true
}

// MarkVerified moves an authenticating candidate to StateVerified only when
// the authentication ceremony confirmed the exact selected identity.
// Anything else fails the candidate: only the selected identity becomes
// the connected peer.
func (t *CandidateTable) MarkVerified(deviceID, authenticatedID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.byID[deviceID]
	if !ok || c.State != StateAuthenticating {
		return false
	}
	if !equalDeviceID(c.DeviceID, authenticatedID) {
		c.State = StateFailed
		c.Failures++
		return false
	}
	c.State = StateVerified
	c.LastSeen = time.Now().UTC()
	return true
}

// MarkFailed records an authentication/connection failure.
func (t *CandidateTable) MarkFailed(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.byID[deviceID]; ok {
		c.State = StateFailed
		c.Failures++
	}
}

// Get returns a copy of the candidate, if present.
func (t *CandidateTable) Get(deviceID string) (*RouteCandidate, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.byID[deviceID]
	if !ok {
		return nil, false
	}
	return copyCandidate(c), true
}

// Remove drops a candidate.
func (t *CandidateTable) Remove(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byID, deviceID)
}

// All returns copies of all candidates.
func (t *CandidateTable) All() []RouteCandidate {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]RouteCandidate, 0, len(t.byID))
	for _, c := range t.byID {
		out = append(out, *copyCandidate(c))
	}
	return out
}

// Sweep expires candidates older than the TTL and enforces the bound.
// Returns the number removed.
func (t *CandidateTable) Sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	removed := 0
	for id, c := range t.byID {
		if now.Sub(c.LastSeen) > t.ttl {
			delete(t.byID, id)
			removed++
		}
	}
	removed += t.enforceBoundLocked()
	return removed
}

// Revalidate installs a new policy (e.g. after an interface/roaming
// change) and drops every candidate whose endpoint no longer validates.
// Returns the number removed.
func (t *CandidateTable) Revalidate(policy RoutePolicy) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.policy = policy
	removed := 0
	ctx := context.Background()
	for id, c := range t.byID {
		if _, err := policy.ValidateEndpoint(ctx, c.Endpoint.HostPort); err != nil {
			delete(t.byID, id)
			removed++
		}
	}
	return removed
}

// enforceBoundLocked evicts oldest-first until the table fits. A candidate
// with a dial in flight (StateAuthenticating) is evicted last.
func (t *CandidateTable) enforceBoundLocked() int {
	if len(t.byID) <= t.max {
		return 0
	}
	all := make([]*RouteCandidate, 0, len(t.byID))
	for _, c := range t.byID {
		all = append(all, c)
	}
	sort.Slice(all, func(i, j int) bool {
		ri, rj := evictRank(all[i].State), evictRank(all[j].State)
		if ri != rj {
			return ri < rj
		}
		return all[i].LastSeen.Before(all[j].LastSeen)
	})
	removed := 0
	for len(t.byID) > t.max && removed < len(all) {
		delete(t.byID, all[removed].DeviceID)
		removed++
	}
	return removed
}

func evictRank(s CandidateState) int {
	if s == StateAuthenticating {
		return 1
	}
	return 0
}

func copyCandidate(c *RouteCandidate) *RouteCandidate {
	dup := *c
	dup.Endpoint.IPs = append([]net.IP(nil), c.Endpoint.IPs...)
	return &dup
}

// equalDeviceID compares device IDs in constant time to avoid leaking
// prefix information through timing.
func equalDeviceID(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func itoa(n uint16) string {
	return fmt.Sprintf("%d", n)
}
