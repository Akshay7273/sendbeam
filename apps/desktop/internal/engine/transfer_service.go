// Package engine exposes the SendBeam engine to the desktop frontend through
// Wails services. WebRTC, crypto, file I/O, durability, and trust logic stay
// in the Go engine (packages/engine); these services are only a thin
// presentation seam, exactly as the CLI consumes the engine through its
// public API.
//
// Lifecycle & Network Recovery Architecture:
// Desktop network disruption, host sleep/wake recovery, and transport reconnection
// are driven automatically by the engine's adaptive supervisor and reconnecting
// signaling transport (packages/engine/wsclient and packages/engine/transfer).
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/desktop/internal/lifecycle"
	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/receiver"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/transfercenter"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
	qrcode "github.com/skip2/go-qrcode"
)

// TransferEventName is the single event name the service emits for every live
// transfer update. The payload is a TransferEvent snapshot; the frontend
// re-renders from the latest snapshot per transfer id.
const TransferEventName = "sendbeam:transfer"

// ConsentEventName is emitted to the frontend when incoming transfer consent is requested.
const ConsentEventName = "sendbeam:consent"

// DefaultServer mirrors the CLI's default signaling server, so a desktop peer
// pairs with CLI and browser peers of the same deployment out of the box.
const DefaultServer = "wss://localhost:8443/ws"

// FileInfo is one file in the transfer set, for aggregate display.
type FileInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// TransferEvent is a live snapshot of one transfer's state. Kind tells the
// frontend what changed; the rest are the current values (progress events are
// throttled to a bounded cadence, the terminal kind is always emitted).
type TransferEvent struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // invite | phase | connect | transport | manifest | progress | state | done | error

	// Invite (offerer, kind=invite).
	Code string `json:"code,omitempty"`
	Link string `json:"link,omitempty"`
	QR   string `json:"qr,omitempty"` // data URL of the invite QR

	// Handshake (kind=phase).
	Phase string `json:"phase,omitempty"`

	// Secure channel (kind=connect).
	Fingerprint string `json:"fingerprint,omitempty"`

	// Byte path (kind=transport).
	Transport string `json:"transport,omitempty"`

	// File set (kind=manifest).
	Files      []FileInfo `json:"files,omitempty"`
	TotalBytes int64      `json:"totalBytes,omitempty"`

	// Progress (kind=progress): cumulative acknowledged bytes, percent,
	// five-second rolling rate, ETA, current file, aggregate state.
	DoneBytes   int64   `json:"doneBytes,omitempty"`
	Percent     int     `json:"percent,omitempty"`
	RateBps     float64 `json:"rateBps,omitempty"`
	ETA         string  `json:"eta,omitempty"`
	CurrentFile string  `json:"currentFile,omitempty"`
	FileBytes   int64   `json:"fileBytes,omitempty"`
	FileSize    int64   `json:"fileSize,omitempty"`
	FilesDone   int     `json:"filesDone,omitempty"`
	FilesTotal  int     `json:"filesTotal,omitempty"`
	RemainingMS int64   `json:"remainingMs,omitempty"` // -1 when unknown
	State       string  `json:"state,omitempty"`       // running | paused | canceled
	Paused      bool    `json:"paused,omitempty"`
	Canceled    bool    `json:"canceled,omitempty"`
	Failed      bool    `json:"failed,omitempty"`
	Resumed     bool    `json:"resumed,omitempty"`

	// Terminal (kind=done/error).
	Digest  string `json:"digest,omitempty"`
	OutDir  string `json:"outDir,omitempty"`
	OutPath string `json:"outPath,omitempty"`
	Error   string `json:"error,omitempty"`

	// Handoff (kind=done, V20-PR06): "text"/"link" for an encrypted handoff.
	// Content is the verified payload held in memory for deliberate
	// Copy/Save/Open — it was never written to disk.
	ContentKind string `json:"contentKind,omitempty"`
	Content     string `json:"content,omitempty"`
}

// DurableTransferItem describes an interrupted transfer (sender or receiver)
// surfaced to the desktop management UI.
type DurableTransferItem struct {
	TransferID     string   `json:"transferId"`
	Role           string   `json:"role"` // send | receive
	TotalBytes     int64    `json:"totalBytes"`
	CommittedBytes int64    `json:"committedBytes"`
	Files          int      `json:"files"`
	CreatedAt      int64    `json:"createdAt"`
	UpdatedAt      int64    `json:"updatedAt"`
	Status         string   `json:"status"`
	Resumable      bool     `json:"resumable"`
	Paths          []string `json:"paths,omitempty"`
}

// DurableInspectResult is the diagnostic outcome of inspecting a durable journal.
type DurableInspectResult struct {
	TransferID          string     `json:"transferId"`
	TotalBytes          int64      `json:"totalBytes"`
	CommittedBytes      int64      `json:"committedBytes"`
	CreatedAt           int64      `json:"createdAt"`
	UpdatedAt           int64      `json:"updatedAt"`
	ProtocolVersion     string     `json:"protocolVersion"`
	ManifestFingerprint string     `json:"manifestFingerprint"`
	JournalPath         string     `json:"journalPath"`
	PartialDir          string     `json:"partialDir"`
	Resumable           bool       `json:"resumable"`
	Problems            []string   `json:"problems,omitempty"`
	Files               []FileInfo `json:"files,omitempty"`
}

// completedDestination stores the verified final output path alongside its exact trusted destination root.
type completedDestination struct {
	Path string
	Root string
}

// SignalDialer returns the signaling signal for one transfer side. The desktop
// uses the same wsclient as the CLI (browser/CLI interop by construction);
// tests inject loopback ends.
type SignalDialer func(ctx context.Context, server string, role wire.Role) (transfer.Signal, error)

// defaultDialer dials the real signaling server exactly as the CLI does.
func defaultDialer(ctx context.Context, server string, _ wire.Role) (transfer.Signal, error) {
	return wsclient.NewReconnectingSignal(ctx, server, wsclient.DialOptions{})
}

// TransferService drives one or more engine transfers through transfer.Run,
// streaming TransferEvent snapshots to the frontend. All WebRTC, crypto, file
// I/O, durability, and trust logic stays in packages/engine.
type TransferService struct {
	emit func(name string, data any) // nil in tests; wired to app events in main
	dial SignalDialer

	// forceRelay skips direct negotiation (loopback tests; production leaves it
	// false so the adaptive direct/relay racer runs). iceServers nil uses the
	// engine's default STUN; an explicit empty slice is host-only (loopback).
	forceRelay bool
	iceServers []webrtc.ICEServer

	mu   sync.Mutex
	next int
	runs map[string]*transferRun

	configStore           *config.Store
	notifier              lifecycle.Notifier
	revealMgr             *lifecycle.RevealManager
	picker                Picker
	senderStore           *transfer.SenderStore
	durableStoreFn        func(outDir string) (*transfer.DurableStore, error)
	completedDestinations map[string]completedDestination

	// tcCenter is the lazily-initialized transfer center (V20-PR03) over the
	// shared jobs store; guarded by mu.
	tcCenter *transfercenter.Center

	nativeReceiver       *receiver.Listener
	nativeReceiverCancel context.CancelFunc
	// nativeReceiverBase is the receiver config as constructed at startup.
	// ApplyNetworkPolicy re-derives the live config from it so a policy
	// change (e.g. to local-only) takes effect without an app restart.
	nativeReceiverBase *receiver.Config

	deviceService *DeviceService

	// V20-PR07: share inbox for OS Share / Send to / Open with launches.
	// Paths that arrive before the frontend has subscribed to events are
	// staged here; the frontend drains them on boot with TakeStagedShares.
	// shareUIReady is set by the first TakeStagedShares call.
	shareMu      sync.Mutex
	stagedShares [][]string
	shareUIReady bool
}

// SetDeviceService sets the device service reference for targeted sends and peer trust resolution.
func (s *TransferService) SetDeviceService(ds *DeviceService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceService = ds
}

// DeviceService returns the configured device service or nil.
func (s *TransferService) DeviceService() *DeviceService {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceService
}

// SetPicker sets the native dialog picker provider (e.g. Wails dialogs).
func (s *TransferService) SetPicker(p Picker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.picker = p
}

func (s *TransferService) requirePaddingConfig() bool {
	if s.configStore != nil {
		if cfg, err := s.configStore.Load(); err == nil {
			return cfg.RequirePadding
		}
	}
	return false
}

func (s *TransferService) isDeviceRequirePadding(peerDeviceID string) bool {
	s.mu.Lock()
	ds := s.deviceService
	s.mu.Unlock()
	if ds != nil {
		if dev, err := ds.GetStore().GetDevice(context.Background(), peerDeviceID); err == nil && dev != nil {
			return dev.Policy.RequirePadding
		}
	}
	return false
}

// NewTransferService builds the service. emit is the frontend sink (wails
// app.Event.Emit in production, a recorder in tests); dial is the signaling
// seam (nil uses the real wsclient).
func NewTransferService(emit func(name string, data any), dial SignalDialer) *TransferService {
	if dial == nil {
		dial = defaultDialer
	}
	cfgStore, _ := config.NewStore("", nil)
	sStoreDir, _ := transfer.SenderStoreDir()
	var sStore *transfer.SenderStore
	if sStoreDir != "" {
		sStore, _ = transfer.OpenSenderStore(sStoreDir)
	}

	return &TransferService{
		emit:                  emit,
		dial:                  dial,
		runs:                  map[string]*transferRun{},
		configStore:           cfgStore,
		notifier:              lifecycle.DefaultNotifier(),
		revealMgr:             lifecycle.NewRevealManager(nil),
		senderStore:           sStore,
		durableStoreFn:        transfer.OpenStore,
		completedDestinations: map[string]completedDestination{},
	}
}

// SetNotifier sets the notification sink.
func (s *TransferService) SetNotifier(n lifecycle.Notifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifier = n
}

// SetRevealManager sets the reveal manager.
func (s *TransferService) SetRevealManager(r *lifecycle.RevealManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revealMgr = r
}

// SetConfigStore sets the config store.
func (s *TransferService) SetConfigStore(cs *config.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configStore = cs
}

// SetSenderStore sets the sender store for tests.
func (s *TransferService) SetSenderStore(ss *transfer.SenderStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senderStore = ss
}

// SetDurableStoreFn overrides the durable store factory for tests.
func (s *TransferService) SetDurableStoreFn(fn func(outDir string) (*transfer.DurableStore, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durableStoreFn = fn
}

func (s *TransferService) openDurableStore(outDir string) (*transfer.DurableStore, error) {
	s.mu.Lock()
	fn := s.durableStoreFn
	s.mu.Unlock()
	if fn == nil {
		fn = transfer.OpenStore
	}
	return fn(outDir)
}

func (s *TransferService) recordCompleted(id string, dest completedDestination) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completedDestinations[id] = dest
}

func parseTURNServer(rawURL string) (urlNoUser, username, password string) {
	trimmed := strings.TrimSpace(rawURL)
	scheme := ""
	rest := trimmed
	if strings.HasPrefix(trimmed, "turns:") {
		scheme = "turns:"
		rest = strings.TrimPrefix(trimmed, "turns:")
	} else if strings.HasPrefix(trimmed, "turn:") {
		scheme = "turn:"
		rest = strings.TrimPrefix(trimmed, "turn:")
	} else {
		return trimmed, "", ""
	}

	rest = strings.TrimPrefix(rest, "//")
	if atIdx := strings.LastIndex(rest, "@"); atIdx != -1 {
		userInfo := rest[:atIdx]
		hostPort := rest[atIdx+1:]
		if colonIdx := strings.Index(userInfo, ":"); colonIdx != -1 {
			username = userInfo[:colonIdx]
			password = userInfo[colonIdx+1:]
		} else {
			username = userInfo
		}
		urlNoUser = scheme + hostPort
		return urlNoUser, username, password
	}

	return trimmed, "", ""
}

func (s *TransferService) resolveICEServers() ([]webrtc.ICEServer, error) {
	s.mu.Lock()
	override := s.iceServers
	cs := s.configStore
	s.mu.Unlock()

	if override != nil {
		return override, nil
	}
	if cs == nil {
		return nil, nil
	}
	cfg, err := cs.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if len(cfg.ICEServers) == 0 {
		return nil, nil
	}

	var resolved []webrtc.ICEServer
	for _, raw := range cfg.ICEServers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "turn:") || strings.HasPrefix(raw, "turns:") {
			urlNoUser, username, pwd := parseTURNServer(raw)
			if pwd != "" {
				return nil, fmt.Errorf("turn server %q contains an embedded password; storing credentials in configuration is forbidden", raw)
			}
			srv := webrtc.ICEServer{
				URLs: []string{urlNoUser},
			}
			if username != "" {
				srv.Username = username
				cred, err := cs.GetTurnCredential(urlNoUser, username)
				if err != nil && !errors.Is(err, config.ErrSecretStoreUnavailable) {
					cred, err = cs.GetTurnCredential(raw, username)
				}
				if err != nil {
					if errors.Is(err, config.ErrSecretStoreUnavailable) {
						return nil, fmt.Errorf("turn server %q requires credentials but protected secret store is unavailable: %w", raw, err)
					}
					return nil, fmt.Errorf("turn credential not found for %s (user %s): %w", raw, username, err)
				}
				srv.Credential = string(cred)
				srv.CredentialType = webrtc.ICECredentialTypePassword
			}
			resolved = append(resolved, srv)
		} else {
			resolved = append(resolved, webrtc.ICEServer{
				URLs: []string{raw},
			})
		}
	}
	return resolved, nil
}

// setLoopbackConfig is the test seam for the loopback relay: host-only ICE and
// the forced-relay path, mirroring the engine's own parity tests.
func (s *TransferService) setLoopbackConfig() {
	s.forceRelay = true
	s.iceServers = []webrtc.ICEServer{}
}

// Handle identifies a started transfer.
type Handle struct {
	ID   string `json:"id"`
	Role string `json:"role"` // send | receive
}

// transferRun is one in-flight transfer. It owns the engine Controls once the
// channel opens and the rolling rate samples for speed/ETA.
type transferRun struct {
	id   string
	role wire.Role

	svc  *TransferService
	ctx  context.Context
	canc context.CancelFunc

	mu       sync.Mutex
	controls transfer.Controls

	files       []FileInfo
	totalBytes  int64
	doneBytes   int64
	reused      int64 // verified baseline reused at resume (0 for fresh transfers)
	fileIdx     int
	fileBytes   int64
	fileSize    int64
	filesDone   int
	paused      bool
	canceled    bool
	failed      bool
	resumed     bool
	transport   string
	fingerprint string

	samples []progressSample
	now     func() time.Time
}

type progressSample struct {
	at    time.Time
	bytes int64
}

// Send starts an offerer (send) transfer for the given files/folders and
// returns immediately. The invite (code/link/QR) is streamed as an invite
// event once the room is allocated.
func (s *TransferService) Send(paths []string, server string) (Handle, error) {
	if len(paths) == 0 {
		return Handle{}, errors.New("no files or folders selected")
	}
	if server == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}
	if err := validatePaths(paths); err != nil {
		return Handle{}, err
	}
	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleOfferer)
	sources, total, err := transfer.NewOSFileSources(paths)
	if err != nil {
		s.remove(r)
		return Handle{}, err
	}
	for _, src := range sources {
		meta := src.Meta()
		r.mu.Lock()
		r.files = append(r.files, FileInfo{Name: meta.Name, Size: meta.Size})
		r.totalBytes += meta.Size
		r.mu.Unlock()
	}
	_ = total

	go r.runSend(r.ctx, server, sources, paths, iceServers)
	return Handle{ID: id, Role: "send"}, nil
}

// targetedPeer holds the trust-bound resolution of a paired device for an
// opaque-rendezvous send, shared by file sends and encrypted handoffs.
type targetedPeer struct {
	opaqueOpts   *rendezvous.OpaqueOptions
	label        string
	deviceID     string
	peerDeviceID string
}

// resolveTargetedPeer performs the trust-bound device lookup, revocation check,
// pair-secret resolution, and opaque rendezvous construction for a targeted send.
// The pair credential — not labels or last-seen — is what authenticates the peer.
func (s *TransferService) resolveTargetedPeer(deviceID string) (*targetedPeer, error) {
	if deviceID == "" {
		return nil, errors.New("device ID is required")
	}
	ds := s.DeviceService()
	if ds == nil {
		return nil, errors.New("device service not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dev, err := ds.GetStore().GetDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device %s not found: %w", deviceID, err)
	}
	tombstones := ds.GetTombstoneStore()
	if dev.Revoked || (tombstones != nil && tombstones.HasTombstone(ctx, dev.DeviceID)) {
		return nil, fmt.Errorf("trust for device %q is revoked", dev.LocalLabel)
	}
	kPair, err := ds.GetCredentialStore().ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
	if err != nil || len(kPair) == 0 {
		return nil, fmt.Errorf("failed to resolve pair secret for device %q: %w", dev.LocalLabel, err)
	}
	peerPubKey, err := wire.ParsePublicKeyHex(dev.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key for device %q: %w", dev.LocalLabel, err)
	}
	localID, err := ds.GetIdentityManager().GetOrCreateIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to get local identity: %w", err)
	}

	handle := wire.DeriveRendezvousHandleForTime(kPair, time.Now().UTC(), wire.DefaultRendezvousEpochWindow)
	replayCache := wire.NewNonceReplayCache(5 * time.Minute)
	opaqueOpts := &rendezvous.OpaqueOptions{
		Role:              rendezvous.RoleOfferer,
		Handle:            handle,
		LocalIdentity:     localID,
		PeerDeviceID:      dev.DeviceID,
		PeerPublicKey:     peerPubKey,
		KPair:             kPair,
		PairCredentialRef: dev.PairCredentialRef,
		// V20-PR06: advertise handoff support so the negotiated intersection
		// can grant it; without this the driver's fail-closed downgrade
		// check would refuse every targeted handoff even to a capable peer.
		LocalCaps:   []string{"sendbeam/3", "rendezvous", "resume", wire.HandoffCapability},
		ReplayCache: replayCache,
		Tombstones:  tombstones,
		TrustStore:  ds.GetStore(),
	}
	return &targetedPeer{
		opaqueOpts:   opaqueOpts,
		label:        dev.LocalLabel,
		deviceID:     dev.DeviceID,
		peerDeviceID: dev.DeviceID,
	}, nil
}

// resolveSendServer applies the configured server URL default.
func (s *TransferService) resolveSendServer(server string) string {
	if server == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}
	return server
}

// SendToDevice starts a targeted send to a paired trusted device using sendbeam/3 opaque rendezvous.
func (s *TransferService) SendToDevice(paths []string, deviceID string, server string) (Handle, error) {
	if len(paths) == 0 {
		return Handle{}, errors.New("no files or folders selected")
	}
	server = s.resolveSendServer(server)
	if err := validatePaths(paths); err != nil {
		return Handle{}, err
	}
	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	peer, err := s.resolveTargetedPeer(deviceID)
	if err != nil {
		return Handle{}, err
	}

	sources, total, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleOfferer)
	for _, src := range sources {
		meta := src.Meta()
		r.mu.Lock()
		r.files = append(r.files, FileInfo{Name: meta.Name, Size: meta.Size})
		r.totalBytes += meta.Size
		r.mu.Unlock()
	}
	_ = total

	go r.runSendTargeted(r.ctx, server, sources, nil, iceServers, peer.opaqueOpts, peer.label, peer.peerDeviceID, "")
	return Handle{ID: id, Role: "send"}, nil
}

// SendToDeviceLocal sends files to a trusted device over the LAN only — no
// signaling server, STUN/TURN, or relay is contacted (V21-PR06). The peer
// must be a non-revoked trusted device currently seen on the LAN
// (DeviceService presence); otherwise the send fails closed with a clear
// error instead of falling back to public infrastructure.
func (s *TransferService) SendToDeviceLocal(paths []string, deviceID string) (Handle, error) {
	if len(paths) == 0 {
		return Handle{}, errors.New("no files or folders selected")
	}
	if err := validatePaths(paths); err != nil {
		return Handle{}, err
	}
	peer, err := s.resolveTargetedPeer(deviceID)
	if err != nil {
		return Handle{}, err
	}
	ds := s.DeviceService()
	if ds == nil {
		return Handle{}, errors.New("device service not available")
	}
	endpoint, ok := ds.DirectEndpointFor(deviceID)
	if !ok {
		return Handle{}, fmt.Errorf("device %q is not reachable on the local network (no live LAN endpoint); local-only send refuses any online fallback", peer.label)
	}

	sources, total, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleOfferer)
	for _, src := range sources {
		meta := src.Meta()
		r.mu.Lock()
		r.files = append(r.files, FileInfo{Name: meta.Name, Size: meta.Size})
		r.totalBytes += meta.Size
		r.mu.Unlock()
	}
	_ = total

	go r.runSendLocal(r.ctx, sources, peer, endpoint)
	return Handle{ID: id, Role: "send"}, nil
}

// runSendLocal drives one local-only offerer transfer through
// packages/engine/localtransfer, mirroring runSendTargeted's progress and
// event flow. The peer endpoint was validated against the interface-derived
// route policy before dialing.
func (r *transferRun) runSendLocal(ctx context.Context, sources []wire.FileSource, peer *targetedPeer, endpoint string) {
	defer r.svc.remove(r)
	if err := r.doSendLocal(ctx, sources, peer, endpoint); err != nil {
		r.fail(err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
	}
}

// doSendLocal performs one local-only offerer transfer attempt (V21-PR06).
// It reports connect/progress/transport events and publishes completion on
// success; on failure it returns the error without failing the run, so a
// prefer-local caller can fall back to the online path on the same run.
func (r *transferRun) doSendLocal(ctx context.Context, sources []wire.FileSource, peer *targetedPeer, endpoint string) error {

	lastProgress := time.Time{}
	emitProgress := func() {
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond {
			return
		}
		lastProgress = now
		r.publish("progress")
	}

	// Route gate: the discovered LAN endpoint must validate against the
	// local interfaces. A stale or spoofed presence entry pointing
	// off-LAN fails closed here. AllowLoopback stays true (V21-PR07
	// review): loopback cannot cause public egress, the peer is still
	// trust-gated and Opaque-authenticated, and same-host operation
	// needs it.
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	if _, err := tab.AddManual(peer.peerDeviceID, endpoint); err != nil {
		return fmt.Errorf("local endpoint rejected: %w", err)
	}

	requirePadding := r.svc.requirePaddingConfig() || r.svc.isDeviceRequirePadding(peer.peerDeviceID)

	out, err := localtransfer.Transfer(ctx, localtransfer.Options{
		Identity:       peer.opaqueOpts.LocalIdentity,
		Store:          r.svc.DeviceService().GetStore(),
		Resolver:       r.svc.DeviceService().GetCredentialStore(),
		Table:          tab,
		PeerDeviceID:   peer.peerDeviceID,
		PeerLabel:      peer.label,
		Role:           rendezvous.RoleOfferer,
		Sources:        sources,
		RequirePadding: requirePadding,
		Private:        requirePadding,
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnProgress: func(n int64) {
			r.mu.Lock()
			r.doneBytes = n
			r.recordSample(n)
			r.mu.Unlock()
			emitProgress()
		},
	})
	if err != nil {
		return err
	}

	r.mu.Lock()
	var done int64
	for i, f := range out.Files {
		done += f.Size
		if i < len(r.files) {
			r.files[i].Size = f.Size
		}
	}
	r.doneBytes = done
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		summary := fmt.Sprintf("Sent %d file(s) (%s) to %s over the local network", len(out.Files), humanBytes(r.totalBytes), peer.label)
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, "")
	}
	return nil
}

// resetLeg clears per-attempt progress so a fallback leg starts clean on
// the same run (V21-PR07). The file list and totals are kept.
func (r *transferRun) resetLeg() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.doneBytes = 0
	r.reused = 0
	r.fileIdx = 0
	r.fileBytes = 0
	r.fileSize = 0
	r.filesDone = 0
	r.paused = false
	r.canceled = false
	r.failed = false
	r.resumed = false
	r.transport = ""
	r.fingerprint = ""
	r.samples = nil
}

// runSendPreferLocal tries the LAN path first and falls back to the online
// path explicitly when the local attempt fails (V21-PR07). Both legs share
// one run so progress, transport, and state events stay coherent in the UI;
// the fallback is announced as a state event, never silent.
func (r *transferRun) runSendPreferLocal(ctx context.Context, server string, sources []wire.FileSource, iceServers []webrtc.ICEServer, peer *targetedPeer, endpoint string) {
	defer r.svc.remove(r)

	r.publish("state", func(ev *TransferEvent) { ev.State = "trying local route…" })
	if err := r.doSendLocal(ctx, sources, peer, endpoint); err == nil {
		return
	} else {
		r.publish("state", func(ev *TransferEvent) {
			ev.State = "local route failed; falling back to online"
		})
	}
	r.resetLeg()
	r.runSendTargetedCore(ctx, server, sources, iceServers, peer.opaqueOpts, peer.label, peer.peerDeviceID, "")
}

// SendToDevicePreferLocal sends files to a trusted device preferring the
// LAN path (V21-PR07): when the peer has a live local endpoint the transfer
// tries the offline route first and falls back to the online path
// explicitly if it fails; with no live endpoint it goes online directly.
// The route taken is visible in the transfer's transport/state events.
func (s *TransferService) SendToDevicePreferLocal(paths []string, deviceID string, server string) (Handle, error) {
	if len(paths) == 0 {
		return Handle{}, errors.New("no files or folders selected")
	}
	server = s.resolveSendServer(server)
	if err := validatePaths(paths); err != nil {
		return Handle{}, err
	}
	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	peer, err := s.resolveTargetedPeer(deviceID)
	if err != nil {
		return Handle{}, err
	}

	sources, total, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleOfferer)
	for _, src := range sources {
		meta := src.Meta()
		r.mu.Lock()
		r.files = append(r.files, FileInfo{Name: meta.Name, Size: meta.Size})
		r.totalBytes += meta.Size
		r.mu.Unlock()
	}
	_ = total

	ds := s.DeviceService()
	if ds == nil {
		return Handle{}, errors.New("device service not available")
	}
	if endpoint, ok := ds.DirectEndpointFor(deviceID); ok {
		go r.runSendPreferLocal(r.ctx, server, sources, iceServers, peer, endpoint)
		return Handle{ID: id, Role: "send"}, nil
	}
	// No live LAN endpoint: nothing local to prefer, go online directly.
	go r.runSendTargeted(r.ctx, server, sources, nil, iceServers, peer.opaqueOpts, peer.label, peer.peerDeviceID, "")
	return Handle{ID: id, Role: "send"}, nil
}

// kind must be "text" or "link". The envelope is a single in-memory payload of
// at most 256 KiB; it is never recorded as a sender job and never resumes —
// the payload is verified before the receiver may Copy/Save/Open it.
func (s *TransferService) SendHandoffToDevice(kind, text, deviceID, server string) (Handle, error) {
	if kind != wire.ContentKindText && kind != wire.ContentKindLink {
		return Handle{}, fmt.Errorf("handoff kind must be %q or %q", wire.ContentKindText, wire.ContentKindLink)
	}
	server = s.resolveSendServer(server)
	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	peer, err := s.resolveTargetedPeer(deviceID)
	if err != nil {
		return Handle{}, err
	}

	src, err := transfer.NewTextSource(kind, text)
	if err != nil {
		return Handle{}, err
	}
	sources := []wire.FileSource{src}

	id := s.newID()
	r := s.newRun(id, wire.RoleOfferer)
	meta := src.Meta()
	r.files = append(r.files, FileInfo{Name: meta.Name, Size: meta.Size})
	r.totalBytes += meta.Size

	go r.runSendTargeted(r.ctx, server, sources, nil, iceServers, peer.opaqueOpts, peer.label, peer.peerDeviceID, kind)
	return Handle{ID: id, Role: "send"}, nil
}

// BroadcastSend sends files concurrently to multiple trusted devices.
func (s *TransferService) BroadcastSend(paths []string, deviceIDs []string, server string) ([]transfer.TargetResult, error) {
	if len(paths) == 0 {
		return nil, errors.New("no files or folders selected")
	}
	if len(deviceIDs) == 0 {
		return nil, errors.New("no target devices selected")
	}
	if server == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}
	if err := validatePaths(paths); err != nil {
		return nil, err
	}
	iceServers, err := s.resolveICEServers()
	if err != nil {
		return nil, err
	}

	ds := s.DeviceService()
	if ds == nil {
		return nil, errors.New("device service not available")
	}

	ctx := context.Background()
	localID, err := ds.GetIdentityManager().GetOrCreateIdentity()
	if err != nil {
		return nil, fmt.Errorf("local identity error: %w", err)
	}

	sources, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return nil, err
	}

	replayCache := wire.NewNonceReplayCache(5 * time.Minute)
	targets := make([]transfer.BroadcastTarget, 0, len(deviceIDs))

	for _, devID := range deviceIDs {
		dev, err := ds.GetStore().GetDevice(ctx, devID)
		if err != nil {
			return nil, fmt.Errorf("device %s not found: %w", devID, err)
		}
		tombstones := ds.GetTombstoneStore()
		if dev.Revoked || (tombstones != nil && tombstones.HasTombstone(ctx, dev.DeviceID)) {
			return nil, fmt.Errorf("trust for device %q is revoked", dev.LocalLabel)
		}
		kPair, err := ds.GetCredentialStore().ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err != nil || len(kPair) == 0 {
			return nil, fmt.Errorf("failed to resolve pair secret for device %q: %w", dev.LocalLabel, err)
		}
		peerPubKey, err := wire.ParsePublicKeyHex(dev.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key for device %q: %w", dev.LocalLabel, err)
		}

		handle := wire.DeriveRendezvousHandleForTime(kPair, time.Now().UTC(), wire.DefaultRendezvousEpochWindow)
		opaqueOpts := &rendezvous.OpaqueOptions{
			Role:              rendezvous.RoleOfferer,
			Handle:            handle,
			LocalIdentity:     localID,
			PeerDeviceID:      dev.DeviceID,
			PeerPublicKey:     peerPubKey,
			KPair:             kPair,
			PairCredentialRef: dev.PairCredentialRef,
			// V20-PR06: advertise handoff support so the negotiated intersection
			// can grant it; without this the driver's fail-closed downgrade
			// check would refuse every targeted handoff even to a capable peer.
			LocalCaps:   []string{"sendbeam/3", "rendezvous", "resume", wire.HandoffCapability},
			ReplayCache: replayCache,
			Tombstones:  tombstones,
			TrustStore:  ds.GetStore(),
		}

		requirePadding := s.requirePaddingConfig() || dev.Policy.RequirePadding
		spec := transfer.Spec{
			Opaque:         opaqueOpts,
			PeerDeviceID:   dev.DeviceID,
			PeerLabel:      dev.LocalLabel,
			Sources:        sources,
			ICEServers:     iceServers,
			ForceRelay:     s.forceRelay,
			RequirePadding: requirePadding,
			Private:        requirePadding,
		}

		targets = append(targets, transfer.BroadcastTarget{
			ID:    dev.DeviceID,
			Label: dev.LocalLabel,
			Dial: func(dialCtx context.Context) (transfer.Signal, error) {
				return s.dial(dialCtx, server, wire.RoleOfferer)
			},
			Spec: spec,
		})
	}

	bResult := transfer.RunBroadcast(ctx, targets, transfer.BroadcastOptions{
		Concurrency: 4,
	})

	return bResult.Results, nil
}

// Receive starts a joiner (receive) transfer for a code (or a full invite
// link) into destDir and returns immediately. The file set is streamed as a
// manifest event once the sender's manifest arrives.
func (s *TransferService) Receive(code string, destDir string, server string) (Handle, error) {
	if code == "" {
		return Handle{}, errors.New("an invite code (or link) is required")
	}
	code = normalizeCode(code)
	if destDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				destDir = cfg.DownloadDir
			}
		}
		if destDir == "" {
			destDir = "."
		}
	}
	if server == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return Handle{}, fmt.Errorf("create destination: %w", err)
	}
	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleJoiner)

	go r.runReceive(r.ctx, code, destDir, server, iceServers)
	return Handle{ID: id, Role: "receive"}, nil
}

// StageSharePaths queues share paths (OS Share / Send to / Open with) that
// arrived before the frontend was ready to receive the drop event. The
// frontend drains them on boot with TakeStagedShares.
func (s *TransferService) StageSharePaths(paths []string) {
	if len(paths) == 0 {
		return
	}
	cp := append([]string(nil), paths...)
	s.shareMu.Lock()
	s.stagedShares = append(s.stagedShares, cp)
	s.shareMu.Unlock()
}

// TakeStagedShares atomically drains staged share paths and marks the share
// UI ready: after this call the frontend is subscribed to transfer events, so
// new shares can be dropped straight into the composer.
func (s *TransferService) TakeStagedShares() []string {
	s.shareMu.Lock()
	defer s.shareMu.Unlock()
	s.shareUIReady = true
	var out []string
	for _, batch := range s.stagedShares {
		out = append(out, batch...)
	}
	s.stagedShares = nil
	return out
}

// ShareUIReady reports whether the frontend has drained the share inbox at
// least once (i.e. it is subscribed to transfer events).
func (s *TransferService) ShareUIReady() bool {
	s.shareMu.Lock()
	defer s.shareMu.Unlock()
	return s.shareUIReady
}

// Drop starts a send for paths dropped onto the window, mirroring Send.
func (s *TransferService) Drop(paths []string) (Handle, error) {
	return s.Send(paths, "")
}

// Pause pauses the transfer with id (both sides stop producing new data).
func (s *TransferService) Pause(id string) error {
	return s.control(id, func(c transfer.Controls) error { return c.Pause() })
}

// Resume resumes the transfer with id.
func (s *TransferService) Resume(id string) error {
	return s.control(id, func(c transfer.Controls) error { return c.Resume() })
}

// Cancel cancels the transfer with id.
func (s *TransferService) Cancel(id string) error {
	return s.control(id, func(c transfer.Controls) error { return c.Cancel("canceled by user") })
}

// ListInterrupted surfaces interrupted durable receive journals and sender records.
func (s *TransferService) ListInterrupted(outDir string) ([]DurableTransferItem, error) {
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}

	var items []DurableTransferItem

	// 1. Durable receive entries
	if store, err := s.openDurableStore(outDir); err == nil {
		if entries, err := store.List(); err == nil {
			for _, e := range entries {
				item := DurableTransferItem{
					TransferID:     e.TransferID,
					Role:           "receive",
					TotalBytes:     e.TotalSize,
					CommittedBytes: e.CommittedBytes,
					Files:          e.Files,
					CreatedAt:      e.UpdatedAt,
					UpdatedAt:      e.UpdatedAt,
					Status:         durableStatus(e),
					Resumable:      e.JournalOK && e.PartialOK && e.HasResumeSecret,
				}
				items = append(items, item)
			}
		}
	}

	// 2. Interrupted sender records
	s.mu.Lock()
	sstore := s.senderStore
	s.mu.Unlock()
	if sstore != nil {
		if senderEntries, err := sstore.List(); err == nil {
			for _, e := range senderEntries {
				item := DurableTransferItem{
					TransferID:     e.TransferID,
					Role:           "send",
					TotalBytes:     e.TotalSize,
					CommittedBytes: 0,
					Files:          e.Files,
					CreatedAt:      e.CreatedAt,
					UpdatedAt:      e.UpdatedAt,
					Status:         senderStatus(e),
					Resumable:      e.RecordOK && e.HasResumeSecret,
					Paths:          e.Paths,
				}
				items = append(items, item)
			}
		}
	}

	return items, nil
}

// InspectInterrupted checks the consistency of one interrupted receive journal.
func (s *TransferService) InspectInterrupted(transferID string, outDir string) (DurableInspectResult, error) {
	if transferID == "" {
		return DurableInspectResult{}, errors.New("transfer id is required")
	}
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}
	store, err := s.openDurableStore(outDir)
	if err != nil {
		return DurableInspectResult{}, err
	}
	ins, err := store.Inspect(transferID)
	if err != nil {
		return DurableInspectResult{}, err
	}

	res := DurableInspectResult{
		TransferID:          ins.Journal.TransferID,
		TotalBytes:          ins.Total,
		CommittedBytes:      ins.Committed,
		CreatedAt:           ins.Journal.CreatedAt,
		UpdatedAt:           ins.Journal.UpdatedAt,
		ProtocolVersion:     ins.Journal.ProtocolVersion,
		ManifestFingerprint: ins.Journal.ManifestFingerprint,
		JournalPath:         ins.JournalPath,
		PartialDir:          ins.PartialDir,
		Resumable:           ins.Resumable,
		Problems:            ins.Problems,
	}
	for _, f := range ins.Journal.Files {
		res.Files = append(res.Files, FileInfo{Name: f.Name, Size: f.Size})
	}
	return res, nil
}

// ResumeInterrupted resumes an interrupted receive transfer using its stored credentials.
func (s *TransferService) ResumeInterrupted(transferID string, code string, destDir string, server string) (Handle, error) {
	if transferID == "" {
		return Handle{}, errors.New("transfer id is required")
	}
	if code == "" {
		return Handle{}, errors.New("an invite code from the sender is required to resume")
	}
	code = normalizeCode(code)
	if destDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				destDir = cfg.DownloadDir
			}
		}
		if destDir == "" {
			destDir = "."
		}
	}
	if server == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}

	store, err := s.openDurableStore(destDir)
	if err != nil {
		return Handle{}, err
	}
	ins, err := store.Inspect(transferID)
	if err != nil {
		return Handle{}, err
	}
	if !ins.Resumable {
		return Handle{}, fmt.Errorf("transfer %s is not resumable: %s", transferID, strings.Join(ins.Problems, "; "))
	}
	if ins.Journal.ResumeSecret == nil {
		return Handle{}, fmt.Errorf("transfer %s has no resume credential (legacy state); restart required", transferID)
	}
	secret, err := wire.DecodeResumeSecretEnvelope(&wire.ResumeSecretEnvelope{
		Version: ins.Journal.ResumeSecret.Version,
		Value:   ins.Journal.ResumeSecret.Value,
	})
	if err != nil {
		return Handle{}, fmt.Errorf("decode resume credential for %s: %w", transferID, err)
	}

	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleJoiner)
	go r.runResumeReceive(r.ctx, transferID, code, destDir, server, secret, ins, iceServers)
	return Handle{ID: id, Role: "receive"}, nil
}

// DiscardInterrupted removes persistent state for one transfer id (idempotent).
func (s *TransferService) DiscardInterrupted(transferID string, outDir string) error {
	if transferID == "" {
		return errors.New("transfer id is required")
	}
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}

	// Discard receive journal + partials
	if store, err := s.openDurableStore(outDir); err == nil {
		_ = store.Discard(transferID)
	}
	// Discard sender record
	s.mu.Lock()
	sstore := s.senderStore
	s.mu.Unlock()
	if sstore != nil {
		_ = sstore.Discard(transferID)
	}
	return nil
}

// DiscardAllInterrupted removes all durable transfer journals and sender records (idempotent).
func (s *TransferService) DiscardAllInterrupted(outDir string) error {
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}
	if store, err := s.openDurableStore(outDir); err == nil {
		_ = store.DiscardAll()
	}
	s.mu.Lock()
	sstore := s.senderStore
	s.mu.Unlock()
	if sstore != nil {
		_ = sstore.DiscardAll()
	}
	return nil
}

// RevealCompleted reveals the verified completed transfer output in the OS file manager.
// The backend derives the path and bounds it strictly to the exact trusted destination root
// recorded upon verified completion.
func (s *TransferService) RevealCompleted(id string) error {
	s.mu.Lock()
	dest, ok := s.completedDestinations[id]
	rm := s.revealMgr
	s.mu.Unlock()

	if !ok || dest.Path == "" || dest.Root == "" {
		return fmt.Errorf("no verified completed output found for transfer %q", id)
	}
	if rm == nil {
		rm = lifecycle.NewRevealManager(nil)
	}
	return rm.Reveal(dest.Path, dest.Root)
}

// GetConfig returns the desktop persistent configuration.
func (s *TransferService) GetConfig() (config.DesktopConfig, error) {
	s.mu.Lock()
	cs := s.configStore
	s.mu.Unlock()
	if cs == nil {
		return config.DefaultConfig(), nil
	}
	return cs.Load()
}

// SaveConfig saves the desktop persistent configuration.
func (s *TransferService) SaveConfig(cfg config.DesktopConfig) error {
	s.mu.Lock()
	cs := s.configStore
	s.mu.Unlock()
	if cs == nil {
		return errors.New("config store not available")
	}
	return cs.Save(cfg)
}

// SaveConfigPatch merges a partial config update into the stored config
// (V21-PR07). Only keys present in the patch change; everything else is
// preserved. The settings UI must call this (not SaveConfig) so saving
// one section never wipes fields managed elsewhere (theme, update
// channel, network policy, ...). Unknown keys and mistyped values fail
// closed before anything is written.
func (s *TransferService) SaveConfigPatch(patch map[string]any) error {
	s.mu.Lock()
	cs := s.configStore
	s.mu.Unlock()
	if cs == nil {
		return errors.New("config store not available")
	}
	cfg, err := cs.Load()
	if err != nil {
		return err
	}
	if err := config.ApplyPatch(&cfg, patch); err != nil {
		return err
	}
	return cs.Save(cfg)
}

// ActiveCount returns the number of in-flight transfers.
func (s *TransferService) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runs)
}

// Shutdown gracefully cancels active transfers and waits for bounded teardown.
func (s *TransferService) Shutdown(timeout time.Duration) error {
	s.mu.Lock()
	runs := make([]*transferRun, 0, len(s.runs))
	for _, r := range s.runs {
		runs = append(runs, r)
	}
	s.mu.Unlock()

	if len(runs) == 0 {
		return nil
	}

	for _, r := range runs {
		r.canc()
		r.mu.Lock()
		ctrl := r.controls
		r.mu.Unlock()
		if ctrl != nil {
			_ = ctrl.Cancel("application shutting down")
		}
	}

	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		remaining := len(s.runs)
		s.mu.Unlock()
		if remaining == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	s.mu.Lock()
	nativeRecv := s.nativeReceiver
	nativeCancel := s.nativeReceiverCancel
	s.nativeReceiver = nil
	s.nativeReceiverCancel = nil
	s.mu.Unlock()

	if nativeCancel != nil {
		nativeCancel()
	}
	if nativeRecv != nil {
		_ = nativeRecv.Close()
	}

	return nil
}

// StartNativeReceiverWithPolicy starts the background listener from a base
// config, then applies the persisted network policy: in local-only mode the
// public signaling rendezvous is not started (LAN discovery only), so the
// background receiver performs zero public egress (V21-PR06). The base
// config is retained so ApplyNetworkPolicy can re-apply on policy changes.
func (s *TransferService) StartNativeReceiverWithPolicy(base receiver.Config) error {
	s.mu.Lock()
	cp := base
	s.nativeReceiverBase = &cp
	s.mu.Unlock()
	return s.ApplyNetworkPolicy()
}

// ApplyNetworkPolicy restarts the background receiver so its network
// behavior matches the persisted policy. Safe to call when the receiver was
// never started (it just records the policy for the next start).
func (s *TransferService) ApplyNetworkPolicy() error {
	policy := netpolicy.Online
	if cfg, err := s.GetConfig(); err == nil {
		if p, perr := netpolicy.Parse(cfg.NetworkPolicy); perr == nil {
			policy = p
		}
	}
	s.mu.Lock()
	base := s.nativeReceiverBase
	s.mu.Unlock()
	if base == nil {
		return nil
	}
	live := *base
	if policy == netpolicy.LocalOnly {
		// No public rendezvous: the listener keeps LAN discovery only.
		live.Server = ""
		live.Dialer = nil
	}
	if err := s.StopNativeReceiver(); err != nil {
		return err
	}
	return s.StartNativeReceiver(live)
}

// StartNativeReceiver starts the background listener using the shared native receiver package.
func (s *TransferService) StartNativeReceiver(cfg receiver.Config) error {
	s.mu.Lock()
	if s.nativeReceiver != nil {
		s.mu.Unlock()
		return errors.New("native receiver already running")
	}

	if s.requirePaddingConfig() {
		cfg.RequirePadding = true
		cfg.Private = true
	}

	origStart := cfg.OnTransferStart
	cfg.OnTransferStart = func(transferID string, peerDeviceID string, manifest wire.Manifest) {
		if origStart != nil {
			origStart(transferID, peerDeviceID, manifest)
		}
		files := make([]FileInfo, len(manifest.Files))
		for i, f := range manifest.Files {
			files[i] = FileInfo{Name: f.Name, Size: f.Size}
		}
		if s.emit != nil {
			s.emit(TransferEventName, TransferEvent{
				ID:         transferID,
				Kind:       "manifest",
				Files:      files,
				TotalBytes: manifest.TotalSize,
				FilesTotal: len(manifest.Files),
				State:      "running",
			})
		}
	}

	origProgress := cfg.OnFileProgress
	cfg.OnFileProgress = func(peerDeviceID string, fileIdx int, fileBytes, ackBytes int64) {
		if origProgress != nil {
			origProgress(peerDeviceID, fileIdx, fileBytes, ackBytes)
		}
	}

	origComplete := cfg.OnTransferComplete
	cfg.OnTransferComplete = func(peerDeviceID string, outcome *transfer.Outcome) {
		if origComplete != nil {
			origComplete(peerDeviceID, outcome)
		}
		if outcome != nil && outcome.ContentKind == "" {
			// V20-PR06: a handoff has no on-disk path — nothing to record.
			s.recordCompleted(outcome.TransferID, completedDestination{
				Path: outcome.Path,
				Root: cfg.DestDir,
			})
			if s.emit != nil {
				ev := TransferEvent{
					ID:        outcome.TransferID,
					Kind:      "done",
					Digest:    outcome.Digest,
					OutDir:    cfg.DestDir,
					OutPath:   outcome.Path,
					State:     "completed",
					Percent:   100,
					DoneBytes: outcome.Size,
				}
				if outcome.ContentKind != "" {
					// V20-PR06: the verified handoff payload rides the event so the
					// UI can offer deliberate Copy/Save/Open — never auto-opened.
					ev.ContentKind = outcome.ContentKind
					ev.Content = string(outcome.Content)
				}
				s.emit(TransferEventName, ev)
			}
			if s.notifier != nil {
				if outcome.ContentKind != "" {
					s.notifier.NotifySuccess("Handoff Received", fmt.Sprintf("Verified %s handoff from %s — not opened automatically", outcome.ContentKind, peerDeviceID), "")
				} else {
					s.notifier.NotifySuccess("Transfer Complete", fmt.Sprintf("Received %s", outcome.Name), outcome.Path)
				}
			}
		}
	}

	origErr := cfg.OnTransferError
	cfg.OnTransferError = func(peerDeviceID string, err error) {
		if origErr != nil {
			origErr(peerDeviceID, err)
		}
		if s.emit != nil {
			s.emit(TransferEventName, TransferEvent{
				Kind:   "error",
				Error:  err.Error(),
				State:  "error",
				Failed: true,
			})
		}
	}

	origConsentReq := cfg.OnConsentRequested
	cfg.OnConsentRequested = func(req receiver.ConsentRequest) {
		if origConsentReq != nil {
			origConsentReq(req)
		}
		if s.emit != nil {
			s.emit(ConsentEventName, req)
			s.emit(TransferEventName, TransferEvent{
				ID:          req.TransferID,
				Kind:        "consent_requested",
				TotalBytes:  req.TotalSize,
				OutDir:      req.DestDir,
				State:       "waiting_consent",
				ContentKind: req.ContentKind,
			})
		}
	}

	listener, err := receiver.NewListener(cfg)
	if err != nil {
		s.mu.Unlock()
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.nativeReceiver = listener
	s.nativeReceiverCancel = cancel
	s.mu.Unlock()

	go func() {
		_ = listener.Start(ctx)
	}()

	return nil
}

// StopNativeReceiver stops the background listener.
func (s *TransferService) StopNativeReceiver() error {
	s.mu.Lock()
	listener := s.nativeReceiver
	cancel := s.nativeReceiverCancel
	s.nativeReceiver = nil
	s.nativeReceiverCancel = nil
	s.mu.Unlock()

	if listener == nil {
		return nil
	}
	if cancel != nil {
		cancel()
	}
	return listener.Close()
}

// NativeReceiver returns the active native receiver instance or nil.
func (s *TransferService) NativeReceiver() *receiver.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nativeReceiver
}

// RespondConsent resolves a pending incoming transfer consent request.
func (s *TransferService) RespondConsent(transferID string, decision receiver.ConsentDecision) error {
	s.mu.Lock()
	listener := s.nativeReceiver
	s.mu.Unlock()

	if listener == nil {
		return errors.New("native receiver is not running")
	}
	return listener.RespondConsent(transferID, decision)
}

// PendingConsents returns all currently pending consent requests awaiting user decision.
func (s *TransferService) PendingConsents() []receiver.ConsentRequest {
	s.mu.Lock()
	listener := s.nativeReceiver
	s.mu.Unlock()

	if listener == nil {
		return nil
	}
	return listener.PendingConsent()
}

// control looks up the live Controls for id and applies fn.
func (s *TransferService) control(id string, fn func(transfer.Controls) error) error {
	s.mu.Lock()
	r, ok := s.runs[id]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("no active transfer %q", id)
	}
	r.mu.Lock()
	c := r.controls
	r.mu.Unlock()
	if c == nil {
		return fmt.Errorf("transfer %q has not connected yet", id)
	}
	return fn(c)
}

func (s *TransferService) newID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("t%d", s.next)
}

func (s *TransferService) newRun(id string, role wire.Role) *transferRun {
	ctx, canc := context.WithCancel(context.Background())
	r := &transferRun{
		id: id, role: role, svc: s, ctx: ctx, canc: canc,
		now: time.Now,
	}
	s.mu.Lock()
	s.runs[id] = r
	s.mu.Unlock()
	return r
}

func (s *TransferService) remove(r *transferRun) {
	r.canc()
	s.mu.Lock()
	delete(s.runs, r.id)
	s.mu.Unlock()
}

// publish sends a snapshot event to the frontend (and to tests via the
// injected emit sink). Phase is set by the callbacks via mut; the rest are the
// current run values.
func (r *transferRun) publish(kind string, mut ...func(*TransferEvent)) {
	r.mu.Lock()
	ev := &TransferEvent{
		ID:          r.id,
		Kind:        kind,
		Transport:   r.transport,
		Fingerprint: r.fingerprint,
		Files:       append([]FileInfo(nil), r.files...),
		TotalBytes:  r.totalBytes,
		DoneBytes:   r.doneBytes,
		FileBytes:   r.fileBytes,
		FileSize:    r.fileSize,
		FilesDone:   r.filesDone,
		FilesTotal:  len(r.files),
		State:       r.stateString(),
		Paused:      r.paused,
		Canceled:    r.canceled,
		Failed:      r.failed,
		Resumed:     r.resumed,
		RemainingMS: -1,
	}
	if r.totalBytes > 0 {
		ev.Percent = int(r.doneBytes * 100 / r.totalBytes)
	}
	rate, eta := r.rateAndETA()
	if rate > 0 {
		ev.RateBps = rate
		ev.ETA = formatETA(eta)
		ev.RemainingMS = eta.Milliseconds()
	}
	if r.fileIdx >= 0 && r.fileIdx < len(r.files) {
		ev.CurrentFile = r.files[r.fileIdx].Name
	}
	r.mu.Unlock()

	for _, m := range mut {
		m(ev)
	}
	if r.svc.emit != nil {
		r.svc.emit(TransferEventName, ev)
	}
}

func (r *transferRun) stateString() string {
	switch {
	case r.failed:
		return "failed"
	case r.canceled:
		return "canceled"
	case r.paused:
		return "paused"
	default:
		return "running"
	}
}

// rateAndETA computes the five-second rolling rate and remaining duration from
// the sampled acknowledged bytes (mirrors the CLI progress math).
func (r *transferRun) rateAndETA() (float64, time.Duration) {
	if len(r.samples) < 2 {
		return 0, 0
	}
	first, last := r.samples[0], r.samples[len(r.samples)-1]
	elapsed := last.at.Sub(first.at).Seconds()
	if elapsed <= 0 || last.bytes <= first.bytes {
		return 0, 0
	}
	rate := float64(last.bytes-first.bytes) / elapsed
	remaining := r.totalBytes - r.reused - r.doneBytes
	if remaining < 0 {
		remaining = 0
	}
	if rate <= 0 {
		return rate, 0
	}
	return rate, time.Duration(float64(time.Second) * float64(remaining) / rate)
}

func (r *transferRun) recordSample(bytes int64) {
	now := r.now()
	r.samples = append(r.samples, progressSample{at: now, bytes: bytes})
	cutoff := now.Add(-5 * time.Second)
	for len(r.samples) > 2 && !r.samples[1].at.After(cutoff) {
		r.samples = r.samples[1:]
	}
}

// runSend drives the offerer side of the transfer.
func (r *transferRun) runSend(ctx context.Context, server string, sources []wire.FileSource, paths []string, iceServers []webrtc.ICEServer) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleOfferer)
	if err != nil {
		r.fail("dial: " + err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", "dial: "+err.Error())
		}
		return
	}
	defer sig.Close()

	lastProgress := time.Time{}
	emitProgress := func() {
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond {
			return
		}
		lastProgress = now
		r.publish("progress")
	}

	var transferID string
	var onSendManifest func(wire.Manifest) error
	var resumeCtx *transfer.ResumeContext
	reused := false
	r.svc.mu.Lock()
	sstore := r.svc.senderStore
	r.svc.mu.Unlock()
	if sstore != nil {
		var prepErr error
		transferID, onSendManifest, reused, prepErr = transfer.PrepareSender(sstore, paths, sources)
		if prepErr != nil {
			r.fail("prepare sender: " + prepErr.Error())
			if r.svc.notifier != nil {
				r.svc.notifier.NotifyFailure("Transfer Failed", "prepare sender: "+prepErr.Error())
			}
			return
		}
		if reused {
			if srec, ok, lookupErr := sstore.Lookup(transfer.PathKey(paths)); lookupErr == nil && ok && srec.ResumeSecret != nil {
				if secret, err := wire.DecodeResumeSecretEnvelope(srec.ResumeSecret); err == nil {
					resumeCtx = &transfer.ResumeContext{
						TransferID:          srec.TransferID,
						ManifestFingerprint: srec.ManifestFingerprint,
						Role:                wire.RoleOfferer,
						ResumeSecret:        secret,
					}
				}
			}
		}
	}

	caps := rendezvous.DefaultCaps()
	if resumeCtx != nil {
		caps.Features = append(caps.Features, wire.ResumeAuthCapability)
	}

	requirePadding := r.svc.requirePaddingConfig()

	spec := transfer.Spec{
		Session: rendezvous.Options{
			Role:      rendezvous.RoleOfferer,
			LocalCaps: &caps,
			OnPhase: func(p rendezvous.Phase) {
				r.publish("phase", func(ev *TransferEvent) { ev.Phase = string(p) })
			},
			OnCode: func(code string) {
				r.publish("invite", func(ev *TransferEvent) {
					ev.Code = code
					ev.Link = inviteLink(server, code)
					ev.QR = qrDataURL(ev.Link)
				})
			},
		},
		Sources:        sources,
		TransferID:     transferID,
		RequirePadding: requirePadding,
		Private:        requirePadding,
		OnSendManifest: onSendManifest,
		OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
			if sstore != nil {
				return sstore.AttachResumeSecret(manifest, resumeRoot, !reused)
			}
			return nil
		},
		Resume: resumeCtx,
		OnResume: func(res transfer.ResumeResult) {
			if res.Authenticated {
				r.mu.Lock()
				r.resumed = true
				r.mu.Unlock()
				r.publish("progress", func(ev *TransferEvent) { ev.Resumed = true })
			}
		},
		ForceRelay:     r.svc.forceRelay,
		ICEServers:     iceServers,
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnFileProgress: r.onFileProgress,
		OnResumeProgress: func(reusedBytes int64) {
			r.mu.Lock()
			r.reused = reusedBytes
			r.mu.Unlock()
		},
		OnProgress: func(n int64) {
			r.mu.Lock()
			r.doneBytes = n
			r.recordSample(n)
			r.mu.Unlock()
			emitProgress()
		},
		OnControls: func(c transfer.Controls) {
			r.mu.Lock()
			r.controls = c
			r.mu.Unlock()
			r.publish("connect") // controls ready
		},
		OnStateChange: r.onState,
	}

	out, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		r.fail(err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
		return
	}
	r.mu.Lock()
	var done int64
	for i, f := range out.Files {
		done += f.Size
		if i < len(r.files) {
			r.files[i].Size = f.Size
		}
	}
	r.doneBytes = done
	// Verified success: every file in the set completed.
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	if sstore != nil && transferID != "" {
		_ = sstore.Discard(transferID)
	}

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		summary := fmt.Sprintf("Sent %d file(s) (%s)", len(out.Files), humanBytes(r.totalBytes))
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, "")
	}
}

// runSendTargeted drives an offerer transfer targeted to a specific paired device via opaque rendezvous.
// contentKind is "" for file sends or "text"/"link" for an encrypted handoff (V20-PR06).
func (r *transferRun) runSendTargeted(ctx context.Context, server string, sources []wire.FileSource, _ []string, iceServers []webrtc.ICEServer, opaqueOpts *rendezvous.OpaqueOptions, peerLabel, peerDeviceID, contentKind string) {
	defer r.svc.remove(r)
	r.runSendTargetedCore(ctx, server, sources, iceServers, opaqueOpts, peerLabel, peerDeviceID, contentKind)
}

// runSendTargetedCore is the online offerer path without run lifecycle
// management, so a prefer-local run can fall back to it after a failed
// local attempt on the same run (V21-PR07).
func (r *transferRun) runSendTargetedCore(ctx context.Context, server string, sources []wire.FileSource, iceServers []webrtc.ICEServer, opaqueOpts *rendezvous.OpaqueOptions, peerLabel, peerDeviceID, contentKind string) {

	sig, err := r.svc.dial(ctx, server, wire.RoleOfferer)
	if err != nil {
		r.fail("dial: " + err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", "dial: "+err.Error())
		}
		return
	}
	defer sig.Close()

	lastProgress := time.Time{}
	emitProgress := func() {
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond {
			return
		}
		lastProgress = now
		r.publish("progress")
	}

	requirePadding := r.svc.requirePaddingConfig() || r.svc.isDeviceRequirePadding(peerDeviceID)

	spec := transfer.Spec{
		Opaque:         opaqueOpts,
		PeerDeviceID:   peerDeviceID,
		PeerLabel:      peerLabel,
		Sources:        sources,
		ContentKind:    contentKind,
		ForceRelay:     r.svc.forceRelay,
		ICEServers:     iceServers,
		RequirePadding: requirePadding,
		Private:        requirePadding,
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnFileProgress: r.onFileProgress,
		OnProgress: func(n int64) {
			r.mu.Lock()
			r.doneBytes = n
			r.recordSample(n)
			r.mu.Unlock()
			emitProgress()
		},
		OnControls: func(c transfer.Controls) {
			r.mu.Lock()
			r.controls = c
			r.mu.Unlock()
			r.publish("connect")
		},
		OnStateChange: r.onState,
	}

	out, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		r.fail(err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
		return
	}

	r.mu.Lock()
	var done int64
	for i, f := range out.Files {
		done += f.Size
		if i < len(r.files) {
			r.files[i].Size = f.Size
		}
	}
	r.doneBytes = done
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		summary := fmt.Sprintf("Sent %d file(s) (%s) to %s", len(out.Files), humanBytes(r.totalBytes), peerLabel)
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, "")
	}
}

// runReceive drives the joiner side of the transfer.
func (r *transferRun) runReceive(ctx context.Context, code, destDir, server string, iceServers []webrtc.ICEServer) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleJoiner)
	if err != nil {
		r.fail("dial: " + err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", "dial: "+err.Error())
		}
		return
	}
	defer sig.Close()

	lastProgress := time.Time{}
	emitProgress := func() {
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond {
			return
		}
		lastProgress = now
		r.publish("progress")
	}
	requirePadding := r.svc.requirePaddingConfig()
	spec := transfer.Spec{
		Session: rendezvous.Options{
			Role: rendezvous.RoleJoiner,
			Code: code,
			OnPhase: func(p rendezvous.Phase) {
				r.publish("phase", func(ev *TransferEvent) { ev.Phase = string(p) })
			},
		},
		DestDir:        destDir,
		ForceRelay:     r.svc.forceRelay,
		ICEServers:     iceServers,
		RequirePadding: requirePadding,
		Private:        requirePadding,
		OnManifestSet: func(m wire.Manifest) {
			r.mu.Lock()
			r.files = r.files[:0]
			r.totalBytes = m.TotalSize
			for _, f := range m.Files {
				r.files = append(r.files, FileInfo{Name: f.Name, Size: f.Size})
			}
			r.mu.Unlock()
			r.publish("manifest")
		},
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnFileProgress: r.onFileProgress,
		OnProgress: func(n int64) {
			r.mu.Lock()
			r.doneBytes = n
			r.recordSample(n)
			r.mu.Unlock()
			emitProgress()
		},
		OnControls: func(c transfer.Controls) {
			r.mu.Lock()
			r.controls = c
			r.mu.Unlock()
			r.publish("connect") // controls ready
		},
		OnStateChange: r.onState,
	}

	out, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		r.fail(err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
		return
	}
	r.mu.Lock()
	r.doneBytes = out.Size
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	outPath := out.Path
	if len(out.Files) > 1 {
		outPath = destDir
	}

	// Record verified completed destination bound strictly to its destination root.
	// V20-PR06: handoffs live only in memory — there is no path to record.
	if out.ContentKind == "" {
		r.svc.recordCompleted(r.id, completedDestination{
			Path: outPath,
			Root: destDir,
		})
	}

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.OutDir = destDir
		if len(out.Files) == 1 {
			ev.OutPath = out.Path
		}
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		label := out.Name
		if len(out.Files) > 1 {
			label = fmt.Sprintf("%d files", len(out.Files))
		}
		summary := fmt.Sprintf("Received %s (%s) into %s", label, humanBytes(out.Size), destDir)
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, outPath)
	}
}

// runResumeReceive drives an interrupted receive transfer resumption.
func (r *transferRun) runResumeReceive(ctx context.Context, transferID, code, destDir, server string, secret []byte, ins *transfer.Inspect, iceServers []webrtc.ICEServer) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleJoiner)
	if err != nil {
		r.fail("dial: " + err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", "dial: "+err.Error())
		}
		return
	}
	defer sig.Close()

	lastProgress := time.Time{}
	emitProgress := func() {
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond {
			return
		}
		lastProgress = now
		r.publish("progress")
	}

	caps := rendezvous.DefaultCaps()
	caps.Features = append(caps.Features, wire.ResumeAuthCapability)

	resumeCtx := &transfer.ResumeContext{
		TransferID:          transferID,
		ManifestFingerprint: ins.Journal.ManifestFingerprint,
		Role:                wire.RoleJoiner,
		ResumeSecret:        secret,
	}

	requirePadding := r.svc.requirePaddingConfig()

	spec := transfer.Spec{
		Session: rendezvous.Options{
			Role:      rendezvous.RoleJoiner,
			Code:      code,
			LocalCaps: &caps,
			OnPhase: func(p rendezvous.Phase) {
				r.publish("phase", func(ev *TransferEvent) { ev.Phase = string(p) })
			},
		},
		DestDir:        destDir,
		ForceRelay:     r.svc.forceRelay,
		ICEServers:     iceServers,
		RequirePadding: requirePadding,
		Private:        requirePadding,
		Resume:         resumeCtx,
		OnResume: func(res transfer.ResumeResult) {
			if res.Authenticated {
				r.mu.Lock()
				r.resumed = true
				r.mu.Unlock()
				r.publish("progress", func(ev *TransferEvent) { ev.Resumed = true })
			}
		},
		OnManifestSet: func(m wire.Manifest) {
			r.mu.Lock()
			r.files = r.files[:0]
			r.totalBytes = m.TotalSize
			for _, f := range m.Files {
				r.files = append(r.files, FileInfo{Name: f.Name, Size: f.Size})
			}
			r.mu.Unlock()
			r.publish("manifest")
		},
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnFileProgress: r.onFileProgress,
		OnResumeProgress: func(reusedBytes int64) {
			r.mu.Lock()
			r.reused = reusedBytes
			r.mu.Unlock()
		},
		OnProgress: func(n int64) {
			r.mu.Lock()
			r.doneBytes = n
			r.recordSample(n)
			r.mu.Unlock()
			emitProgress()
		},
		OnControls: func(c transfer.Controls) {
			r.mu.Lock()
			r.controls = c
			r.mu.Unlock()
			r.publish("connect")
		},
		OnStateChange: r.onState,
	}

	out, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		r.fail(err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
		return
	}
	r.mu.Lock()
	r.doneBytes = out.Size
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	outPath := out.Path
	if len(out.Files) > 1 {
		outPath = destDir
	}

	// Record verified completed destination bound strictly to its destination root.
	// V20-PR06: handoffs live only in memory — there is no path to record.
	if out.ContentKind == "" {
		r.svc.recordCompleted(r.id, completedDestination{
			Path: outPath,
			Root: destDir,
		})
	}

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.OutDir = destDir
		if len(out.Files) == 1 {
			ev.OutPath = out.Path
		}
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		label := out.Name
		if len(out.Files) > 1 {
			label = fmt.Sprintf("%d files", len(out.Files))
		}
		summary := fmt.Sprintf("Received %s (%s) into %s", label, humanBytes(out.Size), destDir)
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, outPath)
	}
}

func (r *transferRun) onTransport(path string) {
	r.mu.Lock()
	r.transport = path
	r.mu.Unlock()
	r.publish("transport")
}

func (r *transferRun) onFileProgress(fileIdx int, fileBytes, _ int64) {
	r.mu.Lock()
	r.fileIdx = fileIdx
	r.fileBytes = fileBytes
	if fileIdx >= 0 && fileIdx < len(r.files) {
		r.fileSize = r.files[fileIdx].Size
		// A file is done when its acknowledged bytes reach its size.
		if fileBytes >= r.files[fileIdx].Size {
			if r.filesDone < fileIdx+1 {
				r.filesDone = fileIdx + 1
			}
		}
	}
	r.mu.Unlock()
}

func (r *transferRun) onState(st wire.TransferState) {
	r.mu.Lock()
	switch st {
	case wire.TransferPaused:
		r.paused = true
	case wire.TransferCanceled:
		r.canceled = true
	default:
		r.paused = false
	}
	r.mu.Unlock()
	r.publish("state")
}

func (r *transferRun) fail(why string) {
	r.mu.Lock()
	r.failed = true
	r.mu.Unlock()
	r.publish("error", func(ev *TransferEvent) { ev.Error = why })
}

// durableStatus renders receiver-side state class.
func durableStatus(entry transfer.DurableEntry) string {
	switch {
	case !entry.PartialOK:
		return "Partial data missing — inspect/discard"
	case !entry.HasResumeSecret:
		return "Legacy — restart required"
	default:
		return "Ready to resume"
	}
}

// senderStatus renders sender-side state class.
func senderStatus(entry transfer.SenderEntry) string {
	if !entry.HasResumeSecret {
		return "Legacy — restart required (no resume credential)"
	}
	return "Ready to resume (re-run to resume with receiver)"
}

// fingerprint renders the SAS fingerprint from the session master, matching
// the CLI exactly.
func fingerprint(master []byte) string {
	sum := sha256.Sum256(append([]byte("sendbeam/sas\x00"), master...))
	return fmt.Sprintf("%02x%02x %02x%02x", sum[0], sum[1], sum[2], sum[3])
}

// inviteLink turns the signaling URL into the web app's join link for the same
// deployment, matching the CLI (wss/ws → https/http, drop /ws, code in the
// fragment so it never hits the server).
func inviteLink(serverURL, code string) string {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	u.Path = "/"
	u.RawQuery = ""
	u.Fragment = code
	return u.String()
}

// normalizeCode accepts a bare code or a full invite link and returns the code.
func normalizeCode(arg string) string {
	arg = strings.TrimSpace(arg)
	if i := strings.LastIndex(arg, "#"); i >= 0 {
		return arg[i+1:]
	}
	return arg
}

// qrDataURL renders the invite link as a QR PNG data URL.
func qrDataURL(link string) string {
	if link == "" {
		return ""
	}
	png, err := qrcode.Encode(link, qrcode.Medium, 320)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

// validatePaths rejects symbolic links and missing paths up front with the
// engine's rules (NewOSFileSources re-validates; this keeps picker feedback
// instant). Also verifies canonical relative path safety to prevent destination escape.
func validatePaths(paths []string) error {
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not supported: %s", p)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("not a regular file or folder: %s", p)
		}
		// Validate base filename cannot contain traversal or invalid characters
		base := filepath.Base(p)
		if _, err := wire.NormalizeTransferPath(base); err != nil {
			return fmt.Errorf("invalid file path %s: %w", p, err)
		}
	}
	return nil
}

// humanBytes formats byte counts cleanly.
func humanBytes(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(1<<30))
	}
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	}
	if n >= 1<<10 {
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// formatETA renders a duration like the CLI (e.g. "2m 5s remaining").
func formatETA(eta time.Duration) string {
	seconds := int64(math.Ceil(eta.Seconds()))
	if seconds < 60 {
		return fmt.Sprintf("%ds remaining", seconds)
	}
	return fmt.Sprintf("%dm %ds remaining", seconds/60, seconds%60)
}
