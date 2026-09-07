// Package receiver coordinates LAN discovery, opaque rendezvous listening, consent policy, and verified transfers.
package receiver

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
)

// Listener coordinates receiving incoming transfers from trusted peers across
// LAN discovery and opaque rendezvous signaling.
type Listener struct {
	cfg        Config
	coord      *rendezvous.PresenceCoordinator
	lanService *discovery.LanDiscoveryService

	mu              sync.Mutex
	running         bool
	closed          bool
	verifiedCount   int
	onceTriggered   bool
	onceCh          chan struct{}
	stopCh          chan struct{}
	activeSessions  map[string]transfer.Signal
	listeningHndls  map[string]bool
	pendingConsents map[string]chan ConsentDecision
	pendingReqs     map[string]ConsentRequest
	replayCache     *wire.NonceReplayCache
}

// NewListener creates a new shared native receiver Listener.
func NewListener(cfg Config) (*Listener, error) {
	if cfg.Identity == nil {
		return nil, errors.New("receiver: local device identity is required")
	}
	if cfg.TrustStore == nil {
		return nil, errors.New("receiver: trust store is required")
	}
	if cfg.Secrets == nil {
		return nil, errors.New("receiver: secret resolver/store is required")
	}
	if cfg.DestDir == "" {
		cfg.DestDir = "."
	}
	absDest, err := filepath.Abs(cfg.DestDir)
	if err != nil {
		return nil, fmt.Errorf("receiver: invalid destination dir: %w", err)
	}
	cfg.DestDir = absDest

	if cfg.EpochWindow <= 0 {
		cfg.EpochWindow = wire.DefaultRendezvousEpochWindow
	}
	if cfg.BeaconInterval <= 0 {
		cfg.BeaconInterval = 3 * time.Second
	}

	coord := rendezvous.NewPresenceCoordinator(cfg.TrustStore, cfg.Secrets, cfg.EpochWindow)

	return &Listener{
		cfg:             cfg,
		coord:           coord,
		onceCh:          make(chan struct{}),
		stopCh:          make(chan struct{}),
		activeSessions:  make(map[string]transfer.Signal),
		listeningHndls:  make(map[string]bool),
		pendingConsents: make(map[string]chan ConsentDecision),
		pendingReqs:     make(map[string]ConsentRequest),
		replayCache:     wire.NewNonceReplayCache(10 * time.Minute),
	}, nil
}

// Start begins listening on LAN and signaling rendezvous channels.
// In Once mode (--once), Start blocks until exactly ONE transfer completes with verified delivery.
func (l *Listener) Start(ctx context.Context) error {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return errors.New("receiver: already running")
	}
	l.running = true
	l.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 1. LAN Discovery Service
	if l.cfg.Port > 0 {
		discCfg := discovery.Config{
			AdvertisePort:  l.cfg.Port,
			BeaconInterval: l.cfg.BeaconInterval,
			EpochWindow:    wire.DefaultLanBeaconEpochWindow,
		}
		l.lanService = discovery.NewLanDiscoveryService(discCfg, l.cfg.TrustStore, l.cfg.Secrets)
		if l.cfg.PacketConn != nil {
			l.lanService.SetPacketConn(l.cfg.PacketConn)
		}
		l.lanService.OnPeerDiscovered(func(peer discovery.DiscoveredPeer) {
			if l.cfg.OnPeerDiscovered != nil {
				l.cfg.OnPeerDiscovered(peer)
			}
		})
		go func() {
			_ = l.lanService.Start(ctx)
		}()
	}

	// 2. Signaling Opaque Rendezvous Listeners
	if l.cfg.Server != "" || l.cfg.Dialer != nil {
		go l.rendezvousLoop(ctx)
	}

	if l.cfg.OnListening != nil {
		l.cfg.OnListening()
	}

	// In Once mode, block until one verified delivery completes or context is cancelled
	if l.cfg.Once {
		select {
		case <-l.onceCh:
			_ = l.Close()
			return nil
		case <-l.stopCh:
			return nil
		case <-ctx.Done():
			_ = l.Close()
			return ctx.Err()
		}
	}

	// In continuous mode, run until context cancellation or explicit Close
	select {
	case <-l.stopCh:
		return nil
	case <-ctx.Done():
		_ = l.Close()
		return ctx.Err()
	}
}

func (l *Listener) dialSignal(ctx context.Context, serverURL string) (transfer.Signal, error) {
	if l.cfg.Dialer != nil {
		return l.cfg.Dialer(ctx, serverURL)
	}
	return wsclient.Dial(ctx, serverURL, wsclient.DialOptions{
		InsecureSkipVerify: true,
	})
}

func (l *Listener) rendezvousLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	l.refreshHandles(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.refreshHandles(ctx)
		}
	}
}

func (l *Listener) refreshHandles(ctx context.Context) {
	handlesMap, err := l.coord.GetActiveHandles(ctx, time.Now().UTC())
	if err != nil || len(handlesMap) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for deviceID, handles := range handlesMap {
		for _, handle := range handles {
			if l.listeningHndls[handle] {
				continue
			}
			l.listeningHndls[handle] = true
			go l.listenOnHandle(ctx, deviceID, handle)
		}
	}
}

func (l *Listener) listenOnHandle(ctx context.Context, peerDeviceID string, handle string) {
	defer func() {
		l.mu.Lock()
		delete(l.listeningHndls, handle)
		l.mu.Unlock()
	}()

	sig, err := l.dialSignal(ctx, l.cfg.Server)
	if err != nil {
		return
	}
	defer sig.Close()

	sessionKey := fmt.Sprintf("%s:%s", peerDeviceID, handle)
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.activeSessions[sessionKey] = sig
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.activeSessions, sessionKey)
		l.mu.Unlock()
	}()

	// Register as joiner on opaque handle room
	_ = sig.Send(rendezvous.Message{
		Type:   "rendezvous",
		Handle: handle,
		Role:   "joiner",
	})

	_, _ = l.HandleIncomingSession(ctx, sig, peerDeviceID, handle)
}

// HandleIncomingSession runs a complete transfer receive session with a peer over sig.
func (l *Listener) HandleIncomingSession(ctx context.Context, sig transfer.Signal, peerDeviceID string, handle string) (*transfer.Outcome, error) {
	if l.cfg.Tombstones != nil && l.cfg.Tombstones.HasTombstone(ctx, peerDeviceID) {
		sig.Close()
		return nil, wire.ErrTrustedPeerRevoked
	}

	dev, err := l.cfg.TrustStore.GetDevice(ctx, peerDeviceID)
	if err != nil || dev == nil {
		sig.Close()
		return nil, wire.ErrTrustedPeerMismatch
	}
	if dev.Revoked {
		sig.Close()
		return nil, wire.ErrTrustedPeerRevoked
	}

	kPair, err := l.cfg.Secrets.ResolvePairSecret(ctx, peerDeviceID, dev.PairCredentialRef)
	if err != nil || len(kPair) == 0 {
		sig.Close()
		return nil, wire.Errorf(wire.CodeAuth, "resolve pair secret for %s: %v", peerDeviceID, err)
	}

	peerPubKey, err := wire.ParsePublicKeyHex(dev.PublicKey)
	if err != nil {
		sig.Close()
		return nil, wire.Errorf(wire.CodeAuth, "decode peer public key: %v", err)
	}

	spec := transfer.Spec{
		Opaque: &rendezvous.OpaqueOptions{
			Role:              rendezvous.RoleJoiner,
			Handle:            handle,
			LocalIdentity:     l.cfg.Identity,
			PeerDeviceID:      peerDeviceID,
			PeerPublicKey:     peerPubKey,
			KPair:             kPair,
			PairCredentialRef: dev.PairCredentialRef,
			LocalCaps:         []string{"sendbeam/3", "rendezvous", "resume"},
			ReplayCache:       l.replayCache,
			Tombstones:        l.cfg.Tombstones,
			TrustStore:        l.cfg.TrustStore,
		},
		DestDir:      l.cfg.DestDir,
		ForceRelay:   l.cfg.ForceRelay,
		Private:      l.cfg.Private,
		RelayJitter:  l.cfg.RelayJitter,
		ICEServers:   l.cfg.ICEServers,
		PeerDeviceID: peerDeviceID,
		PeerLabel:    dev.LocalLabel,
		Consent: func(cctx context.Context, req transfer.ConsentRequest) (transfer.ConsentDecision, error) {
			return l.evaluateConsent(cctx, dev, req)
		},
		OnManifestSet: func(manifest wire.Manifest) {
			if l.cfg.OnTransferStart != nil {
				l.cfg.OnTransferStart(manifest.TransferID, peerDeviceID, manifest)
			}
		},
		OnProgress: func(ack int64) {
			if l.cfg.OnProgress != nil {
				l.cfg.OnProgress(peerDeviceID, ack)
			}
		},
		OnFileProgress: func(fileIdx int, fileBytes, ackBytes int64) {
			if l.cfg.OnFileProgress != nil {
				l.cfg.OnFileProgress(peerDeviceID, fileIdx, fileBytes, ackBytes)
			}
		},
	}

	outcome, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		if l.cfg.OnTransferError != nil {
			l.cfg.OnTransferError(peerDeviceID, err)
		}
		return nil, err
	}

	// Verified delivery!
	l.mu.Lock()
	l.verifiedCount++
	l.mu.Unlock()

	if l.cfg.OnTransferComplete != nil {
		l.cfg.OnTransferComplete(peerDeviceID, outcome)
	}

	if l.cfg.Once {
		l.triggerOnceComplete()
	}

	return outcome, nil
}

func (l *Listener) evaluateConsent(ctx context.Context, dev *wire.TrustRecord, req transfer.ConsentRequest) (transfer.ConsentDecision, error) {
	manifest := wire.Manifest{
		TransferID: req.TransferID,
		Files:      req.Files,
		TotalSize:  req.TotalSize,
	}

	return EvaluateConsent(ctx, l.cfg.TrustStore, l.cfg.Tombstones, l.cfg.AutoAccept, l.cfg.DestDir, dev.DeviceID, manifest, func(cctx context.Context, creq transfer.ConsentRequest) (transfer.ConsentDecision, error) {
		if l.cfg.ConsentHandler != nil {
			return l.cfg.ConsentHandler(cctx, creq)
		}

		// Asynchronous pending consent queue (desktop UI)
		l.mu.Lock()
		respCh := make(chan ConsentDecision, 1)
		l.pendingConsents[creq.TransferID] = respCh
		l.pendingReqs[creq.TransferID] = creq
		l.mu.Unlock()

		if l.cfg.OnConsentRequested != nil {
			l.cfg.OnConsentRequested(creq)
		}

		defer func() {
			l.mu.Lock()
			delete(l.pendingConsents, creq.TransferID)
			delete(l.pendingReqs, creq.TransferID)
			l.mu.Unlock()
		}()

		select {
		case decision := <-respCh:
			return decision, nil
		case <-cctx.Done():
			return ConsentDecision{Accepted: false, Reason: "request timed out or cancelled"}, cctx.Err()
		}
	})
}

func (l *Listener) triggerOnceComplete() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.onceTriggered {
		l.onceTriggered = true
		select {
		case <-l.onceCh:
		default:
			close(l.onceCh)
		}
	}
}

// VerifiedDeliveries returns the number of successfully verified incoming file deliveries.
func (l *Listener) VerifiedDeliveries() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.verifiedCount
}

// PendingConsent returns a snapshot of all active consent requests awaiting a response.
func (l *Listener) PendingConsent() []ConsentRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]ConsentRequest, 0, len(l.pendingReqs))
	for _, req := range l.pendingReqs {
		out = append(out, req)
	}
	return out
}

// RespondConsent resolves a pending consent request with an acceptance or rejection decision.
func (l *Listener) RespondConsent(transferID string, decision ConsentDecision) error {
	l.mu.Lock()
	ch, ok := l.pendingConsents[transferID]
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("no pending consent request for transfer ID: %s", transferID)
	}
	select {
	case ch <- decision:
		return nil
	default:
		return errors.New("consent response already sent")
	}
}

// Close stops the listener and terminates all active sessions.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.running = false
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
	sessions := make([]transfer.Signal, 0, len(l.activeSessions))
	for _, sig := range l.activeSessions {
		sessions = append(sessions, sig)
	}
	l.mu.Unlock()

	for _, sig := range sessions {
		sig.Close()
	}
	return nil
}
