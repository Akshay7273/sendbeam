// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// localListenPort is the LAN port the desktop's offline listener binds. The
// LAN presence beacon already advertises this port, so peers dial
// <beacon-source-ip>:localListenPort. Binding it (rather than an ephemeral
// port) is what makes the advertised endpoint real.
const localListenPort = 53317

// LocalConsentDecision is the Wails-bound answer to a local incoming-transfer
// consent prompt. It mirrors transfer.ConsentDecision's JSON shape so the
// frontend can share one consent modal.
type LocalConsentDecision struct {
	Accepted bool   `json:"accepted"`
	DestDir  string `json:"destDir,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// localConsentWait blocks one incoming transfer on the user's decision.
type localConsentWait struct {
	req         transfer.ConsentRequest
	fingerprint string
	ch          chan LocalConsentDecision
	expiresAt   time.Time
}

// LocalService is the desktop's offline transfer endpoint (V21-PR06). It
// owns a persistent local rendezvous listener on the LAN and serves incoming
// transfers from paired devices as joiner through localtransfer — no public
// signaling, STUN/TURN, or relay is involved at any step. Outgoing
// local-only sends go through TransferService.SendToDeviceLocal; this
// service is the receive side plus the listener lifecycle the UI controls.
type LocalService struct {
	mu         sync.Mutex
	idMgr      *trust.IdentityManager
	store      trust.Store
	secrets    trust.CredentialStore
	tombstones trust.TombstoneStore
	emit       func(name string, data any)

	// downloadDir resolves the current download directory at receive time.
	downloadDir func() string
	// requirePadding reports the current padding policy at receive time.
	requirePadding func() bool
	// policy reports the current network policy; the listener refuses to
	// start outside local-only and prefer-local so the UI cannot present a
	// listener that the policy would contradict.
	policy func() netpolicy.Policy

	srv    *localrendezvous.Server
	cancel context.CancelFunc
	addr   string
	// port is the LAN port to bind. Production uses localListenPort (the
	// port the presence beacon advertises); tests may override it.
	port int

	pending map[string]*localConsentWait
}

// NewLocalService creates the offline transfer endpoint. Any nil optional
// func is replaced with a safe default.
func NewLocalService(idMgr *trust.IdentityManager, store trust.Store, secrets trust.CredentialStore, tombstones trust.TombstoneStore, emit func(name string, data any)) *LocalService {
	return &LocalService{
		idMgr:      idMgr,
		store:      store,
		secrets:    secrets,
		tombstones: tombstones,
		emit:       emit,
		port:       localListenPort,
		pending:    make(map[string]*localConsentWait),
	}
}

// SetDownloadDir sets the download-directory resolver.
func (s *LocalService) SetDownloadDir(f func() string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downloadDir = f
}

// SetRequirePadding sets the padding-policy resolver.
func (s *LocalService) SetRequirePadding(f func() bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requirePadding = f
}

// SetPolicy sets the network-policy reporter used to gate listener startup.
func (s *LocalService) SetPolicy(f func() netpolicy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = f
}

// SetListenPort overrides the bind port. Tests use an ephemeral port;
// production always uses localListenPort, the port the LAN beacon advertises.
func (s *LocalService) SetListenPort(port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.port = port
}

// Start begins listening for paired devices on the LAN. The bind is the
// wildcard interface on the advertised port: beacons carry only a port, and
// the source IP is the interface the peer reached, so every local interface
// must accept. Admission is still trust-bound — only paired, non-revoked
// devices get a session — so the wildcard bind widens reachability, not
// access. It is an explicit, documented choice, not a silent default.
func (s *LocalService) Start() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return s.addr, nil
	}
	if s.policy != nil {
		if p := s.policy(); p != netpolicy.LocalOnly && p != netpolicy.PreferLocal {
			return "", fmt.Errorf("offline listener requires network policy prefer-local or local-only (current: %s)", p)
		}
	}
	// Fail fast if the identity cannot be established; sessions need it.
	if _, err := s.idMgr.GetOrCreateIdentity(); err != nil {
		return "", err
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv := localrendezvous.NewServer(localrendezvous.Config{
		BindAddr:      fmt.Sprintf("0.0.0.0:%d", s.port),
		AllowWildcard: true,
	}, s.store)
	addr, err := srv.Start(ctx)
	if err != nil {
		cancel()
		return "", fmt.Errorf("offline listener: %w", err)
	}
	s.srv = srv
	s.cancel = cancel
	s.addr = addr.String()
	srv.OnSession(func(sess *localrendezvous.Session) {
		go s.serveSession(sess)
	})
	s.emitEvent(TransferEventName, TransferEvent{
		ID:    "local-listener",
		Kind:  "state",
		State: "listening (local only, " + s.addr + ")",
	})
	return s.addr, nil
}

// Stop shuts the listener down. In-flight receives run to their own
// cancellation; new sessions are refused.
func (s *LocalService) Stop() {
	s.mu.Lock()
	srv := s.srv
	cancel := s.cancel
	s.srv = nil
	s.cancel = nil
	s.addr = ""
	pending := s.pending
	s.pending = make(map[string]*localConsentWait)
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if srv != nil {
		_ = srv.Close()
	}
	for _, w := range pending {
		select {
		case w.ch <- LocalConsentDecision{Accepted: false, Reason: "listener stopped"}:
		default:
		}
	}
}

// ListenAddr returns the current listen address, or "" when stopped.
func (s *LocalService) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// IsListening reports whether the offline listener is up.
func (s *LocalService) IsListening() bool { return s.ListenAddr() != "" }

// serveSession runs one incoming transfer as joiner on an already-admitted
// session. The session was admitted by the rendezvous server (paired,
// non-revoked device only); ServeSession re-verifies trust and the Opaque
// ceremony authenticates the claimed device ID before bytes move.
func (s *LocalService) serveSession(sess *localrendezvous.Session) {
	transferID := randomHex(16)
	s.emitEvent(TransferEventName, TransferEvent{ID: transferID, Kind: "connect", Phase: "local session from " + sess.DeviceID})
	defer func() { _ = sess.Close() }()

	id, err := s.idMgr.GetOrCreateIdentity()
	if err != nil {
		s.emitEvent(TransferEventName, TransferEvent{ID: transferID, Kind: "error", Error: "identity: " + err.Error()})
		return
	}

	// A tombstoned (unpaired and purged) device must never get a session,
	// even if a stale trust record somehow survived.
	if s.tombstones != nil && s.tombstones.HasTombstone(context.Background(), sess.DeviceID) {
		s.emitEvent(TransferEventName, TransferEvent{ID: transferID, Kind: "error", Error: "peer was unpaired (tombstoned)"})
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out, err := localtransfer.ServeSession(ctx, sess, localtransfer.ServeOptions{
		Identity:       id,
		Store:          s.store,
		Resolver:       s.secrets,
		DestDir:        s.resolveDownloadDir(),
		Consent:        s.consentHandler(transferID),
		RequirePadding: s.resolveRequirePadding(),
		Private:        s.resolveRequirePadding(),
		OnTransport: func(t string) {
			s.emitEvent(TransferEventName, TransferEvent{ID: transferID, Kind: "transport", Transport: t + " (local)"})
		},
		OnConnect: func() {
			s.emitEvent(TransferEventName, TransferEvent{ID: transferID, Kind: "connect"})
		},
		OnProgress: func(n int64) {
			s.emitEvent(TransferEventName, TransferEvent{ID: transferID, Kind: "progress", DoneBytes: n})
		},
		OnManifest: func(m wire.FileEntry) {
			s.emitEvent(TransferEventName, TransferEvent{
				ID:         transferID,
				Kind:       "manifest",
				Files:      []FileInfo{{Name: m.Name, Size: m.Size}},
				TotalBytes: m.Size,
			})
		},
	})
	if err != nil {
		s.emitEvent(TransferEventName, TransferEvent{ID: transferID, Kind: "error", Error: err.Error()})
		return
	}
	var fp string
	if out.Handshake != nil {
		fp = fingerprint(out.Handshake.Master)
	}
	s.emitEvent(TransferEventName, TransferEvent{
		ID: transferID, Kind: "done", Percent: 100,
		Digest: fp, DoneBytes: out.Size,
		Files: []FileInfo{{Name: out.Name, Size: out.Size}},
	})
}

// consentHandler prompts the user through the shared consent modal and
// fails closed on timeout, denial, or listener shutdown.
func (s *LocalService) consentHandler(transferID string) transfer.ConsentHandler {
	return func(ctx context.Context, req transfer.ConsentRequest) (transfer.ConsentDecision, error) {
		fp := ""
		if rec, err := s.store.GetDevice(ctx, req.PeerDeviceID); err == nil && rec != nil {
			fp = rec.Fingerprint()
		}
		fileName := ""
		if len(req.Files) > 0 {
			fileName = req.Files[0].Name
			if len(req.Files) > 1 {
				fileName = fmt.Sprintf("%d files", len(req.Files))
			}
		}
		w := &localConsentWait{
			req:         req,
			fingerprint: fp,
			ch:          make(chan LocalConsentDecision, 1),
			expiresAt:   time.Now().Add(5 * time.Minute),
		}
		s.mu.Lock()
		s.pending[transferID] = w
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.pending, transferID)
			s.mu.Unlock()
		}()

		s.emitEvent(ConsentEventName, map[string]any{
			"transferId":   transferID,
			"peerDeviceId": req.PeerDeviceID,
			"peerLabel":    req.PeerLabel,
			"fingerprint":  fp,
			"fileName":     fileName,
			"totalSize":    req.TotalSize,
			"destDir":      req.DestDir,
			"contentKind":  req.ContentKind,
			"local":        true,
			// V22-PR06: the routine origin label (nil for ordinary one-off
			// sends) so the UI can show where the transfer came from.
			"provenance": provenanceEvent(req.Provenance),
		})

		select {
		case d := <-w.ch:
			if !d.Accepted {
				return transfer.ConsentDecision{Accepted: false, Reason: d.Reason}, nil
			}
			dest := d.DestDir
			if dest == "" {
				dest = s.resolveDownloadDir()
			}
			return transfer.ConsentDecision{Accepted: true, DestDir: dest}, nil
		case <-time.After(5 * time.Minute):
			return transfer.ConsentDecision{Accepted: false, Reason: "consent timed out"}, nil
		case <-ctx.Done():
			return transfer.ConsentDecision{Accepted: false, Reason: "cancelled"}, ctx.Err()
		}
	}
}

// provenanceEvent renders the routine origin label for the consent event
// payload (V22-PR06): nil for ordinary one-off sends so the UI can show
// an explicit one-off marker; a small map otherwise.
func provenanceEvent(p *wire.Provenance) map[string]any {
	if p == nil {
		return nil
	}
	return map[string]any{
		"routineId":   p.RoutineID,
		"routineName": p.RoutineName,
		"senderLabel": p.SenderLabel,
		"trigger":     p.Trigger,
		"display":     p.Display(),
	}
}
func (s *LocalService) RespondLocalConsent(transferID string, decision LocalConsentDecision) error {
	s.mu.Lock()
	w, ok := s.pending[transferID]
	s.mu.Unlock()
	if !ok {
		return errors.New("no pending local transfer " + transferID)
	}
	select {
	case w.ch <- decision:
		return nil
	default:
		return errors.New("consent already answered")
	}
}

// PendingLocalConsents lists transfers waiting for the user's decision.
func (s *LocalService) PendingLocalConsents() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.pending))
	for id, w := range s.pending {
		fileName := ""
		if len(w.req.Files) > 0 {
			fileName = w.req.Files[0].Name
		}
		out = append(out, map[string]any{
			"transferId":   id,
			"peerDeviceId": w.req.PeerDeviceID,
			"peerLabel":    w.req.PeerLabel,
			"fingerprint":  w.fingerprint,
			"fileName":     fileName,
			"totalSize":    w.req.TotalSize,
			"local":        true,
		})
	}
	return out
}

func (s *LocalService) resolveDownloadDir() string {
	s.mu.Lock()
	f := s.downloadDir
	s.mu.Unlock()
	if f != nil {
		if d := f(); d != "" {
			return d
		}
	}
	return "."
}

func (s *LocalService) resolveRequirePadding() bool {
	s.mu.Lock()
	f := s.requirePadding
	s.mu.Unlock()
	return f != nil && f()
}

func (s *LocalService) emitEvent(name string, data any) {
	if s.emit != nil {
		s.emit(name, data)
	}
}

func randomHex(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(raw)
}
