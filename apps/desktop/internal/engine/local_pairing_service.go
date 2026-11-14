// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/sendbeam/engine/localpairing"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// LocalPairingService exposes offline first-time pairing to the desktop
// frontend (V21-PR06). It wraps the localpairing package with Wails-bound
// methods and persists the derived pairwise credential on success, exactly
// like the online pairing path, so subsequent local transfers can resolve the
// pair secret.
type LocalPairingService struct {
	mu       sync.Mutex
	identity *trust.IdentityManager
	store    trust.Store
	secrets  trust.CredentialStore

	// Active invitation state (inviter side).
	srv        *localrendezvous.Server
	invitation *localpairing.Invitation
	masterKey  []byte
}

// NewLocalPairingService creates the service. The credential store is
// required for pairing to be usable for transfers: without it the derived
// pair secret is never persisted and sends to the paired device fail.
func NewLocalPairingService(idMgr *trust.IdentityManager, store trust.Store, secrets trust.CredentialStore) *LocalPairingService {
	return &LocalPairingService{identity: idMgr, store: store, secrets: secrets}
}

// LocalInvitationView is the JSON-serializable invitation for the UI.
// The invitation string contains the pairing secret; the frontend must
// render it as a QR code, not log it.
type LocalInvitationView struct {
	Invitation  string `json:"invitation"`
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expiresAt"`
	// QR is a data:image/png;base64 QR encoding of the invitation, for the
	// same scan-to-join UX as online pairing offers.
	QR string `json:"qr"`
}

// CreateInvitation starts the local rendezvous, opens a pairing window,
// and returns the invitation. bindAddr is the listen address as "ip:port";
// empty selects the first LAN interface with an ephemeral port so the
// invitation carries an address other devices can actually reach (a
// loopback-only listener would hand the joiner an unusable address).
// The caller must call CancelInvitation when done (or after pairing).
func (s *LocalPairingService) CreateInvitation(windowSeconds int, bindAddr string) (*LocalInvitationView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return nil, errors.New("a pairing invitation is already active")
	}
	if windowSeconds <= 0 || windowSeconds > 600 {
		return nil, errors.New("window must be between 1 and 600 seconds")
	}
	bind := bindAddr
	if bind == "" {
		lan, err := localrendezvous.LANBindAddr()
		if err != nil {
			return nil, fmt.Errorf("no LAN interface for pairing: %w", err)
		}
		bind = lan
	}

	ctx := context.Background()
	srv := localrendezvous.NewServer(localrendezvous.Config{
		BindAddr:      bind,
		AllowWildcard: false,
	}, s.store)
	addr, err := srv.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("start local rendezvous: %w", err)
	}

	id, err := s.identity.GetOrCreateIdentity()
	if err != nil {
		_ = srv.Close()
		return nil, err
	}
	fingerprint := wire.DeriveDeviceID(id.PublicKey)

	in, err := localpairing.CreateInvitation(srv, addr.String(), fingerprint, time.Duration(windowSeconds)*time.Second)
	if err != nil {
		_ = srv.Close()
		return nil, err
	}
	key, err := in.MasterKey()
	if err != nil {
		_ = srv.Close()
		return nil, err
	}

	s.srv = srv
	s.invitation = in
	s.masterKey = key

	view := &LocalInvitationView{
		Invitation:  in.Encode(),
		Address:     in.Address,
		Fingerprint: in.Fingerprint,
		ExpiresAt:   in.ExpiresAt.Format(time.RFC3339),
	}
	// QR is best-effort: a missing QR never fails invitation creation; the
	// raw invitation string remains usable via copy/paste.
	if png, err := qrcode.Encode(in.Encode(), qrcode.Medium, 256); err == nil {
		view.QR = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}

	return view, nil
}

// AcceptPairing runs the inviter side of the ceremony. It blocks until a
// joiner pairs or the context is canceled. On success it closes the
// invitation.
func (s *LocalPairingService) AcceptPairing(ctx context.Context, deviceName string) (string, error) {
	s.mu.Lock()
	srv := s.srv
	key := s.masterKey
	s.mu.Unlock()

	if srv == nil {
		return "", errors.New("no active invitation")
	}
	if deviceName == "" {
		deviceName = "Desktop"
	}

	coordinator := trust.NewPairingCoordinatorWithCredentials(s.identity, s.store, s.secrets)
	res, err := localpairing.Accept(ctx, srv, localpairing.Options{
		Coordinator: coordinator,
		DeviceName:  deviceName,
		MasterKey:   key,
	})
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.closeLocked()
	s.mu.Unlock()
	return res.PeerRecord.DeviceID, nil
}

// JoinPairing parses an invitation and runs the joiner side of the ceremony.
func (s *LocalPairingService) JoinPairing(ctx context.Context, invitation, deviceName string) (string, error) {
	in, err := localpairing.ParseInvitation(invitation)
	if err != nil {
		return "", fmt.Errorf("invalid invitation: %w", err)
	}
	key, err := in.MasterKey()
	if err != nil {
		return "", fmt.Errorf("invalid invitation: %w", err)
	}
	if deviceName == "" {
		deviceName = "Desktop"
	}

	coordinator := trust.NewPairingCoordinatorWithCredentials(s.identity, s.store, s.secrets)
	res, err := localpairing.Join(ctx, in, localpairing.Options{
		Coordinator: coordinator,
		DeviceName:  deviceName,
		MasterKey:   key,
	})
	if err != nil {
		return "", err
	}
	// The caller should show in.Fingerprint for the user to verify.
	return res.PeerRecord.DeviceID, nil
}

// CancelInvitation closes the active invitation without pairing.
func (s *LocalPairingService) CancelInvitation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *LocalPairingService) closeLocked() {
	if s.srv != nil {
		_ = s.srv.Close()
		s.srv = nil
	}
	s.invitation = nil
	s.masterKey = nil
}

// NetworkPolicyService exposes the user-selected network policy.
type NetworkPolicyService struct {
	get func() netpolicy.Policy
	set func(netpolicy.Policy) error
	// SB-R09: degradation visibility state (see PolicyState).
	mu            sync.Mutex
	degraded      bool
	degradeReason string
	notifyDegrade func(reason string)
}

// NewNetworkPolicyService creates the service with get/set hooks.
func NewNetworkPolicyService(get func() netpolicy.Policy, set func(netpolicy.Policy) error) *NetworkPolicyService {
	return &NetworkPolicyService{get: get, set: set}
}

// GetPolicy returns the current network policy name.
func (s *NetworkPolicyService) GetPolicy() string {
	return s.get().String()
}

// PolicyState is the UI-facing network-policy view (SB-R09, requirement 6):
// it distinguishes a policy the user SELECTED from one the engine DEGRADED
// to after an unusable configuration (SB-R05 fail-closed), so the UI never
// silently implies online access is available when it is blocked. The
// degraded reason text is engine-generated, secret-free, and rendered as
// literal text by the frontend.
type PolicyState struct {
	// Policy is the effective policy name ("online", "prefer-local",
	// "local-only").
	Policy string `json:"policy"`
	// Degraded is true when the effective policy is the SB-R05 fail-closed
	// fallback (LocalOnly) because the configuration was unusable — not
	// because the user selected local-only.
	Degraded bool `json:"degraded"`
	// Reason is the human-readable degradation reason (empty when not
	// degraded). It never contains configuration contents or secrets.
	Reason string `json:"reason,omitempty"`
}

// GetPolicyState returns the effective policy with its degradation state.
// The get hook may itself be the SB-R05 fail-closed closure; to classify the
// degradation WITHOUT asking the closure twice, the state is derived from
// the injected get/set hooks plus an optional degrade notifier wired by
// main.go (SetDegradeNotifier): the first closure that fails closed reports
// through it. When no notifier fired, the effective policy is the user's
// selected one.
func (s *NetworkPolicyService) GetPolicyState() PolicyState {
	s.mu.Lock()
	degraded := s.degraded
	reason := s.degradeReason
	s.mu.Unlock()
	p := s.get().String()
	if degraded {
		return PolicyState{Policy: p, Degraded: true, Reason: reason}
	}
	return PolicyState{Policy: p}
}

// SetDegradeNotifier wires the SB-R05 degradation signal: main.go's
// fail-closed policy closure calls this with a secret-free reason whenever
// config retrieval fails (each failure re-arms the signal; a later healthy
// read clears it).
func (s *NetworkPolicyService) SetDegradeNotifier(fn func(reason string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyDegrade = fn
}

// NoteDegrade records a degradation and notifies the wired notifier (nil
// safe). Called by main.go's fail-closed policy closure (SB-R09: the UI
// must be able to distinguish a selected local-only from the fallback).
func (s *NetworkPolicyService) NoteDegrade(reason string) {
	s.mu.Lock()
	s.degraded = true
	s.degradeReason = reason
	notify := s.notifyDegrade
	s.mu.Unlock()
	if notify != nil {
		notify(reason)
	}
}

// ClearDegrade records a healthy policy read (the fallback was not used).
func (s *NetworkPolicyService) ClearDegrade() {
	s.mu.Lock()
	s.degraded = false
	s.degradeReason = ""
	s.mu.Unlock()
}

// SetPolicy persists the network policy.
func (s *NetworkPolicyService) SetPolicy(policy string) error {
	p, err := netpolicy.Parse(policy)
	if err != nil {
		return err
	}
	return s.set(p)
}

// CreateInvitationView is the Wails-facing invitation entry point: a
// five-minute window with automatic LAN bind selection.
func (s *LocalPairingService) CreateInvitationView() (*LocalInvitationView, error) {
	return s.CreateInvitation(300, "")
}

// JoinInvitation runs the joiner side of a local pairing ceremony with a
// bounded timeout and returns the paired peer's device ID.
func (s *LocalPairingService) JoinInvitation(invitation, deviceName string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	peerID, err := s.JoinPairing(ctx, invitation, deviceName)
	if err != nil {
		return nil, err
	}
	return map[string]string{"peerDeviceId": peerID}, nil
}
