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
// methods.
type LocalPairingService struct {
	mu       sync.Mutex
	identity *trust.IdentityManager
	store    trust.Store

	// Active invitation state (inviter side).
	srv        *localrendezvous.Server
	invitation *localpairing.Invitation
	masterKey  []byte
}

// NewLocalPairingService creates the service.
func NewLocalPairingService(idMgr *trust.IdentityManager, store trust.Store) *LocalPairingService {
	return &LocalPairingService{identity: idMgr, store: store}
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

	coordinator := trust.NewPairingCoordinator(s.identity, s.store)
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

	coordinator := trust.NewPairingCoordinator(s.identity, s.store)
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
}

// NewNetworkPolicyService creates the service with get/set hooks.
func NewNetworkPolicyService(get func() netpolicy.Policy, set func(netpolicy.Policy) error) *NetworkPolicyService {
	return &NetworkPolicyService{get: get, set: set}
}

// GetPolicy returns the current network policy name.
func (s *NetworkPolicyService) GetPolicy() string {
	return s.get().String()
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
