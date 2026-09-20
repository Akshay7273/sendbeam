// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

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
}

// CreateInvitation starts the local rendezvous, opens a pairing window,
// and returns the invitation. The caller must call CancelInvitation when
// done (or after a successful pairing).
func (s *LocalPairingService) CreateInvitation(windowSeconds int) (*LocalInvitationView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return nil, errors.New("a pairing invitation is already active")
	}
	if windowSeconds <= 0 || windowSeconds > 600 {
		return nil, errors.New("window must be between 1 and 600 seconds")
	}

	ctx := context.Background()
	srv := localrendezvous.NewServer(localrendezvous.Config{
		BindAddr: "127.0.0.1:0",
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

	return &LocalInvitationView{
		Invitation:  in.Encode(),
		Address:     in.Address,
		Fingerprint: in.Fingerprint,
		ExpiresAt:   in.ExpiresAt.Format(time.RFC3339),
	}, nil
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
