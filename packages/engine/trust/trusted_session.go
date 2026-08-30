// Package trust manages local device cryptographic identity, pairing, and trusted sessions.
package trust

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/sendbeam/wire"
)

// SecretResolver resolves a raw 32-byte k_pair secret given its credential reference or device ID.
type SecretResolver interface {
	ResolvePairSecret(ctx context.Context, deviceID, pairCredRef string) ([]byte, error)
}

// MemorySecretResolver is an in-memory secret resolver for tests and transient sessions.
type MemorySecretResolver struct {
	secrets map[string][]byte
}

// NewMemorySecretResolver creates a new MemorySecretResolver.
func NewMemorySecretResolver() *MemorySecretResolver {
	return &MemorySecretResolver{
		secrets: make(map[string][]byte),
	}
}

// SetSecret stores a raw k_pair secret keyed by device ID.
func (m *MemorySecretResolver) SetSecret(deviceID string, secret []byte) {
	m.secrets[deviceID] = append([]byte(nil), secret...)
}

// ResolvePairSecret returns the stored k_pair secret for a device.
func (m *MemorySecretResolver) ResolvePairSecret(_ context.Context, deviceID, _ string) ([]byte, error) {
	s, ok := m.secrets[deviceID]
	if !ok || len(s) == 0 {
		return nil, errors.New("pair secret not found")
	}
	return s, nil
}

// TrustedSessionConfig specifies parameters for an initiator connecting to a trusted device.
type TrustedSessionConfig struct {
	PeerDeviceID string
	Capabilities []string
}

// TrustedSessionResult contains the authenticated peer's trust record and derived directional keys.
type TrustedSessionResult struct {
	PeerRecord *wire.TrustRecord
	Keys       *wire.TrustedSessionKeys
}

// TrustedSessionCoordinator manages mutual challenge-response authentication between paired devices.
type TrustedSessionCoordinator struct {
	idMgr    *IdentityManager
	store    Store
	resolver SecretResolver
}

// NewTrustedSessionCoordinator creates a new TrustedSessionCoordinator.
func NewTrustedSessionCoordinator(idMgr *IdentityManager, store Store, resolver SecretResolver) *TrustedSessionCoordinator {
	return &TrustedSessionCoordinator{
		idMgr:    idMgr,
		store:    store,
		resolver: resolver,
	}
}

// InitiateTrustedSession executes the initiator role of the trusted-session authentication handshake.
func (c *TrustedSessionCoordinator) InitiateTrustedSession(ctx context.Context, transport PairingTransport, cfg TrustedSessionConfig) (*TrustedSessionResult, error) {
	if transport == nil {
		return nil, errors.New("pairing transport required")
	}
	if cfg.PeerDeviceID == "" {
		return nil, errors.New("peer device ID required")
	}

	record, err := c.store.GetDevice(ctx, cfg.PeerDeviceID)
	if err != nil {
		return nil, fmt.Errorf("lookup peer in trust store: %w", err)
	}
	if record.Revoked {
		return nil, wire.ErrTrustedPeerRevoked
	}

	peerPub, err := hex.DecodeString(record.PublicKey)
	if err != nil || len(peerPub) != ed25519.PublicKeySize {
		return nil, wire.ErrInvalidPublicKey
	}

	kPair, err := c.resolver.ResolvePairSecret(ctx, cfg.PeerDeviceID, record.PairCredentialRef)
	if err != nil {
		return nil, fmt.Errorf("resolve pair secret: %w", err)
	}

	id, err := c.idMgr.GetOrCreateIdentity()
	if err != nil {
		return nil, fmt.Errorf("get local identity: %w", err)
	}

	// 1. Create and send TrustedAuthInit with mesh revocation records
	now := time.Now().UTC()
	storedRevs, _ := c.store.ListRevocations(ctx)
	revList := make([]wire.RevocationRecord, 0, len(storedRevs))
	for _, r := range storedRevs {
		if r != nil {
			revList = append(revList, *r)
		}
	}

	initMsg, err := wire.NewTrustedAuthInitWithRevocations(id, cfg.PeerDeviceID, record.PairCredentialRef, kPair, cfg.Capabilities, nil, nil, now, revList)
	if err != nil {
		return nil, fmt.Errorf("create trusted auth init: %w", err)
	}

	initData, err := wire.EncodeTrustedAuthMessage(initMsg)
	if err != nil {
		return nil, fmt.Errorf("encode trusted auth init: %w", err)
	}

	if err := transport.SendMessage(ctx, initData); err != nil {
		return nil, fmt.Errorf("send trusted auth init: %w", err)
	}

	// 2. Receive and verify TrustedAuthResponse
	respData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive trusted auth response: %w", err)
	}

	respMsgRaw, err := wire.DecodeTrustedAuthMessage(respData)
	if err != nil {
		return nil, fmt.Errorf("decode trusted auth response: %w", err)
	}

	respMsg, ok := respMsgRaw.(*wire.TrustedAuthResponse)
	if !ok {
		return nil, errors.New("expected trusted auth response message")
	}

	ephemResp, nonceResp, err := wire.VerifyTrustedAuthResponse(respMsg, initMsg, kPair, peerPub, id.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("verify trusted auth response: %w", err)
	}

	// Opportunistically process mesh revocation records piggybacked on response
	c.processIncomingRevocations(ctx, respMsg.Revocations, cfg.PeerDeviceID)

	// 3. Derive forward-secret session keys
	ephemInit, _ := hex.DecodeString(initMsg.EphemeralPub)
	nonceInit, _ := hex.DecodeString(initMsg.Nonce)

	keys, err := wire.DeriveTrustedSessionKeys(kPair, ephemInit, ephemResp, nonceInit, nonceResp, id.DeviceID, cfg.PeerDeviceID, cfg.Capabilities, respMsg.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("derive trusted session keys: %w", err)
	}

	// 4. Send our confirmation and verify peer's confirmation
	confInit := wire.NewTrustedAuthConfirm(keys.SessionMaster, wire.DomainTrustedConfirmInit, id.DeviceID, true)
	confData, err := wire.EncodeTrustedAuthMessage(confInit)
	if err != nil {
		return nil, fmt.Errorf("encode confirm: %w", err)
	}

	if err := transport.SendMessage(ctx, confData); err != nil {
		return nil, fmt.Errorf("send confirm: %w", err)
	}

	peerConfData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive peer confirm: %w", err)
	}

	peerConfRaw, err := wire.DecodeTrustedAuthMessage(peerConfData)
	if err != nil {
		return nil, fmt.Errorf("decode peer confirm: %w", err)
	}

	peerConf, ok := peerConfRaw.(*wire.TrustedAuthConfirm)
	if !ok {
		return nil, errors.New("expected trusted auth confirm message")
	}

	if err := wire.VerifyTrustedAuthConfirm(peerConf, keys.SessionMaster, wire.DomainTrustedConfirmResp, cfg.PeerDeviceID); err != nil {
		return nil, fmt.Errorf("verify peer confirm: %w", err)
	}

	// 5. Update LastSeenAt in local store
	record.LastSeenAt = time.Now().UTC()
	_ = c.store.AddOrUpdateDevice(ctx, record)

	return &TrustedSessionResult{
		PeerRecord: record,
		Keys:       keys,
	}, nil
}

// AcceptTrustedSession executes the responder role of the trusted-session authentication handshake.
func (c *TrustedSessionCoordinator) AcceptTrustedSession(ctx context.Context, transport PairingTransport, capabilities []string) (*TrustedSessionResult, error) {
	if transport == nil {
		return nil, errors.New("pairing transport required")
	}

	id, err := c.idMgr.GetOrCreateIdentity()
	if err != nil {
		return nil, fmt.Errorf("get local identity: %w", err)
	}

	// 1. Receive and verify TrustedAuthInit
	initData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive trusted auth init: %w", err)
	}

	initMsgRaw, err := wire.DecodeTrustedAuthMessage(initData)
	if err != nil {
		return nil, fmt.Errorf("decode trusted auth init: %w", err)
	}

	initMsg, ok := initMsgRaw.(*wire.TrustedAuthInit)
	if !ok {
		return nil, errors.New("expected trusted auth init message")
	}

	record, err := c.store.GetDevice(ctx, initMsg.InitiatorDeviceID)
	if err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, fmt.Errorf("peer not in trust store: %w", err)
	}

	if record.Revoked {
		_ = c.sendRejection(ctx, transport, "revoked")
		return nil, wire.ErrTrustedPeerRevoked
	}

	peerPub, err := hex.DecodeString(record.PublicKey)
	if err != nil || len(peerPub) != ed25519.PublicKeySize {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, wire.ErrInvalidPublicKey
	}

	kPair, err := c.resolver.ResolvePairSecret(ctx, initMsg.InitiatorDeviceID, record.PairCredentialRef)
	if err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, fmt.Errorf("resolve pair secret: %w", err)
	}

	now := time.Now().UTC()
	ephemInit, nonceInit, err := wire.VerifyTrustedAuthInit(initMsg, kPair, peerPub, id.DeviceID, now)
	if err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, fmt.Errorf("verify trusted auth init: %w", err)
	}

	// Opportunistically process mesh revocation records piggybacked on init
	c.processIncomingRevocations(ctx, initMsg.Revocations, initMsg.InitiatorDeviceID)

	// 2. Create and send TrustedAuthResponse with mesh revocation records
	storedRevs, _ := c.store.ListRevocations(ctx)
	revList := make([]wire.RevocationRecord, 0, len(storedRevs))
	for _, r := range storedRevs {
		if r != nil {
			revList = append(revList, *r)
		}
	}

	respMsg, err := wire.NewTrustedAuthResponseWithRevocations(id, initMsg, kPair, capabilities, nil, nil, revList)
	if err != nil {
		return nil, fmt.Errorf("create trusted auth response: %w", err)
	}

	respData, err := wire.EncodeTrustedAuthMessage(respMsg)
	if err != nil {
		return nil, fmt.Errorf("encode trusted auth response: %w", err)
	}

	if err := transport.SendMessage(ctx, respData); err != nil {
		return nil, fmt.Errorf("send trusted auth response: %w", err)
	}

	// 3. Derive forward-secret session keys
	ephemResp, _ := hex.DecodeString(respMsg.EphemeralPub)
	nonceResp, _ := hex.DecodeString(respMsg.Nonce)

	keys, err := wire.DeriveTrustedSessionKeys(kPair, ephemInit, ephemResp, nonceInit, nonceResp, initMsg.InitiatorDeviceID, id.DeviceID, initMsg.Capabilities, capabilities)
	if err != nil {
		return nil, fmt.Errorf("derive trusted session keys: %w", err)
	}

	// 4. Receive peer confirm and send our confirm
	peerConfData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive peer confirm: %w", err)
	}

	peerConfRaw, err := wire.DecodeTrustedAuthMessage(peerConfData)
	if err != nil {
		return nil, fmt.Errorf("decode peer confirm: %w", err)
	}

	peerConf, ok := peerConfRaw.(*wire.TrustedAuthConfirm)
	if !ok {
		return nil, errors.New("expected trusted auth confirm message")
	}

	if err := wire.VerifyTrustedAuthConfirm(peerConf, keys.SessionMaster, wire.DomainTrustedConfirmInit, initMsg.InitiatorDeviceID); err != nil {
		return nil, fmt.Errorf("verify peer confirm: %w", err)
	}

	confResp := wire.NewTrustedAuthConfirm(keys.SessionMaster, wire.DomainTrustedConfirmResp, id.DeviceID, true)
	confData, err := wire.EncodeTrustedAuthMessage(confResp)
	if err != nil {
		return nil, fmt.Errorf("encode confirm: %w", err)
	}

	if err := transport.SendMessage(ctx, confData); err != nil {
		return nil, fmt.Errorf("send confirm: %w", err)
	}

	// 5. Update LastSeenAt in local store
	record.LastSeenAt = time.Now().UTC()
	_ = c.store.AddOrUpdateDevice(ctx, record)

	return &TrustedSessionResult{
		PeerRecord: record,
		Keys:       keys,
	}, nil
}

func (c *TrustedSessionCoordinator) sendRejection(ctx context.Context, transport PairingTransport, status string) error {
	id, _ := c.idMgr.GetOrCreateIdentity()
	resp := &wire.TrustedAuthResponse{
		Type:              wire.MsgTrustedAuthResponse,
		ProtocolVersion:   wire.TrustedAuthProtocolVersion,
		Status:            status,
		ResponderDeviceID: id.DeviceID,
	}
	data, _ := wire.EncodeTrustedAuthMessage(resp)
	return transport.SendMessage(ctx, data)
}

// RevokeDevice explicitly revokes trust for a peer, creates a signed RevocationRecord, and updates the local trust store.
func (c *TrustedSessionCoordinator) RevokeDevice(ctx context.Context, targetDeviceID string) error {
	id, err := c.idMgr.GetOrCreateIdentity()
	if err != nil {
		return fmt.Errorf("get local identity: %w", err)
	}

	dev, err := c.store.GetDevice(ctx, targetDeviceID)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}

	seq := dev.RevocationSeq + 1
	if seq == 1 && dev.RevocationSeq == 0 {
		seq = 1
	}

	rec, err := wire.SignRevocation(id, targetDeviceID, seq, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign revocation record: %w", err)
	}

	return c.store.RevokeDeviceWithRecord(ctx, rec)
}

// processIncomingRevocations parses, authenticates, and applies signed RevocationRecords from trusted peers.
func (c *TrustedSessionCoordinator) processIncomingRevocations(ctx context.Context, revocations []wire.RevocationRecord, _ string) {
	if len(revocations) == 0 {
		return
	}
	now := time.Now().UTC()
	for _, rec := range revocations {
		// 1. Structure validation
		if err := rec.Validate(); err != nil {
			continue
		}

		// 2. Direct pairing prerequisite: Revoker must exist in local trust store
		revokerRec, err := c.store.GetDevice(ctx, rec.RevokerDeviceID)
		if err != nil || revokerRec == nil {
			continue // ignore claims from revokers we have never directly paired with
		}

		// 3. Revoker must be active (not revoked)
		if revokerRec.Revoked {
			continue // revoked devices cannot submit revocations
		}

		// 4. Verify signature against stored revoker public key
		pubKey, err := hex.DecodeString(revokerRec.PublicKey)
		if err != nil || len(pubKey) != ed25519.PublicKeySize {
			continue
		}

		if err := wire.VerifyRevocation(&rec, pubKey, wire.MaxRevocationTimestampSkew, now); err != nil {
			continue
		}

		// 5. Apply revocation to local store
		_ = c.store.RevokeDeviceWithRecord(ctx, &rec)
	}
}
