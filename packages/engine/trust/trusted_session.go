// Package trust manages local device cryptographic identity, pairing, and trusted sessions.
package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
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

// TrustedSessionResult contains the authenticated peer's trust record, derived directional keys, and session lifecycle guard.
type TrustedSessionResult struct {
	PeerRecord *wire.TrustRecord
	Keys       *wire.TrustedSessionKeys
	Unregister func()
}

// TrustedSessionCoordinator manages mutual challenge-response authentication between paired devices.
type TrustedSessionCoordinator struct {
	idMgr       *IdentityManager
	store       Store
	resolver    SecretResolver
	credStore   CredentialStore
	tombstones  TombstoneStore
	clusterID   string
	replayCache *wire.NonceReplayCache

	activeMu       sync.Mutex
	activeSessions map[string]map[int64]context.CancelFunc
	nextSessionID  int64
}

// NewTrustedSessionCoordinator creates a new TrustedSessionCoordinator.
func NewTrustedSessionCoordinator(idMgr *IdentityManager, store Store, resolver SecretResolver) *TrustedSessionCoordinator {
	return &TrustedSessionCoordinator{
		idMgr:       idMgr,
		store:       store,
		resolver:    resolver,
		replayCache: wire.NewNonceReplayCache(10 * time.Minute),
	}
}

// SetTombstoneStore sets the TombstoneStore for persistent tombstone checking (ADR 0010 §4.5).
func (c *TrustedSessionCoordinator) SetTombstoneStore(tombstones TombstoneStore) {
	c.tombstones = tombstones
}

// SetCredentialStore sets the CredentialStore for pair secret lifecycle management (ADR 0010 §4).
func (c *TrustedSessionCoordinator) SetCredentialStore(credStore CredentialStore) {
	c.credStore = credStore
}

// SetClusterID sets the local owner cluster ID for transitive mesh authorization checks (ADR 0010 §4.2).
func (c *TrustedSessionCoordinator) SetClusterID(clusterID string) {
	c.clusterID = clusterID
}

// RegisterActiveSession registers an active in-flight session with a peer device.
// Returns an unregister function that must be called when the session terminates.
func (c *TrustedSessionCoordinator) RegisterActiveSession(peerDeviceID string, cancel context.CancelFunc) func() {
	c.activeMu.Lock()
	defer c.activeMu.Unlock()

	if c.activeSessions == nil {
		c.activeSessions = make(map[string]map[int64]context.CancelFunc)
	}

	c.nextSessionID++
	id := c.nextSessionID

	if c.activeSessions[peerDeviceID] == nil {
		c.activeSessions[peerDeviceID] = make(map[int64]context.CancelFunc)
	}
	c.activeSessions[peerDeviceID][id] = cancel

	var once sync.Once
	return func() {
		once.Do(func() {
			c.activeMu.Lock()
			defer c.activeMu.Unlock()
			if m, ok := c.activeSessions[peerDeviceID]; ok {
				delete(m, id)
				if len(m) == 0 {
					delete(c.activeSessions, peerDeviceID)
				}
			}
		})
	}
}

// AbortActiveSessions immediately invokes the cancel functions for all in-flight sessions
// registered for the specified target device ID, returning the number of aborted sessions (ADR 0010 §4.4 rule 10).
func (c *TrustedSessionCoordinator) AbortActiveSessions(targetDeviceID string) int {
	c.activeMu.Lock()
	m, ok := c.activeSessions[targetDeviceID]
	if !ok || len(m) == 0 {
		c.activeMu.Unlock()
		return 0
	}
	delete(c.activeSessions, targetDeviceID)
	cancels := make([]context.CancelFunc, 0, len(m))
	for _, fn := range m {
		if fn != nil {
			cancels = append(cancels, fn)
		}
	}
	c.activeMu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels)
}

// InitiateTrustedSession executes the initiator role of the trusted-session authentication handshake.
func (c *TrustedSessionCoordinator) InitiateTrustedSession(ctx context.Context, transport PairingTransport, cfg TrustedSessionConfig) (*TrustedSessionResult, error) {
	if transport == nil {
		return nil, errors.New("pairing transport required")
	}
	if cfg.PeerDeviceID == "" {
		return nil, errors.New("peer device ID required")
	}

	// ADR 0010 §4.5: Check if peer has an active tombstone
	if c.tombstones != nil && c.tombstones.HasTombstone(ctx, cfg.PeerDeviceID) {
		return nil, wire.ErrTrustedPeerRevoked
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

	// 1. Generate ephemeral keypair and nonce
	privA, pubA, err := wire.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	nonceA := make([]byte, wire.TrustedAuthNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceA); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	now := time.Now().UTC()
	if err := c.replayCache.CheckAndRecord(id.DeviceID, hex.EncodeToString(nonceA), now); err != nil {
		return nil, err
	}

	storedRevs, _ := c.store.ListRevocations(ctx)
	revList := make([]wire.RevocationRecord, 0, len(storedRevs))
	for _, r := range storedRevs {
		if r != nil {
			revList = append(revList, *r)
		}
	}

	initMsg, err := wire.NewTrustedAuthInitV3(id, cfg.PeerDeviceID, record.PairCredentialRef, kPair, cfg.Capabilities, pubA, nonceA, now, revList)
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

	ephemResp, nonceResp, err := wire.VerifyTrustedAuthResponseV3(respMsg, initMsg, kPair, peerPub, id.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("verify trusted auth response: %w", err)
	}

	if err := c.replayCache.CheckAndRecord(cfg.PeerDeviceID, hex.EncodeToString(nonceResp), now); err != nil {
		return nil, err
	}

	// Opportunistically process mesh revocation records piggybacked on response
	c.processIncomingRevocations(ctx, respMsg.Revocations, cfg.PeerDeviceID)

	// 3. Diffie-Hellman and session key derivation
	ssECDH, err := wire.ComputeX25519SharedSecret(privA, ephemResp)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}
	defer wire.ZeroizeBytes(ssECDH)

	keys, err := wire.DeriveTrustedSessionKeysV3(kPair, ssECDH, pubA, ephemResp, nonceA, nonceResp, id.DeviceID, cfg.PeerDeviceID, cfg.Capabilities, respMsg.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("derive trusted session keys: %w", err)
	}

	// 4. Send our confirmation and verify peer's confirmation
	confInit := wire.NewTrustedAuthConfirmV3(keys.SessionMaster, wire.DomainTrustedConfirmInit3, id.DeviceID, true)
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

	if err := wire.VerifyTrustedAuthConfirmV3(peerConf, keys.SessionMaster, wire.DomainTrustedConfirmResp3, cfg.PeerDeviceID); err != nil {
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

	// ADR 0010 §4.5: Check if initiator has an active tombstone
	if c.tombstones != nil && c.tombstones.HasTombstone(ctx, initMsg.InitiatorDeviceID) {
		_ = c.sendRejection(ctx, transport, "revoked")
		return nil, wire.ErrTrustedPeerRevoked
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
	ephemInit, nonceInit, err := wire.VerifyTrustedAuthInitV3(initMsg, kPair, peerPub, id.DeviceID, now)
	if err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, fmt.Errorf("verify trusted auth init: %w", err)
	}

	if err := c.replayCache.CheckAndRecord(initMsg.InitiatorDeviceID, hex.EncodeToString(nonceInit), now); err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, err
	}

	// Opportunistically process mesh revocation records piggybacked on init
	c.processIncomingRevocations(ctx, initMsg.Revocations, initMsg.InitiatorDeviceID)

	// 2. Generate responder ephemeral keypair and nonce
	privB, pubB, err := wire.GenerateX25519KeyPair()
	if err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	nonceB := make([]byte, wire.TrustedAuthNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceB); err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	if err := c.replayCache.CheckAndRecord(id.DeviceID, hex.EncodeToString(nonceB), now); err != nil {
		_ = c.sendRejection(ctx, transport, "rejected")
		return nil, err
	}

	storedRevs, _ := c.store.ListRevocations(ctx)
	revList := make([]wire.RevocationRecord, 0, len(storedRevs))
	for _, r := range storedRevs {
		if r != nil {
			revList = append(revList, *r)
		}
	}

	respMsg, err := wire.NewTrustedAuthResponseV3(id, initMsg, kPair, capabilities, pubB, nonceB, revList)
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

	// 3. Diffie-Hellman and session key derivation
	ssECDH, err := wire.ComputeX25519SharedSecret(privB, ephemInit)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}
	defer wire.ZeroizeBytes(ssECDH)

	keys, err := wire.DeriveTrustedSessionKeysV3(kPair, ssECDH, ephemInit, pubB, nonceInit, nonceB, initMsg.InitiatorDeviceID, id.DeviceID, initMsg.Capabilities, capabilities)
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

	if err := wire.VerifyTrustedAuthConfirmV3(peerConf, keys.SessionMaster, wire.DomainTrustedConfirmInit3, initMsg.InitiatorDeviceID); err != nil {
		return nil, fmt.Errorf("verify peer confirm: %w", err)
	}

	confResp := wire.NewTrustedAuthConfirmV3(keys.SessionMaster, wire.DomainTrustedConfirmResp3, id.DeviceID, true)
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
		ProtocolVersion:   wire.TrustedAuthProtocolVersionV3,
		Status:            status,
		ResponderDeviceID: id.DeviceID,
	}
	data, _ := wire.EncodeTrustedAuthMessage(resp)
	return transport.SendMessage(ctx, data)
}

// RevokeDevice explicitly revokes trust for a peer, creates a signed RevocationRecord, updates the local trust store,
// stores a tombstone, removes pair credentials, and terminates active sessions (ADR 0010 §4).
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

	if err := c.store.RevokeDeviceWithRecord(ctx, rec); err != nil {
		return err
	}

	if c.tombstones != nil {
		_ = c.tombstones.StoreTombstone(ctx, rec)
	}

	if c.credStore != nil {
		_ = c.credStore.DeletePairSecret(ctx, targetDeviceID)
	}

	c.AbortActiveSessions(targetDeviceID)

	return nil
}

// RevokeSelf creates, signs, and records a self-tombstone announcing that this local device is retired or compromised (ADR 0010 §4.2).
func (c *TrustedSessionCoordinator) RevokeSelf(ctx context.Context) (*wire.RevocationRecord, error) {
	id, err := c.idMgr.GetOrCreateIdentity()
	if err != nil {
		return nil, fmt.Errorf("get local identity: %w", err)
	}

	rec, err := wire.SignSelfTombstone(id, 1, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("sign self-tombstone: %w", err)
	}

	if c.tombstones != nil {
		_ = c.tombstones.StoreTombstone(ctx, rec)
	}

	c.AbortActiveSessions(id.DeviceID)

	return rec, nil
}

// IngestRevocationRecord validates, checks authorization, and applies a signed RevocationRecord
// in strict adherence to ADR 0010 §4.4 (10-step ingestion algorithm).
func (c *TrustedSessionCoordinator) IngestRevocationRecord(ctx context.Context, record *wire.RevocationRecord) error {
	if record == nil {
		return wire.ErrInvalidRevocationRecord
	}

	// 1. Parse and validate record syntax and sequence (Seq > 0)
	if err := record.Validate(); err != nil {
		return err
	}

	now := time.Now().UTC()
	isSelf := record.IsSelfTombstone()
	var isLocal bool
	var revokerPubBytes []byte
	if c.idMgr != nil {
		if localID, err := c.idMgr.GetOrCreateIdentity(); err == nil && localID != nil {
			if record.RevokerDeviceID == localID.DeviceID {
				isLocal = true
				revokerPubBytes = localID.PublicKey
			}
		}
	}

	// 2. Retrieve Revoker A
	if !isLocal {
		revoker, err := c.store.GetDevice(ctx, record.RevokerDeviceID)
		if err != nil || revoker == nil {
			if isSelf {
				// Case 2a: Self-tombstone for unknown device:
				// Record in persistent tombstone cache to prevent future pairing.
				if c.tombstones != nil {
					_ = c.tombstones.StoreTombstone(ctx, record)
				}
				return nil
			}
			// Unknown revoker for third-party device -> fail-closed
			return wire.ErrRevokerUntrusted
		}

		// 3. Check if Revoker A is already revoked locally
		if revoker.Revoked {
			return wire.ErrRevokerUntrusted
		}

		// 4. AUTHORIZATION CHECK (ADR 0010 §4.2 / §4.4)
		if !isSelf {
			// External contact attempting third-party revocation -> rejected fail-closed
			if revoker.Relationship != wire.RelationshipClusterMember && revoker.Relationship != wire.RelationshipClusterOwner {
				return wire.ErrRevocationUnauthorized
			}
			if revoker.ClusterID == "" {
				return wire.ErrRevocationUnauthorized
			}
			if c.clusterID != "" && revoker.ClusterID != c.clusterID {
				return wire.ErrRevocationUnauthorized
			}
		}

		pub, err := hex.DecodeString(revoker.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return wire.ErrRevocationSignatureFailed
		}
		revokerPubBytes = pub
	}

	// 5. Retrieve Target B from local trust store
	target, err := c.store.GetDevice(ctx, record.RevokedDeviceID)
	if err != nil || target == nil {
		// Target B is not in local trust store:
		// Record tombstone in persistent deny-list to prevent future pairing.
		if c.tombstones != nil {
			_ = c.tombstones.StoreTombstone(ctx, record)
		}
		return nil
	}

	// 6. Verify Ed25519 signature of A over Challenge_Revoke
	if err := wire.VerifyRevocation(record, revokerPubBytes, wire.MaxRevocationTimestampSkew, now); err != nil {
		return err
	}

	// 7. Sequence monotonicity check
	if target.Revoked && target.RevocationSeq > 0 && record.Seq <= target.RevocationSeq {
		return wire.ErrRevocationSeqRollback
	}

	// 9. Apply revocation to B in trust store
	if err := c.store.RevokeDeviceWithRecord(ctx, record); err != nil {
		return err
	}

	if c.tombstones != nil {
		_ = c.tombstones.StoreTombstone(ctx, record)
	}

	if c.credStore != nil {
		_ = c.credStore.DeletePairSecret(ctx, record.RevokedDeviceID)
	}

	// 10. Abort any active in-flight transfer sessions with Target B
	c.AbortActiveSessions(record.RevokedDeviceID)

	return nil
}

// processIncomingRevocations parses, authenticates, and applies signed RevocationRecords from trusted peers.
func (c *TrustedSessionCoordinator) processIncomingRevocations(ctx context.Context, revocations []wire.RevocationRecord, _ string) {
	for i := range revocations {
		_ = c.IngestRevocationRecord(ctx, &revocations[i])
	}
}
