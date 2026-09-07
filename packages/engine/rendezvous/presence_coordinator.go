// Package rendezvous provides room-based signaling and privacy-preserving opaque presence coordination.
package rendezvous

import (
	"context"
	"sync"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// PresenceStatus represents truthful presence state for a trusted peer.
type PresenceStatus string

// Truthful presence status constants.
const (
	PresenceOffline    PresenceStatus = "offline"
	PresenceDiscovered PresenceStatus = "discovered"
	PresenceConnecting PresenceStatus = "connecting"
	PresenceConnected  PresenceStatus = "connected"
)

// PeerPresenceRecord stores the latest truthful presence observation for a peer.
type PeerPresenceRecord struct {
	DeviceID  string
	Status    PresenceStatus
	Handle    string
	LastSeen  time.Time
	ExpiresAt time.Time
}

// PresenceCoordinator manages opaque handle calculation and inbound presence verification.
type PresenceCoordinator struct {
	store       trust.Store
	resolver    trust.SecretResolver
	epochWindow time.Duration

	mu      sync.RWMutex
	records map[string]*PeerPresenceRecord
}

// NewPresenceCoordinator creates a new PresenceCoordinator.
func NewPresenceCoordinator(store trust.Store, resolver trust.SecretResolver, epochWindow time.Duration) *PresenceCoordinator {
	if epochWindow <= 0 {
		epochWindow = wire.DefaultRendezvousEpochWindow
	}
	return &PresenceCoordinator{
		store:       store,
		resolver:    resolver,
		epochWindow: epochWindow,
		records:     make(map[string]*PeerPresenceRecord),
	}
}

// GetActiveHandles returns a mapping of DeviceID to candidate handles for all trusted paired devices.
func (c *PresenceCoordinator) GetActiveHandles(ctx context.Context, now time.Time) (map[string][]string, error) {
	devices, err := c.store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	res := make(map[string][]string)
	for _, dev := range devices {
		if dev.Revoked {
			continue
		}
		kPair, err := c.resolver.ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err != nil || len(kPair) == 0 {
			continue
		}
		handles := wire.DeriveRendezvousHandlesWithSkew(kPair, now, c.epochWindow)
		res[dev.DeviceID] = handles
	}
	return res, nil
}

// MatchInboundPresence tests an incoming opaque handle and proof against stored paired devices.
func (c *PresenceCoordinator) MatchInboundPresence(ctx context.Context, handle string, nonce []byte, proof string, now time.Time) (string, bool) {
	if !wire.ValidateRendezvousHandle(handle) {
		return "", false
	}

	devices, err := c.store.ListDevices(ctx)
	if err != nil || len(devices) == 0 {
		return "", false
	}

	for _, dev := range devices {
		if dev.Revoked {
			continue
		}
		kPair, err := c.resolver.ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err != nil || len(kPair) == 0 {
			continue
		}

		if wire.MatchRendezvousHandle(kPair, handle, now, c.epochWindow) {
			if len(proof) > 0 && len(nonce) > 0 {
				if wire.VerifyPresenceProof(kPair, handle, nonce, proof) {
					c.RecordPeerDiscovered(dev.DeviceID, handle, now)
					return dev.DeviceID, true
				}
			} else {
				c.RecordPeerDiscovered(dev.DeviceID, handle, now)
				return dev.DeviceID, true
			}
		}
	}
	return "", false
}

// RecordPeerDiscovered marks a peer as discovered with an expiration window.
func (c *PresenceCoordinator) RecordPeerDiscovered(deviceID, handle string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[deviceID] = &PeerPresenceRecord{
		DeviceID:  deviceID,
		Status:    PresenceDiscovered,
		Handle:    handle,
		LastSeen:  now,
		ExpiresAt: now.Add(c.epochWindow),
	}
}

// SetPeerConnecting marks a peer transition into active connection establishment.
func (c *PresenceCoordinator) SetPeerConnecting(deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.records[deviceID]
	if !ok {
		rec = &PeerPresenceRecord{DeviceID: deviceID}
		c.records[deviceID] = rec
	}
	rec.Status = PresenceConnecting
}

// SetPeerConnected marks a peer as actively connected.
func (c *PresenceCoordinator) SetPeerConnected(deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.records[deviceID]
	if !ok {
		rec = &PeerPresenceRecord{DeviceID: deviceID}
		c.records[deviceID] = rec
	}
	rec.Status = PresenceConnected
	rec.LastSeen = time.Now()
}

// SetPeerDisconnected marks a peer as disconnected/offline.
func (c *PresenceCoordinator) SetPeerDisconnected(deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.records[deviceID]
	if ok {
		rec.Status = PresenceOffline
	}
}

// GetPeerPresence queries truthful presence for a device. If a discovered peer's epoch
// has elapsed without a refreshed handle, it truthfully reports PresenceOffline.
func (c *PresenceCoordinator) GetPeerPresence(deviceID string, now time.Time) PresenceStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.records[deviceID]
	if !ok {
		return PresenceOffline
	}
	if rec.Status == PresenceConnected || rec.Status == PresenceConnecting {
		return rec.Status
	}
	if rec.Status == PresenceDiscovered {
		if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
			// Truthful presence: discovery is ephemeral. Once the epoch window expires, report offline.
			return PresenceOffline
		}
		return PresenceDiscovered
	}
	return PresenceOffline
}

// PruneExpired removes presence records that have expired.
func (c *PresenceCoordinator) PruneExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, rec := range c.records {
		if rec.Status == PresenceDiscovered && !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
			delete(c.records, id)
		}
	}
}
