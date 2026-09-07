package receiver

import (
	"context"
	"net"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// ConsentRequest aliases transfer.ConsentRequest for consumers of the receiver package.
type ConsentRequest = transfer.ConsentRequest

// ConsentDecision aliases transfer.ConsentDecision for consumers of the receiver package.
type ConsentDecision = transfer.ConsentDecision

// ConsentHandler aliases transfer.ConsentHandler for consumers of the receiver package.
type ConsentHandler = transfer.ConsentHandler

// DiscoveredPeer aliases discovery.DiscoveredPeer
type DiscoveredPeer = discovery.DiscoveredPeer

// TransferProgress contains snapshot progress for an in-flight receive.
type TransferProgress struct {
	TransferID        string `json:"transferId"`
	PeerDeviceID      string `json:"peerDeviceId"`
	AcknowledgedBytes int64  `json:"acknowledgedBytes"`
	FileIdx           int    `json:"fileIdx"`
	FileBytes         int64  `json:"fileBytes"`
	FileSize          int64  `json:"fileSize"`
}

// Config configures the shared native receiver.
type Config struct {
	// DestDir is the root directory where accepted files are saved.
	DestDir string

	// AutoAccept when true automatically accepts transfers from trusted devices.
	AutoAccept bool

	// Once when true causes the receiver to stop listening after ONE verified delivery.
	Once bool

	// Server is the signaling server WebSocket URL (e.g. wss://localhost:8443/ws).
	Server string

	// Port is the UDP port for direct local network (LAN) peer discovery.
	Port uint16

	// BeaconInterval is the interval between LAN discovery beacons.
	BeaconInterval time.Duration

	// EpochWindow is the time window for opaque rendezvous handles and LAN beacons.
	EpochWindow time.Duration

	// ICEServers configures WebRTC ICE STUN/TURN servers.
	ICEServers []webrtc.ICEServer

	// ForceRelay forces transfer over signaling relay without direct WebRTC.
	ForceRelay bool

	// Private enables traffic padding negotiation (V17-PR03).
	Private bool

	// RelayJitter adds optional timing jitter for relay frames (V17-PR04).
	RelayJitter time.Duration

	// Identity is the local device identity.
	Identity *wire.DeviceIdentity

	// TrustStore manages trusted paired devices.
	TrustStore trust.Store

	// Secrets provides access to pairwise keys and credentials.
	Secrets trust.CredentialStore

	// Tombstones checks authorization of revoked devices.
	Tombstones trust.TombstoneStore

	// Dialer optionally overrides how the receiver connects to signaling server.
	Dialer func(ctx context.Context, url string) (transfer.Signal, error)

	// PacketConn optionally overrides the UDP socket for LAN discovery (useful in tests).
	PacketConn net.PacketConn

	// ConsentHandler is invoked when explicit user consent is required.
	ConsentHandler ConsentHandler

	// Event hooks
	OnPeerDiscovered   func(peer DiscoveredPeer)
	OnConsentRequested func(req ConsentRequest)
	OnTransferStart    func(transferID string, peerDeviceID string, manifest wire.Manifest)
	OnProgress         func(peerDeviceID string, acknowledgedBytes int64)
	OnFileProgress     func(peerDeviceID string, fileIdx int, fileBytes, ackBytes int64)
	OnTransferComplete func(peerDeviceID string, outcome *transfer.Outcome)
	OnTransferError    func(peerDeviceID string, err error)
	OnListening        func()
}
