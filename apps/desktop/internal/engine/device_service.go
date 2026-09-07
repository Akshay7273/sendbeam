package engine

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
	qrcode "github.com/skip2/go-qrcode"
)

// DeviceEventName is emitted to frontend whenever trusted devices or presence states update.
const DeviceEventName = "sendbeam:devices"

// PairingOfferResult represents the generated invite code and QR code for an offerer pairing session.
type PairingOfferResult struct {
	Code string `json:"code"`
	QR   string `json:"qr"`
}

// TrustedDeviceView is the JSON-serializable representation of a paired device for the UI.
type TrustedDeviceView struct {
	DeviceID       string           `json:"deviceId"`
	LocalLabel     string           `json:"localLabel"`
	Fingerprint    string           `json:"fingerprint"`
	PublicKey      string           `json:"publicKey"`
	Status         string           `json:"status"` // "lan_direct" | "online" | "offline" | "revoked"
	Revoked        bool             `json:"revoked"`
	LastSeenAt     string           `json:"lastSeenAt"`
	FirstSeenAt    string           `json:"firstSeenAt"`
	Capabilities   []string         `json:"capabilities"`
	Policy         wire.TrustPolicy `json:"policy"`
	DirectEndpoint string           `json:"directEndpoint,omitempty"`
}

type discoveredPeerInfo struct {
	ip       net.IP
	port     uint16
	lastSeen time.Time
}

// DeviceService manages trusted device operations and background presence for the desktop UI.
type DeviceService struct {
	mu            sync.RWMutex
	emit          func(name string, data any)
	idMgr         *trust.IdentityManager
	store         trust.Store
	secrets       trust.CredentialStore
	coordinator   *trust.PairingCoordinator
	tombstones    trust.TombstoneStore
	lanDiscovery  *discovery.LanDiscoveryService
	activePeers   map[string]discoveredPeerInfo // deviceID -> info
	configDir     string
	cancel        context.CancelFunc
	pairingMu     sync.Mutex
	pairingCancel context.CancelFunc
}

// NewDeviceService initializes the desktop device service with the default OS-protected credential store.
func NewDeviceService(emit func(name string, data any), customConfigDir string) (*DeviceService, error) {
	return NewDeviceServiceWithCredentials(emit, customConfigDir, nil)
}

// NewDeviceServiceWithCredentials initializes the desktop device service with a custom CredentialStore.
// If customSecrets is nil, it uses trust.NewProtectedCredentialStore(config.DefaultSecretStore()).
func NewDeviceServiceWithCredentials(emit func(name string, data any), customConfigDir string, customSecrets trust.CredentialStore) (*DeviceService, error) {
	dir := customConfigDir
	if dir == "" {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			userConfig = "."
		}
		dir = filepath.Join(userConfig, config.AppDirName)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	idPath := filepath.Join(dir, "identity.key")
	idMgr, err := trust.NewIdentityManager(idPath)
	if err != nil {
		return nil, fmt.Errorf("init identity manager: %w", err)
	}

	trustPath := filepath.Join(dir, "trust.json")
	trustStore, err := trust.NewFileTrustStore(trustPath)
	if err != nil {
		return nil, fmt.Errorf("init trust store: %w", err)
	}

	secrets := customSecrets
	if secrets == nil {
		secStore := config.DefaultSecretStore()
		secrets = trust.NewProtectedCredentialStore(secStore)
	}

	// Migrate legacy plaintext secrets.json if present
	legacySecretsPath := filepath.Join(dir, "secrets.json")
	if _, err := os.Stat(legacySecretsPath); err == nil {
		if err := trust.MigrateLegacyFileSecrets(legacySecretsPath, secrets); err != nil {
			return nil, fmt.Errorf("migrate legacy secrets: %w", err)
		}
	}

	tombstonesPath := filepath.Join(dir, "tombstones.json")
	tombstoneStore, err := trust.NewFileTombstoneStore(tombstonesPath)
	if err != nil {
		return nil, fmt.Errorf("init tombstone store: %w", err)
	}

	coordinator := trust.NewPairingCoordinatorWithCredentials(idMgr, trustStore, secrets)
	coordinator.SetTombstoneStore(tombstoneStore)

	ctx, cancel := context.WithCancel(context.Background())

	discCfg := discovery.Config{
		AdvertisePort:  53317,
		BeaconInterval: 3 * time.Second,
	}
	lanDiscovery := discovery.NewLanDiscoveryService(discCfg, trustStore, secrets)

	svc := &DeviceService{
		emit:         emit,
		idMgr:        idMgr,
		store:        trustStore,
		secrets:      secrets,
		coordinator:  coordinator,
		tombstones:   tombstoneStore,
		lanDiscovery: lanDiscovery,
		activePeers:  make(map[string]discoveredPeerInfo),
		configDir:    dir,
		cancel:       cancel,
	}

	lanDiscovery.OnPeerDiscovered(func(peer discovery.DiscoveredPeer) {
		svc.mu.Lock()
		svc.activePeers[peer.DeviceID] = discoveredPeerInfo{
			ip:       peer.IP,
			port:     peer.Port,
			lastSeen: time.Now().UTC(),
		}
		svc.mu.Unlock()
		svc.notifyDevicesChanged()
	})

	go func() {
		_ = lanDiscovery.Start(ctx)
	}()

	return svc, nil
}

// ListTrustedDevices returns all registered paired devices with honest status.
func (s *DeviceService) ListTrustedDevices() ([]TrustedDeviceView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	views := make([]TrustedDeviceView, 0, len(devices))

	for _, dev := range devices {
		status := "offline"
		var directEndpoint string

		isRevoked := dev.Revoked || (s.tombstones != nil && s.tombstones.HasTombstone(ctx, dev.DeviceID))
		if isRevoked {
			status = "revoked"
		} else if peer, ok := s.activePeers[dev.DeviceID]; ok && now.Sub(peer.lastSeen) < 30*time.Second {
			status = "lan_direct"
			directEndpoint = fmt.Sprintf("%s:%d", peer.ip.String(), peer.port)
		} else if !dev.LastSeenAt.IsZero() && now.Sub(dev.LastSeenAt) < 15*time.Minute {
			status = "online"
		}

		lastSeen := "never"
		if !dev.LastSeenAt.IsZero() {
			lastSeen = dev.LastSeenAt.UTC().Format(time.RFC3339)
		}

		views = append(views, TrustedDeviceView{
			DeviceID:       dev.DeviceID,
			LocalLabel:     dev.LocalLabel,
			Fingerprint:    dev.Fingerprint(),
			PublicKey:      dev.PublicKey,
			Status:         status,
			Revoked:        isRevoked,
			LastSeenAt:     lastSeen,
			FirstSeenAt:    dev.FirstSeenAt.UTC().Format(time.RFC3339),
			Capabilities:   dev.Capabilities,
			Policy:         dev.Policy,
			DirectEndpoint: directEndpoint,
		})
	}
	return views, nil
}

// RenameDevice updates a device's local label in the trust database.
func (s *DeviceService) RenameDevice(deviceID string, newLabel string) error {
	trimmed := strings.TrimSpace(newLabel)
	if trimmed == "" {
		return errors.New("device name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rec, err := s.store.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}

	rec.LocalLabel = trimmed
	if err := s.store.AddOrUpdateDevice(ctx, rec); err != nil {
		return err
	}

	s.notifyDevicesChanged()
	return nil
}

// UpdateDevicePolicy updates authorization and auto-accept safety policy.
func (s *DeviceService) UpdateDevicePolicy(deviceID string, policy wire.TrustPolicy) error {
	if policy.AutoAccept {
		if policy.AutoAcceptDestDir == "" {
			return errors.New("destination directory is required when auto-accept is enabled")
		}
		if !filepath.IsAbs(policy.AutoAcceptDestDir) {
			return errors.New("destination directory must be an absolute path")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.store.UpdatePolicy(ctx, deviceID, policy); err != nil {
		return err
	}

	s.notifyDevicesChanged()
	return nil
}

// UnpairDevice revokes or purges trust credentials for a device.
func (s *DeviceService) UnpairDevice(deviceID string, purge bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if wire.ValidateDeviceID(deviceID) {
		id, err := s.idMgr.GetOrCreateIdentity()
		if err != nil {
			return fmt.Errorf("get local identity: %w", err)
		}

		dev, err := s.store.GetDevice(ctx, deviceID)
		if err != nil && !errors.Is(err, trust.ErrDeviceNotFound) {
			return err
		}

		seq := uint64(1)
		if dev != nil && dev.RevocationSeq > 0 {
			seq = dev.RevocationSeq + 1
		}

		rec, err := wire.SignRevocation(id, deviceID, seq, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("sign revocation record: %w", err)
		}

		if s.tombstones != nil {
			if err := s.tombstones.StoreTombstone(ctx, rec); err != nil {
				return fmt.Errorf("store tombstone: %w", err)
			}
		}

		if purge {
			if err := s.store.UnpairDevice(ctx, deviceID); err != nil {
				return err
			}
		} else {
			if err := s.store.RevokeDeviceWithRecord(ctx, rec); err != nil {
				return err
			}
		}
	} else {
		if purge {
			if err := s.store.UnpairDevice(ctx, deviceID); err != nil {
				return err
			}
		} else {
			if err := s.store.RevokeDevice(ctx, deviceID); err != nil {
				return err
			}
		}
	}

	// Deletion errors are fatal; both purge and non-purge paths delete pair credentials
	if err := s.secrets.DeletePairSecret(ctx, deviceID); err != nil && !errors.Is(err, trust.ErrDeviceNotFound) && !errors.Is(err, trust.ErrSecretNotFound) && !errors.Is(err, trust.ErrSecretStoreUnavailable) {
		return fmt.Errorf("delete pair secret: %w", err)
	}

	s.mu.Lock()
	delete(s.activePeers, deviceID)
	s.mu.Unlock()

	s.notifyDevicesChanged()
	return nil
}

// PairDevice joins a pairing room with the given invite code and completes mutual device pairing.
func (s *DeviceService) PairDevice(serverURL, inviteCode, customLabel string, autoAccept bool, destDir string) (*TrustedDeviceView, error) {
	if inviteCode == "" {
		return nil, errors.New("invite code is required")
	}
	server := serverURL
	if server == "" {
		server = DefaultServer
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "Desktop Device"
	}

	opts := rendezvous.Options{
		Role: wire.RoleJoiner,
		Code: inviteCode,
	}

	dopts := wsclient.DialOptions{
		InsecureSkipVerify: true,
	}

	pairSess, err := wsclient.RendezvousPair(ctx, server, dopts, opts)
	if err != nil {
		return nil, fmt.Errorf("pairing handshake failed: %w", err)
	}
	defer pairSess.Close()

	cfg := trust.PairingSessionConfig{
		DeviceName:   hostname,
		Capabilities: []string{"transfer.v1", "transfer.v2", "lan_direct"},
		MasterKey:    pairSess.Result.Master,
		AutoAccept:   autoAccept,
		DestDir:      destDir,
	}

	pairResult, err := s.coordinator.AcceptPairing(ctx, pairSess, cfg)
	if err != nil {
		return nil, fmt.Errorf("pairing ceremony failed: %w", err)
	}
	if customLabel != "" {
		pairResult.PeerRecord.LocalLabel = customLabel
		_ = s.store.AddOrUpdateDevice(ctx, pairResult.PeerRecord)
	}

	s.notifyDevicesChanged()

	pubBytes, _ := hex.DecodeString(pairResult.PeerRecord.PublicKey)
	fp := wire.FormatFingerprint(pubBytes)

	return &TrustedDeviceView{
		DeviceID:     pairResult.PeerRecord.DeviceID,
		LocalLabel:   pairResult.PeerRecord.LocalLabel,
		Fingerprint:  fp,
		PublicKey:    pairResult.PeerRecord.PublicKey,
		Status:       "online",
		Revoked:      false,
		LastSeenAt:   time.Now().UTC().Format(time.RFC3339),
		FirstSeenAt:  pairResult.PeerRecord.FirstSeenAt.UTC().Format(time.RFC3339),
		Capabilities: pairResult.PeerRecord.Capabilities,
		Policy:       pairResult.PeerRecord.Policy,
	}, nil
}

// StartPairingOffer starts an offerer pairing session, returning the invite code and QR code.
// The ceremony completes asynchronously when a peer connects with the invite code.
func (s *DeviceService) StartPairingOffer(serverURL, customLabel string, autoAccept bool, destDir string) (*PairingOfferResult, error) {
	if autoAccept {
		if destDir == "" {
			return nil, errors.New("destination directory is required when auto-accept is enabled")
		}
		if !filepath.IsAbs(destDir) {
			return nil, errors.New("destination directory must be an absolute path")
		}
	}
	server := serverURL
	if server == "" {
		server = DefaultServer
	}

	s.pairingMu.Lock()
	if s.pairingCancel != nil {
		s.pairingCancel()
		s.pairingCancel = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	s.pairingCancel = cancel
	s.pairingMu.Unlock()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SendBeam Desktop"
	}

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	opts := rendezvous.Options{
		Role: wire.RoleOfferer,
		OnCode: func(code string) {
			select {
			case codeChan <- code:
			default:
			}
		},
	}
	dopts := wsclient.DialOptions{
		InsecureSkipVerify: true,
	}

	go func() {
		pairSess, err := wsclient.RendezvousPair(ctx, server, dopts, opts)
		if err != nil {
			select {
			case errChan <- err:
			default:
			}
			return
		}
		defer pairSess.Close()

		cfg := trust.PairingSessionConfig{
			DeviceName:   hostname,
			Capabilities: []string{"transfer.v1", "transfer.v2", "lan_direct"},
			MasterKey:    pairSess.Result.Master,
			AutoAccept:   autoAccept,
			DestDir:      destDir,
		}

		pairResult, err := s.coordinator.InitiatePairing(ctx, pairSess, cfg)
		if err != nil {
			if s.emit != nil {
				s.emit("sendbeam:pairing_failed", map[string]any{
					"error": err.Error(),
				})
			}
			return
		}

		if customLabel != "" {
			pairResult.PeerRecord.LocalLabel = customLabel
			_ = s.store.AddOrUpdateDevice(ctx, pairResult.PeerRecord)
		}

		s.notifyDevicesChanged()
		if s.emit != nil {
			s.emit("sendbeam:pairing_complete", map[string]any{
				"deviceId":   pairResult.PeerRecord.DeviceID,
				"localLabel": pairResult.PeerRecord.LocalLabel,
			})
		}
	}()

	select {
	case code := <-codeChan:
		var qr string
		if png, err := qrcode.Encode(code, qrcode.Medium, 256); err == nil {
			qr = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
		}
		return &PairingOfferResult{
			Code: code,
			QR:   qr,
		}, nil
	case err := <-errChan:
		_ = s.CancelPairingOffer()
		return nil, fmt.Errorf("pairing offer failed: %w", err)
	case <-time.After(15 * time.Second):
		_ = s.CancelPairingOffer()
		return nil, errors.New("timed out waiting for pairing room allocation")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// CancelPairingOffer cancels an in-progress pairing offer session.
func (s *DeviceService) CancelPairingOffer() error {
	s.pairingMu.Lock()
	defer s.pairingMu.Unlock()
	if s.pairingCancel != nil {
		s.pairingCancel()
		s.pairingCancel = nil
	}
	return nil
}

// GetIdentityManager returns the local IdentityManager.
func (s *DeviceService) GetIdentityManager() *trust.IdentityManager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.idMgr
}

// GetStore returns the local TrustStore.
func (s *DeviceService) GetStore() trust.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.store
}

// GetCredentialStore returns the local CredentialStore.
func (s *DeviceService) GetCredentialStore() trust.CredentialStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secrets
}

// GetTombstoneStore returns the local TombstoneStore.
func (s *DeviceService) GetTombstoneStore() trust.TombstoneStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tombstones
}

func (s *DeviceService) notifyDevicesChanged() {
	if s.emit == nil {
		return
	}
	devices, err := s.ListTrustedDevices()
	if err == nil {
		s.emit(DeviceEventName, devices)
	}
}

// Close gracefully stops the device service.
func (s *DeviceService) Close() {
	_ = s.CancelPairingOffer()
	if s.cancel != nil {
		s.cancel()
	}
}
