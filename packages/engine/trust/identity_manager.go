// Package trust manages local device cryptographic identity and paired device trust records.
package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sendbeam/wire"
)

var (
	// ErrIdentityNotFound is returned when identity key does not exist.
	ErrIdentityNotFound = errors.New("device identity not found")

	// ErrCorruptIdentityFile is returned when identity key file exists but is corrupted.
	// Invariant: identities must NEVER be silently regenerated or overwritten after corrupt reads.
	ErrCorruptIdentityFile = errors.New("corrupt device identity key file; refusing to overwrite or regenerate")
)

// IdentityManager manages local device cryptographic identity and seed persistence.
type IdentityManager struct {
	mu           sync.RWMutex
	keyFilePath  string
	currIdentity *wire.DeviceIdentity
}

// NewIdentityManager creates an IdentityManager that persists the device private seed to keyFilePath.
func NewIdentityManager(keyFilePath string) (*IdentityManager, error) {
	cleanPath := filepath.Clean(keyFilePath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}

	mgr := &IdentityManager{
		keyFilePath: cleanPath,
	}

	return mgr, nil
}

// NewMemoryIdentityManager creates an in-memory IdentityManager with a pre-configured identity (useful for tests).
func NewMemoryIdentityManager(id *wire.DeviceIdentity) *IdentityManager {
	return &IdentityManager{
		currIdentity: id,
	}
}

// GetOrCreateIdentity returns the existing device identity or generates and saves a fresh one.
func (m *IdentityManager) GetOrCreateIdentity() (*wire.DeviceIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currIdentity != nil {
		return m.currIdentity, nil
	}

	// Try loading from file
	id, err := m.loadLocked()
	if err == nil {
		m.currIdentity = id
		return id, nil
	}

	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrIdentityNotFound) {
		return nil, fmt.Errorf("load device identity: %w", err)
	}

	// Generate fresh identity only if no file exists
	id, err = wire.GenerateDeviceIdentityFromReader(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate fresh device identity: %w", err)
	}

	if err := m.saveLocked(id); err != nil {
		return nil, fmt.Errorf("save fresh device identity: %w", err)
	}

	m.currIdentity = id
	return id, nil
}

// RotateIdentity generates a new device identity keypair, overwrites the stored key, and returns the new identity.
func (m *IdentityManager) RotateIdentity() (*wire.DeviceIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	newID, err := wire.GenerateDeviceIdentityFromReader(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate rotated device identity: %w", err)
	}

	if err := m.saveLocked(newID); err != nil {
		return nil, fmt.Errorf("save rotated device identity: %w", err)
	}

	m.currIdentity = newID
	return newID, nil
}

// CurrentIdentity returns the cached identity or nil if not yet initialized.
func (m *IdentityManager) CurrentIdentity() *wire.DeviceIdentity {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currIdentity
}

func (m *IdentityManager) loadLocked() (*wire.DeviceIdentity, error) {
	data, err := os.ReadFile(m.keyFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrIdentityNotFound
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: key file exists but is empty (0 bytes)", ErrCorruptIdentityFile)
	}

	// Seed is stored as raw 32 bytes or 64-character hex
	var seed []byte
	if len(data) == ed25519.SeedSize {
		seed = data
	} else {
		decoded, err := hex.DecodeString(string(data))
		if err == nil && len(decoded) == ed25519.SeedSize {
			seed = decoded
		} else {
			return nil, fmt.Errorf("%w: invalid seed data format or length (%d bytes)", ErrCorruptIdentityFile, len(data))
		}
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return wire.NewDeviceIdentity(pub, priv)
}

func (m *IdentityManager) saveLocked(id *wire.DeviceIdentity) error {
	seed := id.PrivateKey.Seed()

	dir := filepath.Dir(m.keyFilePath)
	tmpFile, err := os.CreateTemp(dir, "identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp identity file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp identity file: %w", err)
	}

	if _, err := tmpFile.Write(seed); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp identity file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp identity file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp identity file: %w", err)
	}

	if err := os.Rename(tmpName, m.keyFilePath); err != nil {
		return fmt.Errorf("atomic rename identity file: %w", err)
	}

	return nil
}
