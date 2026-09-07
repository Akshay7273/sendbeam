// Package trust manages local device cryptographic identity, paired device trust records, and protected credentials.
package trust

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// ErrCorruptSecretStore indicates corrupt or unparseable secret storage on disk.
	ErrCorruptSecretStore = errors.New("corrupt secret store; refusing to overwrite or parse")
	// ErrInvalidPairSecret indicates an invalid pair secret length or parameter.
	ErrInvalidPairSecret = errors.New("invalid pair secret")
)

// CredentialStore defines persistent storage, resolution, and deletion of pairwise secrets (k_pair).
type CredentialStore interface {
	SecretResolver
	SetPairSecret(ctx context.Context, deviceID, pairCredRef string, secret []byte) error
	DeletePairSecret(ctx context.Context, deviceID string) error
	BackendName() string
	IsProtected() bool
}

// ProtectedCredentialStore wraps an OS-protected SecretStore to persist pair credentials.
// Invariant: it strictly refuses silent downgrade to plaintext storage.
type ProtectedCredentialStore struct {
	secretStore SecretStore
}

// NewProtectedCredentialStore creates a ProtectedCredentialStore wrapping an OS-protected SecretStore.
func NewProtectedCredentialStore(secretStore SecretStore) *ProtectedCredentialStore {
	if secretStore == nil {
		secretStore = DefaultSecretStore()
	}
	return &ProtectedCredentialStore{secretStore: secretStore}
}

func (p *ProtectedCredentialStore) pairKey(deviceID string) string {
	return "sendbeam:pair:" + strings.TrimSpace(deviceID)
}

// ResolvePairSecret implements SecretResolver and CredentialStore.
func (p *ProtectedCredentialStore) ResolvePairSecret(_ context.Context, deviceID, _ string) ([]byte, error) {
	if !p.secretStore.IsAvailable() {
		return nil, ErrSecretStoreUnavailable
	}
	key := p.pairKey(deviceID)
	secret, err := p.secretStore.Get(key)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return nil, ErrSecretNotFound
		}
		return nil, err
	}
	return secret, nil
}

// SetPairSecret stores a 32-byte pairwise secret into the OS-protected store.
func (p *ProtectedCredentialStore) SetPairSecret(_ context.Context, deviceID, _ string, secret []byte) error {
	if !p.secretStore.IsAvailable() {
		return ErrSecretStoreUnavailable
	}
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("%w: device ID cannot be empty", ErrInvalidPairSecret)
	}
	if len(secret) != 32 {
		return fmt.Errorf("%w: pair secret must be exactly 32 bytes, got %d", ErrInvalidPairSecret, len(secret))
	}
	key := p.pairKey(deviceID)
	return p.secretStore.Set(key, secret)
}

// DeletePairSecret removes a pairwise secret from the OS-protected store.
func (p *ProtectedCredentialStore) DeletePairSecret(_ context.Context, deviceID string) error {
	if !p.secretStore.IsAvailable() {
		return ErrSecretStoreUnavailable
	}
	key := p.pairKey(deviceID)
	return p.secretStore.Delete(key)
}

// BackendName returns the name of the underlying OS protected backend.
func (p *ProtectedCredentialStore) BackendName() string {
	return p.secretStore.BackendName()
}

// IsProtected reports whether the underlying store is an active OS-protected backend.
func (p *ProtectedCredentialStore) IsProtected() bool {
	return p.secretStore.BackendName() != "memory" && p.secretStore.IsAvailable()
}

// FileSecretStore manages persistent storage of pair secrets on disk with 0600 permissions
// for environments where OS credential facilities are unavailable (e.g. headless CLI).
//
// HEADLESS LIMITATION: FileSecretStore is restricted by POSIX file permissions to the local
// user account; it does not provide hardware enclave or OS-keychain backed encryption at rest.
type FileSecretStore struct {
	path string
	mu   sync.RWMutex
	data map[string]string // deviceID -> hex(k_pair)
}

// NewFileSecretStore initializes a FileSecretStore from disk.
func NewFileSecretStore(path string) (*FileSecretStore, error) {
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create secrets directory: %w", err)
	}

	store := &FileSecretStore{
		path: cleanPath,
		data: make(map[string]string),
	}

	content, err := os.ReadFile(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("read secrets file: %w", err)
	}

	if len(content) == 0 {
		return nil, fmt.Errorf("%w: secrets file exists but is empty (0 bytes)", ErrCorruptSecretStore)
	}

	if err := json.Unmarshal(content, &store.data); err != nil {
		return nil, fmt.Errorf("%w: parse secrets file JSON: %v", ErrCorruptSecretStore, err)
	}

	for k, hexStr := range store.data {
		raw, decErr := hex.DecodeString(hexStr)
		if decErr != nil || len(raw) != 32 {
			return nil, fmt.Errorf("%w: invalid hex secret entry for device %q", ErrCorruptSecretStore, k)
		}
	}

	return store, nil
}

// SetPairSecret persists a pairwise secret to disk atomically with 0600 permissions.
func (f *FileSecretStore) SetPairSecret(_ context.Context, deviceID, _ string, secret []byte) error {
	return f.SetSecret(deviceID, secret)
}

// SetSecret persists a pairwise secret by device ID.
func (f *FileSecretStore) SetSecret(deviceID string, secret []byte) error {
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("%w: device ID cannot be empty", ErrInvalidPairSecret)
	}
	if len(secret) != 32 {
		return fmt.Errorf("%w: pair secret must be exactly 32 bytes, got %d", ErrInvalidPairSecret, len(secret))
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.data[deviceID] = hex.EncodeToString(secret)
	return f.saveLocked()
}

// ResolvePairSecret resolves a stored pairwise secret by device ID.
func (f *FileSecretStore) ResolvePairSecret(_ context.Context, deviceID, _ string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	hexStr, ok := f.data[deviceID]
	if !ok || len(hexStr) == 0 {
		return nil, ErrSecretNotFound
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: decode pair secret: %v", ErrCorruptSecretStore, err)
	}
	return raw, nil
}

// DeletePairSecret removes a pairwise secret from storage and writes back atomically.
func (f *FileSecretStore) DeletePairSecret(_ context.Context, deviceID string) error {
	return f.DeleteSecret(deviceID)
}

// DeleteSecret removes a device secret from storage.
func (f *FileSecretStore) DeleteSecret(deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.data[deviceID]; !ok {
		return nil
	}
	delete(f.data, deviceID)
	return f.saveLocked()
}

func (f *FileSecretStore) saveLocked() error {
	data, err := json.MarshalIndent(f.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}

	dir := filepath.Dir(f.path)
	tmpFile, err := os.CreateTemp(dir, "secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp secrets file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp secrets file: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp secrets file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp secrets file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp secrets file: %w", err)
	}

	// Verify temporary file before rename
	verifyContent, err := os.ReadFile(tmpName)
	if err != nil {
		return fmt.Errorf("verify temp secrets file: %w", err)
	}
	var verifyMap map[string]string
	if err := json.Unmarshal(verifyContent, &verifyMap); err != nil {
		return fmt.Errorf("verify unmarshal temp secrets: %w", err)
	}

	if err := os.Rename(tmpName, f.path); err != nil {
		return fmt.Errorf("atomic rename secrets file: %w", err)
	}

	return nil
}

// BackendName returns "file (headless)".
func (f *FileSecretStore) BackendName() string {
	return "file (headless)"
}

// IsProtected reports false for file-backed storage (headless mode).
func (f *FileSecretStore) IsProtected() bool {
	return false
}

// MemoryCredentialStore provides an in-memory CredentialStore for testing and transient sessions.
type MemoryCredentialStore struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

// NewMemoryCredentialStore creates a new MemoryCredentialStore.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		secrets: make(map[string][]byte),
	}
}

// ResolvePairSecret resolves a secret from memory.
func (m *MemoryCredentialStore) ResolvePairSecret(_ context.Context, deviceID, _ string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.secrets[deviceID]
	if !ok {
		return nil, ErrSecretNotFound
	}
	cpy := make([]byte, len(val))
	copy(cpy, val)
	return cpy, nil
}

// SetPairSecret stores a 32-byte pairwise secret into memory.
func (m *MemoryCredentialStore) SetPairSecret(_ context.Context, deviceID, _ string, secret []byte) error {
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("%w: device ID cannot be empty", ErrInvalidPairSecret)
	}
	if len(secret) != 32 {
		return fmt.Errorf("%w: pair secret must be exactly 32 bytes, got %d", ErrInvalidPairSecret, len(secret))
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	cpy := make([]byte, len(secret))
	copy(cpy, secret)
	m.secrets[deviceID] = cpy
	return nil
}

// DeletePairSecret removes a pairwise secret from memory.
func (m *MemoryCredentialStore) DeletePairSecret(_ context.Context, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.secrets, deviceID)
	return nil
}

// BackendName returns "memory".
func (m *MemoryCredentialStore) BackendName() string {
	return "memory"
}

// IsProtected reports false for in-memory stores.
func (m *MemoryCredentialStore) IsProtected() bool {
	return false
}

// MigrateLegacyFileSecrets migrates secrets from a legacy plaintext secrets.json file
// into a CredentialStore using a crash-safe write-verify-switch workflow.
func MigrateLegacyFileSecrets(secretsPath string, target CredentialStore) error {
	if secretsPath == "" || target == nil {
		return nil
	}

	content, err := os.ReadFile(secretsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read legacy secrets file: %w", err)
	}

	if len(content) == 0 {
		_ = os.Remove(secretsPath)
		return nil
	}

	var legacy map[string]string
	if err := json.Unmarshal(content, &legacy); err != nil {
		return fmt.Errorf("%w: legacy secrets JSON: %v", ErrCorruptSecretStore, err)
	}

	ctx := context.Background()

	// Write each secret to the target store
	for devID, hexSecret := range legacy {
		raw, decErr := hex.DecodeString(hexSecret)
		if decErr != nil || len(raw) != 32 {
			return fmt.Errorf("%w: invalid hex secret for %q in legacy file", ErrCorruptSecretStore, devID)
		}

		if err := target.SetPairSecret(ctx, devID, "", raw); err != nil {
			return fmt.Errorf("migrate secret for %q: %w", devID, err)
		}

		// Verify written secret
		verified, err := target.ResolvePairSecret(ctx, devID, "")
		if err != nil || !bytes.Equal(verified, raw) {
			return fmt.Errorf("verify migrated secret for %q failed: %w", devID, err)
		}
	}

	// Zeroize original file on disk before removing/renaming
	zeros := make([]byte, len(content))
	_ = os.WriteFile(secretsPath, zeros, 0600)

	// Rename to .migrated or remove
	migratedPath := secretsPath + ".migrated"
	if err := os.Rename(secretsPath, migratedPath); err != nil {
		_ = os.Remove(secretsPath)
	}

	return nil
}
