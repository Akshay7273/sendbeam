// Package trust manages local device cryptographic identity, paired device trust records, and persistent tombstones.
package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sendbeam/wire"
)

var (
	// ErrTombstoneNotFound indicates no tombstone record exists for the requested device ID.
	ErrTombstoneNotFound = errors.New("tombstone not found")

	// ErrCorruptTombstoneStore indicates corrupted or unparseable tombstone storage on disk.
	// Invariant: corrupt tombstone databases must NEVER be silently overwritten or regenerated.
	ErrCorruptTombstoneStore = errors.New("corrupt tombstone store; refusing to overwrite or parse")
)

// TombstoneStore defines persistent and in-memory storage and querying of signed revocation tombstones (ADR 0010 §4.5).
type TombstoneStore interface {
	StoreTombstone(ctx context.Context, record *wire.RevocationRecord) error
	GetTombstone(ctx context.Context, deviceID string) (*wire.RevocationRecord, error)
	HasTombstone(ctx context.Context, deviceID string) bool
	ListTombstones(ctx context.Context) ([]*wire.RevocationRecord, error)
}

// MemoryTombstoneStore is an in-memory thread-safe implementation of TombstoneStore for tests and ephemeral sessions.
type MemoryTombstoneStore struct {
	mu         sync.RWMutex
	tombstones map[string]*wire.RevocationRecord
}

// NewMemoryTombstoneStore creates a new MemoryTombstoneStore.
func NewMemoryTombstoneStore() *MemoryTombstoneStore {
	return &MemoryTombstoneStore{
		tombstones: make(map[string]*wire.RevocationRecord),
	}
}

// StoreTombstone records a signed RevocationRecord into the tombstone store, enforcing monotonic sequence numbers.
func (m *MemoryTombstoneStore) StoreTombstone(_ context.Context, record *wire.RevocationRecord) error {
	if record == nil {
		return wire.ErrInvalidRevocationRecord
	}
	if err := record.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.tombstones[record.RevokedDeviceID]
	if ok && existing.RevokerDeviceID == record.RevokerDeviceID {
		if record.Seq <= existing.Seq {
			return wire.ErrRevocationSeqRollback
		}
	}

	recCopy := *record
	m.tombstones[record.RevokedDeviceID] = &recCopy
	return nil
}

// GetTombstone retrieves a tombstone record by device ID.
func (m *MemoryTombstoneStore) GetTombstone(_ context.Context, deviceID string) (*wire.RevocationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.tombstones[deviceID]
	if !ok {
		return nil, ErrTombstoneNotFound
	}
	recCopy := *rec
	return &recCopy, nil
}

// HasTombstone reports whether a device ID has an active tombstone record.
func (m *MemoryTombstoneStore) HasTombstone(_ context.Context, deviceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.tombstones[deviceID]
	return ok
}

// ListTombstones returns all stored tombstone records.
func (m *MemoryTombstoneStore) ListTombstones(_ context.Context) ([]*wire.RevocationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*wire.RevocationRecord, 0, len(m.tombstones))
	for _, rec := range m.tombstones {
		recCopy := *rec
		out = append(out, &recCopy)
	}
	return out, nil
}

type tombstoneFilePayload struct {
	Version    int                      `json:"version"`
	Tombstones []*wire.RevocationRecord `json:"tombstones"`
}

// FileTombstoneStore persists signed revocation tombstones to disk with 0600 permissions
// using atomic write-verify-switch (ADR 0010 §4.5).
type FileTombstoneStore struct {
	filePath   string
	mu         sync.RWMutex
	tombstones map[string]*wire.RevocationRecord
}

// NewFileTombstoneStore loads or creates a persistent FileTombstoneStore at filePath.
func NewFileTombstoneStore(filePath string) (*FileTombstoneStore, error) {
	cleanPath := filepath.Clean(filePath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create tombstone dir: %w", err)
	}

	store := &FileTombstoneStore{
		filePath:   cleanPath,
		tombstones: make(map[string]*wire.RevocationRecord),
	}

	if err := store.loadLocked(); err != nil {
		return nil, err
	}

	return store, nil
}

func (f *FileTombstoneStore) loadLocked() error {
	content, err := os.ReadFile(f.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read tombstone file: %w", err)
	}

	if len(content) == 0 {
		return fmt.Errorf("%w: tombstone file exists but is empty (0 bytes)", ErrCorruptTombstoneStore)
	}

	var payload tombstoneFilePayload
	if err := json.Unmarshal(content, &payload); err != nil {
		return fmt.Errorf("%w: parse tombstone json: %v", ErrCorruptTombstoneStore, err)
	}

	for _, rec := range payload.Tombstones {
		if rec == nil {
			continue
		}
		if err := rec.Validate(); err != nil {
			return fmt.Errorf("%w: invalid tombstone entry for device %q: %v", ErrCorruptTombstoneStore, rec.RevokedDeviceID, err)
		}
		recCopy := *rec
		f.tombstones[rec.RevokedDeviceID] = &recCopy
	}

	return nil
}

func (f *FileTombstoneStore) saveLocked() error {
	records := make([]*wire.RevocationRecord, 0, len(f.tombstones))
	for _, rec := range f.tombstones {
		recCopy := *rec
		records = append(records, &recCopy)
	}

	payload := tombstoneFilePayload{
		Version:    1,
		Tombstones: records,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tombstones: %w", err)
	}

	dir := filepath.Dir(f.filePath)
	tmpFile, err := os.CreateTemp(dir, "tombstones.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp tombstone file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp tombstone file: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp tombstone file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp tombstone file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp tombstone file: %w", err)
	}

	// Verify before replacing live database (write -> verify -> switch)
	verifyData, err := os.ReadFile(tmpName)
	if err != nil {
		return fmt.Errorf("verify temp tombstone file: %w", err)
	}
	var verifyPayload tombstoneFilePayload
	if err := json.Unmarshal(verifyData, &verifyPayload); err != nil {
		return fmt.Errorf("verify unmarshal temp tombstone file: %w", err)
	}

	if err := os.Rename(tmpName, f.filePath); err != nil {
		return fmt.Errorf("atomic rename tombstone file: %w", err)
	}

	return nil
}

// StoreTombstone records a signed RevocationRecord and flushes atomically to disk.
func (f *FileTombstoneStore) StoreTombstone(_ context.Context, record *wire.RevocationRecord) error {
	if record == nil {
		return wire.ErrInvalidRevocationRecord
	}
	if err := record.Validate(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	existing, ok := f.tombstones[record.RevokedDeviceID]
	if ok && existing.RevokerDeviceID == record.RevokerDeviceID {
		if record.Seq <= existing.Seq {
			return wire.ErrRevocationSeqRollback
		}
	}

	recCopy := *record
	f.tombstones[record.RevokedDeviceID] = &recCopy
	return f.saveLocked()
}

// GetTombstone retrieves a tombstone record by device ID from disk cache.
func (f *FileTombstoneStore) GetTombstone(_ context.Context, deviceID string) (*wire.RevocationRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	rec, ok := f.tombstones[deviceID]
	if !ok {
		return nil, ErrTombstoneNotFound
	}
	recCopy := *rec
	return &recCopy, nil
}

// HasTombstone reports whether a device ID exists in the tombstone store.
func (f *FileTombstoneStore) HasTombstone(_ context.Context, deviceID string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	_, ok := f.tombstones[deviceID]
	return ok
}

// ListTombstones returns all stored tombstone records.
func (f *FileTombstoneStore) ListTombstones(_ context.Context) ([]*wire.RevocationRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]*wire.RevocationRecord, 0, len(f.tombstones))
	for _, rec := range f.tombstones {
		recCopy := *rec
		out = append(out, &recCopy)
	}
	return out, nil
}
