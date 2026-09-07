package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

func TestMemoryTombstoneStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTombstoneStore()

	seedA := sha256.Sum256([]byte("seed-tombstone-test-alice"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	idA, err := wire.NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	if err != nil {
		t.Fatal(err)
	}

	targetID := "sb-dev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now().UTC()

	// Store sequence 5
	rec5, err := wire.SignRevocation(idA, targetID, 5, now)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.StoreTombstone(ctx, rec5); err != nil {
		t.Fatalf("StoreTombstone failed: %v", err)
	}

	if !store.HasTombstone(ctx, targetID) {
		t.Fatal("expected HasTombstone to return true")
	}
	if store.HasTombstone(ctx, "sb-dev-unknown000000000000000000000000000000000000000000000000000000") {
		t.Fatal("expected HasTombstone to return false for unknown device")
	}

	got, err := store.GetTombstone(ctx, targetID)
	if err != nil {
		t.Fatalf("GetTombstone failed: %v", err)
	}
	if got.Seq != 5 || got.RevokedDeviceID != targetID {
		t.Fatalf("unexpected tombstone retrieved: %+v", got)
	}

	// Rollback attempt: seq 3 <= 5 fails with ErrRevocationSeqRollback
	rec3, err := wire.SignRevocation(idA, targetID, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreTombstone(ctx, rec3); !errors.Is(err, wire.ErrRevocationSeqRollback) {
		t.Fatalf("expected ErrRevocationSeqRollback on lower sequence, got %v", err)
	}

	// Replay attempt: seq 5 <= 5 fails with ErrRevocationSeqRollback
	if err := store.StoreTombstone(ctx, rec5); !errors.Is(err, wire.ErrRevocationSeqRollback) {
		t.Fatalf("expected ErrRevocationSeqRollback on identical sequence, got %v", err)
	}

	// Forward update: seq 6 > 5 succeeds
	rec6, err := wire.SignRevocation(idA, targetID, 6, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreTombstone(ctx, rec6); err != nil {
		t.Fatalf("forward sequence StoreTombstone failed: %v", err)
	}
	got6, _ := store.GetTombstone(ctx, targetID)
	if got6.Seq != 6 {
		t.Fatalf("expected seq 6, got %d", got6.Seq)
	}

	// Self-tombstone
	selfTomb, err := wire.SignSelfTombstone(idA, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreTombstone(ctx, selfTomb); err != nil {
		t.Fatalf("StoreTombstone for self-tombstone failed: %v", err)
	}
	if !store.HasTombstone(ctx, idA.DeviceID) {
		t.Fatal("expected HasTombstone for self-tombstone to be true")
	}

	list, err := store.ListTombstones(ctx)
	if err != nil {
		t.Fatalf("ListTombstones failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 tombstones, got %d", len(list))
	}
}

func TestFileTombstoneStore(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "tombstones.json")

	store, err := NewFileTombstoneStore(filePath)
	if err != nil {
		t.Fatalf("NewFileTombstoneStore failed: %v", err)
	}

	seedA := sha256.Sum256([]byte("seed-file-tombstone-alice"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	idA, err := wire.NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	if err != nil {
		t.Fatal(err)
	}

	targetID := "sb-dev-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	now := time.Now().UTC()

	rec, err := wire.SignRevocation(idA, targetID, 1, now)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.StoreTombstone(ctx, rec); err != nil {
		t.Fatalf("StoreTombstone failed: %v", err)
	}

	// Check file permissions are 0600
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permissions on tombstone file, got %o", perm)
	}

	// Reload from disk into fresh store instance
	reloaded, err := NewFileTombstoneStore(filePath)
	if err != nil {
		t.Fatalf("reload NewFileTombstoneStore failed: %v", err)
	}
	if !reloaded.HasTombstone(ctx, targetID) {
		t.Fatal("reloaded store missing tombstone")
	}

	got, err := reloaded.GetTombstone(ctx, targetID)
	if err != nil || got.Seq != 1 {
		t.Fatalf("unexpected reloaded tombstone: %+v, err: %v", got, err)
	}

	// Monotonic sequence rollback check
	staleRec, err := wire.SignRevocation(idA, targetID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.StoreTombstone(ctx, staleRec); !errors.Is(err, wire.ErrRevocationSeqRollback) {
		t.Fatalf("expected ErrRevocationSeqRollback on disk store, got %v", err)
	}

	// Corrupt file handling: write invalid JSON
	corruptPath := filepath.Join(tmpDir, "corrupt_tombstones.json")
	if err := os.WriteFile(corruptPath, []byte("not-valid-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTombstoneStore(corruptPath); !errors.Is(err, ErrCorruptTombstoneStore) {
		t.Fatalf("expected ErrCorruptTombstoneStore on corrupt file, got %v", err)
	}
}
