package trust

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

func TestProtectedCredentialStore_WithMemorySecretStore(t *testing.T) {
	ctx := context.Background()
	memSec := NewMemorySecretStore()
	credStore := NewProtectedCredentialStore(memSec)

	if credStore.BackendName() != "memory" {
		t.Errorf("BackendName = %q, want 'memory'", credStore.BackendName())
	}
	if credStore.IsProtected() {
		t.Errorf("IsProtected = true for memory store, want false")
	}

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	devID := "sb-dev-1111222233334444555566667777888811112222333344445555666677778888"

	// 1. Initial resolve returns not found
	_, err := credStore.ResolvePairSecret(ctx, devID, "ref-1")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("ResolvePairSecret before set = %v, want ErrSecretNotFound", err)
	}

	// 2. SetPairSecret
	if err := credStore.SetPairSecret(ctx, devID, "ref-1", secret); err != nil {
		t.Fatalf("SetPairSecret: %v", err)
	}

	// 3. ResolvePairSecret
	got, err := credStore.ResolvePairSecret(ctx, devID, "ref-1")
	if err != nil {
		t.Fatalf("ResolvePairSecret: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("ResolvePairSecret got %x, want %x", got, secret)
	}

	// 4. Invalid secret size must fail
	badSecret := []byte("too-short")
	if err := credStore.SetPairSecret(ctx, devID, "ref-1", badSecret); err == nil {
		t.Fatalf("expected error for short secret, got nil")
	}

	// 5. Empty device ID must fail
	if err := credStore.SetPairSecret(ctx, "", "ref-1", secret); err == nil {
		t.Fatalf("expected error for empty device ID, got nil")
	}

	// 6. DeletePairSecret
	if err := credStore.DeletePairSecret(ctx, devID); err != nil {
		t.Fatalf("DeletePairSecret: %v", err)
	}
	_, err = credStore.ResolvePairSecret(ctx, devID, "ref-1")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("ResolvePairSecret after delete = %v, want ErrSecretNotFound", err)
	}
}

func TestProtectedCredentialStore_UnavailableFailsClosed(t *testing.T) {
	ctx := context.Background()
	unavail := NewUnavailableSecretStore("test simulated headless no-keychain")
	credStore := NewProtectedCredentialStore(unavail)

	secret := make([]byte, 32)
	devID := "sb-dev-1111222233334444555566667777888811112222333344445555666677778888"

	err := credStore.SetPairSecret(ctx, devID, "ref-1", secret)
	if !errors.Is(err, ErrSecretStoreUnavailable) {
		t.Fatalf("SetPairSecret on unavailable = %v, want ErrSecretStoreUnavailable", err)
	}

	_, err = credStore.ResolvePairSecret(ctx, devID, "ref-1")
	if !errors.Is(err, ErrSecretStoreUnavailable) {
		t.Fatalf("ResolvePairSecret on unavailable = %v, want ErrSecretStoreUnavailable", err)
	}

	err = credStore.DeletePairSecret(ctx, devID)
	if !errors.Is(err, ErrSecretStoreUnavailable) {
		t.Fatalf("DeletePairSecret on unavailable = %v, want ErrSecretStoreUnavailable", err)
	}
}

func TestFileSecretStore_LifecycleAndCorruptHandling(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "secrets.json")

	store, err := NewFileSecretStore(filePath)
	if err != nil {
		t.Fatalf("NewFileSecretStore: %v", err)
	}

	if store.IsProtected() {
		t.Errorf("FileSecretStore IsProtected must be false (explicit headless limit)")
	}
	if store.BackendName() != "file (headless)" {
		t.Errorf("BackendName = %q, want 'file (headless)'", store.BackendName())
	}

	secretAlice := make([]byte, 32)
	secretAlice[0] = 0xaa
	devAlice := "sb-dev-alice111122223333444455556666777788881111222233334444555566667777"

	if err := store.SetPairSecret(ctx, devAlice, "ref-alice", secretAlice); err != nil {
		t.Fatalf("SetPairSecret: %v", err)
	}

	// Verify file mode 0600
	fi, err := os.Stat(filePath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("file permissions = %o, want 0600 (err=%v)", fi.Mode().Perm(), err)
	}

	// Reopen from disk
	reloaded, err := NewFileSecretStore(filePath)
	if err != nil {
		t.Fatalf("reopen NewFileSecretStore: %v", err)
	}
	got, err := reloaded.ResolvePairSecret(ctx, devAlice, "")
	if err != nil || !bytes.Equal(got, secretAlice) {
		t.Fatalf("reloaded secret mismatch: got %x, want %x (err=%v)", got, secretAlice, err)
	}

	// Delete
	if err := reloaded.DeletePairSecret(ctx, devAlice); err != nil {
		t.Fatalf("DeletePairSecret: %v", err)
	}
	_, err = reloaded.ResolvePairSecret(ctx, devAlice, "")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound after delete, got %v", err)
	}

	// Corrupt file handling: 0 bytes
	emptyFile := filepath.Join(tmpDir, "empty_secrets.json")
	_ = os.WriteFile(emptyFile, []byte{}, 0600)
	_, err = NewFileSecretStore(emptyFile)
	if !errors.Is(err, ErrCorruptSecretStore) {
		t.Fatalf("expected ErrCorruptSecretStore on 0-byte file, got %v", err)
	}

	// Corrupt file handling: invalid JSON
	badJSONFile := filepath.Join(tmpDir, "bad_json_secrets.json")
	_ = os.WriteFile(badJSONFile, []byte("{ corrupt json ..."), 0600)
	_, err = NewFileSecretStore(badJSONFile)
	if !errors.Is(err, ErrCorruptSecretStore) {
		t.Fatalf("expected ErrCorruptSecretStore on bad JSON, got %v", err)
	}

	// Corrupt file handling: invalid secret length
	badSecretFile := filepath.Join(tmpDir, "bad_secret_secrets.json")
	badData := map[string]string{devAlice: "aabbcc"} // 3 bytes instead of 32
	rawBad, _ := json.Marshal(badData)
	_ = os.WriteFile(badSecretFile, rawBad, 0600)
	_, err = NewFileSecretStore(badSecretFile)
	if !errors.Is(err, ErrCorruptSecretStore) {
		t.Fatalf("expected ErrCorruptSecretStore on short secret, got %v", err)
	}
}

func TestMigrateLegacyFileSecrets(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	legacyFile := filepath.Join(tmpDir, "legacy_secrets.json")

	secret1 := make([]byte, 32)
	secret1[0] = 0x11
	secret2 := make([]byte, 32)
	secret2[0] = 0x22

	dev1 := "sb-dev-1111111111111111111111111111111111111111111111111111111111111111"
	dev2 := "sb-dev-2222222222222222222222222222222222222222222222222222222222222222"

	legacyData := map[string]string{
		dev1: hex.EncodeToString(secret1),
		dev2: hex.EncodeToString(secret2),
	}
	rawJSON, _ := json.MarshalIndent(legacyData, "", "  ")
	if err := os.WriteFile(legacyFile, rawJSON, 0600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	memSec := NewMemorySecretStore()
	target := NewProtectedCredentialStore(memSec)

	// Execute migration
	if err := MigrateLegacyFileSecrets(legacyFile, target); err != nil {
		t.Fatalf("MigrateLegacyFileSecrets failed: %v", err)
	}

	// Verify secrets in target
	got1, err := target.ResolvePairSecret(ctx, dev1, "")
	if err != nil || !bytes.Equal(got1, secret1) {
		t.Fatalf("target dev1 mismatch: got %x, want %x", got1, secret1)
	}
	got2, err := target.ResolvePairSecret(ctx, dev2, "")
	if err != nil || !bytes.Equal(got2, secret2) {
		t.Fatalf("target dev2 mismatch: got %x, want %x", got2, secret2)
	}

	// Verify legacy plaintext file was removed or replaced
	if _, err := os.Stat(legacyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected legacy plaintext file to be removed")
	}

	// Verify .migrated file exists and was zeroized
	migratedFile := legacyFile + ".migrated"
	migratedContent, err := os.ReadFile(migratedFile)
	if err == nil {
		for _, b := range migratedContent {
			if b != 0 {
				t.Fatalf("migrated file contains non-zero bytes; zeroization failed")
			}
		}
	}
}

func TestFileTrustStore_V1MigrationAndCorruptHandling(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	trustPath := filepath.Join(tmpDir, "trust.json")

	id, _ := wire.GenerateDeviceIdentity()
	now := time.Now().UTC().Truncate(time.Second)

	// 1. Create a synthetic v1 trust database (missing relationship & cluster_id, version: 1)
	v1Payload := map[string]any{
		"version":    1,
		"updated_at": now.Format(time.RFC3339),
		"devices": []map[string]any{
			{
				"device_id":           id.DeviceID,
				"public_key":          id.PublicKeyHex(),
				"local_label":         "Old Laptop",
				"pair_credential_ref": "cred-old",
				"capabilities":        []string{wire.CapTransferV1},
				"first_seen_at":       now.Format(time.RFC3339),
				"last_seen_at":        now.Format(time.RFC3339),
				"revoked":             false,
				"policy": map[string]any{
					"auto_accept": false,
				},
			},
		},
	}
	v1Bytes, _ := json.MarshalIndent(v1Payload, "", "  ")
	if err := os.WriteFile(trustPath, v1Bytes, 0600); err != nil {
		t.Fatalf("write v1 trust file: %v", err)
	}

	// 2. Load with NewFileTrustStore
	store, err := NewFileTrustStore(trustPath)
	if err != nil {
		t.Fatalf("NewFileTrustStore on v1 file: %v", err)
	}

	// 3. Verify record was migrated with RelationshipContact
	dev, err := store.GetDevice(ctx, id.DeviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if dev.Relationship != wire.RelationshipContact {
		t.Errorf("Relationship = %q, want %q", dev.Relationship, wire.RelationshipContact)
	}

	// 4. Verify file on disk now has version 2
	data, _ := os.ReadFile(trustPath)
	var verifyPayload struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(data, &verifyPayload)
	if verifyPayload.Version != 2 {
		t.Errorf("migrated file version = %d, want 2", verifyPayload.Version)
	}

	// 5. Corrupt file handling: 0 bytes
	emptyTrustPath := filepath.Join(tmpDir, "empty_trust.json")
	_ = os.WriteFile(emptyTrustPath, []byte{}, 0600)
	_, err = NewFileTrustStore(emptyTrustPath)
	if !errors.Is(err, ErrCorruptTrustStore) {
		t.Fatalf("expected ErrCorruptTrustStore for 0-byte file, got %v", err)
	}

	// 6. Corrupt file handling: invalid JSON
	badTrustPath := filepath.Join(tmpDir, "bad_trust.json")
	_ = os.WriteFile(badTrustPath, []byte("{ bad json ..."), 0600)
	_, err = NewFileTrustStore(badTrustPath)
	if !errors.Is(err, ErrCorruptTrustStore) {
		t.Fatalf("expected ErrCorruptTrustStore for bad JSON, got %v", err)
	}
}
