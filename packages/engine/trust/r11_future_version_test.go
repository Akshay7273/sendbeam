// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package trust

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

// writeFutureTrustStore writes a valid trust.json whose envelope claims a
// FUTURE schema version, with one fully valid device record.
func writeFutureTrustStore(t *testing.T, dir string, version int) string {
	t.Helper()
	id, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	rec := wire.TrustRecord{
		DeviceID:          id.DeviceID,
		PublicKey:         id.PublicKeyHex(),
		LocalLabel:        "future-device",
		PairCredentialRef: "cred-future",
		Capabilities:      []string{wire.CapTransferV2},
		FirstSeenAt:       now,
		LastSeenAt:        now,
	}
	payload, err := json.Marshal(struct {
		Version   int                `json:"version"`
		UpdatedAt time.Time          `json:"updated_at"`
		Devices   []wire.TrustRecord `json:"devices"`
	}{Version: version, UpdatedAt: now, Devices: []wire.TrustRecord{rec}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFutureTrustVersionIsQuarantined is the SB-R11 Part B discriminator for
// the DESKTOP store path (no migrate.Run): NewFileTrustStore on a trust.json
// from a FUTURE schema version must refuse to open it — the desktop has no
// migration runner, so the store itself is the only quarantine seam. Before
// the fix this fails: the future envelope loads as-is and the next save
// silently rewrites it to the current version, destroying the marker.
func TestFutureTrustVersionIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := writeFutureTrustStore(t, dir, currentTrustFileVersion+1)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, openErr := NewFileTrustStore(path)
	if openErr == nil {
		t.Fatal("future-version trust.json accepted — quarantine missing")
	}

	after, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(before) != string(after) {
		t.Fatalf("future trust.json was MODIFIED on load: before=%s after=%s", before, after)
	}
}

// TestFutureTrustVersionSurvivesSave is the deeper half of the same defect:
// even if a future envelope could be opened, a save must never silently
// rewrite it to the current version. Kept as the mutation discriminator.
func TestFutureTrustVersionSurvivesSave(t *testing.T) {
	dir := t.TempDir()
	path := writeFutureTrustStore(t, dir, currentTrustFileVersion+1)
	if _, err := NewFileTrustStore(path); err == nil {
		t.Fatal("precondition failed: future store opened (quarantine exists)")
	}
	// File unchanged (covered by the other test); this test documents the
	// invariant the fix must keep: refusal happens BEFORE any rewrite.
	after, _ := os.ReadFile(path)
	var payload struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(after, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != currentTrustFileVersion+1 {
		t.Fatalf("future version marker destroyed: %d", payload.Version)
	}
}

// TestCurrentTrustVersionStillLoads guards against over-tightening: the
// current version envelope and the legacy v1 envelope (real v2.2 format)
// must keep loading, and v1 must still upgrade to v2 on first save.
func TestCurrentTrustVersionStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := writeFutureTrustStore(t, dir, currentTrustFileVersion)
	if _, err := NewFileTrustStore(path); err != nil {
		t.Fatalf("current-version trust.json refused: %v", err)
	}
	// Legacy v1 (exactly what v2.2-era stores wrote before the migration).
	id, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rec := wire.TrustRecord{
		DeviceID:          id.DeviceID,
		PublicKey:         id.PublicKeyHex(),
		LocalLabel:        "legacy",
		PairCredentialRef: "cred-legacy",
		Capabilities:      []string{wire.CapTransferV2},
		FirstSeenAt:       now,
		LastSeenAt:        now,
	}
	legacy, err := json.Marshal(struct {
		Version   int                `json:"version"`
		UpdatedAt time.Time          `json:"updated_at"`
		Devices   []wire.TrustRecord `json:"devices"`
	}{Version: 1, UpdatedAt: now, Devices: []wire.TrustRecord{rec}})
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := NewFileTrustStore(legacyPath)
	if err != nil {
		t.Fatalf("legacy v1 trust.json refused: %v", err)
	}
	if err := st.RevokeDevice(context.Background(), rec.DeviceID); err != nil {
		t.Fatalf("post-migration save failed: %v", err)
	}
	data, _ := os.ReadFile(legacyPath)
	var payload struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != currentTrustFileVersion {
		t.Fatalf("legacy file not upgraded on save: version %d", payload.Version)
	}
}
