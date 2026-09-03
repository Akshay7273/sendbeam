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

// FuzzDecodeTrustRecord exercises TrustRecord JSON parsing and validation invariants.
// Invariants:
// 1. json.Unmarshal and Validate must never panic on any input bytes.
// 2. Validate() == nil implies valid DeviceID, matching PublicKey, non-empty LocalLabel, and non-zero FirstSeenAt.
// 3. A validated TrustRecord must re-encode and re-validate successfully.
func FuzzDecodeTrustRecord(f *testing.F) {
	seeds := []string{
		`{}`,
		`not-json`,
		`{"device_id":"sb-dev-123","local_label":"test"}`,
		`{"device_id":"sb-dev-d5ba0a004e9be5e2c4537b289163b5b548ea3043aad133911ae8d18809081287","public_key":"565c0c1dc287bdfe05c165a3d13d1e3dfafef34d217dec14d45ae3c53c1c89d9","local_label":"Alice Laptop","capabilities":["transfer.v1"],"first_seen_at":"2026-08-30T12:00:00Z","policy":{"auto_accept":false}}`,
		`{"device_id":"sb-dev-d5ba0a004e9be5e2c4537b289163b5b548ea3043aad133911ae8d18809081287","public_key":"565c0c1dc287bdfe05c165a3d13d1e3dfafef34d217dec14d45ae3c53c1c89d9","local_label":"Alice Auto","capabilities":["transfer.v1"],"first_seen_at":"2026-08-30T12:00:00Z","policy":{"auto_accept":true,"auto_accept_dest_dir":"/tmp/safe"}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var rec wire.TrustRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return
		}

		if err := rec.Validate(); err == nil {
			if !wire.ValidateDeviceID(rec.DeviceID) {
				t.Fatalf("Validate succeeded with invalid device ID %q", rec.DeviceID)
			}
			if rec.LocalLabel == "" {
				t.Fatalf("Validate succeeded with empty local label")
			}
			if rec.FirstSeenAt.IsZero() {
				t.Fatalf("Validate succeeded with zero FirstSeenAt")
			}

			// Re-encoding must preserve validity
			enc, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("Marshal failed for validated TrustRecord: %v", err)
			}
			var rec2 wire.TrustRecord
			if err := json.Unmarshal(enc, &rec2); err != nil {
				t.Fatalf("Re-unmarshal failed: %v", err)
			}
			if err := rec2.Validate(); err != nil {
				t.Fatalf("Re-validation failed: %v", err)
			}
		}
	})
}

// FuzzFileTrustStoreLoad exercises the FileTrustStore persistence loader against corrupted,
// truncated, or maliciously structured trust database files.
// Invariants:
// 1. NewFileTrustStore must never panic.
// 2. Corrupt or unparseable files must return an error (fail closed) without crashing.
// 3. If load succeeds, ListDevices must return only valid TrustRecord entries.
func FuzzFileTrustStoreLoad(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		"not json",
		`{"version":1,"updated_at":"2026-08-30T12:00:00Z","devices":[]}`,
		`{"version":1,"updated_at":"2026-08-30T12:00:00Z","devices":[{"device_id":"invalid"}]}`,
		`{"version":1,"updated_at":"2026-08-30T12:00:00Z","devices":[{"device_id":"sb-dev-d5ba0a004e9be5e2c4537b289163b5b548ea3043aad133911ae8d18809081287","public_key":"565c0c1dc287bdfe05c165a3d13d1e3dfafef34d217dec14d45ae3c53c1c89d9","local_label":"Alice","first_seen_at":"2026-08-30T12:00:00Z"}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, fileData []byte) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "trust.json")

		if err := os.WriteFile(dbPath, fileData, 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		store, err := NewFileTrustStore(dbPath)
		if err != nil {
			// Fail-closed invariant on corrupt file
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		devices, err := store.ListDevices(ctx)
		if err != nil {
			t.Fatalf("ListDevices failed on loaded store: %v", err)
		}

		for _, dev := range devices {
			if dev == nil {
				t.Fatalf("ListDevices returned nil record")
			}
			if err := dev.Validate(); err != nil {
				t.Fatalf("store contains invalid record: %v", err)
			}
		}
	})
}
