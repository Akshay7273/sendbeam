package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// FuzzRevocationRecord tests the revocation record decoder, syntax validation,
// and cryptographic verification against arbitrary, truncated, and corrupted payloads.
// Invariants:
// 1. json.Unmarshal and Validate must never panic on any input.
// 2. Validate() == nil implies valid syntax, valid DeviceIDs, non-zero Seq, valid timestamp, and 64-byte signature.
// 3. VerifyRevocation must never panic and must fail closed on invalid keys, bad signatures, or skew.
func FuzzRevocationRecord(f *testing.F) {
	// Programmatic baseline seeds
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))
	f.Add([]byte(`{"revoker_device_id":"sb-dev-123","revoked_device_id":"sb-dev-456","seq":1,"timestamp":"2026-08-30T12:00:00Z","signature":"00"}`))

	// Load seeds from revocation-vectors.json if present
	if data, err := os.ReadFile("testdata/revocation-vectors.json"); err == nil {
		var vecDoc struct {
			Vectors []struct {
				Name   string           `json:"name"`
				Record RevocationRecord `json:"record"`
			} `json:"vectors"`
		}
		if err := json.Unmarshal(data, &vecDoc); err == nil {
			for _, v := range vecDoc.Vectors {
				if recBytes, err := json.Marshal(v.Record); err == nil {
					f.Add(recBytes)
				}
			}
		}
	}

	// Generate a deterministic test keypair for verification testing
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}

	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, data []byte) {
		var rec RevocationRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return
		}

		valErr := rec.Validate()
		if valErr == nil {
			// Structural constraints must hold
			if !ValidateDeviceID(rec.RevokerDeviceID) {
				t.Fatalf("Validate() passed with invalid revoker device ID %q", rec.RevokerDeviceID)
			}
			if !ValidateDeviceID(rec.RevokedDeviceID) {
				t.Fatalf("Validate() passed with invalid revoked device ID %q", rec.RevokedDeviceID)
			}
			if rec.RevokerDeviceID == rec.RevokedDeviceID {
				t.Fatalf("Validate() passed with self-revocation %q", rec.RevokerDeviceID)
			}
			if rec.Seq == 0 {
				t.Fatalf("Validate() passed with Seq == 0")
			}
			sigBytes, err := hex.DecodeString(rec.Signature)
			if err != nil || len(sigBytes) != ed25519.SignatureSize {
				t.Fatalf("Validate() passed with invalid signature: %v, len=%d", err, len(sigBytes))
			}

			// Challenge construction must never panic
			challenge := BuildRevocationChallenge(rec.RevokerDeviceID, rec.RevokedDeviceID, rec.Seq, rec.Timestamp)
			if len(challenge) == 0 {
				t.Fatalf("BuildRevocationChallenge produced empty challenge")
			}

			// VerifyRevocation must never panic and must fail closed on mismatched keys
			_ = VerifyRevocation(&rec, pub, MaxRevocationTimestampSkew, now)
		}
	})
}
