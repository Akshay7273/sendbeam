package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type RevocationVector struct {
	Name            string `json:"name"`
	RevokerSeedHex  string `json:"revoker_seed_hex"`
	RevokerDeviceID string `json:"revoker_device_id"`
	RevokerPubKey   string `json:"revoker_pub_key_hex"`
	RevokedDeviceID string `json:"revoked_device_id"`
	Seq             uint64 `json:"seq"`
	Timestamp       string `json:"timestamp"`
	ChallengeHex    string `json:"challenge_hex"`
	SignatureHex    string `json:"signature_hex"`
	Valid           bool   `json:"valid"`
}

func TestRevocationVectors_CrossLanguage(t *testing.T) {
	vectorPath := filepath.Join("testdata", "revocation-vectors.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("failed to read test vectors: %v", err)
	}

	var vectors []RevocationVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to unmarshal test vectors: %v", err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			pubBytes, err := hex.DecodeString(v.RevokerPubKey)
			if err != nil {
				t.Fatalf("invalid revoker pub key hex: %v", err)
			}
			pubKey := ed25519.PublicKey(pubBytes)

			rec := &RevocationRecord{
				RevokerDeviceID: v.RevokerDeviceID,
				RevokedDeviceID: v.RevokedDeviceID,
				Seq:             v.Seq,
				Timestamp:       v.Timestamp,
				Signature:       v.SignatureHex,
			}

			// Validate challenge construction
			challenge := BuildRevocationChallenge(v.RevokerDeviceID, v.RevokedDeviceID, v.Seq, v.Timestamp)
			if hex.EncodeToString(challenge) != v.ChallengeHex {
				t.Errorf("challenge mismatch:\ngot  %s\nwant %s", hex.EncodeToString(challenge), v.ChallengeHex)
			}

			now, _ := time.Parse(time.RFC3339, v.Timestamp)
			verifyErr := VerifyRevocation(rec, pubKey, 5*time.Minute, now)

			if v.Valid && verifyErr != nil {
				t.Errorf("expected valid vector to pass verification, got error: %v", verifyErr)
			}
			if !v.Valid && verifyErr == nil {
				t.Errorf("expected invalid vector to fail verification, but it passed")
			}
		})
	}
}

func TestRevocationRecord_ValidationAndErrors(t *testing.T) {
	seed := sha256.Sum256([]byte("test-revoker-seed-12345"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	id, err := NewDeviceIdentity(priv.Public().(ed25519.PublicKey), priv)
	if err != nil {
		t.Fatal(err)
	}

	revokedID := "sb-dev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	// Happy path
	rec, err := SignRevocation(id, revokedID, 1, now)
	if err != nil {
		t.Fatalf("SignRevocation failed: %v", err)
	}

	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate failed on valid record: %v", err)
	}

	if err := VerifyRevocation(rec, id.PublicKey, 5*time.Minute, now); err != nil {
		t.Fatalf("VerifyRevocation failed: %v", err)
	}

	// Self-revocation attempt rejected
	_, err = SignRevocation(id, id.DeviceID, 1, now)
	if err == nil {
		t.Fatal("expected SignRevocation to reject self-revocation")
	}

	// Seq = 0 rejected
	_, err = SignRevocation(id, revokedID, 0, now)
	if err == nil {
		t.Fatal("expected SignRevocation to reject seq = 0")
	}

	// Tampered signature rejected
	tampered := *rec
	tampered.Signature = hex.EncodeToString(make([]byte, 64))
	if err := VerifyRevocation(&tampered, id.PublicKey, 5*time.Minute, now); err == nil {
		t.Fatal("expected tampered signature to fail verification")
	}

	// Tampered revoked ID rejected
	tamperedID := *rec
	tamperedID.RevokedDeviceID = "sb-dev-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := VerifyRevocation(&tamperedID, id.PublicKey, 5*time.Minute, now); err == nil {
		t.Fatal("expected tampered revoked ID to fail verification")
	}

	// Future timestamp beyond skew rejected
	futureTime := now.Add(10 * time.Minute)
	recFuture, err := SignRevocation(id, revokedID, 1, futureTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(recFuture, id.PublicKey, 5*time.Minute, now); err == nil {
		t.Fatal("expected future timestamp beyond skew to fail verification")
	}
}
