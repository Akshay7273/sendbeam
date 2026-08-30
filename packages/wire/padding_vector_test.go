package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type PaddingVector struct {
	Name          string      `json:"name"`
	PlaintextHex  string      `json:"plaintext_hex"`
	UnpaddedLen   int         `json:"unpadded_len"`
	BucketSize    int         `json:"bucket_size"`
	PaddedHex     string      `json:"padded_hex"`
	KeyHex        string      `json:"key_hex"`
	SaltHex       string      `json:"salt_hex"`
	Counter       uint64      `json:"counter"`
	Header        FrameHeader `json:"header"`
	SealedHex     string      `json:"sealed_hex"`
	Valid         bool        `json:"valid"`
	ExpectedError string      `json:"expected_error,omitempty"`
}

func loadPaddingVectors(t *testing.T) []PaddingVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "padding-vectors.json"))
	if err != nil {
		t.Fatalf("reading padding-vectors.json: %v", err)
	}
	var vectors []PaddingVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parsing padding-vectors.json: %v", err)
	}
	return vectors
}

func TestPaddingVectors(t *testing.T) {
	vectors := loadPaddingVectors(t)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(v.PlaintextHex)
			key, _ := hex.DecodeString(v.KeyHex)
			salt, _ := hex.DecodeString(v.SaltHex)
			dir := DirectionalKey{Key: key, Salt: salt}

			if !v.Valid {
				// Negative vector
				if v.SealedHex != "" {
					sealed, _ := hex.DecodeString(v.SealedHex)
					_, err := Open(dir, v.Counter, sealed)
					if err == nil {
						t.Errorf("expected error opening invalid vector %s, got nil", v.Name)
					}
				}
				if v.PaddedHex != "" {
					padded, _ := hex.DecodeString(v.PaddedHex)
					_, err := UnpadPayload(padded)
					if err == nil {
						t.Errorf("expected error unpadding invalid vector %s, got nil", v.Name)
					}
				}
				return
			}

			// Valid vector: verify PadBucketSize
			if bucket := PadBucketSize(len(plaintext)); bucket != v.BucketSize {
				t.Fatalf("PadBucketSize(%d) = %d, want %d", len(plaintext), bucket, v.BucketSize)
			}

			// Verify PadPayload
			padded, err := PadPayload(plaintext)
			if err != nil {
				t.Fatalf("PadPayload: %v", err)
			}
			if hex.EncodeToString(padded) != v.PaddedHex {
				t.Errorf("padded hex mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(padded), v.PaddedHex)
			}

			// Verify UnpadPayload
			unpadded, err := UnpadPayload(padded)
			if err != nil {
				t.Fatalf("UnpadPayload: %v", err)
			}
			if !bytes.Equal(unpadded, plaintext) {
				t.Errorf("unpadded mismatch: got %x, want %x", unpadded, plaintext)
			}

			// Verify SealPadded
			h := FrameHeaderInput{
				Version:  v.Header.Version,
				Type:     v.Header.Type,
				Flags:    v.Header.Flags &^ FrameFlagPadded,
				FileIdx:  v.Header.FileIdx,
				BlockIdx: v.Header.BlockIdx,
				FrameOff: v.Header.FrameOff,
			}
			sealed, err := SealPadded(dir, v.Counter, h, plaintext)
			if err != nil {
				t.Fatalf("SealPadded: %v", err)
			}
			if hex.EncodeToString(sealed) != v.SealedHex {
				t.Errorf("sealed hex mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(sealed), v.SealedHex)
			}

			// Verify Open
			opened, err := Open(dir, v.Counter, sealed)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(opened.Plaintext, plaintext) {
				t.Errorf("opened plaintext mismatch: got %x, want %x", opened.Plaintext, plaintext)
			}
			if opened.Header.Flags&FrameFlagPadded == 0 {
				t.Errorf("expected FrameFlagPadded in opened header")
			}
		})
	}
}
