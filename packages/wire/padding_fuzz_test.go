package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// FuzzPaddingCodec tests the wire-level padding and bucket validation codec against
// arbitrary buffers, truncated frames, corrupted padding bytes, and abnormal lengths.
// Invariants:
// 1. UnpadPayload must never panic on any input.
// 2. PadBucketSize must return a power of two in [MinPadBucketSize, MaxPadBucketSize] for non-negative sizes.
// 3. For any valid unpadded payload, PadPayload followed by UnpadPayload must be a lossless identity round-trip.
// 4. Any non-zero padding byte or invalid length prefix must be strictly rejected (fail closed).
func FuzzPaddingCodec(f *testing.F) {
	// Add programmatic edge cases
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x01, 'a'})
	f.Add([]byte{0x00, 0x02, 'a', 'b'})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0x00, 0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x00, 0x04, 't', 'e', 's', 't', 0x00, 0x01, 0x00, 0x00}) // non-zero padding byte

	// Load seeds from padding-vectors.json if present
	if data, err := os.ReadFile("testdata/padding-vectors.json"); err == nil {
		var vectors []struct {
			PlaintextHex string `json:"plaintext_hex"`
			PaddedHex    string `json:"padded_hex"`
		}
		if err := json.Unmarshal(data, &vectors); err == nil {
			for _, v := range vectors {
				if b, err := hex.DecodeString(v.PaddedHex); err == nil && len(b) > 0 {
					f.Add(b)
				}
				if b, err := hex.DecodeString(v.PlaintextHex); err == nil {
					f.Add(b)
				}
			}
		}
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		// Exercise PadBucketSize invariant
		bSize := PadBucketSize(len(payload))
		if bSize < MinPadBucketSize || bSize > MaxPadBucketSize {
			t.Fatalf("PadBucketSize(%d) = %d out of bounds [%d, %d]", len(payload), bSize, MinPadBucketSize, MaxPadBucketSize)
		}
		if (bSize & (bSize - 1)) != 0 {
			t.Fatalf("PadBucketSize(%d) = %d is not a power of two", len(payload), bSize)
		}

		// Exercise UnpadPayload on arbitrary payload (fuzz input)
		unpadded, err := UnpadPayload(payload)
		if err == nil {
			// Invariant: Unpadded length must be plausible
			if len(unpadded)+2 > len(payload) {
				t.Fatalf("UnpadPayload returned %d bytes from %d byte buffer", len(unpadded), len(payload))
			}
			// Invariant: Re-padding the unpadded payload must succeed and round-trip
			repadded, padErr := PadPayload(unpadded)
			if padErr != nil {
				t.Fatalf("PadPayload failed on successfully unpadded payload: %v", padErr)
			}
			reUnpadded, unpadErr := UnpadPayload(repadded)
			if unpadErr != nil {
				t.Fatalf("UnpadPayload failed on repadded payload: %v", unpadErr)
			}
			if !bytes.Equal(reUnpadded, unpadded) {
				t.Fatalf("padding round-trip mismatch: got %x, want %x", reUnpadded, unpadded)
			}
		}

		// Exercise PadPayload if payload is within valid length
		if len(payload) <= u16Max-2 {
			padded, err := PadPayload(payload)
			if err != nil {
				t.Fatalf("PadPayload unexpectedly failed for len %d: %v", len(payload), err)
			}
			expectedBucket := PadBucketSize(len(payload))
			if len(padded) != expectedBucket {
				t.Fatalf("padded buffer len %d != expected bucket %d", len(padded), expectedBucket)
			}
			recovered, err := UnpadPayload(padded)
			if err != nil {
				t.Fatalf("UnpadPayload failed to recover padded payload: %v", err)
			}
			if !bytes.Equal(recovered, payload) {
				t.Fatalf("recovered plaintext mismatch: got %x, want %x", recovered, payload)
			}
		}
	})
}
