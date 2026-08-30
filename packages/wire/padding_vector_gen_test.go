package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratePaddingVectors(t *testing.T) {
	// Fixed test key & salt
	key, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	salt, _ := hex.DecodeString("a1a2a3a4")
	dir := DirectionalKey{Key: key, Salt: salt}

	cases := []struct {
		name      string
		plaintext string
		counter   uint64
		h         FrameHeaderInput
	}{
		{
			name:      "empty_payload_bucket_256",
			plaintext: "",
			counter:   1,
			h: FrameHeaderInput{
				Version: FrameVersion, Type: FrameControl, Flags: 0,
			},
		},
		{
			name:      "small_control_bucket_256",
			plaintext: "ping",
			counter:   2,
			h: FrameHeaderInput{
				Version: FrameVersion, Type: FrameControl, Flags: 0,
			},
		},
		{
			name:      "boundary_254_bytes_bucket_256",
			plaintext: string(make([]byte, 254)),
			counter:   3,
			h: FrameHeaderInput{
				Version: FrameVersion, Type: FrameBlockData, Flags: 0, BlockIdx: 1, FrameOff: 0,
			},
		},
		{
			name:      "boundary_255_bytes_bucket_512",
			plaintext: string(make([]byte, 255)),
			counter:   4,
			h: FrameHeaderInput{
				Version: FrameVersion, Type: FrameBlockData, Flags: FrameFlagLastInBlock, BlockIdx: 1, FrameOff: 254,
			},
		},
		{
			name:      "data_1000_bytes_bucket_1024",
			plaintext: string(make([]byte, 1000)),
			counter:   5,
			h: FrameHeaderInput{
				Version: FrameVersion, Type: FrameBlockData, Flags: 0, BlockIdx: 2, FrameOff: 0,
			},
		},
		{
			name:      "data_4000_bytes_bucket_4096",
			plaintext: string(make([]byte, 4000)),
			counter:   6,
			h: FrameHeaderInput{
				Version: FrameVersion, Type: FrameBlockData, Flags: 0, BlockIdx: 3, FrameOff: 0,
			},
		},
	}

	var vectors []PaddingVector

	for _, tc := range cases {
		pt := []byte(tc.plaintext)
		if len(pt) > 0 && tc.name != "small_control_bucket_256" {
			// fill with deterministic pattern: (i % 256)
			for i := range pt {
				pt[i] = byte((i*7 + 13) % 256)
			}
		}

		padded, err := PadPayload(pt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		hdr := tc.h
		hdr.Flags |= FrameFlagPadded
		sealed, err := SealPadded(dir, tc.counter, tc.h, pt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		vectors = append(vectors, PaddingVector{
			Name:         tc.name,
			PlaintextHex: hex.EncodeToString(pt),
			UnpaddedLen:  len(pt),
			BucketSize:   len(padded),
			PaddedHex:    hex.EncodeToString(padded),
			KeyHex:       hex.EncodeToString(key),
			SaltHex:      hex.EncodeToString(salt),
			Counter:      tc.counter,
			Header: FrameHeader{
				Version:  hdr.Version,
				Type:     hdr.Type,
				Flags:    hdr.Flags,
				FileIdx:  hdr.FileIdx,
				BlockIdx: hdr.BlockIdx,
				FrameOff: hdr.FrameOff,
				Len:      uint16(len(padded)),
			},
			SealedHex: hex.EncodeToString(sealed),
			Valid:     true,
		})
	}

	// Negative vectors
	// 1. Corrupted padding byte
	badPadded, _ := PadPayload([]byte("hello"))
	badPadded[100] = 0xff
	vectors = append(vectors, PaddingVector{
		Name:          "invalid_nonzero_padding_byte",
		PlaintextHex:  hex.EncodeToString([]byte("hello")),
		UnpaddedLen:   5,
		BucketSize:    256,
		PaddedHex:     hex.EncodeToString(badPadded),
		KeyHex:        hex.EncodeToString(key),
		SaltHex:       hex.EncodeToString(salt),
		Counter:       10,
		Valid:         false,
		ExpectedError: "non-zero padding byte",
	})

	// 2. Length field exceeds bucket
	badLenPadded, _ := PadPayload([]byte("hello"))
	badLenPadded[0] = 0x01
	badLenPadded[1] = 0x00 // len 256 in 256-byte bucket
	vectors = append(vectors, PaddingVector{
		Name:          "invalid_length_exceeds_bucket",
		PlaintextHex:  hex.EncodeToString([]byte("hello")),
		UnpaddedLen:   5,
		BucketSize:    256,
		PaddedHex:     hex.EncodeToString(badLenPadded),
		KeyHex:        hex.EncodeToString(key),
		SaltHex:       hex.EncodeToString(salt),
		Counter:       11,
		Valid:         false,
		ExpectedError: "unpadded length exceeds buffer",
	})

	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	outPath := filepath.Join("testdata", "padding-vectors.json")
	if err := os.WriteFile(outPath, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
