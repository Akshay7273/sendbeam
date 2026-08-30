package wire

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPadBucketSize(t *testing.T) {
	tests := []struct {
		unpaddedLen int
		wantBucket  int
	}{
		{0, 256},
		{1, 256},
		{100, 256},
		{254, 256}, // 254 + 2 = 256
		{255, 512}, // 255 + 2 = 257 -> 512
		{510, 512}, // 510 + 2 = 512
		{511, 1024},
		{1000, 1024},
		{1022, 1024},
		{1023, 2048},
		{4000, 4096},
		{4094, 4096},
		{4095, 8192},
		{16382, 16384},
		{16383, 32768},
		{32766, 32768},
		{32767, 65535},
		{60000, 65535},
		{65533, 65535},
	}

	for _, tc := range tests {
		got := PadBucketSize(tc.unpaddedLen)
		if got != tc.wantBucket {
			t.Errorf("PadBucketSize(%d) = %d, want %d", tc.unpaddedLen, got, tc.wantBucket)
		}
	}
}

func TestPadAndUnpadPayload(t *testing.T) {
	lengths := []int{0, 1, 10, 254, 255, 500, 1022, 1023, 4094, 16382, 32766, 65533}
	for _, l := range lengths {
		payload := make([]byte, l)
		if l > 0 {
			_, _ = rand.Read(payload)
		}

		padded, err := PadPayload(payload)
		if err != nil {
			t.Fatalf("PadPayload(len=%d): %v", l, err)
		}

		expectedBucket := PadBucketSize(l)
		if len(padded) != expectedBucket {
			t.Errorf("len(padded) = %d, want bucket %d", len(padded), expectedBucket)
		}

		unpadded, err := UnpadPayload(padded)
		if err != nil {
			t.Fatalf("UnpadPayload(len=%d): %v", l, err)
		}

		if !bytes.Equal(unpadded, payload) {
			t.Errorf("unpadded != original payload for len %d", l)
		}
	}
}

func TestUnpadPayloadFailClosed(t *testing.T) {
	t.Run("truncated buffer", func(t *testing.T) {
		_, err := UnpadPayload([]byte{0x00})
		if err == nil {
			t.Error("expected error for 1-byte buffer")
		}
	})

	t.Run("length field exceeds buffer", func(t *testing.T) {
		buf := make([]byte, 256)
		buf[0] = 0x01
		buf[1] = 0x00 // declared length 256, but buffer is only 256 (needs 256 + 2 = 258)
		_, err := UnpadPayload(buf)
		if err == nil {
			t.Error("expected error when length + 2 > buffer")
		}
	})

	t.Run("non-zero padding byte", func(t *testing.T) {
		buf := make([]byte, 256)
		buf[0] = 0x00
		buf[1] = 0x04 // declared length 4
		copy(buf[2:6], []byte("test"))
		buf[100] = 0x01 // tampered padding byte
		_, err := UnpadPayload(buf)
		if err == nil {
			t.Error("expected error when padding contains non-zero bytes")
		}
	})
}

func TestSealPaddedAndOpen(t *testing.T) {
	key := make([]byte, aeadKeyBytes)
	salt := make([]byte, aeadSaltBytes)
	_, _ = rand.Read(key)
	_, _ = rand.Read(salt)
	dir := DirectionalKey{Key: key, Salt: salt}

	h := FrameHeaderInput{
		Version:  FrameVersion,
		Type:     FrameBlockData,
		Flags:    FrameFlagLastInBlock,
		FileIdx:  0,
		BlockIdx: 1,
		FrameOff: 0,
	}

	payload := []byte("Hello, private padded world!")
	sealed, err := SealPadded(dir, 1, h, payload)
	if err != nil {
		t.Fatalf("SealPadded: %v", err)
	}

	opened, err := Open(dir, 1, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if opened.Header.Flags&FrameFlagPadded == 0 {
		t.Error("expected FrameFlagPadded in opened header")
	}
	if opened.Header.Flags&FrameFlagLastInBlock == 0 {
		t.Error("expected FrameFlagLastInBlock preserved in opened header")
	}
	if !bytes.Equal(opened.Plaintext, payload) {
		t.Errorf("got plaintext %q, want %q", opened.Plaintext, payload)
	}
}
