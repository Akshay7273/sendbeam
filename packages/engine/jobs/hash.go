package jobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// jobHasher is a domain-separated incremental SHA-256 writer used for the
// source fingerprint. Field values are length-framed so ("ab","c") and
// ("a","bc") can never collide.
type jobHasher struct {
	h bytes.Buffer
}

func newJobHasher() *jobHasher {
	jh := &jobHasher{}
	jh.h.Write([]byte("sendbeam/job-fingerprint\x00"))
	return jh
}

func (jh *jobHasher) writeString(s string) {
	var lb [8]byte
	binary.BigEndian.PutUint64(lb[:], uint64(len(s)))
	jh.h.Write(lb[:])
	jh.h.Write([]byte(s))
	jh.h.Write([]byte{0})
}

func (jh *jobHasher) writeInt64(v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	jh.h.Write(b[:])
	jh.h.Write([]byte{0})
}

func (jh *jobHasher) sum() string {
	sum := sha256.Sum256(jh.h.Bytes())
	return hex.EncodeToString(sum[:])
}

func isLowerHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isLowerHex32(s string) bool { return isLowerHexLen(s, 32) }

func isLowerHex64(s string) bool { return isLowerHexLen(s, 64) }
