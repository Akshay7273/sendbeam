// Command keycheck prints non-secret identifying information about a Minisign
// public key: the key ID, the raw Ed25519 public key hex, and its SHA-256
// fingerprint. It NEVER accepts, reads, prints or derives from secret key
// material, which makes it safe to run on an untrusted workstation and safe
// to paste output into a review thread.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const (
	pubKeyLen       = 42
	untrustedPrefix = "untrusted comment: "
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: keycheck <minisign.pub | base64 key>")
		os.Exit(2)
	}
	pub, keyID, err := parse(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "keycheck: %v\n", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(pub)
	fmt.Printf("key_id_hex=%s\n", strings.ToUpper(hex.EncodeToString(reverse(keyID))))
	fmt.Printf("public_key_hex=%s\n", hex.EncodeToString(pub))
	fmt.Printf("public_key_sha256=%s\n", hex.EncodeToString(sum[:]))
}

// reverse renders the key ID in the human-facing Minisign convention.
func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func parse(input string) ([]byte, []byte, error) {
	s := strings.TrimSpace(input)
	if data, err := os.ReadFile(s); err == nil {
		s = strings.TrimSpace(string(data))
	}
	var b64 string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, untrustedPrefix) {
			b64 = t
			break
		}
	}
	if b64 == "" {
		return nil, nil, fmt.Errorf("no public key line found")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	if len(raw) != pubKeyLen {
		return nil, nil, fmt.Errorf("unexpected key length %d (want %d)", len(raw), pubKeyLen)
	}
	if raw[0] != 'E' || raw[1] != 'd' {
		return nil, nil, fmt.Errorf("unsupported algorithm prefix %q", raw[:2])
	}
	return raw[10:], raw[2:10], nil
}
