package updater

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultMinisignPublicKey is the pinned Ed25519 public key used to verify SendBeam update manifests.
	DefaultMinisignPublicKey = "RWTcyDWHWbxnuo3LVM5mWoZrx0HDwSQzAZvXK1lPRcdtJxshUDxJh+rE"

	// DefaultUpdateBaseURL is the official production update manifest endpoint hosted on GitHub Pages.
	DefaultUpdateBaseURL = "https://akshay7273.github.io/sendbeam/updates"

	sigAlgEd        = "Ed"
	pubKeyLen       = 42
	sigPart1Len     = 74
	sigPart2Len     = 64
	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "
)

var (
	// ErrInvalidSignature is returned when cryptographic signature verification over an update manifest fails.
	ErrInvalidSignature = errors.New("invalid or tampered update manifest signature")

	// ErrDowngradeRejected is returned when attempting to apply a version older than or equal to the current version.
	ErrDowngradeRejected = errors.New("downgrade rejected: target version is not newer than current installation")

	// ErrManifestMalformed is returned when the update manifest is not valid JSON or lacks required fields.
	ErrManifestMalformed = errors.New("malformed update manifest")
)

// VerifyMinisignSignature cryptographically verifies a manifest payload against a minisign signature string and public key.
func VerifyMinisignSignature(content []byte, sigStr string, pubKeyStr string) error {
	pubKey, expectedKeyID, err := parsePublicKey(pubKeyStr)
	if err != nil {
		return fmt.Errorf("%w: invalid public key: %v", ErrInvalidSignature, err)
	}

	sigLines := strings.Split(strings.TrimSpace(sigStr), "\n")
	if len(sigLines) < 4 {
		return fmt.Errorf("%w: signature file must contain at least 4 lines, got %d", ErrInvalidSignature, len(sigLines))
	}

	sig1Raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigLines[1]))
	if err != nil || len(sig1Raw) != sigPart1Len {
		return fmt.Errorf("%w: invalid signature format", ErrInvalidSignature)
	}

	if sig1Raw[0] != 'E' || sig1Raw[1] != 'd' {
		return fmt.Errorf("%w: unsupported signature algorithm", ErrInvalidSignature)
	}

	sigKeyID := sig1Raw[2:10]
	if len(expectedKeyID) == 8 && !bytes.Equal(sigKeyID, expectedKeyID) {
		return fmt.Errorf("%w: key ID mismatch (expected %x, got %x)", ErrInvalidSignature, expectedKeyID, sigKeyID)
	}

	fileSig := sig1Raw[10:74]
	if !ed25519.Verify(pubKey, content, fileSig) {
		return fmt.Errorf("%w: content digest signature verification failed", ErrInvalidSignature)
	}

	if !strings.HasPrefix(sigLines[2], trustedPrefix) {
		return fmt.Errorf("%w: missing trusted comment", ErrInvalidSignature)
	}
	trustedComment := strings.TrimPrefix(sigLines[2], trustedPrefix)

	globalSigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigLines[3]))
	if err != nil || len(globalSigRaw) != sigPart2Len {
		return fmt.Errorf("%w: invalid global signature format", ErrInvalidSignature)
	}

	globalData := append(append([]byte(nil), fileSig...), []byte(trustedComment)...)
	if !ed25519.Verify(pubKey, globalData, globalSigRaw) {
		return fmt.Errorf("%w: trusted comment signature verification failed", ErrInvalidSignature)
	}

	return nil
}

// SignMinisign generates a standard Minisign signature file content for the given payload.
func SignMinisign(content []byte, secretKeyStr string, pubKeyStr string, filename string) (string, error) {
	privKey, err := parsePrivateKey(secretKeyStr)
	if err != nil {
		return "", fmt.Errorf("parsing secret key: %w", err)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	var keyID []byte

	if pubKeyStr != "" {
		_, pKeyID, err := parsePublicKey(pubKeyStr)
		if err == nil && len(pKeyID) == 8 {
			keyID = pKeyID
		}
	}
	if len(keyID) != 8 {
		derived := deriveKeyID(pubKey)
		keyID = derived[:]
	}

	fileSig := ed25519.Sign(privKey, content)

	var sig1Raw [sigPart1Len]byte
	sig1Raw[0] = 'E'
	sig1Raw[1] = 'd'
	copy(sig1Raw[2:10], keyID)
	copy(sig1Raw[10:], fileSig)
	sig1B64 := base64.StdEncoding.EncodeToString(sig1Raw[:])

	if filename == "" {
		filename = "manifest.json"
	}
	tComment := fmt.Sprintf("timestamp:%d\tfile:%s", time.Now().Unix(), filepath.Base(filename))

	globalData := append(append([]byte(nil), fileSig...), []byte(tComment)...)
	globalSig := ed25519.Sign(privKey, globalData)
	globalSigB64 := base64.StdEncoding.EncodeToString(globalSig)

	sigContent := fmt.Sprintf("%ssignature from minisign secret key\n%s\n%s%s\n%s\n",
		untrustedPrefix, sig1B64, trustedPrefix, tComment, globalSigB64)

	return sigContent, nil
}

func parsePublicKey(input string) (ed25519.PublicKey, []byte, error) {
	s := strings.TrimSpace(input)
	if data, err := os.ReadFile(s); err == nil {
		s = strings.TrimSpace(string(data))
	}

	lines := strings.Split(s, "\n")
	var b64 string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, untrustedPrefix) && trimmed != "" {
			b64 = trimmed
			break
		}
	}
	if b64 == "" {
		return nil, nil, errors.New("no public key line found")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	if len(raw) == 32 {
		return ed25519.PublicKey(raw), nil, nil
	}
	if len(raw) == pubKeyLen {
		if raw[0] != 'E' || raw[1] != 'd' {
			return nil, nil, errors.New("unsupported signature algorithm in pubkey")
		}
		keyID := raw[2:10]
		pub := ed25519.PublicKey(raw[10:])
		return pub, keyID, nil
	}

	return nil, nil, fmt.Errorf("unexpected public key length: %d", len(raw))
}

func parsePrivateKey(input string) (ed25519.PrivateKey, error) {
	s := strings.TrimSpace(input)
	if data, err := os.ReadFile(s); err == nil {
		s = strings.TrimSpace(string(data))
	}

	lines := strings.Split(s, "\n")
	var keyText string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, untrustedPrefix) && trimmed != "" {
			keyText = trimmed
			break
		}
	}
	if keyText == "" {
		return nil, errors.New("no secret key content found")
	}

	if len(keyText) == 64 {
		seed, err := hex.DecodeString(keyText)
		if err == nil && len(seed) == 32 {
			return ed25519.NewKeyFromSeed(seed), nil
		}
	}

	if len(keyText) == 128 {
		full, err := hex.DecodeString(keyText)
		if err == nil && len(full) == 64 {
			return ed25519.PrivateKey(full), nil
		}
	}

	if raw, err := base64.StdEncoding.DecodeString(keyText); err == nil {
		if len(raw) == 32 {
			return ed25519.NewKeyFromSeed(raw), nil
		}
		if len(raw) == 64 {
			return ed25519.PrivateKey(raw), nil
		}
	}

	return nil, errors.New("unrecognized private key format")
}

func deriveKeyID(pub ed25519.PublicKey) [8]byte {
	var id [8]byte
	copy(id[:], pub[:8])
	return id
}
