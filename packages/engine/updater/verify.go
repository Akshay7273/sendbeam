package updater

import (
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
	// DefaultMinisignPublicKey is the official pinned SendBeam release verification public key (Ed25519).
	// Public key ID: BA67BC598735C8DC
	DefaultMinisignPublicKey = "RWTcyDWHWbxnuo3LVM5mWoZrx0HDwSQzAZvXK1lPRcdtJxshUDxJh+rE"

	// DefaultUpdateBaseURL is the production static GitHub Pages endpoint hosting signed channel manifests.
	DefaultUpdateBaseURL = "https://akshay7273.github.io/sendbeam/updates"

	sigPart1Len     = 74
	sigPart2Len     = 64
	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "
)

var (
	// ErrInvalidSignature indicates the manifest signature could not be verified against the pinned public key.
	ErrInvalidSignature = errors.New("invalid or tampered update manifest signature")

	// ErrDowngradeRejected indicates the candidate version is equal to or older than the running version.
	ErrDowngradeRejected = errors.New("downgrade rejected: candidate version is not greater than active version")

	// ErrManifestMalformed indicates the downloaded update manifest could not be parsed as valid JSON.
	ErrManifestMalformed = errors.New("malformed update manifest JSON")

	// ErrChannelMismatch indicates the candidate release violates the selected channel policy.
	ErrChannelMismatch = errors.New("candidate release does not match channel policy")

	// ErrNoUpdateAvailable indicates that the active client is already running the latest available version.
	ErrNoUpdateAvailable = errors.New("no update available: SendBeam is up to date")

	// ErrManagedByPackageManager indicates that the installation is managed by an OS package manager.
	ErrManagedByPackageManager = errors.New("application is managed by OS package manager")

	// ErrChecksumMismatch indicates that the computed SHA-256 hash does not match the expected hash.
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrBinaryNotFoundInArchive indicates the expected binary was not found in the archive payload.
	ErrBinaryNotFoundInArchive = errors.New("target binary not found in archive")
)

// VerifyMinisignSignature verifies a Minisign signature over content against the provided base64 public key.
func VerifyMinisignSignature(content []byte, signatureText string, pubKeyStr string) error {
	pubKey, keyID, err := ParseMinisignPublicKey(pubKeyStr)
	if err != nil {
		return fmt.Errorf("%w: invalid public key: %v", ErrInvalidSignature, err)
	}

	sig1Raw, trustedComment, sig2Raw, err := ParseMinisignSignature(signatureText)
	if err != nil {
		return fmt.Errorf("%w: invalid signature format: %v", ErrInvalidSignature, err)
	}

	// Verify key ID matches if signature contains key ID
	sigKeyID := sig1Raw[2:10]
	if len(keyID) == 8 && string(sigKeyID) != string(keyID) {
		return fmt.Errorf("%w: key ID mismatch (expected %s, got %s)",
			ErrInvalidSignature, hex.EncodeToString(keyID), hex.EncodeToString(sigKeyID))
	}

	fileSig := sig1Raw[10:74]
	if !ed25519.Verify(pubKey, content, fileSig) {
		return fmt.Errorf("%w: content digest signature verification failed", ErrInvalidSignature)
	}

	// Verify global signature over (fileSig + trustedComment)
	globalData := append(append([]byte(nil), fileSig...), []byte(trustedComment)...)
	if !ed25519.Verify(pubKey, globalData, sig2Raw) {
		return fmt.Errorf("%w: trusted comment signature verification failed", ErrInvalidSignature)
	}

	return nil
}

// ParseMinisignPublicKey parses a Minisign public key string or file.
func ParseMinisignPublicKey(input string) (ed25519.PublicKey, []byte, error) {
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
	if len(raw) == 42 {
		if raw[0] != 'E' || raw[1] != 'd' {
			return nil, nil, errors.New("unsupported signature algorithm")
		}
		keyID := raw[2:10]
		pub := ed25519.PublicKey(raw[10:])
		return pub, keyID, nil
	}

	return nil, nil, fmt.Errorf("unexpected public key length: %d", len(raw))
}

// ParseMinisignSignature parses a 4-line standard Minisign signature string.
func ParseMinisignSignature(sigStr string) (sig1Raw []byte, trustedComment string, sig2Raw []byte, err error) {
	lines := strings.Split(strings.TrimSpace(sigStr), "\n")
	if len(lines) < 4 {
		return nil, "", nil, fmt.Errorf("signature must have at least 4 lines (got %d)", len(lines))
	}

	sig1B64 := strings.TrimSpace(lines[1])
	sig1Raw, err = base64.StdEncoding.DecodeString(sig1B64)
	if err != nil {
		return nil, "", nil, fmt.Errorf("decoding signature line 2: %w", err)
	}
	if len(sig1Raw) != sigPart1Len {
		return nil, "", nil, fmt.Errorf("invalid signature part 1 length %d (expected %d)", len(sig1Raw), sigPart1Len)
	}

	tCommentLine := strings.TrimSpace(lines[2])
	if !strings.HasPrefix(tCommentLine, trustedPrefix) {
		return nil, "", nil, errors.New("missing trusted comment prefix on line 3")
	}
	trustedComment = strings.TrimPrefix(tCommentLine, trustedPrefix)

	sig2B64 := strings.TrimSpace(lines[3])
	sig2Raw, err = base64.StdEncoding.DecodeString(sig2B64)
	if err != nil {
		return nil, "", nil, fmt.Errorf("decoding global signature line 4: %w", err)
	}
	if len(sig2Raw) != sigPart2Len {
		return nil, "", nil, fmt.Errorf("invalid signature part 2 length %d (expected %d)", len(sig2Raw), sigPart2Len)
	}

	return sig1Raw, trustedComment, sig2Raw, nil
}

// SignMinisign generates a standard Minisign signature for a byte slice given a secret key.
func SignMinisign(content []byte, secretKeyStr, pubKeyPath, filename string) (string, error) {
	privKey, err := parsePrivateKey(secretKeyStr)
	if err != nil {
		return "", err
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	var keyID []byte

	if pubKeyPath != "" {
		_, pKeyID, err := ParseMinisignPublicKey(pubKeyPath)
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

	tComment := fmt.Sprintf("timestamp:%d\tfile:%s", time.Now().Unix(), filepath.Base(filename))

	globalData := append(append([]byte(nil), fileSig...), []byte(tComment)...)
	globalSig := ed25519.Sign(privKey, globalData)
	globalSigB64 := base64.StdEncoding.EncodeToString(globalSig)

	return fmt.Sprintf("%ssignature from minisign secret key\n%s\n%s%s\n%s\n",
		untrustedPrefix, sig1B64, trustedPrefix, tComment, globalSigB64), nil
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
