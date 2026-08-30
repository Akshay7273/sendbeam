package wire

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Revocation-related constants and domain separation (V17-PR01).
const (
	DomainRevocationRecord     = "sendbeam/2 revocation-record:"
	MaxRevocationTimestampSkew = 5 * time.Minute
)

var (
	// ErrInvalidRevocationRecord indicates a malformed or structurally invalid revocation record.
	ErrInvalidRevocationRecord = errors.New("invalid revocation record")

	// ErrRevocationSignatureFailed indicates that the Ed25519 signature in a revocation record failed verification.
	ErrRevocationSignatureFailed = errors.New("revocation signature verification failed")

	// ErrRevocationSelfRevoke indicates a revocation record where the revoker and revoked device IDs are identical.
	ErrRevocationSelfRevoke = errors.New("cannot revoke self in mesh sync")

	// ErrRevocationSeqRollback indicates a revocation sequence number that is less than or equal to an existing record.
	ErrRevocationSeqRollback = errors.New("revocation sequence number rollback")

	// ErrRevocationTimestampSkew indicates that the revocation timestamp is outside acceptable clock skew boundaries.
	ErrRevocationTimestampSkew = errors.New("revocation timestamp outside acceptable window")

	// ErrRevokerUntrusted indicates that the device submitting a revocation is not an active trusted peer.
	ErrRevokerUntrusted = errors.New("revocation revoker is not an active trusted peer")
)

// RevocationRecord represents a cryptographically signed statement asserting that a peer device has been revoked.
type RevocationRecord struct {
	RevokerDeviceID string `json:"revoker_device_id"`
	RevokedDeviceID string `json:"revoked_device_id"`
	Seq             uint64 `json:"seq"`
	Timestamp       string `json:"timestamp"` // RFC 3339 UTC format
	Signature       string `json:"signature"` // hex-encoded Ed25519 signature
}

// BuildRevocationChallenge constructs the canonical binary payload signed by the revoker device.
// Format: DomainRevocationRecord || RevokerDeviceID || RevokedDeviceID || BigEndian(Seq) || Timestamp
func BuildRevocationChallenge(revokerID, revokedID string, seq uint64, timestamp string) []byte {
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)

	buf := make([]byte, 0, len(DomainRevocationRecord)+len(revokerID)+len(revokedID)+8+len(timestamp))
	buf = append(buf, DomainRevocationRecord...)
	buf = append(buf, revokerID...)
	buf = append(buf, revokedID...)
	buf = append(buf, seqBytes...)
	buf = append(buf, timestamp...)
	return buf
}

// SignRevocation creates and signs a new RevocationRecord with the revoker's DeviceIdentity.
func SignRevocation(id *DeviceIdentity, revokedDeviceID string, seq uint64, now time.Time) (*RevocationRecord, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if !ValidateDeviceID(revokedDeviceID) {
		return nil, fmt.Errorf("%w: invalid revoked device id %q", ErrInvalidRevocationRecord, revokedDeviceID)
	}
	if id.DeviceID == revokedDeviceID {
		return nil, ErrRevocationSelfRevoke
	}
	if seq == 0 {
		return nil, fmt.Errorf("%w: seq must be greater than 0", ErrInvalidRevocationRecord)
	}

	tsStr := now.UTC().Format(time.RFC3339)
	challenge := BuildRevocationChallenge(id.DeviceID, revokedDeviceID, seq, tsStr)

	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign revocation record: %w", err)
	}

	return &RevocationRecord{
		RevokerDeviceID: id.DeviceID,
		RevokedDeviceID: revokedDeviceID,
		Seq:             seq,
		Timestamp:       tsStr,
		Signature:       hex.EncodeToString(sig),
	}, nil
}

// Validate checks the structural syntax and field constraints of a RevocationRecord.
func (r *RevocationRecord) Validate() error {
	if r == nil {
		return ErrInvalidRevocationRecord
	}
	if !ValidateDeviceID(r.RevokerDeviceID) {
		return fmt.Errorf("%w: invalid revoker device id %q", ErrInvalidRevocationRecord, r.RevokerDeviceID)
	}
	if !ValidateDeviceID(r.RevokedDeviceID) {
		return fmt.Errorf("%w: invalid revoked device id %q", ErrInvalidRevocationRecord, r.RevokedDeviceID)
	}
	if r.RevokerDeviceID == r.RevokedDeviceID {
		return ErrRevocationSelfRevoke
	}
	if r.Seq == 0 {
		return fmt.Errorf("%w: seq must be > 0", ErrInvalidRevocationRecord)
	}
	if _, err := time.Parse(time.RFC3339, r.Timestamp); err != nil {
		return fmt.Errorf("%w: invalid RFC3339 timestamp %q: %v", ErrInvalidRevocationRecord, r.Timestamp, err)
	}
	sigBytes, err := hex.DecodeString(r.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature must be 64 bytes hex", ErrInvalidRevocationRecord)
	}
	return nil
}

// VerifyRevocation validates the signature and timestamp constraints of a RevocationRecord against the revoker's public key.
func VerifyRevocation(rec *RevocationRecord, revokerPubKey ed25519.PublicKey, maxSkew time.Duration, now time.Time) error {
	if err := rec.Validate(); err != nil {
		return err
	}

	expectedRevokerID := DeriveDeviceID(revokerPubKey)
	if expectedRevokerID != rec.RevokerDeviceID {
		return fmt.Errorf("%w: revoker device ID %q does not match public key derived ID %q", ErrRevocationSignatureFailed, rec.RevokerDeviceID, expectedRevokerID)
	}

	ts, err := time.Parse(time.RFC3339, rec.Timestamp)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp", ErrInvalidRevocationRecord)
	}

	if maxSkew > 0 {
		skew := now.Sub(ts)
		if skew < -maxSkew {
			return fmt.Errorf("%w: timestamp is in the future beyond acceptable skew", ErrRevocationTimestampSkew)
		}
	}

	sigBytes, err := hex.DecodeString(rec.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrRevocationSignatureFailed
	}

	challenge := BuildRevocationChallenge(rec.RevokerDeviceID, rec.RevokedDeviceID, rec.Seq, rec.Timestamp)
	if !VerifyDeviceSignature(revokerPubKey, challenge, sigBytes) {
		return ErrRevocationSignatureFailed
	}

	return nil
}
