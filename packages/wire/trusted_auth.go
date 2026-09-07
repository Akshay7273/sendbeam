package wire

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Trusted-session message types, protocol versions, and domain separation constants (V15-PR03, V19-PR01).
const (
	MsgTrustedAuthInit     = "trusted_auth_init"
	MsgTrustedAuthResponse = "trusted_auth_response"
	MsgTrustedAuthConfirm  = "trusted_auth_confirm"

	TrustedAuthProtocolVersion   = "sendbeam/2"
	TrustedAuthProtocolVersionV3 = "sendbeam/3"

	DomainTrustedInit          = "sendbeam/2 trusted-init:"
	DomainTrustedInitMAC       = "sendbeam/2 trusted-init-mac:"
	DomainTrustedResp          = "sendbeam/2 trusted-resp:"
	DomainTrustedRespMAC       = "sendbeam/2 trusted-resp-mac:"
	DomainTrustedMaster        = "sendbeam/2 session-master:"
	DomainTrustedInitToRespKey = "sendbeam/2 initiator-to-responder key"
	DomainTrustedRespToInitKey = "sendbeam/2 responder-to-initiator key"
	DomainTrustedConfirmInit   = "sendbeam/2 confirm-init:"
	DomainTrustedConfirmResp   = "sendbeam/2 confirm-resp:"

	// sendbeam/3 domain constants (ADR 0010)
	DomainTrustedInit3        = "sendbeam/3 trusted-init:"
	DomainTrustedInitMAC3     = "sendbeam/3 trusted-init-mac:"
	DomainTrustedResp3        = "sendbeam/3 trusted-resp:"
	DomainTrustedRespMAC3     = "sendbeam/3 trusted-resp-mac:"
	DomainTrustedMaster3      = "sendbeam/3 session-master:"
	DomainTrustedInitToResp3  = "sendbeam/3 initiator-to-responder key"
	DomainTrustedRespToInit3  = "sendbeam/3 responder-to-initiator key"
	DomainTrustedConfirmInit3 = "sendbeam/3 confirm-init:"
	DomainTrustedConfirmResp3 = "sendbeam/3 confirm-resp:"
	DomainTrustedTranscript3  = "sendbeam/3 transcript:"

	TrustedAuthNonceSize     = 32
	TrustedAuthEphemeralSize = 32
	X25519KeySize            = 32
	MaxTrustedTimestampSkew  = 5 * time.Minute
)

var (
	// ErrInvalidTrustedMessage indicates a malformed or unrecognizable trusted-session message.
	ErrInvalidTrustedMessage = errors.New("invalid trusted-session message")

	// ErrTrustedTimestampSkew indicates that the message timestamp is outside acceptable clock bounds.
	ErrTrustedTimestampSkew = errors.New("trusted-session timestamp outside acceptable skew window")

	// ErrTrustedSignatureFailed indicates that the Ed25519 signature in trusted authentication failed.
	ErrTrustedSignatureFailed = errors.New("trusted-session signature verification failed")

	// ErrTrustedMACTagFailed indicates that the HMAC-SHA256 authentication tag failed verification.
	ErrTrustedMACTagFailed = errors.New("trusted-session MAC tag verification failed")

	// ErrTrustedPeerMismatch indicates that the claimed peer device ID does not match expected identity.
	ErrTrustedPeerMismatch = errors.New("trusted-session peer device ID mismatch")

	// ErrTrustedPeerRevoked indicates that the peer device has been revoked in local trust store.
	ErrTrustedPeerRevoked = Errorf(CodeAuth, "trusted peer device is revoked")

	// ErrTrustedRejected indicates that the peer explicitly rejected the trusted session.
	ErrTrustedRejected = errors.New("trusted session was rejected by peer")

	// ErrProtocolDowngradeForbidden indicates an attempt to downgrade trusted-session protocol (ADR 0010).
	ErrProtocolDowngradeForbidden = Errorf(CodeCompat, "trusted-session protocol downgrade forbidden")

	// ErrWeakEphemeralKey indicates that the ephemeral public key is weak, low-order, or invalid (ADR 0010).
	ErrWeakEphemeralKey = Errorf(CodeAuth, "ephemeral public key is weak or invalid")

	// ErrSessionReplayDetected indicates that a replayed session handshake was detected (ADR 0010).
	ErrSessionReplayDetected = Errorf(CodeProtocol, "trusted-session replay detected")

	// ErrRevocationUnauthorized indicates that the revoker lacks authority to revoke the device (ADR 0010).
	ErrRevocationUnauthorized = Errorf(CodeAuth, "revocation record is unauthorized")
)

// TrustedAuthInit is sent by the initiating device to authenticate a trusted connection.
type TrustedAuthInit struct {
	Type              string             `json:"type"`
	ProtocolVersion   string             `json:"protocol_version"`
	InitiatorDeviceID string             `json:"initiator_device_id"`
	ResponderDeviceID string             `json:"responder_device_id"`
	PairCredentialRef string             `json:"pair_credential_ref"`
	EphemeralPub      string             `json:"ephemeral_pub"`
	Nonce             string             `json:"nonce"`
	Capabilities      []string           `json:"capabilities"`
	Timestamp         string             `json:"timestamp"`
	Signature         string             `json:"signature"`
	AuthTag           string             `json:"auth_tag"`
	Revocations       []RevocationRecord `json:"revocations,omitempty"`
}

// TrustedAuthResponse is sent by the responder upon verifying the TrustedAuthInit.
type TrustedAuthResponse struct {
	Type              string             `json:"type"`
	ProtocolVersion   string             `json:"protocol_version"`
	Status            string             `json:"status"` // "accepted", "rejected", or "revoked"
	ResponderDeviceID string             `json:"responder_device_id"`
	EphemeralPub      string             `json:"ephemeral_pub,omitempty"`
	Nonce             string             `json:"nonce,omitempty"`
	Capabilities      []string           `json:"capabilities,omitempty"`
	Signature         string             `json:"signature,omitempty"`
	AuthTag           string             `json:"auth_tag,omitempty"`
	Revocations       []RevocationRecord `json:"revocations,omitempty"`
}

// TrustedAuthConfirm finalizes mutual session establishment.
type TrustedAuthConfirm struct {
	Type    string `json:"type"`
	Status  string `json:"status"` // "ready" or "rejected"
	AuthTag string `json:"auth_tag,omitempty"`
}

// TrustedSessionKeys contains directional session keys and negotiated features for sendbeam/2.
type TrustedSessionKeys struct {
	SessionMaster           []byte
	InitiatorToResponderKey []byte
	ResponderToInitiatorKey []byte
	NegotiatedCapabilities  []string
}

// HashCapabilities produces a deterministic canonical SHA-256 digest of capability strings.
func HashCapabilities(caps []string) []byte {
	sorted := make([]string, len(caps))
	copy(sorted, caps)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")
	h := sha256.Sum256([]byte(joined))
	return h[:]
}

// IntersectCapabilities returns the alphabetically sorted set of capabilities supported by both peers.
func IntersectCapabilities(a, b []string) []string {
	set := make(map[string]bool, len(a))
	for _, item := range a {
		set[item] = true
	}
	res := make([]string, 0)
	for _, item := range b {
		if set[item] {
			res = append(res, item)
		}
	}
	sort.Strings(res)
	return res
}

// BuildTrustedInitChallenge constructs the binary payload signed by the initiator.
func BuildTrustedInitChallenge(kPairHash, ephemPub, nonce []byte, initID, respID string, capsHash []byte, timestamp string) []byte {
	buf := make([]byte, 0, len(DomainTrustedInit)+len(kPairHash)+len(ephemPub)+len(nonce)+len(initID)+len(respID)+len(capsHash)+len(timestamp))
	buf = append(buf, DomainTrustedInit...)
	buf = append(buf, kPairHash...)
	buf = append(buf, ephemPub...)
	buf = append(buf, nonce...)
	buf = append(buf, initID...)
	buf = append(buf, respID...)
	buf = append(buf, capsHash...)
	buf = append(buf, timestamp...)
	return buf
}

// BuildTrustedRespChallenge constructs the binary payload signed by the responder.
func BuildTrustedRespChallenge(kPairHash, ephemPubInit, ephemPubResp, nonceInit, nonceResp []byte, initID, respID string, capsHash []byte) []byte {
	buf := make([]byte, 0, len(DomainTrustedResp)+len(kPairHash)+len(ephemPubInit)+len(ephemPubResp)+len(nonceInit)+len(nonceResp)+len(initID)+len(respID)+len(capsHash))
	buf = append(buf, DomainTrustedResp...)
	buf = append(buf, kPairHash...)
	buf = append(buf, ephemPubInit...)
	buf = append(buf, ephemPubResp...)
	buf = append(buf, nonceInit...)
	buf = append(buf, nonceResp...)
	buf = append(buf, initID...)
	buf = append(buf, respID...)
	buf = append(buf, capsHash...)
	return buf
}

// BuildTrustedInitChallengeV3 constructs the binary payload signed by the initiator in sendbeam/3 (ADR 0010).
func BuildTrustedInitChallengeV3(kPairHash, ephemPub, nonce []byte, initID, respID string, capsHash []byte, timestamp string) []byte {
	buf := make([]byte, 0, len(DomainTrustedInit3)+len(kPairHash)+len(ephemPub)+len(nonce)+len(initID)+len(respID)+len(capsHash)+len(timestamp))
	buf = append(buf, DomainTrustedInit3...)
	buf = append(buf, kPairHash...)
	buf = append(buf, ephemPub...)
	buf = append(buf, nonce...)
	buf = append(buf, initID...)
	buf = append(buf, respID...)
	buf = append(buf, capsHash...)
	buf = append(buf, timestamp...)
	return buf
}

// BuildTrustedRespChallengeV3 constructs the binary payload signed by the responder in sendbeam/3 (ADR 0010).
func BuildTrustedRespChallengeV3(kPairHash, ephemPubInit, ephemPubResp, nonceInit, nonceResp []byte, initID, respID string, capsHash []byte) []byte {
	buf := make([]byte, 0, len(DomainTrustedResp3)+len(kPairHash)+len(ephemPubInit)+len(ephemPubResp)+len(nonceInit)+len(nonceResp)+len(initID)+len(respID)+len(capsHash))
	buf = append(buf, DomainTrustedResp3...)
	buf = append(buf, kPairHash...)
	buf = append(buf, ephemPubInit...)
	buf = append(buf, ephemPubResp...)
	buf = append(buf, nonceInit...)
	buf = append(buf, nonceResp...)
	buf = append(buf, initID...)
	buf = append(buf, respID...)
	buf = append(buf, capsHash...)
	return buf
}

// BuildTrustedTranscriptV3 constructs the canonical transcript bound into the sendbeam/3 session master key (ADR 0010).
func BuildTrustedTranscriptV3(kPairHash, ephemPubInit, ephemPubResp, nonceInit, nonceResp []byte, initID, respID string, capsHash []byte) []byte {
	buf := make([]byte, 0, len(DomainTrustedTranscript3)+len(kPairHash)+len(ephemPubInit)+len(ephemPubResp)+len(nonceInit)+len(nonceResp)+len(initID)+len(respID)+len(capsHash))
	buf = append(buf, DomainTrustedTranscript3...)
	buf = append(buf, kPairHash...)
	buf = append(buf, ephemPubInit...)
	buf = append(buf, ephemPubResp...)
	buf = append(buf, nonceInit...)
	buf = append(buf, nonceResp...)
	buf = append(buf, initID...)
	buf = append(buf, respID...)
	buf = append(buf, capsHash...)
	return buf
}

// GenerateX25519KeyPair generates a fresh ephemeral X25519 keypair and returns (privateKey, 32-byte publicKey, error).
func GenerateX25519KeyPair() (*ecdh.PrivateKey, []byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// ComputeX25519SharedSecret computes the Diffie-Hellman shared secret between private scalar and peer public key.
// It verifies that peer public key and output are valid non-zero Curve25519 points (rejects weak points fail-closed).
func ComputeX25519SharedSecret(priv *ecdh.PrivateKey, peerPubBytes []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("x25519 private key required")
	}
	if len(peerPubBytes) != X25519KeySize {
		return nil, ErrWeakEphemeralKey
	}
	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWeakEphemeralKey, err)
	}
	ss, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWeakEphemeralKey, err)
	}
	allZeros := make([]byte, X25519KeySize)
	if subtle.ConstantTimeCompare(ss, allZeros) == 1 {
		return nil, ErrWeakEphemeralKey
	}
	return ss, nil
}

// ComputeTrustedMACTag computes the HMAC-SHA256 authentication tag over a challenge using k_pair.
func ComputeTrustedMACTag(kPair []byte, domain string, challenge []byte) string {
	mac := hmac.New(sha256.New, kPair)
	mac.Write([]byte(domain))
	mac.Write(challenge)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyTrustedMACTag checks a MAC tag in constant time.
func VerifyTrustedMACTag(kPair []byte, domain string, challenge []byte, tagHex string) bool {
	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil || len(tagBytes) != sha256.Size {
		return false
	}
	expectedHex := ComputeTrustedMACTag(kPair, domain, challenge)
	expectedBytes, _ := hex.DecodeString(expectedHex)
	return subtle.ConstantTimeCompare(tagBytes, expectedBytes) == 1
}

// DeriveTrustedSessionKeys derives pairwise authenticated directional traffic keys from ephemeral material and k_pair.
// Note: This derivation provides mutual authentication and replay resistance, but does not provide forward secrecy
// against compromise of k_pair. An ephemeral Diffie-Hellman authenticated key exchange is scheduled for v1.9.
func DeriveTrustedSessionKeys(kPair, ephemPubInit, ephemPubResp, nonceInit, nonceResp []byte, initID, respID string, capsInit, capsResp []string) (*TrustedSessionKeys, error) {
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPubInit) != TrustedAuthEphemeralSize || len(ephemPubResp) != TrustedAuthEphemeralSize {
		return nil, errors.New("invalid ephemeral public key size")
	}
	if len(nonceInit) != TrustedAuthNonceSize || len(nonceResp) != TrustedAuthNonceSize {
		return nil, errors.New("invalid nonce size")
	}

	negotiated := IntersectCapabilities(capsInit, capsResp)
	capsHash := HashCapabilities(negotiated)

	// Mix ephemeral material and k_pair into IKM
	ephemMix := make([]byte, 0, len(ephemPubInit)+len(ephemPubResp)+len(nonceInit)+len(nonceResp))
	ephemMix = append(ephemMix, ephemPubInit...)
	ephemMix = append(ephemMix, ephemPubResp...)
	ephemMix = append(ephemMix, nonceInit...)
	ephemMix = append(ephemMix, nonceResp...)

	mac := hmac.New(sha256.New, kPair)
	mac.Write(ephemMix)
	ikm := mac.Sum(nil)

	salt := make([]byte, 0, len(nonceInit)+len(nonceResp))
	salt = append(salt, nonceInit...)
	salt = append(salt, nonceResp...)

	kPairHash := sha256.Sum256(kPair)
	transcript := BuildTrustedRespChallenge(kPairHash[:], ephemPubInit, ephemPubResp, nonceInit, nonceResp, initID, respID, capsHash)

	infoMaster := append([]byte(DomainTrustedMaster), transcript...)
	sessionMaster, err := hkdfSHA256(ikm, salt, infoMaster, 32)
	if err != nil {
		return nil, fmt.Errorf("derive session master: %w", err)
	}

	kI2R, err := hkdfSHA256(sessionMaster, nil, []byte(DomainTrustedInitToRespKey), 32)
	if err != nil {
		return nil, fmt.Errorf("derive i2r key: %w", err)
	}

	kR2I, err := hkdfSHA256(sessionMaster, nil, []byte(DomainTrustedRespToInitKey), 32)
	if err != nil {
		return nil, fmt.Errorf("derive r2i key: %w", err)
	}

	return &TrustedSessionKeys{
		SessionMaster:           sessionMaster,
		InitiatorToResponderKey: kI2R,
		ResponderToInitiatorKey: kR2I,
		NegotiatedCapabilities:  negotiated,
	}, nil
}

// DeriveTrustedSessionKeysV3 derives directional traffic keys using forward-secret ephemeral Diffie-Hellman and k_pair (ADR 0010).
func DeriveTrustedSessionKeysV3(kPair, ssECDH, ephemPubInit, ephemPubResp, nonceInit, nonceResp []byte, initID, respID string, capsInit, capsResp []string) (*TrustedSessionKeys, error) {
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ssECDH) != X25519KeySize {
		return nil, ErrWeakEphemeralKey
	}
	allZeros := make([]byte, X25519KeySize)
	if subtle.ConstantTimeCompare(ssECDH, allZeros) == 1 {
		return nil, ErrWeakEphemeralKey
	}
	if len(ephemPubInit) != X25519KeySize || len(ephemPubResp) != X25519KeySize {
		return nil, errors.New("invalid ephemeral public key size")
	}
	if len(nonceInit) != TrustedAuthNonceSize || len(nonceResp) != TrustedAuthNonceSize {
		return nil, errors.New("invalid nonce size")
	}

	negotiated := IntersectCapabilities(capsInit, capsResp)
	capsHash := HashCapabilities(negotiated)
	kPairHash := sha256.Sum256(kPair)

	transcript := BuildTrustedTranscriptV3(kPairHash[:], ephemPubInit, ephemPubResp, nonceInit, nonceResp, initID, respID, capsHash)
	infoMaster := append([]byte(DomainTrustedMaster3), transcript...)

	sessionMaster, err := hkdfSHA256(ssECDH, kPair, infoMaster, 32)
	if err != nil {
		return nil, fmt.Errorf("derive session master: %w", err)
	}

	kI2R, err := hkdfSHA256(sessionMaster, nil, []byte(DomainTrustedInitToResp3), 32)
	if err != nil {
		return nil, fmt.Errorf("derive i2r key: %w", err)
	}

	kR2I, err := hkdfSHA256(sessionMaster, nil, []byte(DomainTrustedRespToInit3), 32)
	if err != nil {
		return nil, fmt.Errorf("derive r2i key: %w", err)
	}

	return &TrustedSessionKeys{
		SessionMaster:           sessionMaster,
		InitiatorToResponderKey: kI2R,
		ResponderToInitiatorKey: kR2I,
		NegotiatedCapabilities:  negotiated,
	}, nil
}

// ComputeTrustedConfirmTag computes the confirmation tag for the session master.
func ComputeTrustedConfirmTag(sessionMaster []byte, domain string, deviceID string) string {
	mac := hmac.New(sha256.New, sessionMaster)
	mac.Write([]byte(domain))
	mac.Write([]byte(deviceID))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyTrustedConfirmTag verifies the confirmation tag in constant time.
func VerifyTrustedConfirmTag(sessionMaster []byte, domain string, deviceID, tagHex string) bool {
	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil || len(tagBytes) != sha256.Size {
		return false
	}
	expectedHex := ComputeTrustedConfirmTag(sessionMaster, domain, deviceID)
	expectedBytes, _ := hex.DecodeString(expectedHex)
	return subtle.ConstantTimeCompare(tagBytes, expectedBytes) == 1
}

// NewTrustedAuthInit creates a signed and MAC-authenticated TrustedAuthInit message.
func NewTrustedAuthInit(id *DeviceIdentity, respDeviceID, credRef string, kPair []byte, caps []string, ephemPub, nonce []byte, now time.Time) (*TrustedAuthInit, error) {
	return NewTrustedAuthInitWithRevocations(id, respDeviceID, credRef, kPair, caps, ephemPub, nonce, now, nil)
}

// NewTrustedAuthInitWithRevocations creates a signed and MAC-authenticated TrustedAuthInit message including mesh RevocationRecords.
func NewTrustedAuthInitWithRevocations(id *DeviceIdentity, respDeviceID, credRef string, kPair []byte, caps []string, ephemPub, nonce []byte, now time.Time, revocations []RevocationRecord) (*TrustedAuthInit, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPub) != TrustedAuthEphemeralSize {
		ephemPub = make([]byte, TrustedAuthEphemeralSize)
		if _, err := rand.Read(ephemPub); err != nil {
			return nil, err
		}
	}
	if len(nonce) != TrustedAuthNonceSize {
		nonce = make([]byte, TrustedAuthNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	tsStr := now.UTC().Format(time.RFC3339)
	capsHash := HashCapabilities(caps)
	kPairHash := sha256.Sum256(kPair)

	challenge := BuildTrustedInitChallenge(kPairHash[:], ephemPub, nonce, id.DeviceID, respDeviceID, capsHash, tsStr)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign trusted init: %w", err)
	}

	tag := ComputeTrustedMACTag(kPair, DomainTrustedInitMAC, challenge)

	return &TrustedAuthInit{
		Type:              MsgTrustedAuthInit,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		InitiatorDeviceID: id.DeviceID,
		ResponderDeviceID: respDeviceID,
		PairCredentialRef: credRef,
		EphemeralPub:      hex.EncodeToString(ephemPub),
		Nonce:             hex.EncodeToString(nonce),
		Capabilities:      caps,
		Timestamp:         tsStr,
		Signature:         hex.EncodeToString(sig),
		AuthTag:           tag,
		Revocations:       revocations,
	}, nil
}

// VerifyTrustedAuthInit validates format, clock skew, Ed25519 signature, and HMAC tag of a TrustedAuthInit.
func VerifyTrustedAuthInit(init *TrustedAuthInit, kPair []byte, initPubKey ed25519.PublicKey, localDeviceID string, now time.Time) ([]byte, []byte, error) {
	if init == nil || init.Type != MsgTrustedAuthInit || init.ProtocolVersion != TrustedAuthProtocolVersion {
		return nil, nil, ErrInvalidTrustedMessage
	}
	if init.ResponderDeviceID != localDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}
	if !ValidateDeviceID(init.InitiatorDeviceID) {
		return nil, nil, ErrInvalidDeviceID
	}

	expectedInitID := DeriveDeviceID(initPubKey)
	if expectedInitID != init.InitiatorDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	ts, err := time.Parse(time.RFC3339, init.Timestamp)
	if err != nil {
		return nil, nil, ErrInvalidTrustedMessage
	}
	skew := now.Sub(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxTrustedTimestampSkew {
		return nil, nil, ErrTrustedTimestampSkew
	}

	ephemPub, err := hex.DecodeString(init.EphemeralPub)
	if err != nil || len(ephemPub) != TrustedAuthEphemeralSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	nonce, err := hex.DecodeString(init.Nonce)
	if err != nil || len(nonce) != TrustedAuthNonceSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	sigBytes, err := hex.DecodeString(init.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrTrustedSignatureFailed
	}

	capsHash := HashCapabilities(init.Capabilities)
	kPairHash := sha256.Sum256(kPair)
	challenge := BuildTrustedInitChallenge(kPairHash[:], ephemPub, nonce, init.InitiatorDeviceID, init.ResponderDeviceID, capsHash, init.Timestamp)

	if !VerifyDeviceSignature(initPubKey, challenge, sigBytes) {
		return nil, nil, ErrTrustedSignatureFailed
	}

	if !VerifyTrustedMACTag(kPair, DomainTrustedInitMAC, challenge, init.AuthTag) {
		return nil, nil, ErrTrustedMACTagFailed
	}

	return ephemPub, nonce, nil
}

// NewTrustedAuthResponse creates a signed and MAC-authenticated TrustedAuthResponse message.
func NewTrustedAuthResponse(id *DeviceIdentity, init *TrustedAuthInit, kPair []byte, caps []string, ephemPub, nonce []byte) (*TrustedAuthResponse, error) {
	return NewTrustedAuthResponseWithRevocations(id, init, kPair, caps, ephemPub, nonce, nil)
}

// NewTrustedAuthResponseWithRevocations creates a signed TrustedAuthResponse message including mesh RevocationRecords.
func NewTrustedAuthResponseWithRevocations(id *DeviceIdentity, init *TrustedAuthInit, kPair []byte, caps []string, ephemPub, nonce []byte, revocations []RevocationRecord) (*TrustedAuthResponse, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPub) != TrustedAuthEphemeralSize {
		ephemPub = make([]byte, TrustedAuthEphemeralSize)
		if _, err := rand.Read(ephemPub); err != nil {
			return nil, err
		}
	}
	if len(nonce) != TrustedAuthNonceSize {
		nonce = make([]byte, TrustedAuthNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	ephemInit, _ := hex.DecodeString(init.EphemeralPub)
	nonceInit, _ := hex.DecodeString(init.Nonce)

	negotiated := IntersectCapabilities(init.Capabilities, caps)
	capsHash := HashCapabilities(negotiated)
	kPairHash := sha256.Sum256(kPair)

	challenge := BuildTrustedRespChallenge(kPairHash[:], ephemInit, ephemPub, nonceInit, nonce, init.InitiatorDeviceID, id.DeviceID, capsHash)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign trusted response: %w", err)
	}

	tag := ComputeTrustedMACTag(kPair, DomainTrustedRespMAC, challenge)

	return &TrustedAuthResponse{
		Type:              MsgTrustedAuthResponse,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		Status:            "accepted",
		ResponderDeviceID: id.DeviceID,
		EphemeralPub:      hex.EncodeToString(ephemPub),
		Nonce:             hex.EncodeToString(nonce),
		Capabilities:      caps,
		Signature:         hex.EncodeToString(sig),
		AuthTag:           tag,
		Revocations:       revocations,
	}, nil
}

// VerifyTrustedAuthResponse validates the format, Ed25519 signature, and HMAC tag of a TrustedAuthResponse.
func VerifyTrustedAuthResponse(resp *TrustedAuthResponse, init *TrustedAuthInit, kPair []byte, respPubKey ed25519.PublicKey, localDeviceID string) ([]byte, []byte, error) {
	if resp == nil || resp.Type != MsgTrustedAuthResponse || resp.ProtocolVersion != TrustedAuthProtocolVersion {
		return nil, nil, ErrInvalidTrustedMessage
	}
	if localDeviceID != "" && init.InitiatorDeviceID != localDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}
	if resp.Status != "accepted" {
		if resp.Status == "revoked" {
			return nil, nil, ErrTrustedPeerRevoked
		}
		return nil, nil, ErrTrustedRejected
	}
	if resp.ResponderDeviceID != init.ResponderDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	expectedRespID := DeriveDeviceID(respPubKey)
	if expectedRespID != resp.ResponderDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	ephemInit, _ := hex.DecodeString(init.EphemeralPub)
	nonceInit, _ := hex.DecodeString(init.Nonce)

	ephemResp, err := hex.DecodeString(resp.EphemeralPub)
	if err != nil || len(ephemResp) != TrustedAuthEphemeralSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	nonceResp, err := hex.DecodeString(resp.Nonce)
	if err != nil || len(nonceResp) != TrustedAuthNonceSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	sigBytes, err := hex.DecodeString(resp.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrTrustedSignatureFailed
	}

	negotiated := IntersectCapabilities(init.Capabilities, resp.Capabilities)
	capsHash := HashCapabilities(negotiated)
	kPairHash := sha256.Sum256(kPair)
	challenge := BuildTrustedRespChallenge(kPairHash[:], ephemInit, ephemResp, nonceInit, nonceResp, init.InitiatorDeviceID, resp.ResponderDeviceID, capsHash)

	if !VerifyDeviceSignature(respPubKey, challenge, sigBytes) {
		return nil, nil, ErrTrustedSignatureFailed
	}

	if !VerifyTrustedMACTag(kPair, DomainTrustedRespMAC, challenge, resp.AuthTag) {
		return nil, nil, ErrTrustedMACTagFailed
	}

	return ephemResp, nonceResp, nil
}

// NewTrustedAuthConfirm creates a TrustedAuthConfirm message.
func NewTrustedAuthConfirm(sessionMaster []byte, domain, localDeviceID string, ready bool) *TrustedAuthConfirm {
	if !ready {
		return &TrustedAuthConfirm{
			Type:   MsgTrustedAuthConfirm,
			Status: "rejected",
		}
	}
	tag := ComputeTrustedConfirmTag(sessionMaster, domain, localDeviceID)
	return &TrustedAuthConfirm{
		Type:    MsgTrustedAuthConfirm,
		Status:  "ready",
		AuthTag: tag,
	}
}

// VerifyTrustedAuthConfirm verifies a peer's confirmation tag.
func VerifyTrustedAuthConfirm(confirm *TrustedAuthConfirm, sessionMaster []byte, domain, peerDeviceID string) error {
	if confirm == nil || confirm.Type != MsgTrustedAuthConfirm {
		return ErrInvalidTrustedMessage
	}
	if confirm.Status != "ready" {
		return ErrTrustedRejected
	}
	if !VerifyTrustedConfirmTag(sessionMaster, domain, peerDeviceID, confirm.AuthTag) {
		return ErrTrustedMACTagFailed
	}
	return nil
}

// ZeroizeBytes safely clears a byte slice in memory.
func ZeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NewTrustedAuthInitV3 creates a signed and MAC-authenticated TrustedAuthInit message under sendbeam/3.
func NewTrustedAuthInitV3(id *DeviceIdentity, respDeviceID, credRef string, kPair []byte, caps []string, ephemPub, nonce []byte, now time.Time, revocations []RevocationRecord) (*TrustedAuthInit, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPub) != X25519KeySize {
		return nil, errors.New("invalid ephemeral public key size")
	}
	if len(nonce) != TrustedAuthNonceSize {
		return nil, errors.New("invalid nonce size")
	}

	tsStr := now.UTC().Format(time.RFC3339)
	capsHash := HashCapabilities(caps)
	kPairHash := sha256.Sum256(kPair)

	challenge := BuildTrustedInitChallengeV3(kPairHash[:], ephemPub, nonce, id.DeviceID, respDeviceID, capsHash, tsStr)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign trusted init: %w", err)
	}

	tag := ComputeTrustedMACTag(kPair, DomainTrustedInitMAC3, challenge)

	return &TrustedAuthInit{
		Type:              MsgTrustedAuthInit,
		ProtocolVersion:   TrustedAuthProtocolVersionV3,
		InitiatorDeviceID: id.DeviceID,
		ResponderDeviceID: respDeviceID,
		PairCredentialRef: credRef,
		EphemeralPub:      hex.EncodeToString(ephemPub),
		Nonce:             hex.EncodeToString(nonce),
		Capabilities:      caps,
		Timestamp:         tsStr,
		Signature:         hex.EncodeToString(sig),
		AuthTag:           tag,
		Revocations:       revocations,
	}, nil
}

// VerifyTrustedAuthInitV3 validates format, protocol version, clock skew, Ed25519 signature, and HMAC tag for sendbeam/3.
func VerifyTrustedAuthInitV3(init *TrustedAuthInit, kPair []byte, initPubKey ed25519.PublicKey, localDeviceID string, now time.Time) ([]byte, []byte, error) {
	if init == nil || init.Type != MsgTrustedAuthInit {
		return nil, nil, ErrInvalidTrustedMessage
	}
	if init.ProtocolVersion != TrustedAuthProtocolVersionV3 {
		if init.ProtocolVersion == TrustedAuthProtocolVersion || init.ProtocolVersion == "sendbeam/1" {
			return nil, nil, ErrProtocolDowngradeForbidden
		}
		return nil, nil, ErrInvalidTrustedMessage
	}
	if init.ResponderDeviceID != localDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}
	if !ValidateDeviceID(init.InitiatorDeviceID) {
		return nil, nil, ErrInvalidDeviceID
	}

	expectedInitID := DeriveDeviceID(initPubKey)
	if expectedInitID != init.InitiatorDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	ts, err := time.Parse(time.RFC3339, init.Timestamp)
	if err != nil {
		return nil, nil, ErrInvalidTrustedMessage
	}
	skew := now.Sub(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxTrustedTimestampSkew {
		return nil, nil, ErrTrustedTimestampSkew
	}

	ephemPub, err := hex.DecodeString(init.EphemeralPub)
	if err != nil || len(ephemPub) != X25519KeySize {
		return nil, nil, ErrWeakEphemeralKey
	}

	nonce, err := hex.DecodeString(init.Nonce)
	if err != nil || len(nonce) != TrustedAuthNonceSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	sigBytes, err := hex.DecodeString(init.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrTrustedSignatureFailed
	}

	capsHash := HashCapabilities(init.Capabilities)
	kPairHash := sha256.Sum256(kPair)
	challenge := BuildTrustedInitChallengeV3(kPairHash[:], ephemPub, nonce, init.InitiatorDeviceID, init.ResponderDeviceID, capsHash, init.Timestamp)

	if !VerifyDeviceSignature(initPubKey, challenge, sigBytes) {
		return nil, nil, ErrTrustedSignatureFailed
	}

	if !VerifyTrustedMACTag(kPair, DomainTrustedInitMAC3, challenge, init.AuthTag) {
		return nil, nil, ErrTrustedMACTagFailed
	}

	return ephemPub, nonce, nil
}

// NewTrustedAuthResponseV3 creates a signed and MAC-authenticated TrustedAuthResponse under sendbeam/3.
func NewTrustedAuthResponseV3(id *DeviceIdentity, init *TrustedAuthInit, kPair []byte, caps []string, ephemPub, nonce []byte, revocations []RevocationRecord) (*TrustedAuthResponse, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPub) != X25519KeySize {
		return nil, errors.New("invalid ephemeral public key size")
	}
	if len(nonce) != TrustedAuthNonceSize {
		return nil, errors.New("invalid nonce size")
	}

	ephemInit, err := hex.DecodeString(init.EphemeralPub)
	if err != nil || len(ephemInit) != X25519KeySize {
		return nil, ErrWeakEphemeralKey
	}
	nonceInit, err := hex.DecodeString(init.Nonce)
	if err != nil || len(nonceInit) != TrustedAuthNonceSize {
		return nil, ErrInvalidTrustedMessage
	}

	negotiated := IntersectCapabilities(init.Capabilities, caps)
	capsHash := HashCapabilities(negotiated)
	kPairHash := sha256.Sum256(kPair)

	challenge := BuildTrustedRespChallengeV3(kPairHash[:], ephemInit, ephemPub, nonceInit, nonce, init.InitiatorDeviceID, id.DeviceID, capsHash)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign trusted response: %w", err)
	}

	tag := ComputeTrustedMACTag(kPair, DomainTrustedRespMAC3, challenge)

	return &TrustedAuthResponse{
		Type:              MsgTrustedAuthResponse,
		ProtocolVersion:   TrustedAuthProtocolVersionV3,
		Status:            "accepted",
		ResponderDeviceID: id.DeviceID,
		EphemeralPub:      hex.EncodeToString(ephemPub),
		Nonce:             hex.EncodeToString(nonce),
		Capabilities:      caps,
		Signature:         hex.EncodeToString(sig),
		AuthTag:           tag,
		Revocations:       revocations,
	}, nil
}

// VerifyTrustedAuthResponseV3 validates format, protocol version, Ed25519 signature, and HMAC tag for sendbeam/3.
func VerifyTrustedAuthResponseV3(resp *TrustedAuthResponse, init *TrustedAuthInit, kPair []byte, respPubKey ed25519.PublicKey, localDeviceID string) ([]byte, []byte, error) {
	if resp == nil || resp.Type != MsgTrustedAuthResponse {
		return nil, nil, ErrInvalidTrustedMessage
	}
	if resp.ProtocolVersion != TrustedAuthProtocolVersionV3 {
		if resp.ProtocolVersion == TrustedAuthProtocolVersion || resp.ProtocolVersion == "sendbeam/1" {
			return nil, nil, ErrProtocolDowngradeForbidden
		}
		return nil, nil, ErrInvalidTrustedMessage
	}
	if localDeviceID != "" && init.InitiatorDeviceID != localDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}
	if resp.Status != "accepted" {
		if resp.Status == "revoked" {
			return nil, nil, ErrTrustedPeerRevoked
		}
		return nil, nil, ErrTrustedRejected
	}
	if resp.ResponderDeviceID != init.ResponderDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	expectedRespID := DeriveDeviceID(respPubKey)
	if expectedRespID != resp.ResponderDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	ephemInit, err := hex.DecodeString(init.EphemeralPub)
	if err != nil || len(ephemInit) != X25519KeySize {
		return nil, nil, ErrWeakEphemeralKey
	}
	nonceInit, err := hex.DecodeString(init.Nonce)
	if err != nil || len(nonceInit) != TrustedAuthNonceSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	ephemResp, err := hex.DecodeString(resp.EphemeralPub)
	if err != nil || len(ephemResp) != X25519KeySize {
		return nil, nil, ErrWeakEphemeralKey
	}

	nonceResp, err := hex.DecodeString(resp.Nonce)
	if err != nil || len(nonceResp) != TrustedAuthNonceSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	sigBytes, err := hex.DecodeString(resp.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrTrustedSignatureFailed
	}

	negotiated := IntersectCapabilities(init.Capabilities, resp.Capabilities)
	capsHash := HashCapabilities(negotiated)
	kPairHash := sha256.Sum256(kPair)
	challenge := BuildTrustedRespChallengeV3(kPairHash[:], ephemInit, ephemResp, nonceInit, nonceResp, init.InitiatorDeviceID, resp.ResponderDeviceID, capsHash)

	if !VerifyDeviceSignature(respPubKey, challenge, sigBytes) {
		return nil, nil, ErrTrustedSignatureFailed
	}

	if !VerifyTrustedMACTag(kPair, DomainTrustedRespMAC3, challenge, resp.AuthTag) {
		return nil, nil, ErrTrustedMACTagFailed
	}

	return ephemResp, nonceResp, nil
}

// NewTrustedAuthConfirmV3 creates a TrustedAuthConfirm message for sendbeam/3.
func NewTrustedAuthConfirmV3(sessionMaster []byte, domain, localDeviceID string, ready bool) *TrustedAuthConfirm {
	return NewTrustedAuthConfirm(sessionMaster, domain, localDeviceID, ready)
}

// VerifyTrustedAuthConfirmV3 verifies a peer's confirmation tag for sendbeam/3.
func VerifyTrustedAuthConfirmV3(confirm *TrustedAuthConfirm, sessionMaster []byte, domain, peerDeviceID string) error {
	return VerifyTrustedAuthConfirm(confirm, sessionMaster, domain, peerDeviceID)
}

// NonceReplayCache tracks recently seen (deviceID, nonce) tuples to detect replays within the timestamp skew window.
type NonceReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

// NewNonceReplayCache creates a new replay cache with the given TTL (defaults to 10 minutes).
func NewNonceReplayCache(ttl time.Duration) *NonceReplayCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &NonceReplayCache{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

// CheckAndRecord returns ErrSessionReplayDetected if the key was already seen within TTL, otherwise records it.
func (c *NonceReplayCache) CheckAndRecord(deviceID, nonceHex string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Add(-c.ttl)
	for k, exp := range c.seen {
		if exp.Before(cutoff) {
			delete(c.seen, k)
		}
	}

	key := deviceID + ":" + nonceHex
	if exp, exists := c.seen[key]; exists && exp.After(cutoff) {
		return ErrSessionReplayDetected
	}

	c.seen[key] = now
	return nil
}

// EncodeTrustedAuthMessage marshals any trusted authentication message into compact JSON bytes.
func EncodeTrustedAuthMessage(msg any) ([]byte, error) {
	return json.Marshal(msg)
}

// DecodeTrustedAuthMessage unmarshals a trusted authentication message into its concrete type.
func DecodeTrustedAuthMessage(data []byte) (any, error) {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTrustedMessage, err)
	}

	switch peek.Type {
	case MsgTrustedAuthInit:
		var init TrustedAuthInit
		if err := json.Unmarshal(data, &init); err != nil {
			return nil, err
		}
		return &init, nil
	case MsgTrustedAuthResponse:
		var resp TrustedAuthResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	case MsgTrustedAuthConfirm:
		var conf TrustedAuthConfirm
		if err := json.Unmarshal(data, &conf); err != nil {
			return nil, err
		}
		return &conf, nil
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidTrustedMessage, peek.Type)
	}
}
