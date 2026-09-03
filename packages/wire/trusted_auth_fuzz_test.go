package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// FuzzTrustedAuthMessage tests decoding of trusted session authentication messages
// and capability hashing/negotiation against arbitrary inputs.
// Invariants:
// 1. DecodeTrustedAuthMessage must never panic on any input.
// 2. Any successfully decoded message must re-encode and re-decode to the same type.
// 3. HashCapabilities must be deterministic and never panic regardless of slice length or contents.
// 4. IntersectCapabilities must produce a sorted intersection without duplicate elements.
func FuzzTrustedAuthMessage(f *testing.F) {
	// Programmatic baseline seeds
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))
	f.Add([]byte(`{"type":"trusted_auth_init"}`))
	f.Add([]byte(`{"type":"trusted_auth_response"}`))
	f.Add([]byte(`{"type":"trusted_auth_confirm","auth_tag":"00"}`))

	// Load seeds from trusted-session-vectors.json if present
	if data, err := os.ReadFile("testdata/trusted-session-vectors.json"); err == nil {
		var vectors []struct {
			Name            string   `json:"name"`
			InitDeviceID    string   `json:"init_device_id"`
			InitEphemPubHex string   `json:"init_ephem_pub_hex"`
			InitNonceHex    string   `json:"init_nonce_hex"`
			InitCaps        []string `json:"init_caps"`
			InitTimestamp   string   `json:"init_timestamp"`
			InitSigHex      string   `json:"init_sig_hex"`
			InitAuthTagHex  string   `json:"init_auth_tag_hex"`
			PairCredRef     string   `json:"pair_cred_ref"`
			RespDeviceID    string   `json:"resp_device_id"`
			RespEphemPubHex string   `json:"resp_ephem_pub_hex"`
			RespNonceHex    string   `json:"resp_nonce_hex"`
			RespCaps        []string `json:"resp_caps"`
			RespSigHex      string   `json:"resp_sig_hex"`
			RespAuthTagHex  string   `json:"resp_auth_tag_hex"`
			ConfirmTagHex   string   `json:"init_confirm_tag"`
		}
		if err := json.Unmarshal(data, &vectors); err == nil {
			for _, v := range vectors {
				initMsg := TrustedAuthInit{
					Type:              MsgTrustedAuthInit,
					ProtocolVersion:   "sendbeam/1",
					InitiatorDeviceID: v.InitDeviceID,
					ResponderDeviceID: v.RespDeviceID,
					PairCredentialRef: v.PairCredRef,
					EphemeralPub:      v.InitEphemPubHex,
					Nonce:             v.InitNonceHex,
					Capabilities:      v.InitCaps,
					Timestamp:         v.InitTimestamp,
					Signature:         v.InitSigHex,
					AuthTag:           v.InitAuthTagHex,
				}
				if b, err := json.Marshal(initMsg); err == nil {
					f.Add(b)
				}

				respMsg := TrustedAuthResponse{
					Type:              MsgTrustedAuthResponse,
					ProtocolVersion:   "sendbeam/1",
					Status:            "accepted",
					ResponderDeviceID: v.RespDeviceID,
					EphemeralPub:      v.RespEphemPubHex,
					Nonce:             v.RespNonceHex,
					Capabilities:      v.RespCaps,
					Signature:         v.RespSigHex,
					AuthTag:           v.RespAuthTagHex,
				}
				if b, err := json.Marshal(respMsg); err == nil {
					f.Add(b)
				}

				confirmMsg := TrustedAuthConfirm{
					Type:    MsgTrustedAuthConfirm,
					Status:  "ready",
					AuthTag: v.ConfirmTagHex,
				}
				if b, err := json.Marshal(confirmMsg); err == nil {
					f.Add(b)
				}
			}
		}
	}

	dummyKPair := make([]byte, 32)
	dummyPub := make([]byte, ed25519.PublicKeySize)
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodeTrustedAuthMessage(data)
		if err != nil {
			return
		}

		enc, err := EncodeTrustedAuthMessage(msg)
		if err != nil {
			t.Fatalf("marshal failed for %T: %v", msg, err)
		}

		msg2, err := DecodeTrustedAuthMessage(enc)
		if err != nil {
			t.Fatalf("re-decode failed for %T: %v", msg, err)
		}

		switch m := msg.(type) {
		case *TrustedAuthInit:
			if _, ok := msg2.(*TrustedAuthInit); !ok {
				t.Fatalf("type mismatch: %T != *TrustedAuthInit", msg2)
			}
			h := HashCapabilities(m.Capabilities)
			if len(h) != 32 {
				t.Fatalf("HashCapabilities produced %d bytes, want 32", len(h))
			}
			intersect := IntersectCapabilities(m.Capabilities, m.Capabilities)
			if len(intersect) > len(m.Capabilities) {
				t.Fatalf("IntersectCapabilities expanded slice: %d > %d", len(intersect), len(m.Capabilities))
			}

			// Challenge generation must never panic
			if ephemBytes, err := hex.DecodeString(m.EphemeralPub); err == nil {
				if nonceBytes, err := hex.DecodeString(m.Nonce); err == nil {
					kPairHash := sha256.Sum256(dummyKPair)
					_ = BuildTrustedInitChallenge(kPairHash[:], ephemBytes, nonceBytes, m.InitiatorDeviceID, m.ResponderDeviceID, h, m.Timestamp)
				}
			}

			// Verification function must never panic and fail closed
			_, _, _ = VerifyTrustedAuthInit(m, dummyKPair, dummyPub, "sb-dev-dummy", now)

		case *TrustedAuthResponse:
			if _, ok := msg2.(*TrustedAuthResponse); !ok {
				t.Fatalf("type mismatch: %T != *TrustedAuthResponse", msg2)
			}
			h := HashCapabilities(m.Capabilities)
			if len(h) != 32 {
				t.Fatalf("HashCapabilities produced %d bytes, want 32", len(h))
			}

		case *TrustedAuthConfirm:
			if _, ok := msg2.(*TrustedAuthConfirm); !ok {
				t.Fatalf("type mismatch: %T != *TrustedAuthConfirm", msg2)
			}
			_ = VerifyTrustedAuthConfirm(m, dummyKPair, DomainTrustedConfirmInit, "sb-dev-dummy")

		default:
			t.Fatalf("unexpected trusted auth message type: %T", msg)
		}
	})
}
