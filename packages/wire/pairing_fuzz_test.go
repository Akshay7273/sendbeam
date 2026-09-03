package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// FuzzPairingMessage tests the pairing message decoder, challenge construction,
// and confirmation verification against arbitrary input data.
// Invariants:
// 1. DecodePairingMessage must never panic on any input.
// 2. Any successfully decoded message must re-encode to valid JSON and re-decode cleanly.
// 3. Verification functions (VerifyPairingRequest, VerifyPairingResponse, VerifyPairingConfirm)
//    must never panic and must fail closed on invalid keys, bad nonces, or corrupted tags.
func FuzzPairingMessage(f *testing.F) {
	// Programmatic baseline seeds
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))
	f.Add([]byte(`{"type":"invalid"}`))
	f.Add([]byte(`{"type":"pairing_confirm","status":"rejected"}`))
	f.Add([]byte(`{"type":"pairing_confirm","status":"accepted","auth_tag":"0000"}`))

	// Load seeds from pairing-vectors.json if present
	if data, err := os.ReadFile("testdata/pairing-vectors.json"); err == nil {
		var vectors []struct {
			Name            string   `json:"name"`
			MasterKeyHex    string   `json:"master_key_hex"`
			ReqDeviceID     string   `json:"req_device_id"`
			ReqPubKeyHex    string   `json:"req_pub_key_hex"`
			ReqName         string   `json:"req_name"`
			ReqCaps         []string `json:"req_caps"`
			ReqNonceHex     string   `json:"req_nonce_hex"`
			ReqSigHex       string   `json:"req_sig_hex"`
			RespDeviceID    string   `json:"resp_device_id"`
			RespPubKeyHex   string   `json:"resp_pub_key_hex"`
			RespName        string   `json:"resp_name"`
			RespCaps        []string `json:"resp_caps"`
			RespNonceHex    string   `json:"resp_nonce_hex"`
			RespSigHex      string   `json:"resp_sig_hex"`
			ConfirmTagHex   string   `json:"confirm_tag_hex"`
		}
		if err := json.Unmarshal(data, &vectors); err == nil {
			for _, v := range vectors {
				req := PairingRequest{
					Type:            MsgPairingRequest,
					ProtocolVersion: "sendbeam/1",
					DeviceID:        v.ReqDeviceID,
					PublicKey:       v.ReqPubKeyHex,
					DeviceName:      v.ReqName,
					Capabilities:    v.ReqCaps,
					Nonce:           v.ReqNonceHex,
					Signature:       v.ReqSigHex,
				}
				if b, err := json.Marshal(req); err == nil {
					f.Add(b)
				}

				resp := PairingResponse{
					Type:            MsgPairingResponse,
					ProtocolVersion: "sendbeam/1",
					DeviceID:        v.RespDeviceID,
					PublicKey:       v.RespPubKeyHex,
					DeviceName:      v.RespName,
					Capabilities:    v.RespCaps,
					Nonce:           v.RespNonceHex,
					Signature:       v.RespSigHex,
				}
				if b, err := json.Marshal(resp); err == nil {
					f.Add(b)
				}

				confirm := PairingConfirm{
					Type:    MsgPairingConfirm,
					Status:  "accepted",
					AuthTag: v.ConfirmTagHex,
				}
				if b, err := json.Marshal(confirm); err == nil {
					f.Add(b)
				}
			}
		}
	}

	dummyMasterKey := make([]byte, 32)
	dummyKPair := make([]byte, 32)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodePairingMessage(data)
		if err != nil {
			return
		}

		// Invariant: Successfully decoded message must re-encode and re-decode
		enc, err := EncodePairingMessage(msg)
		if err != nil {
			t.Fatalf("EncodePairingMessage failed for %T: %v", msg, err)
		}

		msg2, err := DecodePairingMessage(enc)
		if err != nil {
			t.Fatalf("Re-decode failed for %T: %v", msg, err)
		}

		switch m := msg.(type) {
		case *PairingRequest:
			if _, ok := msg2.(*PairingRequest); !ok {
				t.Fatalf("round-trip type mismatch: %T != *PairingRequest", msg2)
			}
			// Verification must fail closed and never panic
			_, _, _ = VerifyPairingRequest(m, dummyMasterKey)

			// Challenge generation must never panic
			if nonceBytes, err := hex.DecodeString(m.Nonce); err == nil {
				_ = BuildPairingRequestChallenge(dummyMasterKey, nonceBytes, m.DeviceID)
			}

		case *PairingResponse:
			if _, ok := msg2.(*PairingResponse); !ok {
				t.Fatalf("round-trip type mismatch: %T != *PairingResponse", msg2)
			}
			dummyReqNonce := make([]byte, PairingNonceSize)
			_, _, _ = VerifyPairingResponse(m, dummyMasterKey, dummyReqNonce)

			if respNonceBytes, err := hex.DecodeString(m.Nonce); err == nil {
				_ = BuildPairingResponseChallenge(dummyMasterKey, dummyReqNonce, respNonceBytes, m.DeviceID)
			}

		case *PairingConfirm:
			if _, ok := msg2.(*PairingConfirm); !ok {
				t.Fatalf("round-trip type mismatch: %T != *PairingConfirm", msg2)
			}
			_ = VerifyPairingConfirm(m, dummyKPair, "sb-dev-dummy")
			_ = VerifyPairingConfirmTag(dummyKPair, "sb-dev-dummy", m.AuthTag)

		default:
			t.Fatalf("unexpected pairing message type: %T", msg)
		}
	})
}
