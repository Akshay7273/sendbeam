package wire_test

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/sendbeam/wire"
)

type diffRecord struct {
	Category string          `json:"category"`
	CaseID   string          `json:"case_id"`
	Seed     int64           `json:"seed"`
	Desc     string          `json:"desc"`
	Payload  json.RawMessage `json:"payload"`
}

func loadTSVectors(t *testing.T) []diffRecord {
	t.Helper()
	f, err := os.Open("testdata/diffgen-ts.jsonl")
	if err != nil {
		t.Fatalf("failed to open testdata/diffgen-ts.jsonl: %v", err)
	}
	defer func() { _ = f.Close() }()

	var records []diffRecord
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec diffRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("failed to parse jsonl line: %v", err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error reading diffgen-ts.jsonl: %v", err)
	}
	return records
}

func TestDifferential_TS_to_Go(t *testing.T) {
	records := loadTSVectors(t)
	if len(records) == 0 {
		t.Fatal("no TS differential records found")
	}

	byCat := make(map[string][]diffRecord)
	for _, r := range records {
		byCat[r.Category] = append(byCat[r.Category], r)
	}

	t.Run("frame_header", func(t *testing.T) {
		cases := byCat["frame_header"]
		if len(cases) == 0 {
			t.Fatal("no frame_header cases")
		}
		for _, c := range cases {
			var p struct {
				Header struct {
					Version  uint8  `json:"Version"`
					Type     uint8  `json:"Type"`
					Flags    uint8  `json:"Flags"`
					FileIdx  uint16 `json:"FileIdx"`
					BlockIdx uint32 `json:"BlockIdx"`
					FrameOff uint32 `json:"FrameOff"`
					Len      uint16 `json:"Len"`
				} `json:"header"`
				EncodedHex string `json:"encoded_hex"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}
			raw, err := hex.DecodeString(p.EncodedHex)
			if err != nil {
				t.Fatalf("%s (seed=%d): decode hex: %v", c.CaseID, c.Seed, err)
			}

			// 1. Decode TS bytes in Go
			h, err := wire.DecodeFrameHeader(raw)
			if err != nil {
				t.Fatalf("%s (seed=%d): DecodeFrameHeader failed: %v", c.CaseID, c.Seed, err)
			}
			if h.Version != p.Header.Version || h.Type != p.Header.Type || h.Flags != p.Header.Flags ||
				h.FileIdx != p.Header.FileIdx || h.BlockIdx != p.Header.BlockIdx ||
				h.FrameOff != p.Header.FrameOff || h.Len != p.Header.Len {
				t.Fatalf("%s (seed=%d): decoded header mismatch: got %+v, expected %+v", c.CaseID, c.Seed, h, p.Header)
			}

			// 2. Re-encode in Go and verify exact byte match with TS
			reEncoded := wire.EncodeFrameHeader(h)
			if hex.EncodeToString(reEncoded) != p.EncodedHex {
				t.Fatalf("%s (seed=%d): re-encoded hex mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(reEncoded), p.EncodedHex)
			}
		}
	})

	t.Run("padding", func(t *testing.T) {
		cases := byCat["padding"]
		if len(cases) == 0 {
			t.Fatal("no padding cases")
		}
		for _, c := range cases {
			var p struct {
				PlaintextHex string `json:"plaintext_hex"`
				BucketSize   int    `json:"bucket_size"`
				PaddedHex    string `json:"padded_hex"`
				Corrupted    bool   `json:"corrupted"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}
			plain, _ := hex.DecodeString(p.PlaintextHex)
			padded, _ := hex.DecodeString(p.PaddedHex)

			if p.Corrupted {
				_, err := wire.UnpadPayload(padded)
				if err == nil {
					t.Fatalf("%s (seed=%d): expected UnpadPayload to fail on corrupted input", c.CaseID, c.Seed)
				}
				continue
			}

			// 1. Bucket size matches
			if b := wire.PadBucketSize(len(plain)); b != p.BucketSize {
				t.Fatalf("%s (seed=%d): bucket size mismatch: got %d, expected %d", c.CaseID, c.Seed, b, p.BucketSize)
			}

			// 2. Padding matches
			goPadded, err := wire.PadPayload(plain)
			if err != nil {
				t.Fatalf("%s (seed=%d): PadPayload error: %v", c.CaseID, c.Seed, err)
			}
			if hex.EncodeToString(goPadded) != p.PaddedHex {
				t.Fatalf("%s (seed=%d): PadPayload hex mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(goPadded), p.PaddedHex)
			}

			// 3. Unpadding recovers original plaintext
			unpadded, err := wire.UnpadPayload(padded)
			if err != nil {
				t.Fatalf("%s (seed=%d): UnpadPayload error: %v", c.CaseID, c.Seed, err)
			}
			if hex.EncodeToString(unpadded) != p.PlaintextHex {
				t.Fatalf("%s (seed=%d): UnpadPayload mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(unpadded), p.PlaintextHex)
			}
		}
	})

	t.Run("control", func(t *testing.T) {
		cases := byCat["control"]
		if len(cases) == 0 {
			t.Fatal("no control cases")
		}
		for _, c := range cases {
			var p struct {
				MsgType    string          `json:"msg_type"`
				JSONStr    string          `json:"json_str"`
				EncodedHex string          `json:"encoded_hex"`
				Structured json.RawMessage `json:"structured"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}
			raw, _ := hex.DecodeString(p.EncodedHex)

			// 1. Decode TS JSON in Go
			msg, err := wire.DecodeControl(raw)
			if err != nil {
				t.Fatalf("%s (seed=%d): DecodeControl error: %v", c.CaseID, c.Seed, err)
			}

			// 2. Re-encode in Go
			goEncoded, err := wire.EncodeControl(msg)
			if err != nil {
				t.Fatalf("%s (seed=%d): EncodeControl error: %v", c.CaseID, c.Seed, err)
			}

			// 3. Compare JSON semantic equivalence
			var expectedObj, gotObj any
			if err := json.Unmarshal([]byte(p.JSONStr), &expectedObj); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal expected JSON: %v", c.CaseID, c.Seed, err)
			}
			if err := json.Unmarshal(goEncoded, &gotObj); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal got JSON: %v", c.CaseID, c.Seed, err)
			}
			if !reflect.DeepEqual(expectedObj, gotObj) {
				t.Fatalf("%s (seed=%d): JSON mismatch: expected %s, got %s", c.CaseID, c.Seed, p.JSONStr, string(goEncoded))
			}
		}
	})

	t.Run("revocation", func(t *testing.T) {
		cases := byCat["revocation"]
		if len(cases) == 0 {
			t.Fatal("no revocation cases")
		}
		for _, c := range cases {
			var p struct {
				RevokerID    string               `json:"revoker_id"`
				RevokedID    string               `json:"revoked_id"`
				Seq          uint64               `json:"seq"`
				Timestamp    string               `json:"timestamp"`
				ChallengeHex string               `json:"challenge_hex"`
				SignatureHex string               `json:"signature_hex"`
				PublicKeyHex string               `json:"public_key_hex"`
				Record       wire.RevocationRecord `json:"record"`
				Valid        bool                 `json:"valid"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}

			// 1. Challenge construction byte-for-byte matches
			chal := wire.BuildRevocationChallenge(p.RevokerID, p.RevokedID, p.Seq, p.Timestamp)
			if hex.EncodeToString(chal) != p.ChallengeHex {
				t.Fatalf("%s (seed=%d): challenge mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(chal), p.ChallengeHex)
			}

			// 2. Validate structural integrity
			if err := p.Record.Validate(); err != nil {
				t.Fatalf("%s (seed=%d): record.Validate() error: %v", c.CaseID, c.Seed, err)
			}

			// 3. Verify signature
			pub, _ := hex.DecodeString(p.PublicKeyHex)
			sig, _ := hex.DecodeString(p.SignatureHex)
			if !ed25519.Verify(pub, chal, sig) {
				t.Fatalf("%s (seed=%d): ed25519.Verify failed", c.CaseID, c.Seed)
			}
		}
	})

	t.Run("pairing", func(t *testing.T) {
		cases := byCat["pairing"]
		if len(cases) == 0 {
			t.Fatal("no pairing cases")
		}
		for _, c := range cases {
			var p struct {
				MasterKeyHex     string `json:"master_key_hex"`
				ReqNonceHex      string `json:"req_nonce_hex"`
				RespNonceHex     string `json:"resp_nonce_hex"`
				DeviceIDA        string `json:"device_id_a"`
				PubAHex          string `json:"pub_a_hex"`
				DeviceIDB        string `json:"device_id_b"`
				PubBHex          string `json:"pub_b_hex"`
				ReqChallengeHex  string `json:"req_challenge_hex"`
				RespChallengeHex string `json:"resp_challenge_hex"`
				KPairHex         string `json:"k_pair_hex"`
				CredRef          string `json:"cred_ref"`
				ConfirmPeerID    string `json:"confirm_peer_id"`
				ConfirmTagHex    string `json:"confirm_tag_hex"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}
			masterKey, _ := hex.DecodeString(p.MasterKeyHex)
			reqNonce, _ := hex.DecodeString(p.ReqNonceHex)
			respNonce, _ := hex.DecodeString(p.RespNonceHex)
			pubA, _ := hex.DecodeString(p.PubAHex)
			pubB, _ := hex.DecodeString(p.PubBHex)

			// 1. Request challenge
			reqChal := wire.BuildPairingRequestChallenge(masterKey, reqNonce, p.DeviceIDA)
			if hex.EncodeToString(reqChal) != p.ReqChallengeHex {
				t.Fatalf("%s (seed=%d): req challenge mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(reqChal), p.ReqChallengeHex)
			}

			// 2. Response challenge
			respChal := wire.BuildPairingResponseChallenge(masterKey, reqNonce, respNonce, p.DeviceIDB)
			if hex.EncodeToString(respChal) != p.RespChallengeHex {
				t.Fatalf("%s (seed=%d): resp challenge mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(respChal), p.RespChallengeHex)
			}

			// 3. Credential derivation
			kPair, credRef, err := wire.DerivePairCredential(masterKey, reqNonce, respNonce, pubA, pubB)
			if err != nil {
				t.Fatalf("%s (seed=%d): DerivePairCredential error: %v", c.CaseID, c.Seed, err)
			}
			if hex.EncodeToString(kPair) != p.KPairHex {
				t.Fatalf("%s (seed=%d): k_pair mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(kPair), p.KPairHex)
			}
			if credRef != p.CredRef {
				t.Fatalf("%s (seed=%d): cred_ref mismatch: got %s, expected %s", c.CaseID, c.Seed, credRef, p.CredRef)
			}

			// 4. Confirm tag
			tag := wire.ComputePairingConfirmTag(kPair, p.ConfirmPeerID)
			if tag != p.ConfirmTagHex {
				t.Fatalf("%s (seed=%d): confirm tag mismatch: got %s, expected %s", c.CaseID, c.Seed, tag, p.ConfirmTagHex)
			}
			if !wire.VerifyPairingConfirmTag(kPair, p.ConfirmPeerID, p.ConfirmTagHex) {
				t.Fatalf("%s (seed=%d): VerifyPairingConfirmTag failed", c.CaseID, c.Seed)
			}
		}
	})

	t.Run("trusted_auth", func(t *testing.T) {
		cases := byCat["trusted_auth"]
		if len(cases) == 0 {
			t.Fatal("no trusted_auth cases")
		}
		for _, c := range cases {
			var p struct {
				CapabilitiesA    []string `json:"capabilities_a"`
				CapabilitiesB    []string `json:"capabilities_b"`
				HashAHex         string   `json:"hash_a_hex"`
				HashBHex         string   `json:"hash_b_hex"`
				IntersectResult  []string `json:"intersect_result"`
				KPairHashHex     string   `json:"k_pair_hash_hex"`
				InitiatorID      string   `json:"initiator_id"`
				ResponderID      string   `json:"responder_id"`
				EphemeralPubHex  string   `json:"ephemeral_pub_hex"`
				NonceHex         string   `json:"nonce_hex"`
				EphemRespPubHex  string   `json:"ephem_resp_pub_hex"`
				NonceRespHex     string   `json:"nonce_resp_hex"`
				Timestamp        string   `json:"timestamp"`
				InitChallengeHex string   `json:"init_challenge_hex"`
				RespChallengeHex string   `json:"resp_challenge_hex"`
				ConfirmTagHex    string   `json:"confirm_tag_hex"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}

			// 1. Capability hashing
			hashA := wire.HashCapabilities(p.CapabilitiesA)
			if hex.EncodeToString(hashA) != p.HashAHex {
				t.Fatalf("%s (seed=%d): hashA mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(hashA), p.HashAHex)
			}

			// 2. Capability intersection
			intersect := wire.IntersectCapabilities(p.CapabilitiesA, p.CapabilitiesB)
			if !reflect.DeepEqual(intersect, p.IntersectResult) {
				t.Fatalf("%s (seed=%d): intersect mismatch: got %+v, expected %+v", c.CaseID, c.Seed, intersect, p.IntersectResult)
			}

			// 3. Challenges
			kPairHash, _ := hex.DecodeString(p.KPairHashHex)
			ephemInit, _ := hex.DecodeString(p.EphemeralPubHex)
			nonceInit, _ := hex.DecodeString(p.NonceHex)
			ephemResp, _ := hex.DecodeString(p.EphemRespPubHex)
			nonceResp, _ := hex.DecodeString(p.NonceRespHex)
			hashBBytes, _ := hex.DecodeString(p.HashBHex)

			initChal := wire.BuildTrustedInitChallenge(kPairHash, ephemInit, nonceInit, p.InitiatorID, p.ResponderID, hashA, p.Timestamp)
			if hex.EncodeToString(initChal) != p.InitChallengeHex {
				t.Fatalf("%s (seed=%d): init challenge mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(initChal), p.InitChallengeHex)
			}

			respChal := wire.BuildTrustedRespChallenge(kPairHash, ephemInit, ephemResp, nonceInit, nonceResp, p.InitiatorID, p.ResponderID, hashBBytes)
			if hex.EncodeToString(respChal) != p.RespChallengeHex {
				t.Fatalf("%s (seed=%d): resp challenge mismatch: got %s, expected %s", c.CaseID, c.Seed, hex.EncodeToString(respChal), p.RespChallengeHex)
			}
		}
	})

	t.Run("words", func(t *testing.T) {
		cases := byCat["words"]
		if len(cases) == 0 {
			t.Fatal("no words cases")
		}
		for _, c := range cases {
			var p struct {
				RawInput    string `json:"raw_input"`
				Normalized  string `json:"normalized"`
				IsValidCode bool   `json:"is_valid_code"`
				Room        int    `json:"room"`
				Words       string `json:"words"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}

			// 1. Normalization
			norm := wire.NormalizeCode(p.RawInput)
			if norm != p.Normalized {
				t.Fatalf("%s (seed=%d): NormalizeCode mismatch: got %s, expected %s", c.CaseID, c.Seed, norm, p.Normalized)
			}

			// 2. Parsing
			parsed, err := wire.ParseCode(p.RawInput)
			if p.IsValidCode {
				if err != nil {
					t.Fatalf("%s (seed=%d): ParseCode unexpected error: %v", c.CaseID, c.Seed, err)
				}
				if parsed.Room != p.Room || parsed.Words != p.Words {
					t.Fatalf("%s (seed=%d): ParseCode mismatch: got %+v, expected room=%d words=%s", c.CaseID, c.Seed, parsed, p.Room, p.Words)
				}
			} else {
				if err == nil {
					t.Fatalf("%s (seed=%d): expected ParseCode to error on invalid input %q", c.CaseID, c.Seed, p.RawInput)
				}
			}
		}
	})

	t.Run("safe_path", func(t *testing.T) {
		cases := byCat["safe_path"]
		if len(cases) == 0 {
			t.Fatal("no safe_path cases")
		}
		for _, c := range cases {
			var p struct {
				RawPath        string `json:"raw_path"`
				NormalizedPath string `json:"normalized_path"`
				IsValid        bool   `json:"is_valid"`
			}
			if err := json.Unmarshal(c.Payload, &p); err != nil {
				t.Fatalf("%s (seed=%d): unmarshal payload: %v", c.CaseID, c.Seed, err)
			}

			norm, err := wire.NormalizeTransferPath(p.RawPath)
			if p.IsValid {
				if err != nil {
					t.Fatalf("%s (seed=%d): NormalizeTransferPath unexpected error: %v", c.CaseID, c.Seed, err)
				}
				if norm != p.NormalizedPath {
					t.Fatalf("%s (seed=%d): NormalizeTransferPath mismatch: got %s, expected %s", c.CaseID, c.Seed, norm, p.NormalizedPath)
				}
			} else {
				if err == nil {
					t.Fatalf("%s (seed=%d): expected NormalizeTransferPath to error on %q", c.CaseID, c.Seed, p.RawPath)
				}
			}
		}
	})
}
