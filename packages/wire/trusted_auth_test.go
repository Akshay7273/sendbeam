package wire

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type TrustedSessionTestVector struct {
	Name             string   `json:"name"`
	KPairHex         string   `json:"k_pair_hex"`
	PairCredRef      string   `json:"pair_cred_ref"`
	InitSeedHex      string   `json:"init_seed_hex"`
	InitDeviceID     string   `json:"init_device_id"`
	InitPubKeyHex    string   `json:"init_pub_key_hex"`
	InitEphemPubHex  string   `json:"init_ephem_pub_hex"`
	InitNonceHex     string   `json:"init_nonce_hex"`
	InitCaps         []string `json:"init_caps"`
	InitTimestamp    string   `json:"init_timestamp"`
	InitSigHex       string   `json:"init_sig_hex"`
	InitAuthTagHex   string   `json:"init_auth_tag_hex"`
	RespSeedHex      string   `json:"resp_seed_hex"`
	RespDeviceID     string   `json:"resp_device_id"`
	RespPubKeyHex    string   `json:"resp_pub_key_hex"`
	RespEphemPubHex  string   `json:"resp_ephem_pub_hex"`
	RespNonceHex     string   `json:"resp_nonce_hex"`
	RespCaps         []string `json:"resp_caps"`
	RespSigHex       string   `json:"resp_sig_hex"`
	RespAuthTagHex   string   `json:"resp_auth_tag_hex"`
	SessionMasterHex string   `json:"session_master_hex"`
	I2RKeyHex        string   `json:"i2r_key_hex"`
	R2IKeyHex        string   `json:"r2i_key_hex"`
	InitConfirmTag   string   `json:"init_confirm_tag"`
	RespConfirmTag   string   `json:"resp_confirm_tag"`
}

func TestTrustedAuthEndToEnd(t *testing.T) {
	seedA := sha256.Sum256([]byte("seed-device-alice-trusted-v15"))
	seedB := sha256.Sum256([]byte("seed-device-bob-trusted-v15"))
	kPair := sha256.Sum256([]byte("shared-k-pair-secret-alice-bob"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	privA := ed25519.NewKeyFromSeed(seedA[:])
	pubA := privA.Public().(ed25519.PublicKey)
	idA, err := NewDeviceIdentity(pubA, privA)
	if err != nil {
		t.Fatalf("NewDeviceIdentity A: %v", err)
	}

	privB := ed25519.NewKeyFromSeed(seedB[:])
	pubB := privB.Public().(ed25519.PublicKey)
	idB, err := NewDeviceIdentity(pubB, privB)
	if err != nil {
		t.Fatalf("NewDeviceIdentity B: %v", err)
	}

	fixedTime, _ := time.Parse(time.RFC3339, "2026-08-21T12:00:00Z")

	ephemPubA := sha256.Sum256([]byte("ephem-alice-fixed-1"))
	nonceA := sha256.Sum256([]byte("nonce-alice-fixed-1"))

	ephemPubB := sha256.Sum256([]byte("ephem-bob-fixed-2"))
	nonceB := sha256.Sum256([]byte("nonce-bob-fixed-2"))

	capsA := []string{"transfer.v1", "transfer.v2", "auto_accept"}
	capsB := []string{"transfer.v1", "transfer.v2", "lan_direct"}

	// Alice creates TrustedAuthInit
	initMsg, err := NewTrustedAuthInit(idA, idB.DeviceID, credRef, kPair[:], capsA, ephemPubA[:], nonceA[:], fixedTime)
	if err != nil {
		t.Fatalf("NewTrustedAuthInit: %v", err)
	}

	// Bob verifies TrustedAuthInit
	ephemAVerified, nonceAVerified, err := VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, fixedTime)
	if err != nil {
		t.Fatalf("VerifyTrustedAuthInit: %v", err)
	}
	if hex.EncodeToString(ephemAVerified) != hex.EncodeToString(ephemPubA[:]) {
		t.Errorf("ephem A mismatch")
	}

	// Bob creates TrustedAuthResponse
	respMsg, err := NewTrustedAuthResponse(idB, initMsg, kPair[:], capsB, ephemPubB[:], nonceB[:])
	if err != nil {
		t.Fatalf("NewTrustedAuthResponse: %v", err)
	}

	// Alice verifies TrustedAuthResponse
	ephemBVerified, nonceBVerified, err := VerifyTrustedAuthResponse(respMsg, initMsg, kPair[:], idB.PublicKey, idA.DeviceID)
	if err != nil {
		t.Fatalf("VerifyTrustedAuthResponse: %v", err)
	}
	if hex.EncodeToString(ephemBVerified) != hex.EncodeToString(ephemPubB[:]) {
		t.Errorf("ephem B mismatch")
	}

	// Both derive directional session keys
	keysAlice, err := DeriveTrustedSessionKeys(kPair[:], ephemPubA[:], ephemBVerified, nonceA[:], nonceBVerified, idA.DeviceID, idB.DeviceID, capsA, respMsg.Capabilities)
	if err != nil {
		t.Fatalf("DeriveTrustedSessionKeys Alice: %v", err)
	}

	keysBob, err := DeriveTrustedSessionKeys(kPair[:], ephemAVerified, ephemPubB[:], nonceAVerified, nonceB[:], initMsg.InitiatorDeviceID, idB.DeviceID, initMsg.Capabilities, capsB)
	if err != nil {
		t.Fatalf("DeriveTrustedSessionKeys Bob: %v", err)
	}

	if hex.EncodeToString(keysAlice.SessionMaster) != hex.EncodeToString(keysBob.SessionMaster) {
		t.Errorf("SessionMaster mismatch")
	}
	if hex.EncodeToString(keysAlice.InitiatorToResponderKey) != hex.EncodeToString(keysBob.InitiatorToResponderKey) {
		t.Errorf("I2RKey mismatch")
	}
	if hex.EncodeToString(keysAlice.ResponderToInitiatorKey) != hex.EncodeToString(keysBob.ResponderToInitiatorKey) {
		t.Errorf("R2IKey mismatch")
	}

	// Confirmation handshake
	confirmAlice := NewTrustedAuthConfirm(keysAlice.SessionMaster, DomainTrustedConfirmInit, idA.DeviceID, true)
	if err := VerifyTrustedAuthConfirm(confirmAlice, keysBob.SessionMaster, DomainTrustedConfirmInit, idA.DeviceID); err != nil {
		t.Errorf("Bob failed to verify Alice confirm: %v", err)
	}

	confirmBob := NewTrustedAuthConfirm(keysBob.SessionMaster, DomainTrustedConfirmResp, idB.DeviceID, true)
	if err := VerifyTrustedAuthConfirm(confirmBob, keysAlice.SessionMaster, DomainTrustedConfirmResp, idB.DeviceID); err != nil {
		t.Errorf("Alice failed to verify Bob confirm: %v", err)
	}

	// Generate deterministic test vector
	vector := TrustedSessionTestVector{
		Name:             "alice_bob_trusted_session",
		KPairHex:         hex.EncodeToString(kPair[:]),
		PairCredRef:      credRef,
		InitSeedHex:      hex.EncodeToString(seedA[:]),
		InitDeviceID:     idA.DeviceID,
		InitPubKeyHex:    hex.EncodeToString(idA.PublicKey),
		InitEphemPubHex:  hex.EncodeToString(ephemPubA[:]),
		InitNonceHex:     hex.EncodeToString(nonceA[:]),
		InitCaps:         capsA,
		InitTimestamp:    initMsg.Timestamp,
		InitSigHex:       initMsg.Signature,
		InitAuthTagHex:   initMsg.AuthTag,
		RespSeedHex:      hex.EncodeToString(seedB[:]),
		RespDeviceID:     idB.DeviceID,
		RespPubKeyHex:    hex.EncodeToString(idB.PublicKey),
		RespEphemPubHex:  hex.EncodeToString(ephemPubB[:]),
		RespNonceHex:     hex.EncodeToString(nonceB[:]),
		RespCaps:         capsB,
		RespSigHex:       respMsg.Signature,
		RespAuthTagHex:   respMsg.AuthTag,
		SessionMasterHex: hex.EncodeToString(keysAlice.SessionMaster),
		I2RKeyHex:        hex.EncodeToString(keysAlice.InitiatorToResponderKey),
		R2IKeyHex:        hex.EncodeToString(keysAlice.ResponderToInitiatorKey),
		InitConfirmTag:   confirmAlice.AuthTag,
		RespConfirmTag:   confirmBob.AuthTag,
	}

	vecData, err := json.MarshalIndent([]TrustedSessionTestVector{vector}, "", "  ")
	if err != nil {
		t.Fatalf("marshal test vector: %v", err)
	}

	targetPath := filepath.Join("testdata", "trusted-session-vectors.json")
	if err := os.WriteFile(targetPath, vecData, 0644); err != nil {
		t.Fatalf("write trusted-session-vectors.json: %v", err)
	}
}

func TestTrustedAuthAdversarialRejections(t *testing.T) {
	seedA := sha256.Sum256([]byte("seed-device-alice-adv-t"))
	seedB := sha256.Sum256([]byte("seed-device-bob-adv-t"))
	kPair := sha256.Sum256([]byte("k-pair-adv-shared"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	privB := ed25519.NewKeyFromSeed(seedB[:])
	idA, _ := NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	idB, _ := NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)

	now := time.Now().UTC()
	initMsg, _ := NewTrustedAuthInit(idA, idB.DeviceID, "cred-ref", kPair[:], []string{"transfer.v1"}, nil, nil, now)

	// 1. Clock skew > 5 minutes
	expiredTime := now.Add(-10 * time.Minute)
	if _, _, err := VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, expiredTime); !errors.Is(err, ErrTrustedTimestampSkew) {
		t.Errorf("expected ErrTrustedTimestampSkew, got %v", err)
	}

	// 2. Peer mismatch
	if _, _, err := VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, "sb-dev-wrong", now); !errors.Is(err, ErrTrustedPeerMismatch) {
		t.Errorf("expected ErrTrustedPeerMismatch on wrong responder, got %v", err)
	}

	// 3. Forged signature
	tamperedSig := *initMsg
	tamperedSig.Signature = hex.EncodeToString(make([]byte, 64))
	if _, _, err := VerifyTrustedAuthInit(&tamperedSig, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed, got %v", err)
	}

	// 4. Wrong k_pair fails signature challenge binding
	wrongKPair := sha256.Sum256([]byte("rogue-k-pair"))
	if _, _, err := VerifyTrustedAuthInit(initMsg, wrongKPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed on wrong k_pair, got %v", err)
	}

	// 5. Tampered AuthTag
	tamperedMAC := *initMsg
	tamperedMAC.AuthTag = hex.EncodeToString(make([]byte, 32))
	if _, _, err := VerifyTrustedAuthInit(&tamperedMAC, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedMACTagFailed) {
		t.Errorf("expected ErrTrustedMACTagFailed, got %v", err)
	}

	// 6. Revoked status in response
	respRevoked := &TrustedAuthResponse{
		Type:              MsgTrustedAuthResponse,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		Status:            "revoked",
		ResponderDeviceID: idB.DeviceID,
	}
	if _, _, err := VerifyTrustedAuthResponse(respRevoked, initMsg, kPair[:], idB.PublicKey, idA.DeviceID); !errors.Is(err, ErrTrustedPeerRevoked) {
		t.Errorf("expected ErrTrustedPeerRevoked, got %v", err)
	}
}

func TestTrustedAuthCodec(t *testing.T) {
	init := &TrustedAuthInit{
		Type:              MsgTrustedAuthInit,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		InitiatorDeviceID: "sb-dev-1111",
		ResponderDeviceID: "sb-dev-2222",
		PairCredentialRef: "cred-1234",
		EphemeralPub:      hex.EncodeToString(make([]byte, 32)),
		Nonce:             hex.EncodeToString(make([]byte, 32)),
		Capabilities:      []string{"transfer.v1"},
		Timestamp:         "2026-08-21T12:00:00Z",
		Signature:         hex.EncodeToString(make([]byte, 64)),
		AuthTag:           hex.EncodeToString(make([]byte, 32)),
	}

	data, err := EncodeTrustedAuthMessage(init)
	if err != nil {
		t.Fatalf("EncodeTrustedAuthMessage: %v", err)
	}

	decoded, err := DecodeTrustedAuthMessage(data)
	if err != nil {
		t.Fatalf("DecodeTrustedAuthMessage: %v", err)
	}

	initDecoded, ok := decoded.(*TrustedAuthInit)
	if !ok {
		t.Fatalf("expected *TrustedAuthInit, got %T", decoded)
	}
	if initDecoded.InitiatorDeviceID != init.InitiatorDeviceID {
		t.Errorf("initiator device id mismatch")
	}
}

type TrustedSessionV3TestVector struct {
	Name                string   `json:"name"`
	ProtocolVersion     string   `json:"protocol_version"`
	KPairHex            string   `json:"k_pair_hex"`
	PairCredRef         string   `json:"pair_cred_ref"`
	InitSeedHex         string   `json:"init_seed_hex"`
	InitDeviceID        string   `json:"init_device_id"`
	InitPubKeyHex       string   `json:"init_pub_key_hex"`
	InitEphemPrivHex    string   `json:"init_ephem_priv_hex"`
	InitEphemPubHex     string   `json:"init_ephem_pub_hex"`
	InitNonceHex        string   `json:"init_nonce_hex"`
	InitCaps            []string `json:"init_caps"`
	InitTimestamp       string   `json:"init_timestamp"`
	InitSigHex          string   `json:"init_sig_hex"`
	InitAuthTagHex      string   `json:"init_auth_tag_hex"`
	RespSeedHex         string   `json:"resp_seed_hex"`
	RespDeviceID        string   `json:"resp_device_id"`
	RespPubKeyHex       string   `json:"resp_pub_key_hex"`
	RespEphemPrivHex    string   `json:"resp_ephem_priv_hex"`
	RespEphemPubHex     string   `json:"resp_ephem_pub_hex"`
	RespNonceHex        string   `json:"resp_nonce_hex"`
	RespCaps            []string `json:"resp_caps"`
	RespSigHex          string   `json:"resp_sig_hex"`
	RespAuthTagHex      string   `json:"resp_auth_tag_hex"`
	ECDHSharedSecretHex string   `json:"ecdh_shared_secret_hex"`
	SessionMasterHex    string   `json:"session_master_hex"`
	I2RKeyHex           string   `json:"i2r_key_hex"`
	R2IKeyHex           string   `json:"r2i_key_hex"`
	InitConfirmTag      string   `json:"init_confirm_tag"`
	RespConfirmTag      string   `json:"resp_confirm_tag"`
}

func TestTrustedAuthV3_Vectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "trusted-session-v3-vectors.json"))
	if err != nil {
		t.Fatalf("read test vector file: %v", err)
	}

	var vectors []TrustedSessionV3TestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}

	curve := ecdh.X25519()

	for _, vec := range vectors {
		t.Run(vec.Name, func(t *testing.T) {
			kPair, _ := hex.DecodeString(vec.KPairHex)
			initSeed, _ := hex.DecodeString(vec.InitSeedHex)
			respSeed, _ := hex.DecodeString(vec.RespSeedHex)
			initPriv := ed25519.NewKeyFromSeed(initSeed)
			respPriv := ed25519.NewKeyFromSeed(respSeed)
			initPub := initPriv.Public().(ed25519.PublicKey)
			respPub := respPriv.Public().(ed25519.PublicKey)

			initID, _ := NewDeviceIdentity(initPub, initPriv)
			respID, _ := NewDeviceIdentity(respPub, respPriv)

			initEphemPrivBytes, _ := hex.DecodeString(vec.InitEphemPrivHex)
			initEphemPriv, err := curve.NewPrivateKey(initEphemPrivBytes)
			if err != nil {
				t.Fatalf("init ephem priv: %v", err)
			}
			initEphemPub := initEphemPriv.PublicKey().Bytes()
			if hex.EncodeToString(initEphemPub) != vec.InitEphemPubHex {
				t.Errorf("init ephem pub mismatch: got %s, want %s", hex.EncodeToString(initEphemPub), vec.InitEphemPubHex)
			}

			respEphemPrivBytes, _ := hex.DecodeString(vec.RespEphemPrivHex)
			respEphemPriv, err := curve.NewPrivateKey(respEphemPrivBytes)
			if err != nil {
				t.Fatalf("resp ephem priv: %v", err)
			}
			respEphemPub := respEphemPriv.PublicKey().Bytes()
			if hex.EncodeToString(respEphemPub) != vec.RespEphemPubHex {
				t.Errorf("resp ephem pub mismatch: got %s, want %s", hex.EncodeToString(respEphemPub), vec.RespEphemPubHex)
			}

			initNonce, _ := hex.DecodeString(vec.InitNonceHex)
			respNonce, _ := hex.DecodeString(vec.RespNonceHex)
			ts, _ := time.Parse(time.RFC3339, vec.InitTimestamp)

			// 1. Create and verify Init
			initMsg, err := NewTrustedAuthInitV3(initID, respID.DeviceID, vec.PairCredRef, kPair, vec.InitCaps, initEphemPub, initNonce, ts, nil)
			if err != nil {
				t.Fatalf("NewTrustedAuthInitV3: %v", err)
			}
			if initMsg.Signature != vec.InitSigHex {
				t.Errorf("Init signature mismatch: got %s, want %s", initMsg.Signature, vec.InitSigHex)
			}
			if initMsg.AuthTag != vec.InitAuthTagHex {
				t.Errorf("Init auth tag mismatch: got %s, want %s", initMsg.AuthTag, vec.InitAuthTagHex)
			}

			verEphemInit, verNonceInit, err := VerifyTrustedAuthInitV3(initMsg, kPair, initPub, respID.DeviceID, ts)
			if err != nil {
				t.Fatalf("VerifyTrustedAuthInitV3: %v", err)
			}
			if hex.EncodeToString(verEphemInit) != vec.InitEphemPubHex {
				t.Errorf("verified ephem init mismatch")
			}
			if hex.EncodeToString(verNonceInit) != vec.InitNonceHex {
				t.Errorf("verified nonce init mismatch")
			}

			// 2. Create and verify Response
			respMsg, err := NewTrustedAuthResponseV3(respID, initMsg, kPair, vec.RespCaps, respEphemPub, respNonce, nil)
			if err != nil {
				t.Fatalf("NewTrustedAuthResponseV3: %v", err)
			}
			if respMsg.Signature != vec.RespSigHex {
				t.Errorf("Resp signature mismatch: got %s, want %s", respMsg.Signature, vec.RespSigHex)
			}
			if respMsg.AuthTag != vec.RespAuthTagHex {
				t.Errorf("Resp auth tag mismatch: got %s, want %s", respMsg.AuthTag, vec.RespAuthTagHex)
			}

			verEphemResp, verNonceResp, err := VerifyTrustedAuthResponseV3(respMsg, initMsg, kPair, respPub, initID.DeviceID)
			if err != nil {
				t.Fatalf("VerifyTrustedAuthResponseV3: %v", err)
			}
			if hex.EncodeToString(verEphemResp) != vec.RespEphemPubHex {
				t.Errorf("verified ephem resp mismatch")
			}
			if hex.EncodeToString(verNonceResp) != vec.RespNonceHex {
				t.Errorf("verified nonce resp mismatch")
			}

			// 3. ECDH shared secret
			ssA, err := ComputeX25519SharedSecret(initEphemPriv, verEphemResp)
			if err != nil {
				t.Fatalf("ComputeX25519SharedSecret A: %v", err)
			}
			ssB, err := ComputeX25519SharedSecret(respEphemPriv, verEphemInit)
			if err != nil {
				t.Fatalf("ComputeX25519SharedSecret B: %v", err)
			}
			if hex.EncodeToString(ssA) != vec.ECDHSharedSecretHex {
				t.Errorf("ssA mismatch: got %s, want %s", hex.EncodeToString(ssA), vec.ECDHSharedSecretHex)
			}
			if hex.EncodeToString(ssB) != vec.ECDHSharedSecretHex {
				t.Errorf("ssB mismatch: got %s, want %s", hex.EncodeToString(ssB), vec.ECDHSharedSecretHex)
			}

			// 4. Derive keys
			keysA, err := DeriveTrustedSessionKeysV3(kPair, ssA, initEphemPub, verEphemResp, initNonce, verNonceResp, initID.DeviceID, respID.DeviceID, vec.InitCaps, respMsg.Capabilities)
			if err != nil {
				t.Fatalf("DeriveTrustedSessionKeysV3 A: %v", err)
			}
			keysB, err := DeriveTrustedSessionKeysV3(kPair, ssB, verEphemInit, respEphemPub, verNonceInit, respNonce, initMsg.InitiatorDeviceID, respID.DeviceID, initMsg.Capabilities, vec.RespCaps)
			if err != nil {
				t.Fatalf("DeriveTrustedSessionKeysV3 B: %v", err)
			}

			if hex.EncodeToString(keysA.SessionMaster) != vec.SessionMasterHex {
				t.Errorf("SessionMaster mismatch: got %s, want %s", hex.EncodeToString(keysA.SessionMaster), vec.SessionMasterHex)
			}
			if hex.EncodeToString(keysB.SessionMaster) != vec.SessionMasterHex {
				t.Errorf("SessionMaster B mismatch")
			}
			if hex.EncodeToString(keysA.InitiatorToResponderKey) != vec.I2RKeyHex {
				t.Errorf("I2R mismatch: got %s, want %s", hex.EncodeToString(keysA.InitiatorToResponderKey), vec.I2RKeyHex)
			}
			if hex.EncodeToString(keysA.ResponderToInitiatorKey) != vec.R2IKeyHex {
				t.Errorf("R2I mismatch: got %s, want %s", hex.EncodeToString(keysA.ResponderToInitiatorKey), vec.R2IKeyHex)
			}

			// 5. Confirm tags
			confA := NewTrustedAuthConfirmV3(keysA.SessionMaster, DomainTrustedConfirmInit3, initID.DeviceID, true)
			if confA.AuthTag != vec.InitConfirmTag {
				t.Errorf("confA tag mismatch: got %s, want %s", confA.AuthTag, vec.InitConfirmTag)
			}
			if err := VerifyTrustedAuthConfirmV3(confA, keysB.SessionMaster, DomainTrustedConfirmInit3, initID.DeviceID); err != nil {
				t.Errorf("Verify confirm A failed: %v", err)
			}

			confB := NewTrustedAuthConfirmV3(keysB.SessionMaster, DomainTrustedConfirmResp3, respID.DeviceID, true)
			if confB.AuthTag != vec.RespConfirmTag {
				t.Errorf("confB tag mismatch: got %s, want %s", confB.AuthTag, vec.RespConfirmTag)
			}
			if err := VerifyTrustedAuthConfirmV3(confB, keysA.SessionMaster, DomainTrustedConfirmResp3, respID.DeviceID); err != nil {
				t.Errorf("Verify confirm B failed: %v", err)
			}
		})
	}
}

func TestTrustedAuthV3_DowngradeRejection(t *testing.T) {
	seedA := sha256.Sum256([]byte("seed-device-alice-downgrade"))
	seedB := sha256.Sum256([]byte("seed-device-bob-downgrade"))
	kPair := sha256.Sum256([]byte("k-pair-downgrade"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	privB := ed25519.NewKeyFromSeed(seedB[:])
	idA, _ := NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	idB, _ := NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)

	now := time.Now().UTC()

	// 1. Initiator sends sendbeam/2 to sendbeam/3 verifier -> ErrProtocolDowngradeForbidden
	initV2, _ := NewTrustedAuthInit(idA, idB.DeviceID, "cred-ref", kPair[:], []string{"transfer.v1"}, nil, nil, now)
	if _, _, err := VerifyTrustedAuthInitV3(initV2, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrProtocolDowngradeForbidden) {
		t.Errorf("expected ErrProtocolDowngradeForbidden on v2 init, got %v", err)
	}

	// 1b. Initiator sends sendbeam/1 -> ErrProtocolDowngradeForbidden
	initV1 := *initV2
	initV1.ProtocolVersion = "sendbeam/1"
	if _, _, err := VerifyTrustedAuthInitV3(&initV1, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrProtocolDowngradeForbidden) {
		t.Errorf("expected ErrProtocolDowngradeForbidden on v1 init, got %v", err)
	}

	// 2. Responder sends sendbeam/2 response to sendbeam/3 initiator -> ErrProtocolDowngradeForbidden
	_, pubEphemA, _ := GenerateX25519KeyPair()
	initV3, _ := NewTrustedAuthInitV3(idA, idB.DeviceID, "cred-ref", kPair[:], []string{"transfer.v1"}, pubEphemA, make([]byte, 32), now, nil)

	respV2 := &TrustedAuthResponse{
		Type:              MsgTrustedAuthResponse,
		ProtocolVersion:   "sendbeam/2",
		Status:            "accepted",
		ResponderDeviceID: idB.DeviceID,
	}
	if _, _, err := VerifyTrustedAuthResponseV3(respV2, initV3, kPair[:], idB.PublicKey, idA.DeviceID); !errors.Is(err, ErrProtocolDowngradeForbidden) {
		t.Errorf("expected ErrProtocolDowngradeForbidden on v2 response, got %v", err)
	}
}

func TestTrustedAuthV3_WeakEphemeralKeys(t *testing.T) {
	priv, _, _ := GenerateX25519KeyPair()

	// 1. Invalid key size
	if _, err := ComputeX25519SharedSecret(priv, make([]byte, 31)); !errors.Is(err, ErrWeakEphemeralKey) {
		t.Errorf("expected ErrWeakEphemeralKey on 31 bytes, got %v", err)
	}
	if _, err := ComputeX25519SharedSecret(priv, make([]byte, 33)); !errors.Is(err, ErrWeakEphemeralKey) {
		t.Errorf("expected ErrWeakEphemeralKey on 33 bytes, got %v", err)
	}

	// 2. Low-order points (all zero or known weak points)
	allZeros := make([]byte, 32)
	if _, err := ComputeX25519SharedSecret(priv, allZeros); !errors.Is(err, ErrWeakEphemeralKey) {
		t.Errorf("expected ErrWeakEphemeralKey on all zeros, got %v", err)
	}

	// Point 1 (order 1)
	point1 := make([]byte, 32)
	point1[0] = 1
	if _, err := ComputeX25519SharedSecret(priv, point1); !errors.Is(err, ErrWeakEphemeralKey) {
		t.Errorf("expected ErrWeakEphemeralKey on point 1, got %v", err)
	}
}

func TestTrustedAuthV3_ReplayProtection(t *testing.T) {
	cache := NewNonceReplayCache(5 * time.Minute)
	now := time.Now().UTC()
	devID := "sb-dev-alice123"
	nonceHex := "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"

	// First time: succeeds
	if err := cache.CheckAndRecord(devID, nonceHex, now); err != nil {
		t.Fatalf("first check failed: %v", err)
	}

	// Immediate replay: ErrSessionReplayDetected
	if err := cache.CheckAndRecord(devID, nonceHex, now.Add(10*time.Second)); !errors.Is(err, ErrSessionReplayDetected) {
		t.Errorf("expected ErrSessionReplayDetected, got %v", err)
	}

	// Different device with same nonce: succeeds
	if err := cache.CheckAndRecord("sb-dev-bob456", nonceHex, now); err != nil {
		t.Errorf("different device check failed: %v", err)
	}

	// Same device with different nonce: succeeds
	diffNonce := "112233445566778899aabbccdd00112233445566778899aabbccdd0011223344"
	if err := cache.CheckAndRecord(devID, diffNonce, now); err != nil {
		t.Errorf("different nonce check failed: %v", err)
	}

	// After TTL expires (6 minutes later): succeeds
	if err := cache.CheckAndRecord(devID, nonceHex, now.Add(6*time.Minute)); err != nil {
		t.Errorf("check after TTL failed: %v", err)
	}
}

func TestTrustedAuthV3_AdversarialTampering(t *testing.T) {
	seedA := sha256.Sum256([]byte("seed-device-alice-v3-adv"))
	seedB := sha256.Sum256([]byte("seed-device-bob-v3-adv"))
	kPair := sha256.Sum256([]byte("k-pair-v3-adv-shared"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	privB := ed25519.NewKeyFromSeed(seedB[:])
	idA, _ := NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	idB, _ := NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)

	now := time.Now().UTC()
	_, ephemPubA, _ := GenerateX25519KeyPair()
	nonceA := make([]byte, 32)
	nonceA[0] = 42

	initMsg, _ := NewTrustedAuthInitV3(idA, idB.DeviceID, "cred-ref", kPair[:], []string{"transfer.v2", "mesh_sync"}, ephemPubA, nonceA, now, nil)

	// 1. Clock skew > 5 minutes
	expiredTime := now.Add(-10 * time.Minute)
	if _, _, err := VerifyTrustedAuthInitV3(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, expiredTime); !errors.Is(err, ErrTrustedTimestampSkew) {
		t.Errorf("expected ErrTrustedTimestampSkew, got %v", err)
	}

	// 2. Peer mismatch
	if _, _, err := VerifyTrustedAuthInitV3(initMsg, kPair[:], idA.PublicKey, "sb-dev-wrong", now); !errors.Is(err, ErrTrustedPeerMismatch) {
		t.Errorf("expected ErrTrustedPeerMismatch on wrong responder, got %v", err)
	}

	// 3. Forged signature
	tamperedSig := *initMsg
	tamperedSig.Signature = hex.EncodeToString(make([]byte, 64))
	if _, _, err := VerifyTrustedAuthInitV3(&tamperedSig, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed, got %v", err)
	}

	// 4. Tampered AuthTag
	tamperedMAC := *initMsg
	tamperedMAC.AuthTag = hex.EncodeToString(make([]byte, 32))
	if _, _, err := VerifyTrustedAuthInitV3(&tamperedMAC, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedMACTagFailed) {
		t.Errorf("expected ErrTrustedMACTagFailed, got %v", err)
	}

	// 5. Capability tampering in init
	tamperedCaps := *initMsg
	tamperedCaps.Capabilities = []string{"transfer.v2", "malicious_cap"}
	if _, _, err := VerifyTrustedAuthInitV3(&tamperedCaps, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed on tampered capabilities, got %v", err)
	}

	// 6. Ephemeral pub tampering in init
	tamperedEphem := *initMsg
	_, anotherPub, _ := GenerateX25519KeyPair()
	tamperedEphem.EphemeralPub = hex.EncodeToString(anotherPub)
	if _, _, err := VerifyTrustedAuthInitV3(&tamperedEphem, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed on tampered ephemeral pub, got %v", err)
	}

	// 7. Responder creates response, adversary tampers response capabilities
	_, ephemPubB, _ := GenerateX25519KeyPair()
	nonceB := make([]byte, 32)
	nonceB[0] = 99
	respMsg, _ := NewTrustedAuthResponseV3(idB, initMsg, kPair[:], []string{"transfer.v2", "mesh_sync"}, ephemPubB, nonceB, nil)

	tamperedRespCaps := *respMsg
	tamperedRespCaps.Capabilities = []string{"transfer.v2"}
	if _, _, err := VerifyTrustedAuthResponseV3(&tamperedRespCaps, initMsg, kPair[:], idB.PublicKey, idA.DeviceID); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed on tampered response capabilities, got %v", err)
	}
}

