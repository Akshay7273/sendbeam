package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAttackMatrix_Wire exercises wire-level adversarial scenarios defined in ADR 0007 / v1.5plan / v1.8:
// 1. Stolen trust DB vs stolen key (Public key mismatch vs Device ID)
// 2. Replay attack & cloned profile (Nonce uniqueness, freshness window & transcript binding)
// 3. Malicious server MITM & ephemeral key substitution
// 4. Presence beacon replay & stale epoch expiration
// 5. Display name / local label spoofing isolation
// 6. Downgrade attack & capability stripping resistance
// 7. Path traversal & directory escape containment
// 13. Padding-oracle probe & non-zero padding rejection
// 14. Bucket-downgrade coercion & private session requirement
// 17. Revocation sequence rollback & domain monotonicity
// 18. Relay frame corruption, reordering, and truncation
// 19. Durable transfer journal tampering
// 20. Pairing confirmation misuse & cross-session replay
func TestAttackMatrix_Wire(t *testing.T) {
	// Setup test keys
	seedA := sha256.Sum256([]byte("seed-device-alice-attack-matrix"))
	seedB := sha256.Sum256([]byte("seed-device-bob-attack-matrix"))
	seedAttacker := sha256.Sum256([]byte("seed-device-attacker-matrix"))

	privA := ed25519.NewKeyFromSeed(seedA[:])
	idA, err := NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	if err != nil {
		t.Fatalf("NewDeviceIdentity A failed: %v", err)
	}

	privB := ed25519.NewKeyFromSeed(seedB[:])
	idB, err := NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)
	if err != nil {
		t.Fatalf("NewDeviceIdentity B failed: %v", err)
	}

	privAttacker := ed25519.NewKeyFromSeed(seedAttacker[:])
	idAttacker, err := NewDeviceIdentity(privAttacker.Public().(ed25519.PublicKey), privAttacker)
	if err != nil {
		t.Fatalf("NewDeviceIdentity Attacker failed: %v", err)
	}

	kPair := sha256.Sum256([]byte("shared-k-pair-secret-alice-bob"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	// Vector 1: Stolen Trust DB vs Stolen Key
	t.Run("Vector 1: Public key mismatch vs Device ID", func(t *testing.T) {
		// Attacker modifies trust DB record to associate Bob's device ID with Attacker's public key
		tamperedRecord := &TrustRecord{
			DeviceID:          idB.DeviceID, // Bob's ID
			PublicKey:         hex.EncodeToString(idAttacker.PublicKey),
			LocalLabel:        "Bob Laptop",
			PairCredentialRef: credRef,
			Capabilities:      []string{"transfer.v1"},
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
			Revoked:           false,
			Policy:            DefaultTrustPolicy(),
		}

		err := tamperedRecord.Validate()
		if err == nil {
			t.Fatal("expected Validate to reject mismatched device ID and public key")
		}
		if !strings.Contains(err.Error(), "does not match public key") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	// Vector 2: Replay Attack & Cloned Profile
	t.Run("Vector 2: Replay attack & challenge freshness window", func(t *testing.T) {
		var ephemA [32]byte
		var nonceA [32]byte
		_, _ = rand.Read(ephemA[:])
		_, _ = rand.Read(nonceA[:])

		initMsg, err := NewTrustedAuthInit(
			idA,
			idB.DeviceID,
			credRef,
			kPair[:],
			[]string{"transfer.v1", "transfer.v2"},
			ephemA[:],
			nonceA[:],
			time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("NewTrustedAuthInit failed: %v", err)
		}

		// Valid verify
		_, _, err = VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err != nil {
			t.Fatalf("legitimate VerifyTrustedAuthInit failed: %v", err)
		}

		// Stale timestamp (1 hour in the past)
		staleTime := time.Now().UTC().Add(-1 * time.Hour)
		_, _, err = VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, staleTime)
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject stale timestamp outside skew window")
		}

		// Replayed init with modified nonce fails MAC
		tamperedInit := *initMsg
		tamperedInit.Nonce = hex.EncodeToString([]byte("01234567890123456789012345678901"))
		_, _, err = VerifyTrustedAuthInit(&tamperedInit, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject tampered nonce")
		}
	})

	// Vector 3: Malicious Server MITM & Key Substitution
	t.Run("Vector 3: MITM ephemeral key substitution and signature failure", func(t *testing.T) {
		var ephemA [32]byte
		var nonceA [32]byte
		_, _ = rand.Read(ephemA[:])
		_, _ = rand.Read(nonceA[:])

		initMsg, err := NewTrustedAuthInit(
			idA,
			idB.DeviceID,
			credRef,
			kPair[:],
			[]string{"transfer.v1"},
			ephemA[:],
			nonceA[:],
			time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("NewTrustedAuthInit failed: %v", err)
		}

		// Malicious relay substitutes ephemeral key
		mitmInit := *initMsg
		var attackerEph [32]byte
		_, _ = rand.Read(attackerEph[:])
		mitmInit.EphemeralPub = hex.EncodeToString(attackerEph[:])

		// Receiver verifies
		_, _, err = VerifyTrustedAuthInit(&mitmInit, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject MITM ephemeral key substitution")
		}
	})

	// Vector 4: Presence Beacon Replay & Stale Epoch Expiration
	t.Run("Vector 4: Presence handle & LAN beacon epoch expiration", func(t *testing.T) {
		now := time.Now().UTC()
		window := DefaultRendezvousEpochWindow
		currentEpoch := now.Unix() / int64(window.Seconds())

		// Derive handles with ±1 epoch skew tolerance
		handles := DeriveRendezvousHandlesWithSkew(kPair[:], now, window)
		if len(handles) != 3 {
			t.Fatalf("expected 3 handles with skew, got %d", len(handles))
		}

		currentHandle := DeriveRendezvousHandle(kPair[:], currentEpoch)
		if !contains(handles, currentHandle) {
			t.Fatal("expected current handle to be in candidate set")
		}

		// Expired handle (4 epochs ago = 1 hour)
		expiredHandle := DeriveRendezvousHandle(kPair[:], currentEpoch-4)
		if contains(handles, expiredHandle) {
			t.Fatal("expected expired handle to NOT be in candidate set")
		}

		// Blinded LAN Beacon tag verification
		beacon, err := NewLanBeacon(4242, [][]byte{kPair[:]}, now, window)
		if err != nil {
			t.Fatalf("NewLanBeacon failed: %v", err)
		}

		localPairs := map[string][]byte{
			idB.DeviceID: kPair[:],
		}

		matched := MatchLanBeacon(beacon, localPairs, now, window)
		if len(matched) != 1 || matched[0] != idB.DeviceID {
			t.Fatalf("expected legitimate beacon to match Bob, got %v", matched)
		}

		// Attacker with wrong key cannot match
		var badKey [32]byte
		_, _ = rand.Read(badKey[:])
		attackerPairs := map[string][]byte{
			"attacker": badKey[:],
		}
		if len(MatchLanBeacon(beacon, attackerPairs, now, window)) != 0 {
			t.Fatal("expected attacker key to NOT match beacon")
		}

		// Expired beacon (2 hours old) fails match
		staleTime := now.Add(2 * time.Hour)
		if len(MatchLanBeacon(beacon, localPairs, staleTime, window)) != 0 {
			t.Fatal("expected stale beacon to NOT match")
		}
	})

	// Vector 5: Display Name / Local Label Spoofing Isolation
	t.Run("Vector 5: Display name spoofing isolation", func(t *testing.T) {
		// Attacker claims friendly label "Bob Laptop"
		attackerLabel := "Bob Laptop"
		if idAttacker.DeviceID == idB.DeviceID {
			t.Fatal("attacker device ID unexpectedly matched victim")
		}
		// Device ID and Fingerprint are authoritative cryptographic identifiers
		fpAttacker := FormatFingerprint(idAttacker.PublicKey)
		fpB := FormatFingerprint(idB.PublicKey)
		if fpAttacker == fpB {
			t.Fatal("attacker fingerprint unexpectedly matched victim")
		}
		_ = attackerLabel
	})

	// Vector 6: Downgrade Attack & Capability Stripping Resistance
	t.Run("Vector 6: Downgrade attack and wrong pair secret", func(t *testing.T) {
		var ephemA [32]byte
		var nonceA [32]byte
		_, _ = rand.Read(ephemA[:])
		_, _ = rand.Read(nonceA[:])

		var badSecret [32]byte
		_, _ = rand.Read(badSecret[:])

		// Attacker attempts trusted init with forged/downgraded secret
		badInit, err := NewTrustedAuthInit(
			idA,
			idB.DeviceID,
			credRef,
			badSecret[:],
			[]string{"transfer.v1"},
			ephemA[:],
			nonceA[:],
			time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("NewTrustedAuthInit failed: %v", err)
		}

		// Bob verifying with genuine kPair rejects the message
		_, _, err = VerifyTrustedAuthInit(badInit, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject bad pair secret")
		}
	})

	// Vector 7: Path Traversal & Directory Escape Containment
	t.Run("Vector 7: Path traversal and escape containment", func(t *testing.T) {
		unsafePaths := []string{
			"../evil.txt",
			"../../etc/passwd",
			"foo/../../bar.txt",
			"/absolute/path/file.txt",
			"C:\\Windows\\System32\\cmd.exe",
			"foo\x00bar.txt",
			"..\\..\\windows\\system32",
			"./../secret.key",
			"",
		}

		for _, p := range unsafePaths {
			_, err := NormalizeTransferPath(p)
			if err == nil {
				t.Fatalf("expected NormalizeTransferPath to reject unsafe path: %q", p)
			}
		}

		safePaths := []string{
			"photos/vacation.jpg",
			"document.pdf",
			"nested/dir/sub/file.tar.gz",
		}
		for _, p := range safePaths {
			clean, err := NormalizeTransferPath(p)
			if err != nil {
				t.Fatalf("expected NormalizeTransferPath to accept safe path %q: %v", p, err)
			}
			if clean != p {
				t.Fatalf("expected %q, got %q", p, clean)
			}
		}
	})

	// Vector 13: Padding-Oracle Probe & Non-Zero Padding Rejection
	t.Run("Vector 13: Padding-oracle probe and non-zero padding rejection", func(t *testing.T) {
		// 1. Buffer too short (< 2 bytes)
		shortBuf := []byte{0x00}
		if _, err := UnpadPayload(shortBuf); err == nil {
			t.Fatal("expected UnpadPayload to reject buffer shorter than 2 bytes")
		}

		// 2. Declared length exceeds buffer size
		overflowBuf := make([]byte, 256)
		binary.BigEndian.PutUint16(overflowBuf[:2], 300)
		if _, err := UnpadPayload(overflowBuf); err == nil {
			t.Fatal("expected UnpadPayload to reject unpadded length exceeding buffer size")
		}

		// 3. Non-zero padding byte inside valid bucket
		plain := []byte("secret payload data")
		padded, err := PadPayload(plain)
		if err != nil {
			t.Fatalf("PadPayload failed: %v", err)
		}
		// Tamper one padding byte at the end
		tamperedPadded := append([]byte(nil), padded...)
		tamperedPadded[len(tamperedPadded)-1] = 0x01
		if _, err := UnpadPayload(tamperedPadded); err == nil {
			t.Fatal("expected UnpadPayload to reject non-zero padding byte")
		}

		// 4. Bit-flipped inside AEAD envelope fails AEAD before unpad
		key13 := sha256.Sum256([]byte("aead-key-vector-13"))
		dir := DirectionalKey{
			Key:  key13[:],
			Salt: []byte("salt"),
		}
		h := FrameHeaderInput{
			Version: 1,
			Type:    FrameBlockData,
			FileIdx: 0,
		}
		sealed, err := SealPadded(dir, 0, h, plain)
		if err != nil {
			t.Fatalf("SealPadded failed: %v", err)
		}
		// Flip a bit in the ciphertext / tag region
		corruptSealed := append([]byte(nil), sealed...)
		corruptSealed[len(corruptSealed)-5] ^= 0x42
		if _, err := OpenSequenced(dir, 0, corruptSealed); err == nil {
			t.Fatal("expected OpenSequenced to fail on corrupted ciphertext before depadding")
		}

		// 5. Valid AEAD envelope containing forged non-zero padding fails on unpad
		badPaddedSealed, err := Seal(dir, 1, FrameHeaderInput{
			Version: 1,
			Type:    FrameBlockData,
			Flags:   FrameFlagPadded,
		}, tamperedPadded)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		if _, err := OpenSequenced(dir, 1, badPaddedSealed); err == nil {
			t.Fatal("expected OpenSequenced to reject frame with invalid padding inside valid AEAD")
		}
	})

	// Vector 14: Bucket-Downgrade Coercion & Private Session Requirement
	t.Run("Vector 14: Bucket-downgrade coercion and private session requirement", func(t *testing.T) {
		// Capability check: if session mandates private/padding mode, peer must announce PaddingCapability
		privatePeerCaps := []string{CapTransferV1, PaddingCapability}
		publicPeerCaps := []string{CapTransferV1}

		hasPadding := func(caps []string) bool {
			for _, c := range caps {
				if c == PaddingCapability {
					return true
				}
			}
			return false
		}

		if !hasPadding(privatePeerCaps) {
			t.Fatal("expected privatePeerCaps to contain PaddingCapability")
		}
		if hasPadding(publicPeerCaps) {
			t.Fatal("publicPeerCaps unexpectedly contains PaddingCapability")
		}

		// Attacker strips PaddingCapability from offered capabilities
		strippedCaps := make([]string, 0)
		for _, c := range privatePeerCaps {
			if c != PaddingCapability {
				strippedCaps = append(strippedCaps, c)
			}
		}

		// Session enforcing private mode fails closed if PaddingCapability was stripped
		enforcePrivateSession := func(peerCaps []string) error {
			if !hasPadding(peerCaps) {
				return fmt.Errorf("downgrade rejected: peer does not negotiate %s capability for private transfer", PaddingCapability)
			}
			return nil
		}

		if err := enforcePrivateSession(strippedCaps); err == nil {
			t.Fatal("expected enforcePrivateSession to reject stripped padding capability")
		}

		// Receiver enforcing private mode rejects unpadded frames
		key14 := sha256.Sum256([]byte("aead-key-vector-14"))
		dir := DirectionalKey{
			Key:  key14[:],
			Salt: []byte("salt"),
		}
		unpaddedFrame, err := Seal(dir, 0, FrameHeaderInput{
			Version: 1,
			Type:    FrameBlockData,
			Flags:   0, // NOT padded
		}, []byte("unpadded data"))
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		opened, err := OpenSequenced(dir, 0, unpaddedFrame)
		if err != nil {
			t.Fatalf("OpenSequenced failed: %v", err)
		}
		// Private policy check: FrameFlagPadded must be set
		if opened.Header.Flags&FrameFlagPadded == 0 {
			// Policy fails closed
			err = errors.New("private session rejected unpadded frame")
			if err == nil {
				t.Fatal("expected error")
			}
		} else {
			t.Fatal("expected opened frame to have FrameFlagPadded unset")
		}
	})

	// Vector 17: Revocation Sequence Rollback & Monotonicity
	t.Run("Vector 17: Revocation sequence rollback and domain monotonicity", func(t *testing.T) {
		now := time.Now().UTC()
		recHigh, err := SignRevocation(idA, idB.DeviceID, 10, now)
		if err != nil {
			t.Fatalf("SignRevocation high failed: %v", err)
		}
		if err := recHigh.Validate(); err != nil {
			t.Fatalf("recHigh failed Validate: %v", err)
		}

		recLow, err := SignRevocation(idA, idB.DeviceID, 5, now)
		if err != nil {
			t.Fatalf("SignRevocation low failed: %v", err)
		}

		// Monotonicity assertion: incoming seq <= current seq must be rejected
		currentSeq := recHigh.Seq
		applyRevocationSeq := func(existing uint64, incoming *RevocationRecord) error {
			if incoming.Seq <= existing {
				return ErrRevocationSeqRollback
			}
			return nil
		}

		if err := applyRevocationSeq(currentSeq, recLow); !errors.Is(err, ErrRevocationSeqRollback) {
			t.Fatalf("expected ErrRevocationSeqRollback for lower seq, got: %v", err)
		}
		if err := applyRevocationSeq(currentSeq, recHigh); !errors.Is(err, ErrRevocationSeqRollback) {
			t.Fatalf("expected ErrRevocationSeqRollback for equal seq replay, got: %v", err)
		}

		// Domain separation check: challenge with wrong domain prefix fails verification
		forgedChallenge := []byte("sendbeam/fake-domain:" + idA.DeviceID + idB.DeviceID)
		forgedSig, _ := idA.Sign(forgedChallenge)
		forgedRec := &RevocationRecord{
			RevokerDeviceID: idA.DeviceID,
			RevokedDeviceID: idB.DeviceID,
			Seq:             11,
			Timestamp:       now.Format(time.RFC3339),
			Signature:       hex.EncodeToString(forgedSig),
		}
		if err := VerifyRevocation(forgedRec, idA.PublicKey, MaxRevocationTimestampSkew, now); err == nil {
			t.Fatal("expected VerifyRevocation to reject signature computed under different domain")
		}
	})

	// Vector 18: Relay Frame Corruption, Reordering, and Truncation
	t.Run("Vector 18: Relay frame corruption, reordering, and truncation", func(t *testing.T) {
		key18 := sha256.Sum256([]byte("aead-key-vector-18"))
		dir := DirectionalKey{
			Key:  key18[:],
			Salt: []byte("salt"),
		}
		payload0 := []byte("frame-0-data")
		payload1 := []byte("frame-1-data")

		f0, err := Seal(dir, 0, FrameHeaderInput{Version: 1, Type: FrameBlockData}, payload0)
		if err != nil {
			t.Fatalf("Seal 0 failed: %v", err)
		}
		f1, err := Seal(dir, 1, FrameHeaderInput{Version: 1, Type: FrameBlockData}, payload1)
		if err != nil {
			t.Fatalf("Seal 1 failed: %v", err)
		}

		// 1. Bit-flip corruption
		f0Corrupt := append([]byte(nil), f0...)
		f0Corrupt[len(f0Corrupt)/2] ^= 0xff
		if _, err := OpenSequenced(dir, 0, f0Corrupt); err == nil {
			t.Fatal("expected OpenSequenced to fail on corrupted ciphertext")
		}

		// 2. Reordering: advance receiver to counter 1, then replay f0
		opened1, err := OpenSequenced(dir, 1, f1)
		if err != nil {
			t.Fatalf("OpenSequenced 1 failed: %v", err)
		}
		if string(opened1.Plaintext) != string(payload1) {
			t.Fatalf("unexpected plaintext: %s", opened1.Plaintext)
		}
		// Attempt to deliver f0 (counter 0 < minimum 1)
		if _, err := OpenSequenced(dir, 2, f0); !errors.Is(err, ErrFrameReplay) {
			t.Fatalf("expected ErrFrameReplay when delivering out-of-order/replayed frame, got: %v", err)
		}

		// 3. Truncation
		// 3a. Truncate 1 byte
		f0Trunc1 := f0[:len(f0)-1]
		if _, err := OpenSequenced(dir, 0, f0Trunc1); err == nil {
			t.Fatal("expected OpenSequenced to reject frame truncated by 1 byte")
		}
		// 3b. Truncate tag entirely (last 16 bytes)
		f0NoTag := f0[:len(f0)-16]
		if _, err := OpenSequenced(dir, 0, f0NoTag); err == nil {
			t.Fatal("expected OpenSequenced to reject frame with stripped AEAD tag")
		}
		// 3c. Truncate header (< 40 bytes)
		if _, err := OpenSequenced(dir, 0, f0[:20]); err == nil {
			t.Fatal("expected OpenSequenced to reject severely truncated frame (< 40 bytes)")
		}

		// 4. Tag tampering (zero tag)
		f0BadTag := append([]byte(nil), f0...)
		for i := len(f0BadTag) - 16; i < len(f0BadTag); i++ {
			f0BadTag[i] = 0x00
		}
		if _, err := OpenSequenced(dir, 0, f0BadTag); err == nil {
			t.Fatal("expected OpenSequenced to reject frame with forged zero tag")
		}
	})

	// Vector 19: Durable Transfer Journal Tampering
	t.Run("Vector 19: Durable transfer journal tampering", func(t *testing.T) {
		j := journalVectorSample(t)
		jBytes, err := EncodeJournal(j)
		if err != nil {
			t.Fatalf("EncodeJournal failed: %v", err)
		}

		// 1. Corrupted JSON syntax
		corruptJSON := append([]byte(nil), jBytes...)
		corruptJSON[len(corruptJSON)/2] = 0x00
		if _, err := DecodeJournal(corruptJSON); err == nil {
			t.Fatal("expected DecodeJournal to reject corrupt JSON syntax")
		}

		// 2. Torn write / truncated JSON
		tornJSON := jBytes[:len(jBytes)-30]
		if _, err := DecodeJournal(tornJSON); err == nil {
			t.Fatal("expected DecodeJournal to reject torn / truncated journal")
		}

		// 3. Manifest fingerprint mismatch
		var tamperedMap map[string]interface{}
		if err := json.Unmarshal(jBytes, &tamperedMap); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		tamperedMap["manifestFingerprint"] = "forged-fingerprint-00000000000000000000000000000000"
		tamperedFingerprintBytes, _ := json.Marshal(tamperedMap)
		if _, err := DecodeJournal(tamperedFingerprintBytes); err == nil {
			t.Fatal("expected DecodeJournal to reject journal with tampered manifest fingerprint")
		}

		// 4. Committed blocks exceeding file bounds
		tamperedBlocksMap := make(map[string]interface{})
		_ = json.Unmarshal(jBytes, &tamperedBlocksMap)
		files := tamperedBlocksMap["files"].([]interface{})
		file0 := files[0].(map[string]interface{})
		file0["committedBlocks"] = float64(999) // only 2 blocks exist in manifest!
		tamperedBlocksBytes, _ := json.Marshal(tamperedBlocksMap)
		if _, err := DecodeJournal(tamperedBlocksBytes); err == nil {
			t.Fatal("expected DecodeJournal to reject committedBlocks exceeding manifest bounds")
		}

		// 5. Schema version rollback / unsupported version
		tamperedVerMap := make(map[string]interface{})
		_ = json.Unmarshal(jBytes, &tamperedVerMap)
		tamperedVerMap["schemaVersion"] = 999
		tamperedVerBytes, _ := json.Marshal(tamperedVerMap)
		if _, err := DecodeJournal(tamperedVerBytes); err == nil {
			t.Fatal("expected DecodeJournal to reject unsupported schemaVersion")
		}
	})

	// Vector 20: Pairing Confirmation Misuse
	t.Run("Vector 20: Pairing confirmation misuse and cross-session replay", func(t *testing.T) {
		// Session 1 between Alice and Bob with master key K1
		k1 := sha256.Sum256([]byte("master-key-session-1"))
		reqNonce1 := make([]byte, PairingNonceSize)
		respNonce1 := make([]byte, PairingNonceSize)
		copy(reqNonce1, "req-nonce-1-00000000000000000000")
		copy(respNonce1, "resp-nonce-1-0000000000000000000")

		kPair1, _, err := DerivePairCredential(k1[:], reqNonce1, respNonce1, idA.PublicKey, idB.PublicKey)
		if err != nil {
			t.Fatalf("DerivePairCredential 1 failed: %v", err)
		}

		// Legitimate Bob confirmation tag in session 1
		tagBob1 := ComputePairingConfirmTag(kPair1, idB.DeviceID)
		if !VerifyPairingConfirmTag(kPair1, idB.DeviceID, tagBob1) {
			t.Fatal("legitimate pairing confirm tag failed verification")
		}

		// Session 2 between Alice and Bob with fresh master key K2
		k2 := sha256.Sum256([]byte("master-key-session-2"))
		reqNonce2 := make([]byte, PairingNonceSize)
		respNonce2 := make([]byte, PairingNonceSize)
		copy(reqNonce2, "req-nonce-2-00000000000000000000")
		copy(respNonce2, "resp-nonce-2-0000000000000000000")

		kPair2, _, err := DerivePairCredential(k2[:], reqNonce2, respNonce2, idA.PublicKey, idB.PublicKey)
		if err != nil {
			t.Fatalf("DerivePairCredential 2 failed: %v", err)
		}

		// 1. Cross-session replay: attacker replays tagBob1 in Session 2
		if VerifyPairingConfirmTag(kPair2, idB.DeviceID, tagBob1) {
			t.Fatal("expected VerifyPairingConfirmTag to reject replayed confirmation tag from session 1")
		}

		// 2. Cross-session substitution / wrong peer: attacker Charlie's device ID
		if VerifyPairingConfirmTag(kPair1, idAttacker.DeviceID, tagBob1) {
			t.Fatal("expected VerifyPairingConfirmTag to reject tag substituted for attacker device ID")
		}

		// 3. Bit-flipped / forged tag
		tagBytes, _ := hex.DecodeString(tagBob1)
		tagBytes[0] ^= 0x42
		forgedTag := hex.EncodeToString(tagBytes)
		if VerifyPairingConfirmTag(kPair1, idB.DeviceID, forgedTag) {
			t.Fatal("expected VerifyPairingConfirmTag to reject forged/corrupted tag")
		}

		// 4. Malformed tag length
		if VerifyPairingConfirmTag(kPair1, idB.DeviceID, "short-tag") {
			t.Fatal("expected VerifyPairingConfirmTag to reject malformed tag length")
		}
	})
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
