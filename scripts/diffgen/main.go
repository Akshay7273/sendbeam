package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/sendbeam/wire"
)

// DifferentialRecord represents one cross-language parity test case in JSON Lines format.
type DifferentialRecord struct {
	Category string          `json:"category"`
	CaseID   string          `json:"case_id"`
	Seed     int64           `json:"seed"`
	Desc     string          `json:"desc"`
	Payload  json.RawMessage `json:"payload"`
}

// FrameHeaderPayload records a binary frame header test case.
type FrameHeaderPayload struct {
	Header     wire.FrameHeader `json:"header"`
	EncodedHex string           `json:"encoded_hex"`
}

// PaddingPayload records a padding codec test case.
type PaddingPayload struct {
	PlaintextHex string `json:"plaintext_hex"`
	BucketSize   int    `json:"bucket_size"`
	PaddedHex    string `json:"padded_hex"`
	Corrupted    bool   `json:"corrupted,omitempty"`
	CorruptType  string `json:"corrupt_type,omitempty"`
}

// ControlPayload records a JSON control frame test case.
type ControlPayload struct {
	MsgType    string          `json:"msg_type"`
	JSONStr    string          `json:"json_str"`
	EncodedHex string          `json:"encoded_hex"`
	Structured json.RawMessage `json:"structured"`
}

// RevocationPayload records an Ed25519 revocation challenge and signature test case.
type RevocationPayload struct {
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

// PairingPayload records a SPAKE2+ pairing handshake test case.
type PairingPayload struct {
	MasterKeyHex      string `json:"master_key_hex"`
	ReqNonceHex       string `json:"req_nonce_hex"`
	RespNonceHex      string `json:"resp_nonce_hex"`
	DeviceIDA         string `json:"device_id_a"`
	PubAHex           string `json:"pub_a_hex"`
	DeviceIDB         string `json:"device_id_b"`
	PubBHex           string `json:"pub_b_hex"`
	ReqChallengeHex   string `json:"req_challenge_hex"`
	RespChallengeHex  string `json:"resp_challenge_hex"`
	KPairHex          string `json:"k_pair_hex"`
	CredRef           string `json:"cred_ref"`
	ConfirmPeerID     string `json:"confirm_peer_id"`
	ConfirmTagHex     string `json:"confirm_tag_hex"`
}

// TrustedAuthPayload records a trusted-session challenge and capabilities test case.
type TrustedAuthPayload struct {
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

// WordsPayload records an invite-code normalization and parsing test case.
type WordsPayload struct {
	RawInput    string `json:"raw_input"`
	Normalized  string `json:"normalized"`
	IsValidCode bool   `json:"is_valid_code"`
	Room        int    `json:"room,omitempty"`
	Words       string `json:"words,omitempty"`
}

// SafePathPayload records a manifest path normalization test case.
type SafePathPayload struct {
	RawPath        string `json:"raw_path"`
	NormalizedPath string `json:"normalized_path,omitempty"`
	IsValid        bool   `json:"is_valid"`
}

func main() {
	countFlag := flag.Int("count", 1000, "number of test cases per category")
	seedFlag := flag.Int64("seed", 1337, "seed for deterministic pseudo-random generator")
	maxPadFlag := flag.Int("max-pad-len", 512, "maximum plaintext length for randomized padding cases")
	outFlag := flag.String("out", "", "output file path (default stdout)")
	flag.Parse()

	rng := rand.New(rand.NewSource(*seedFlag))

	var out *os.File
	var err error
	if *outFlag != "" {
		out, err = os.Create(*outFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	encoder := json.NewEncoder(out)

	writeRecord := func(category, caseID, desc string, payloadObj any) {
		pBytes, err := json.Marshal(payloadObj)
		if err != nil {
			panic(fmt.Sprintf("marshal payload: %v", err))
		}
		rec := DifferentialRecord{
			Category: category,
			CaseID:   caseID,
			Seed:     *seedFlag,
			Desc:     desc,
			Payload:  pBytes,
		}
		if err := encoder.Encode(rec); err != nil {
			panic(fmt.Sprintf("encode record: %v", err))
		}
	}

	generateFrameHeaders(rng, *countFlag, writeRecord)
	generatePaddingCases(rng, *countFlag, *maxPadFlag, writeRecord)
	generateControlMessages(rng, *countFlag, writeRecord)
	generateRevocationCases(rng, *countFlag, writeRecord)
	generatePairingCases(rng, *countFlag, writeRecord)
	generateTrustedAuthCases(rng, *countFlag, writeRecord)
	generateWordsCases(rng, *countFlag, writeRecord)
	generateSafePathCases(rng, *countFlag, writeRecord)
}

func generateFrameHeaders(rng *rand.Rand, count int, write func(string, string, string, any)) {
	// 1. Boundary & corner cases
	edgeHeaders := []wire.FrameHeader{
		{Version: 1, Type: wire.FrameCaps, Flags: 0, FileIdx: 0, BlockIdx: 0, FrameOff: 0, Len: 0},
		{Version: 1, Type: wire.FrameBlockData, Flags: wire.FrameFlagLastInBlock, FileIdx: 1, BlockIdx: 1, FrameOff: 1024, Len: 16384},
		{Version: 1, Type: wire.FrameBlockData, Flags: wire.FrameFlagPadded, FileIdx: 65535, BlockIdx: 4294967295, FrameOff: 4294967295, Len: 65535},
		{Version: 255, Type: 255, Flags: 255, FileIdx: 65535, BlockIdx: 4294967295, FrameOff: 4294967295, Len: 65535},
	}
	for i, h := range edgeHeaders {
		buf := wire.EncodeFrameHeader(h)
		write("frame_header", fmt.Sprintf("fh_edge_%d", i), "boundary frame header", FrameHeaderPayload{
			Header:     h,
			EncodedHex: hex.EncodeToString(buf),
		})
	}

	// 2. Randomized cases
	for i := 0; i < count; i++ {
		h := wire.FrameHeader{
			Version:  uint8(rng.Intn(256)),
			Type:     uint8(rng.Intn(256)),
			Flags:    uint8(rng.Intn(256)),
			FileIdx:  uint16(rng.Intn(65536)),
			BlockIdx: rng.Uint32(),
			FrameOff: rng.Uint32(),
			Len:      uint16(rng.Intn(65536)),
		}
		buf := wire.EncodeFrameHeader(h)
		write("frame_header", fmt.Sprintf("fh_rand_%d", i), "randomized frame header", FrameHeaderPayload{
			Header:     h,
			EncodedHex: hex.EncodeToString(buf),
		})
	}
}

func generatePaddingCases(rng *rand.Rand, count, maxPadLen int, write func(string, string, string, any)) {
	// 1. Specific bucket boundary lengths
	allBoundaryLens := []int{0, 1, 253, 254, 255, 510, 511, 1022, 1023, 2046, 2047, 4094, 4095, 8190, 8191, 16382, 16383, 32766}
	for i, l := range allBoundaryLens {
		if l > maxPadLen && maxPadLen < 32766 && l > 1023 {
			continue
		}
		plain := make([]byte, l)
		for j := range plain {
			plain[j] = byte((j + i) % 256)
		}
		bucket := wire.PadBucketSize(l)
		padded, err := wire.PadPayload(plain)
		if err != nil {
			panic(err)
		}
		write("padding", fmt.Sprintf("pad_boundary_%d", i), fmt.Sprintf("boundary length %d", l), PaddingPayload{
			PlaintextHex: hex.EncodeToString(plain),
			BucketSize:   bucket,
			PaddedHex:    hex.EncodeToString(padded),
		})
	}

	// 2. Randomized lengths
	for i := 0; i < count; i++ {
		l := rng.Intn(maxPadLen + 1)
		plain := make([]byte, l)
		rng.Read(plain)
		bucket := wire.PadBucketSize(l)
		padded, err := wire.PadPayload(plain)
		if err != nil {
			panic(err)
		}
		write("padding", fmt.Sprintf("pad_rand_%d", i), fmt.Sprintf("random length %d", l), PaddingPayload{
			PlaintextHex: hex.EncodeToString(plain),
			BucketSize:   bucket,
			PaddedHex:    hex.EncodeToString(padded),
		})
	}

	// 3. Corrupted padding cases
	for i := 0; i < 50; i++ {
		plain := make([]byte, 200)
		padded, _ := wire.PadPayload(plain)
		// Corrupt: insert non-zero byte in padding region
		corruptIdx := 2 + len(plain) + 1 + rng.Intn(len(padded)-(2+len(plain)+1))
		padded[corruptIdx] = byte(1 + rng.Intn(255))
		write("padding", fmt.Sprintf("pad_corrupt_byte_%d", i), "non-zero padding byte", PaddingPayload{
			PlaintextHex: hex.EncodeToString(plain),
			BucketSize:   len(padded),
			PaddedHex:    hex.EncodeToString(padded),
			Corrupted:    true,
			CorruptType:  "non_zero_padding",
		})
	}
}

func generateControlMessages(rng *rand.Rand, count int, write func(string, string, string, any)) {
	// 1. Manifest messages
	testNames := []string{
		"file.txt",
		"docs/readme.md",
		"assets/image (1).png",
		"data & stats <2026>.csv",
		"unicode_測試_🚀.bin",
	}

	for i := 0; i < count/4; i++ {
		numFiles := 1 + rng.Intn(3)
		files := make([]wire.FileEntry, numFiles)
		var totalSize int64
		for f := 0; f < numFiles; f++ {
			name := testNames[(i+f)%len(testNames)]
			size := int64(rng.Intn(5000000))
			blockSize := 1048576
			blocks := int((size + int64(blockSize) - 1) / int64(blockSize))
			if size == 0 {
				blocks = 0
			}
			h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", name, size)))
			digest := hex.EncodeToString(h[:])
			files[f] = wire.FileEntry{
				Idx:          f,
				Name:         name,
				Size:         size,
				Mime:         "application/octet-stream",
				LastModified: 1700000000000 + int64(i*1000),
				BlockSize:    blockSize,
				Blocks:       blocks,
				FileDigest:   digest,
			}
			totalSize += size
		}
		m := wire.Manifest{
			Type:       wire.FrameManifest,
			TransferID: fmt.Sprintf("tid-%08x", i),
			Files:      files,
			TotalSize:  totalSize,
		}
		encoded, err := wire.EncodeControl(m)
		if err != nil {
			panic(err)
		}
		var raw json.RawMessage
		_ = json.Unmarshal(encoded, &raw)
		write("control", fmt.Sprintf("ctrl_manifest_%d", i), "manifest message", ControlPayload{
			MsgType:    "manifest",
			JSONStr:    string(encoded),
			EncodedHex: hex.EncodeToString(encoded),
			Structured: raw,
		})
	}

	// 2. Ack & BlockHash
	for i := 0; i < count/4; i++ {
		ack := wire.Ack{
			Type:     wire.FrameAck,
			FileIdx:  rng.Intn(10),
			BlockIdx: rng.Intn(500),
		}
		encoded, _ := wire.EncodeControl(ack)
		var raw json.RawMessage
		_ = json.Unmarshal(encoded, &raw)
		write("control", fmt.Sprintf("ctrl_ack_%d", i), "block ack message", ControlPayload{
			MsgType:    "ack",
			JSONStr:    string(encoded),
			EncodedHex: hex.EncodeToString(encoded),
			Structured: raw,
		})
	}

	// 3. Nack
	for i := 0; i < count/4; i++ {
		reason := wire.NackMissing
		if i%2 == 1 {
			reason = wire.NackTimeout
		}
		nack := wire.Nack{
			Type:     wire.FrameNack,
			FileIdx:  rng.Intn(10),
			BlockIdx: rng.Intn(500),
			Reason:   reason,
		}
		encoded, _ := wire.EncodeControl(nack)
		var raw json.RawMessage
		_ = json.Unmarshal(encoded, &raw)
		write("control", fmt.Sprintf("ctrl_nack_%d", i), "file nack message", ControlPayload{
			MsgType:    "nack",
			JSONStr:    string(encoded),
			EncodedHex: hex.EncodeToString(encoded),
			Structured: raw,
		})
	}

	// 4. Control op (pause / resume) & Done
	for i := 0; i < count/4; i++ {
		op := wire.ControlPause
		if i%2 == 1 {
			op = wire.ControlResume
		}
		ctrl := wire.Control{
			Type: wire.FrameControl,
			Op:   op,
		}
		encoded, _ := wire.EncodeControl(ctrl)
		var raw json.RawMessage
		_ = json.Unmarshal(encoded, &raw)
		write("control", fmt.Sprintf("ctrl_pause_%d", i), "control op message", ControlPayload{
			MsgType:    "control",
			JSONStr:    string(encoded),
			EncodedHex: hex.EncodeToString(encoded),
			Structured: raw,
		})
	}
}

func generateRevocationCases(rng *rand.Rand, count int, write func(string, string, string, any)) {
	for i := 0; i < count; i++ {
		seedA := make([]byte, ed25519.SeedSize)
		seedB := make([]byte, ed25519.SeedSize)
		rng.Read(seedA)
		rng.Read(seedB)

		privA := ed25519.NewKeyFromSeed(seedA)
		pubA := privA.Public().(ed25519.PublicKey)
		privB := ed25519.NewKeyFromSeed(seedB)
		pubB := privB.Public().(ed25519.PublicKey)

		revokerID := wire.DeriveDeviceID(pubA)
		revokedID := wire.DeriveDeviceID(pubB)
		seq := uint64(1 + rng.Int63n(100000))
		ts := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute).Format(time.RFC3339)

		challenge := wire.BuildRevocationChallenge(revokerID, revokedID, seq, ts)
		sig := ed25519.Sign(privA, challenge)

		rec := wire.RevocationRecord{
			RevokerDeviceID: revokerID,
			RevokedDeviceID: revokedID,
			Seq:             seq,
			Timestamp:       ts,
			Signature:       hex.EncodeToString(sig),
		}

		write("revocation", fmt.Sprintf("revoc_%d", i), "ed25519 revocation challenge and signature", RevocationPayload{
			RevokerID:    revokerID,
			RevokedID:    revokedID,
			Seq:          seq,
			Timestamp:    ts,
			ChallengeHex: hex.EncodeToString(challenge),
			SignatureHex: hex.EncodeToString(sig),
			PublicKeyHex: hex.EncodeToString(pubA),
			Record:       rec,
			Valid:        true,
		})
	}
}

func generatePairingCases(rng *rand.Rand, count int, write func(string, string, string, any)) {
	for i := 0; i < count; i++ {
		masterKey := make([]byte, 32)
		reqNonce := make([]byte, 32)
		respNonce := make([]byte, 32)
		rng.Read(masterKey)
		rng.Read(reqNonce)
		rng.Read(respNonce)

		seedA := make([]byte, ed25519.SeedSize)
		seedB := make([]byte, ed25519.SeedSize)
		rng.Read(seedA)
		rng.Read(seedB)

		pubA := ed25519.NewKeyFromSeed(seedA).Public().(ed25519.PublicKey)
		pubB := ed25519.NewKeyFromSeed(seedB).Public().(ed25519.PublicKey)

		devA := wire.DeriveDeviceID(pubA)
		devB := wire.DeriveDeviceID(pubB)

		reqChallenge := wire.BuildPairingRequestChallenge(masterKey, reqNonce, devA)
		respChallenge := wire.BuildPairingResponseChallenge(masterKey, reqNonce, respNonce, devB)

		kPair, credRef, err := wire.DerivePairCredential(masterKey, reqNonce, respNonce, pubA, pubB)
		if err != nil {
			panic(err)
		}

		confirmTag := wire.ComputePairingConfirmTag(kPair, devB)

		write("pairing", fmt.Sprintf("pair_%d", i), "pairing challenges and derivations", PairingPayload{
			MasterKeyHex:     hex.EncodeToString(masterKey),
			ReqNonceHex:      hex.EncodeToString(reqNonce),
			RespNonceHex:     hex.EncodeToString(respNonce),
			DeviceIDA:        devA,
			PubAHex:          hex.EncodeToString(pubA),
			DeviceIDB:        devB,
			PubBHex:          hex.EncodeToString(pubB),
			ReqChallengeHex:  hex.EncodeToString(reqChallenge),
			RespChallengeHex: hex.EncodeToString(respChallenge),
			KPairHex:         hex.EncodeToString(kPair),
			CredRef:          credRef,
			ConfirmPeerID:    devB,
			ConfirmTagHex:    confirmTag,
		})
	}
}

func generateTrustedAuthCases(rng *rand.Rand, count int, write func(string, string, string, any)) {
	allCaps := []string{"streaming", "resume", "lan-sync", "padding", "e2ee", "blob-store", "priority", "compression"}

	for i := 0; i < count; i++ {
		capsA := sampleCaps(rng, allCaps)
		capsB := sampleCaps(rng, allCaps)

		hashA := wire.HashCapabilities(capsA)
		hashB := wire.HashCapabilities(capsB)
		intersect := wire.IntersectCapabilities(capsA, capsB)

		kPairHash := make([]byte, 32)
		ephemInit := make([]byte, 32)
		ephemResp := make([]byte, 32)
		nonceInit := make([]byte, 32)
		nonceResp := make([]byte, 32)
		rng.Read(kPairHash)
		rng.Read(ephemInit)
		rng.Read(ephemResp)
		rng.Read(nonceInit)
		rng.Read(nonceResp)

		initID := fmt.Sprintf("dev-%08x", rng.Uint32())
		respID := fmt.Sprintf("dev-%08x", rng.Uint32())
		ts := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339)

		initChal := wire.BuildTrustedInitChallenge(kPairHash, ephemInit, nonceInit, initID, respID, hashA, ts)
		respChal := wire.BuildTrustedRespChallenge(kPairHash, ephemInit, ephemResp, nonceInit, nonceResp, initID, respID, hashB)

		sessionMaster := make([]byte, 32)
		rng.Read(sessionMaster)
		confirmTag := wire.ComputeTrustedConfirmTag(sessionMaster, wire.DomainTrustedConfirmInit, respID)

		write("trusted_auth", fmt.Sprintf("ta_%d", i), "trusted auth capabilities and challenges", TrustedAuthPayload{
			CapabilitiesA:    capsA,
			CapabilitiesB:    capsB,
			HashAHex:         hex.EncodeToString(hashA),
			HashBHex:         hex.EncodeToString(hashB),
			IntersectResult:  intersect,
			KPairHashHex:     hex.EncodeToString(kPairHash),
			InitiatorID:      initID,
			ResponderID:      respID,
			EphemeralPubHex:  hex.EncodeToString(ephemInit),
			NonceHex:         hex.EncodeToString(nonceInit),
			EphemRespPubHex:  hex.EncodeToString(ephemResp),
			NonceRespHex:     hex.EncodeToString(nonceResp),
			Timestamp:        ts,
			InitChallengeHex: hex.EncodeToString(initChal),
			RespChallengeHex: hex.EncodeToString(respChal),
			ConfirmTagHex:    confirmTag,
		})
	}
}

func sampleCaps(rng *rand.Rand, pool []string) []string {
	n := 1 + rng.Intn(len(pool))
	perm := rng.Perm(len(pool))
	res := make([]string, n)
	for i := 0; i < n; i++ {
		res[i] = pool[perm[i]]
	}
	return res
}

func generateWordsCases(rng *rand.Rand, count int, write func(string, string, string, any)) {
	// Standard valid codes
	validSamples := []string{
		"42-brave-otter",
		"1001-ant-ape",
		"7-falcon-wolf-deer",
		"  99 - CAT - DOG  ",
		"500_owl.fox",
		"12345--tiger__bear",
	}

	for i, s := range validSamples {
		norm := wire.NormalizeCode(s)
		parsed, err := wire.ParseCode(s)
		write("words", fmt.Sprintf("words_sample_%d", i), "standard word code", WordsPayload{
			RawInput:    s,
			Normalized:  norm,
			IsValidCode: err == nil,
			Room:        parsed.Room,
			Words:       parsed.Words,
		})
	}

	// Randomized strings
	for i := 0; i < count; i++ {
		room := 1 + rng.Intn(999999)
		wordCount := 1 + rng.Intn(3)
		words := make([]string, wordCount)
		for w := 0; w < wordCount; w++ {
			// Pick words or random characters
			words[w] = fmt.Sprintf("word%d", rng.Intn(100))
		}
		raw := fmt.Sprintf("%d-%s", room, strings.Join(words, "-"))
		if rng.Intn(2) == 1 {
			raw = strings.ToUpper(raw)
		}
		norm := wire.NormalizeCode(raw)
		parsed, err := wire.ParseCode(raw)
		write("words", fmt.Sprintf("words_rand_%d", i), "randomized word code", WordsPayload{
			RawInput:    raw,
			Normalized:  norm,
			IsValidCode: err == nil,
			Room:        parsed.Room,
			Words:       parsed.Words,
		})
	}

	// Invalid strings
	invalidSamples := []string{
		"",
		"---",
		"room-words",
		"-123-falcon",
		"123",
		"123-",
		"!@#$%^",
	}
	for i, s := range invalidSamples {
		norm := wire.NormalizeCode(s)
		parsed, err := wire.ParseCode(s)
		write("words", fmt.Sprintf("words_invalid_%d", i), "invalid word code", WordsPayload{
			RawInput:    s,
			Normalized:  norm,
			IsValidCode: err == nil,
			Room:        parsed.Room,
			Words:       parsed.Words,
		})
	}
}

func generateSafePathCases(rng *rand.Rand, count int, write func(string, string, string, any)) {
	// Valid relative paths
	validPaths := []string{
		"file.txt",
		"docs/readme.md",
		"a/b/c/d/e.png",
		"src/lib/index.ts",
		"folder/file with spaces (1).pdf",
		"nested/path/to/data.json",
		"foo\\bar\\baz.txt",
	}
	for i, p := range validPaths {
		norm, err := wire.NormalizeTransferPath(p)
		write("safe_path", fmt.Sprintf("sp_valid_%d", i), "valid relative path", SafePathPayload{
			RawPath:        p,
			NormalizedPath: norm,
			IsValid:        err == nil,
		})
	}

	// Invalid paths
	invalidPaths := []string{
		"",
		"/etc/passwd",
		"\\Windows\\System32",
		"C:\\boot.ini",
		"d:/data.txt",
		"../secret.txt",
		"foo/../../bar.txt",
		"con.txt",
		"aux",
		"nul.dat",
		"com1.log",
		"bad|char.txt",
		"bad<char>.txt",
		"trailing-space ",
		"trailing-dot.",
	}
	for i, p := range invalidPaths {
		norm, err := wire.NormalizeTransferPath(p)
		write("safe_path", fmt.Sprintf("sp_invalid_%d", i), "invalid relative path", SafePathPayload{
			RawPath:        p,
			NormalizedPath: norm,
			IsValid:        err == nil,
		})
	}

	// Random combinations
	for i := 0; i < count; i++ {
		depth := 1 + rng.Intn(5)
		parts := make([]string, depth)
		for d := 0; d < depth; d++ {
			parts[d] = fmt.Sprintf("seg_%d", rng.Intn(1000))
		}
		p := strings.Join(parts, "/")
		if rng.Intn(3) == 0 {
			p = strings.ReplaceAll(p, "/", "\\")
		}
		norm, err := wire.NormalizeTransferPath(p)
		write("safe_path", fmt.Sprintf("sp_rand_%d", i), "random safe path", SafePathPayload{
			RawPath:        p,
			NormalizedPath: norm,
			IsValid:        err == nil,
		})
	}
}
