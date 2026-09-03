package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func writeCorpusByteSlice(dir string, data []byte) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	h := sha256.Sum256(data)
	filename := hex.EncodeToString(h[:])
	path := filepath.Join(dir, filename)

	content := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", string(data))
	return os.WriteFile(path, []byte(content), 0644)
}

func writeCorpusString(dir string, val string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	h := sha256.Sum256([]byte(val))
	filename := hex.EncodeToString(h[:])
	path := filepath.Join(dir, filename)

	content := fmt.Sprintf("go test fuzz v1\nstring(%q)\n", val)
	return os.WriteFile(path, []byte(content), 0644)
}

func writeCorpusMulti(dir string, lines ...string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var sum []byte
	content := "go test fuzz v1\n"
	for _, l := range lines {
		content += l + "\n"
		sum = append(sum, []byte(l)...)
	}
	h := sha256.Sum256(sum)
	filename := hex.EncodeToString(h[:])
	path := filepath.Join(dir, filename)
	return os.WriteFile(path, []byte(content), 0644)
}

func main() {
	fmt.Println("Generating seed corpora under testdata/fuzz/...")

	// 1. packages/wire/testdata/fuzz/FuzzWordsCode
	wordsSeeds := []string{
		"0-brave-otter",
		"1-swift-fox",
		"42-ant-ape",
		"999-cedar-cliff",
		"0-ant",
		"0--brave--otter",
		" 0 - brave - otter ",
	}
	for _, s := range wordsSeeds {
		_ = writeCorpusString("packages/wire/testdata/fuzz/FuzzWordsCode", s)
	}

	// 2. packages/wire/testdata/fuzz/FuzzNormalizeTransferPath
	pathSeeds := []string{
		"safe/file.txt",
		"../escape",
		`C:\escape`,
		"nul",
		"猫/写真.jpg",
		"sub/folder/file.pdf",
	}
	for _, s := range pathSeeds {
		_ = writeCorpusString("packages/wire/testdata/fuzz/FuzzNormalizeTransferPath", s)
	}

	// 3. packages/wire/testdata/fuzz/FuzzDecodeControl
	controlSeeds := []string{
		`{"type":2,"files":[{"idx":0,"name":"a.txt","size":0,"mime":"","lastModified":1,"blockSize":8,"blocks":0,"fileDigest":"aa"}],"totalSize":0}`,
		`{"type":4,"fileIdx":0,"blockIdx":0,"sha256":"aa"}`,
		`{"type":6,"fileIdx":0,"blockIdx":1}`,
		`{"type":7,"fileIdx":0,"blockIdx":1,"reason":"integrity"}`,
		`{"type":8,"op":"pause"}`,
		`{"type":9,"fileDigest":"aa"}`,
		`{"type":11,"reason":"integrity"}`,
		`{"type":12,"transferId":"x","files":[{"idx":0,"haveBlocks":3}]}`,
		`{"type":10}`,
	}
	for _, s := range controlSeeds {
		_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzDecodeControl", []byte(s))
	}

	// 4. packages/wire/testdata/fuzz/FuzzDecodeFrameHeader
	headerSeeds := [][]byte{
		{0, 1, 2, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 16},
		{1, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
	}
	for _, s := range headerSeeds {
		_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzDecodeFrameHeader", s)
	}

	// 5. packages/wire/testdata/fuzz/FuzzValidateManifest & FuzzDecodeManifestShape
	manifestSeeds := []string{
		`{"type":2,"files":[{"idx":0,"name":"a.bin","size":9,"mime":"","lastModified":1,"blockSize":8,"blocks":2,"fileDigest":"aa"}],"totalSize":9}`,
		`{"type":2,"files":[{"idx":0,"name":"big","size":100,"mime":"","lastModified":1,"blockSize":1000,"blocks":1,"fileDigest":"aa"}],"totalSize":100}`,
		`{"type":2,"files":[{"idx":0,"name":"zero","size":0,"mime":"","lastModified":0,"blockSize":1,"blocks":0,"fileDigest":"aa"}],"totalSize":0}`,
	}
	for _, s := range manifestSeeds {
		_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzValidateManifest", []byte(s))
		_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzDecodeManifestShape", []byte(s))
	}

	// 6. packages/wire/testdata/fuzz/FuzzPaddingCodec from padding-vectors.json
	if data, err := os.ReadFile("packages/wire/testdata/padding-vectors.json"); err == nil {
		var vectors []struct {
			PaddedHex    string `json:"padded_hex"`
			PlaintextHex string `json:"plaintext_hex"`
		}
		if err := json.Unmarshal(data, &vectors); err == nil {
			for i, v := range vectors {
				if i > 8 {
					break
				}
				if b, err := hex.DecodeString(v.PaddedHex); err == nil && len(b) > 0 {
					_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzPaddingCodec", b)
				}
			}
		}
	}

	// 7. packages/wire/testdata/fuzz/FuzzRevocationRecord from revocation-vectors.json
	if data, err := os.ReadFile("packages/wire/testdata/revocation-vectors.json"); err == nil {
		var doc struct {
			Vectors []struct {
				Record any `json:"record"`
			} `json:"vectors"`
		}
		if err := json.Unmarshal(data, &doc); err == nil {
			for _, v := range doc.Vectors {
				if b, err := json.Marshal(v.Record); err == nil {
					_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzRevocationRecord", b)
				}
			}
		}
	}

	// 8. packages/wire/testdata/fuzz/FuzzPairingMessage from pairing-vectors.json
	if data, err := os.ReadFile("packages/wire/testdata/pairing-vectors.json"); err == nil {
		var vectors []struct {
			ReqDeviceID  string   `json:"req_device_id"`
			ReqPubKeyHex string   `json:"req_pub_key_hex"`
			ReqName      string   `json:"req_name"`
			ReqCaps      []string `json:"req_caps"`
			ReqNonceHex  string   `json:"req_nonce_hex"`
			ReqSigHex    string   `json:"req_sig_hex"`
		}
		if err := json.Unmarshal(data, &vectors); err == nil {
			for _, v := range vectors {
				req := map[string]any{
					"type":             "pairing_request",
					"protocol_version": "sendbeam/1",
					"device_id":        v.ReqDeviceID,
					"public_key":       v.ReqPubKeyHex,
					"device_name":      v.ReqName,
					"capabilities":     v.ReqCaps,
					"nonce":            v.ReqNonceHex,
					"signature":        v.ReqSigHex,
				}
				if b, err := json.Marshal(req); err == nil {
					_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzPairingMessage", b)
				}
			}
		}
	}

	// 9. packages/wire/testdata/fuzz/FuzzTrustedAuthMessage from trusted-session-vectors.json
	if data, err := os.ReadFile("packages/wire/testdata/trusted-session-vectors.json"); err == nil {
		var vectors []struct {
			InitDeviceID    string   `json:"init_device_id"`
			RespDeviceID    string   `json:"resp_device_id"`
			PairCredRef     string   `json:"pair_cred_ref"`
			InitEphemPubHex string   `json:"init_ephem_pub_hex"`
			InitNonceHex    string   `json:"init_nonce_hex"`
			InitCaps        []string `json:"init_caps"`
			InitTimestamp   string   `json:"init_timestamp"`
			InitSigHex      string   `json:"init_sig_hex"`
			InitAuthTagHex  string   `json:"init_auth_tag_hex"`
		}
		if err := json.Unmarshal(data, &vectors); err == nil {
			for _, v := range vectors {
				initMsg := map[string]any{
					"type":                "trusted_auth_init",
					"protocol_version":    "sendbeam/1",
					"initiator_device_id": v.InitDeviceID,
					"responder_device_id": v.RespDeviceID,
					"pair_credential_ref": v.PairCredRef,
					"ephemeral_pub":       v.InitEphemPubHex,
					"nonce":               v.InitNonceHex,
					"capabilities":        v.InitCaps,
					"timestamp":           v.InitTimestamp,
					"signature":           v.InitSigHex,
					"auth_tag":            v.InitAuthTagHex,
				}
				if b, err := json.Marshal(initMsg); err == nil {
					_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzTrustedAuthMessage", b)
				}
			}
		}
	}

	// 10. packages/wire/testdata/fuzz/FuzzDecodeJournal & packages/engine/transfer/testdata/fuzz/FuzzDurableJournalApply
	if data, err := os.ReadFile("docs/test-vectors/durable-journal.json"); err == nil {
		var doc struct {
			Journal           string `json:"journal"`
			JournalWithSecret string `json:"journalWithSecret"`
		}
		if err := json.Unmarshal(data, &doc); err == nil {
			if doc.Journal != "" {
				_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzDecodeJournal", []byte(doc.Journal))
				_ = writeCorpusByteSlice("packages/engine/transfer/testdata/fuzz/FuzzDurableJournalApply", []byte(doc.Journal))
			}
			if doc.JournalWithSecret != "" {
				_ = writeCorpusByteSlice("packages/wire/testdata/fuzz/FuzzDecodeJournal", []byte(doc.JournalWithSecret))
				_ = writeCorpusByteSlice("packages/engine/transfer/testdata/fuzz/FuzzDurableJournalApply", []byte(doc.JournalWithSecret))
			}
		}
	}

	// 11. packages/engine/rendezvous/testdata/fuzz/FuzzUnmarshalMessage
	rendezvousSeeds := []string{
		`{"type":"create"}`,
		`{"type":"created","room":7}`,
		`{"type":"join","room":1}`,
		`{"type":"pake","msg":"AQID"}`,
		`{"type":"confirm","mac":"AQID"}`,
		`{"type":"caps","frame":"AQID"}`,
		`{"type":"sdp","seq":0,"sdp":"v=0","mac":"AA"}`,
		`{"type":"ice","seq":1,"cand":"c","mac":"AA"}`,
		`{"type":"relay_credit","bytes":1024}`,
	}
	for _, s := range rendezvousSeeds {
		_ = writeCorpusByteSlice("packages/engine/rendezvous/testdata/fuzz/FuzzUnmarshalMessage", []byte(s))
	}

	// 12. packages/engine/trust/testdata/fuzz/FuzzDecodeTrustRecord & FuzzFileTrustStoreLoad
	trustSeeds := []string{
		`{"device_id":"sb-dev-d5ba0a004e9be5e2c4537b289163b5b548ea3043aad133911ae8d18809081287","public_key":"565c0c1dc287bdfe05c165a3d13d1e3dfafef34d217dec14d45ae3c53c1c89d9","local_label":"Alice Laptop","capabilities":["transfer.v1"],"first_seen_at":"2026-08-30T12:00:00Z","policy":{"auto_accept":false}}`,
	}
	for _, s := range trustSeeds {
		_ = writeCorpusByteSlice("packages/engine/trust/testdata/fuzz/FuzzDecodeTrustRecord", []byte(s))
	}
	storeSeeds := []string{
		`{"version":1,"updated_at":"2026-08-30T12:00:00Z","devices":[{"device_id":"sb-dev-d5ba0a004e9be5e2c4537b289163b5b548ea3043aad133911ae8d18809081287","public_key":"565c0c1dc287bdfe05c165a3d13d1e3dfafef34d217dec14d45ae3c53c1c89d9","local_label":"Alice","first_seen_at":"2026-08-30T12:00:00Z"}]}`,
	}
	for _, s := range storeSeeds {
		_ = writeCorpusByteSlice("packages/engine/trust/testdata/fuzz/FuzzFileTrustStoreLoad", []byte(s))
	}

	// 13. packages/engine/updater/testdata/fuzz/FuzzParseChannelManifest & FuzzParseChecksums
	manifestSeedsUpdater := []string{
		`{"schema_version":1,"version":"v1.7.0","channel":"stable","assets":{"linux-amd64":{"name":"sendbeam-cli-linux-amd64.tar.gz","size":100,"download_url":"https://example.com/asset","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}}`,
	}
	for _, s := range manifestSeedsUpdater {
		_ = writeCorpusByteSlice("packages/engine/updater/testdata/fuzz/FuzzParseChannelManifest", []byte(s))
	}
	checksumSeeds := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  sendbeam-cli-linux-amd64.tar.gz\na591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e *sendbeam-cli-windows-amd64.zip\n",
	}
	for _, s := range checksumSeeds {
		_ = writeCorpusByteSlice("packages/engine/updater/testdata/fuzz/FuzzParseChecksums", []byte(s))
	}

	// 14. apps/server/internal/signal/testdata/fuzz
	serverMsgSeeds := []string{
		`{"type":"create"}`,
		`{"type":"join","room":1}`,
		`{"type":"resume","room":1,"role":"offerer"}`,
		`{"type":"relay_credit","bytes":1024}`,
		`{"type":"bye","reason":"user"}`,
	}
	for _, s := range serverMsgSeeds {
		_ = writeCorpusByteSlice("apps/server/internal/signal/testdata/fuzz/FuzzClientMsg", []byte(s))
		_ = writeCorpusByteSlice("apps/server/internal/signal/testdata/fuzz/FuzzServerMessageValidation", []byte(s))
	}

	proxySeeds := []string{
		"127.0.0.1/32, 10.0.0.0/8, 192.168.0.0/16, ::1/128",
		"10.0.0.0/8",
	}
	for _, s := range proxySeeds {
		_ = writeCorpusString("apps/server/internal/signal/testdata/fuzz/FuzzParseTrustedProxies", s)
	}

	_ = writeCorpusMulti("apps/server/internal/signal/testdata/fuzz/FuzzClientIP",
		`string("127.0.0.1:12345")`,
		`string("198.51.100.1")`,
		`string("198.51.100.2")`,
		`string("198.51.100.3")`,
	)

	fmt.Println("Seed corpora generated successfully.")
}
