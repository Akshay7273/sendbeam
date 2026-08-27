package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sigPart1Len     = 74
	sigPart2Len     = 64
	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "
)

type ReleaseAsset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
}

type ChannelManifest struct {
	SchemaVersion       int                     `json:"schema_version"`
	Version             string                  `json:"version"`
	Channel             string                  `json:"channel"`
	MinSupportedVersion string                  `json:"min_supported_version,omitempty"`
	PublishedAt         time.Time               `json:"published_at"`
	ReleaseNotes        string                  `json:"release_notes,omitempty"`
	Assets              map[string]ReleaseAsset `json:"assets"`
}

func main() {
	var (
		versionFlag   = flag.String("version", "", "product version (e.g. 1.6.0 or 1.6.0-rc1)")
		tagFlag       = flag.String("tag", "", "release tag (e.g. v1.6.0 or v1.6.0-rc1)")
		channelFlag   = flag.String("channel", "auto", "update channel (stable, beta, or auto)")
		repoFlag      = flag.String("repo", "Akshay7273/sendbeam", "GitHub repository owner/name")
		sumsFlag      = flag.String("sums", "SHA256SUMS.txt", "path to SHA256SUMS.txt manifest")
		assetDirFlag  = flag.String("dir", ".", "directory containing release assets")
		outDirFlag    = flag.String("out", "updates", "output directory for manifest files")
		keyFlag       = flag.String("key", "", "minisign secret key or seed (or MINISIGN_SECRET_KEY env)")
		pubKeyFlag    = flag.String("pubkey", "minisign.pub", "minisign public key file")
		minSupported  = flag.String("min-supported", "1.0.0", "minimum supported version")
		notesFlag     = flag.String("notes", "", "release notes summary")
	)
	flag.Parse()

	if *versionFlag == "" && *tagFlag == "" {
		fmt.Fprintf(os.Stderr, "error: either --version or --tag is required\n")
		os.Exit(1)
	}

	version := *versionFlag
	tag := *tagFlag
	if version == "" {
		version = strings.TrimPrefix(tag, "v")
	}
	if tag == "" {
		tag = "v" + version
	}

	// Parse checksums
	checksums, err := parseChecksums(*sumsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading checksums %s: %v\n", *sumsFlag, err)
		os.Exit(1)
	}

	// Build assets map
	assets := make(map[string]ReleaseAsset)
	for filename, sha := range checksums {
		// Skip non-distribution files
		if strings.HasSuffix(filename, ".spdx.json") ||
			strings.HasSuffix(filename, ".txt") ||
			strings.HasSuffix(filename, ".minisig") ||
			strings.HasSuffix(filename, ".sigstore.json") ||
			strings.HasSuffix(filename, ".bundle") {
			continue
		}

		downloadURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", *repoFlag, tag, filename)
		var size int64 = 0
		filePath := filepath.Join(*assetDirFlag, filename)
		if fi, err := os.Stat(filePath); err == nil {
			size = fi.Size()
		}

		asset := ReleaseAsset{
			Name:        filename,
			Size:        size,
			DownloadURL: downloadURL,
			SHA256:      sha,
		}

		// Key by canonical platform ID if CLI archive
		platformKey := detectPlatformKey(filename)
		if platformKey != "" {
			assets[platformKey] = asset
		}
		assets[filename] = asset
	}

	if err := os.MkdirAll(*outDirFlag, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Determine target channels
	var channels []string
	switch strings.ToLower(*channelFlag) {
	case "stable":
		channels = []string{"stable"}
	case "beta":
		channels = []string{"beta"}
	case "auto":
		if strings.Contains(version, "-") {
			channels = []string{"beta"}
		} else {
			channels = []string{"stable", "beta"}
		}
	default:
		channels = []string{*channelFlag}
	}

	secKey := *keyFlag
	if secKey == "" {
		secKey = os.Getenv("MINISIGN_SECRET_KEY")
	}

	now := time.Now().UTC()

	for _, ch := range channels {
		manifest := ChannelManifest{
			SchemaVersion:       1,
			Version:             version,
			Channel:             ch,
			MinSupportedVersion: *minSupported,
			PublishedAt:         now,
			ReleaseNotes:        *notesFlag,
			Assets:              assets,
		}

		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error serializing manifest for %s: %v\n", ch, err)
			os.Exit(1)
		}
		data = append(data, '\n')

		jsonFile := filepath.Join(*outDirFlag, ch+".json")
		if err := os.WriteFile(jsonFile, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", jsonFile, err)
			os.Exit(1)
		}
		fmt.Printf("Generated manifest: %s (%d assets)\n", jsonFile, len(assets))

		if secKey != "" {
			sigContent, err := signPayload(data, secKey, *pubKeyFlag, ch+".json")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error signing %s: %v\n", jsonFile, err)
				os.Exit(1)
			}

			sigFile := filepath.Join(*outDirFlag, ch+".json.minisig")
			if err := os.WriteFile(sigFile, []byte(sigContent), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing %s: %v\n", sigFile, err)
				os.Exit(1)
			}
			fmt.Printf("Signed manifest: %s\n", sigFile)
		}
	}
}

func detectPlatformKey(filename string) string {
	switch {
	case strings.Contains(filename, "sendbeam-cli-linux-amd64"):
		return "linux-amd64"
	case strings.Contains(filename, "sendbeam-cli-linux-arm64"):
		return "linux-arm64"
	case strings.Contains(filename, "sendbeam-cli-darwin-amd64"):
		return "darwin-amd64"
	case strings.Contains(filename, "sendbeam-cli-darwin-arm64"):
		return "darwin-arm64"
	case strings.Contains(filename, "sendbeam-cli-windows-amd64"):
		return "windows-amd64"
	case strings.Contains(filename, "sendbeam-cli-windows-arm64"):
		return "windows-arm64"
	default:
		return ""
	}
}

func parseChecksums(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := strings.ToLower(fields[0])
		if len(hash) != 64 {
			continue
		}
		name := strings.TrimPrefix(strings.Join(fields[1:], " "), "*")
		result[strings.TrimSpace(name)] = hash
	}
	return result, scanner.Err()
}

func signPayload(content []byte, secretKeyStr, pubKeyPath, filename string) (string, error) {
	privKey, err := parsePrivateKey(secretKeyStr)
	if err != nil {
		return "", err
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	var keyID []byte

	if pubKeyPath != "" {
		_, pKeyID, err := parsePublicKey(pubKeyPath)
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

func parsePublicKey(input string) (ed25519.PublicKey, []byte, error) {
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
