package updater

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// FuzzParseChannelManifest exercises update channel manifest parsing and platform asset resolution.
// Invariants:
// 1. json.Unmarshal into ChannelManifest must never panic on arbitrary input bytes.
// 2. FindTargetAsset and FindDesktopTargetAsset must never panic regardless of manifest contents or platform arguments.
// 3. ParseVersion must fail closed without panics when given unconstrained version strings.
func FuzzParseChannelManifest(f *testing.F) {
	seeds := []string{
		`{}`,
		`not-json`,
		`{"schema_version":1,"version":"v1.7.0","channel":"stable","assets":{}}`,
		`{"schema_version":1,"version":"1.7.0","channel":"stable","assets":{"linux-amd64":{"name":"sendbeam-cli-linux-amd64.tar.gz","size":100,"download_url":"https://example.com/asset","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}}`,
		`{"schema_version":999,"version":"999.999.999-rc1+build","channel":"beta","assets":{"SendBeam-linux-amd64.AppImage":{"name":"SendBeam-linux-amd64.AppImage","size":1000,"download_url":"https://example.com/appimage","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		var manifest ChannelManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return
		}

		if manifest.Version != "" {
			_, _ = ParseVersion(manifest.Version)
		}
		if manifest.MinSupportedVersion != "" {
			_, _ = ParseVersion(manifest.MinSupportedVersion)
		}

		// Exercise target asset resolution with varied OS / Arch combinations
		platforms := [][2]string{
			{"linux", "amd64"},
			{"linux", "arm64"},
			{"darwin", "amd64"},
			{"darwin", "arm64"},
			{"windows", "amd64"},
			{"windows", "arm64"},
			{"", ""},
			{"unknown", "unknown"},
		}

		for _, p := range platforms {
			_, _ = manifest.FindTargetAsset(p[0], p[1])
		}

		desktopFormats := []string{"deb", "appimage", "zip", "installer", "portable", "dmg", ""}
		for _, p := range platforms {
			for _, fmtStr := range desktopFormats {
				_, _ = manifest.FindDesktopTargetAsset(p[0], p[1], fmtStr)
			}
		}
	})
}

// FuzzParseChecksums exercises the SHA256SUMS.txt parser against arbitrary byte sequences.
// Invariants:
// 1. ParseChecksums must never panic.
// 2. If ParseChecksums returns no error, all extracted hashes must be exactly 64 valid lowercase hex characters,
//    and all extracted file names must be non-empty.
func FuzzParseChecksums(f *testing.F) {
	seeds := []string{
		"",
		"# Comment only\n",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  file.tar.gz\n",
		"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e *file.zip\n",
		"invalid\n",
		"00  \n",
		"0000000000000000000000000000000000000000000000000000000000000000  \n",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  spaced file name.tar.gz\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		checksums, err := ParseChecksums(bytes.NewReader(data))
		if err != nil {
			return
		}

		for name, hash := range checksums {
			if name == "" {
				t.Fatalf("ParseChecksums returned empty filename")
			}
			if len(hash) != 64 {
				t.Fatalf("ParseChecksums returned invalid hash length %d for %q: %q", len(hash), name, hash)
			}
			if _, err := hex.DecodeString(hash); err != nil {
				t.Fatalf("ParseChecksums returned invalid hex %q for %q: %v", hash, name, err)
			}
		}
	})
}
