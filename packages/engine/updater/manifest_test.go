package updater

import (
	"strings"
	"testing"
)

func TestParseChecksums(t *testing.T) {
	manifest := `# Official SHA256 checksums
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  sendbeam-cli-linux-amd64.tar.gz
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e *sendbeam-cli-windows-amd64.zip

# Comment line
c71d0310f3f63811d9a4691c624271c6151b90c372707158298f4c4e7c69f695  sendbeam-cli-darwin-arm64.tar.gz
`

	checksums, err := ParseChecksums(strings.NewReader(manifest))
	if err != nil {
		t.Fatalf("ParseChecksums failed: %v", err)
	}

	if len(checksums) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(checksums))
	}

	if checksums["sendbeam-cli-linux-amd64.tar.gz"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("mismatched hash for linux: %s", checksums["sendbeam-cli-linux-amd64.tar.gz"])
	}

	if checksums["sendbeam-cli-windows-amd64.zip"] != "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" {
		t.Errorf("mismatched hash for windows: %s", checksums["sendbeam-cli-windows-amd64.zip"])
	}
}

func TestParseChecksumsInvalid(t *testing.T) {
	badManifest := `not-a-valid-sha256  sendbeam-cli-linux-amd64.tar.gz`
	_, err := ParseChecksums(strings.NewReader(badManifest))
	if err == nil {
		t.Error("expected error for invalid sha256 length, got nil")
	}
}

func TestTargetNames(t *testing.T) {
	if got := TargetCLIArchiveName("linux", "amd64"); got != "sendbeam-cli-linux-amd64.tar.gz" {
		t.Errorf("unexpected linux archive name %q", got)
	}
	if got := TargetCLIArchiveName("windows", "amd64"); got != "sendbeam-cli-windows-amd64.zip" {
		t.Errorf("unexpected windows archive name %q", got)
	}
	if got := TargetCLIBinaryName("linux"); got != "sendbeam" {
		t.Errorf("unexpected linux binary name %q", got)
	}
	if got := TargetCLIBinaryName("windows"); got != "sendbeam.exe" {
		t.Errorf("unexpected windows binary name %q", got)
	}
	if got := TargetDesktopAssetName("linux", "amd64", "appimage"); got != "SendBeam-linux-amd64.AppImage" {
		t.Errorf("unexpected linux appimage name %q", got)
	}
	if got := TargetDesktopAssetName("windows", "amd64", "installer"); got != "SendBeam-windows-amd64-installer.exe" {
		t.Errorf("unexpected windows installer name %q", got)
	}
	if got := TargetDesktopAssetName("darwin", "arm64", "dmg"); got != "SendBeam-macos-universal.dmg" {
		t.Errorf("unexpected macos dmg name %q", got)
	}
}

func TestChannelManifest_FindTargetAsset(t *testing.T) {
	manifest := ChannelManifest{
		SchemaVersion: 1,
		Version:       "1.6.0",
		Channel:       "stable",
		Assets: map[string]ReleaseAsset{
			"linux-amd64": {
				Name:        "sendbeam-cli-linux-amd64.tar.gz",
				DownloadURL: "https://example.com/sendbeam-cli-linux-amd64.tar.gz",
				SHA256:      "4a7f123456789012345678901234567890123456789012345678901234567890",
				Size:        1000,
			},
			"windows-amd64": {
				Name:        "sendbeam-cli-windows-amd64.zip",
				DownloadURL: "https://example.com/sendbeam-cli-windows-amd64.zip",
				SHA256:      "5b8e123456789012345678901234567890123456789012345678901234567890",
				Size:        2000,
			},
			"SendBeam-linux-amd64.AppImage": {
				Name:        "SendBeam-linux-amd64.AppImage",
				DownloadURL: "https://example.com/SendBeam-linux-amd64.AppImage",
				SHA256:      "6c9f123456789012345678901234567890123456789012345678901234567890",
				Size:        50000000,
			},
		},
	}

	asset, err := manifest.FindTargetAsset("linux", "amd64")
	if err != nil {
		t.Fatalf("FindTargetAsset(linux, amd64) failed: %v", err)
	}
	if asset.Name != "sendbeam-cli-linux-amd64.tar.gz" {
		t.Errorf("unexpected asset name: %s", asset.Name)
	}

	assetWin, err := manifest.FindTargetAsset("windows", "amd64")
	if err != nil {
		t.Fatalf("FindTargetAsset(windows, amd64) failed: %v", err)
	}
	if assetWin.Name != "sendbeam-cli-windows-amd64.zip" {
		t.Errorf("unexpected asset name: %s", assetWin.Name)
	}

	assetDesktop, err := manifest.FindDesktopTargetAsset("linux", "amd64", "appimage")
	if err != nil {
		t.Fatalf("FindDesktopTargetAsset(linux, amd64) failed: %v", err)
	}
	if assetDesktop.Name != "SendBeam-linux-amd64.AppImage" {
		t.Errorf("unexpected desktop asset: %s", assetDesktop.Name)
	}

	_, err = manifest.FindTargetAsset("freebsd", "arm")
	if err == nil {
		t.Error("expected error for unsupported platform, got nil")
	}
}

func TestVerifyMinisignSignature(t *testing.T) {
	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := DefaultMinisignPublicKey

	payload := []byte(`{"version":"1.6.0","channel":"stable"}`)

	sig, err := SignMinisign(payload, testSeed, testPub, "stable.json")
	if err != nil {
		t.Fatalf("SignMinisign failed: %v", err)
	}

	// 1. Valid signature
	if err := VerifyMinisignSignature(payload, sig, testPub); err != nil {
		t.Fatalf("VerifyMinisignSignature failed on valid signature: %v", err)
	}

	// 2. Tampered payload
	tamperedPayload := []byte(`{"version":"1.6.0","channel":"tampered"}`)
	if err := VerifyMinisignSignature(tamperedPayload, sig, testPub); err == nil {
		t.Error("expected signature error on tampered payload, got nil")
	}

	// 3. Tampered signature
	tamperedSig := strings.Replace(sig, "RWT", "AAA", 1)
	if err := VerifyMinisignSignature(payload, tamperedSig, testPub); err == nil {
		t.Error("expected signature error on tampered signature, got nil")
	}

	// 4. Wrong public key
	wrongPub := "RWSfFakePublicKeyForTestingOnly1234567890123456789012345678"
	if err := VerifyMinisignSignature(payload, sig, wrongPub); err == nil {
		t.Error("expected signature error on wrong public key, got nil")
	}
}
