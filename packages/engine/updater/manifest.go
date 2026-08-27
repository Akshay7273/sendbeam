package updater

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"
)

// ReleaseAsset represents an available downloadable binary or distribution archive.
type ReleaseAsset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256,omitempty"`
}

// ReleaseMetadata represents the release record and available assets.
type ReleaseMetadata struct {
	Version      Version           `json:"version"`
	TagName      string            `json:"tag_name"`
	Prerelease   bool              `json:"prerelease"`
	PublishedAt  time.Time         `json:"published_at"`
	ReleaseNotes string            `json:"release_notes,omitempty"`
	Assets       []ReleaseAsset    `json:"assets"`
	Checksums    map[string]string `json:"checksums,omitempty"` // filename -> lowercase hex sha256
}

// ChannelManifest represents the canonical, signed JSON update manifest published per release channel.
type ChannelManifest struct {
	SchemaVersion       int                     `json:"schema_version"`
	Version             string                  `json:"version"`
	Channel             string                  `json:"channel"`
	MinSupportedVersion string                  `json:"min_supported_version,omitempty"`
	PublishedAt         time.Time               `json:"published_at"`
	ReleaseNotes        string                  `json:"release_notes,omitempty"`
	Assets              map[string]ReleaseAsset `json:"assets"`
}

// FindTargetAsset finds the asset matching the expected platform from the channel manifest.
func (cm *ChannelManifest) FindTargetAsset(targetOS, targetArch string) (*ReleaseAsset, error) {
	if cm.Assets == nil {
		return nil, fmt.Errorf("no assets defined in channel manifest for %s/%s", targetOS, targetArch)
	}

	platformKey := fmt.Sprintf("%s-%s", targetOS, targetArch)
	if asset, ok := cm.Assets[platformKey]; ok {
		return &asset, nil
	}

	archiveName := TargetCLIArchiveName(targetOS, targetArch)
	if asset, ok := cm.Assets[archiveName]; ok {
		return &asset, nil
	}

	// Also search values by Name
	for _, asset := range cm.Assets {
		if asset.Name == archiveName {
			return &asset, nil
		}
	}

	return nil, fmt.Errorf("no distribution artifact found in manifest for %s/%s (expected %q)", targetOS, targetArch, archiveName)
}

// FindDesktopTargetAsset finds the desktop installer or bundle matching the expected platform.
func (cm *ChannelManifest) FindDesktopTargetAsset(targetOS, targetArch, format string) (*ReleaseAsset, error) {
	if cm.Assets == nil {
		return nil, fmt.Errorf("no assets defined in channel manifest for desktop %s/%s", targetOS, targetArch)
	}

	expectedName := TargetDesktopAssetName(targetOS, targetArch, format)
	if asset, ok := cm.Assets[expectedName]; ok {
		return &asset, nil
	}

	// Search by prefix / suffix match
	for name, asset := range cm.Assets {
		if strings.EqualFold(name, expectedName) || strings.EqualFold(asset.Name, expectedName) {
			return &asset, nil
		}
	}

	// Fallback to platform key search
	for name, asset := range cm.Assets {
		switch targetOS {
		case "linux":
			if strings.HasSuffix(name, ".AppImage") && (strings.Contains(name, targetArch) || targetArch == "amd64") {
				return &asset, nil
			}
		case "windows":
			if format == "zip" || format == "portable" {
				if strings.Contains(name, "windows") && strings.HasSuffix(name, ".zip") {
					return &asset, nil
				}
			} else {
				if strings.Contains(name, "windows") && (strings.HasSuffix(name, "-installer.exe") || strings.HasSuffix(name, ".exe")) {
					return &asset, nil
				}
			}
		case "darwin":
			if strings.Contains(name, "macos") || strings.Contains(name, "darwin") {
				if format == "dmg" && strings.HasSuffix(name, ".dmg") {
					return &asset, nil
				}
				if format == "zip" && strings.HasSuffix(name, ".zip") {
					return &asset, nil
				}
				if strings.HasSuffix(name, ".dmg") || strings.HasSuffix(name, ".zip") {
					return &asset, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no desktop distribution artifact found in manifest for %s/%s (format: %s, expected %q)",
		targetOS, targetArch, format, expectedName)
}

// FindTargetAsset finds the asset matching the expected platform archive or binary in release metadata.
func (rm *ReleaseMetadata) FindTargetAsset(targetOS, targetArch string) (*ReleaseAsset, error) {
	archiveName := TargetCLIArchiveName(targetOS, targetArch)
	for i := range rm.Assets {
		if rm.Assets[i].Name == archiveName {
			asset := rm.Assets[i]
			if asset.SHA256 == "" && rm.Checksums != nil {
				asset.SHA256 = rm.Checksums[archiveName]
			}
			return &asset, nil
		}
	}
	return nil, fmt.Errorf("no distribution artifact found for %s/%s (expected %q)", targetOS, targetArch, archiveName)
}

// ParseChecksums parses a standard SHA256SUMS.txt manifest stream into a filename -> sha256 map.
func ParseChecksums(r io.Reader) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(r)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: <sha256> [* ]<filename>
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		hash := strings.ToLower(fields[0])
		if len(hash) != 64 {
			return nil, fmt.Errorf("line %d: invalid sha256 hash length (%d != 64)", lineNum, len(hash))
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return nil, fmt.Errorf("line %d: invalid hex in sha256 hash %q: %w", lineNum, hash, err)
		}

		name := strings.TrimPrefix(strings.Join(fields[1:], " "), "*")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		result[name] = hash
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading checksum manifest: %w", err)
	}

	return result, nil
}

// TargetCLIArchiveName returns the canonical archive filename for a given OS and architecture.
func TargetCLIArchiveName(targetOS, targetArch string) string {
	ext := "tar.gz"
	if targetOS == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("sendbeam-cli-%s-%s.%s", targetOS, targetArch, ext)
}

// TargetCLIBinaryName returns the executable filename for a given OS.
func TargetCLIBinaryName(targetOS string) string {
	if targetOS == "windows" {
		return "sendbeam.exe"
	}
	return "sendbeam"
}

// TargetDesktopAssetName returns the desktop bundle or installer filename for a given OS, arch, and format.
func TargetDesktopAssetName(targetOS, targetArch, format string) string {
	switch targetOS {
	case "linux":
		if format == "deb" {
			return fmt.Sprintf("sendbeam-desktop_%s.deb", targetArch)
		}
		return fmt.Sprintf("SendBeam-linux-%s.AppImage", targetArch)
	case "windows":
		if format == "zip" || format == "portable" {
			return fmt.Sprintf("SendBeam-windows-%s-portable.zip", targetArch)
		}
		return fmt.Sprintf("SendBeam-windows-%s-installer.exe", targetArch)
	case "darwin":
		if format == "zip" {
			return "SendBeam-macos-universal.zip"
		}
		return "SendBeam-macos-universal.dmg"
	default:
		return fmt.Sprintf("SendBeam-%s-%s", targetOS, targetArch)
	}
}

// CurrentPlatformArchiveName returns the expected CLI archive name for the active runtime platform.
func CurrentPlatformArchiveName() string {
	return TargetCLIArchiveName(runtime.GOOS, runtime.GOARCH)
}
