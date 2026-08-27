package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyDesktopUpdate_AppImage_HappyPath(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")

	oldContent := []byte("AppImage-v1.4.0-content")
	if err := os.WriteFile(targetAppImage, oldContent, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newContent := []byte("AppImage-v1.5.0-updated-content")
	expectedHash := sha256Hex(newContent)

	opts := DesktopApplyOptions{
		TargetPath:     targetAppImage,
		TargetOS:       "linux",
		TargetArch:     "amd64",
		Format:         "appimage",
		ExpectedSHA256: expectedHash,
		ArchiveName:    "SendBeam-linux-amd64.AppImage",
	}

	res, err := ApplyDesktopUpdate(context.Background(), bytes.NewReader(newContent), opts)
	if err != nil {
		t.Fatalf("ApplyDesktopUpdate failed: %v", err)
	}

	if res == nil || !res.Applied || !res.NeedsRestart {
		t.Fatalf("unexpected result: %+v", res)
	}

	// Verify target file was replaced
	got, err := os.ReadFile(targetAppImage)
	if err != nil {
		t.Fatalf("ReadFile after update: %v", err)
	}
	if !bytes.Equal(got, newContent) {
		t.Fatalf("content mismatch: got %q, expected %q", string(got), string(newContent))
	}

	// Verify backup is cleaned up
	if _, err := os.Stat(targetAppImage + ".old"); !os.IsNotExist(err) {
		t.Errorf("backup file still exists: %v", err)
	}
}

func TestApplyDesktopUpdate_AppImage_ChecksumMismatch(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")

	oldContent := []byte("AppImage-v1.4.0-content")
	if err := os.WriteFile(targetAppImage, oldContent, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newContent := []byte("AppImage-tampered-content")
	opts := DesktopApplyOptions{
		TargetPath:     targetAppImage,
		TargetOS:       "linux",
		TargetArch:     "amd64",
		Format:         "appimage",
		ExpectedSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		ArchiveName:    "SendBeam-linux-amd64.AppImage",
	}

	_, err := ApplyDesktopUpdate(context.Background(), bytes.NewReader(newContent), opts)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}

	// Original AppImage must be untouched
	got, _ := os.ReadFile(targetAppImage)
	if !bytes.Equal(got, oldContent) {
		t.Fatalf("target was modified on checksum failure: %q", string(got))
	}
}

func TestApplyDesktopUpdate_MacAppBundle_HappyPath(t *testing.T) {
	tempDir := t.TempDir()
	targetApp := filepath.Join(tempDir, "SendBeam.app")

	if err := os.MkdirAll(filepath.Join(targetApp, "Contents", "MacOS"), 0755); err != nil {
		t.Fatalf("MkdirAll targetApp: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetApp, "Contents", "MacOS", "sendbeam"), []byte("mac-binary-v1.4.0"), 0755); err != nil {
		t.Fatalf("WriteFile mac binary: %v", err)
	}

	// Create zip payload with new SendBeam.app
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("SendBeam.app/Contents/MacOS/sendbeam")
	_, _ = w.Write([]byte("mac-binary-v1.5.0-updated"))
	_ = zw.Close()

	zipData := buf.Bytes()
	expectedHash := sha256Hex(zipData)

	opts := DesktopApplyOptions{
		TargetPath:     targetApp,
		TargetOS:       "darwin",
		TargetArch:     "universal",
		Format:         "app",
		ExpectedSHA256: expectedHash,
		ArchiveName:    "SendBeam-macos-universal.zip",
	}

	res, err := ApplyDesktopUpdate(context.Background(), bytes.NewReader(zipData), opts)
	if err != nil {
		t.Fatalf("ApplyDesktopUpdate mac failed: %v", err)
	}

	if res == nil || !res.Applied || !res.NeedsRestart {
		t.Fatalf("unexpected mac result: %+v", res)
	}

	// Verify updated binary
	got, err := os.ReadFile(filepath.Join(targetApp, "Contents", "MacOS", "sendbeam"))
	if err != nil {
		t.Fatalf("ReadFile after mac update: %v", err)
	}
	if string(got) != "mac-binary-v1.5.0-updated" {
		t.Fatalf("mac app binary content mismatch: got %q", string(got))
	}

	// Verify backup is cleaned up
	if _, err := os.Stat(targetApp + ".old"); !os.IsNotExist(err) {
		t.Errorf("backup mac app bundle still exists: %v", err)
	}
}

func TestApplyDesktopUpdate_WindowsInstaller_HappyPath(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam-desktop.exe")

	if err := os.WriteFile(targetBinary, []byte("windows-exe"), 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	installerPayload := []byte("NSIS-installer-executable-payload")
	expectedHash := sha256Hex(installerPayload)

	opts := DesktopApplyOptions{
		TargetPath:     targetBinary,
		TargetOS:       "windows",
		TargetArch:     "amd64",
		Format:         "installer",
		ExpectedSHA256: expectedHash,
		ArchiveName:    "SendBeam-windows-amd64-installer.exe",
	}

	res, err := ApplyDesktopUpdate(context.Background(), bytes.NewReader(installerPayload), opts)
	if err != nil {
		t.Fatalf("ApplyDesktopUpdate windows failed: %v", err)
	}

	if res == nil || !res.Applied || !res.NeedsRestart || res.InstallerPath == "" {
		t.Fatalf("unexpected windows installer result: %+v", res)
	}

	defer func() { _ = os.Remove(res.InstallerPath) }()

	staged, err := os.ReadFile(res.InstallerPath)
	if err != nil {
		t.Fatalf("reading staged installer %s: %v", res.InstallerPath, err)
	}
	if !bytes.Equal(staged, installerPayload) {
		t.Fatalf("staged installer content mismatch: got %q", string(staged))
	}
}

func TestApplyDesktopUpdate_PackageManager_FailsClosed(t *testing.T) {
	t.Setenv("SENDBEAM_PACKAGE_MANAGER", "deb")

	tempDir := t.TempDir()
	targetApp := filepath.Join(tempDir, "SendBeam.AppImage")
	_ = os.WriteFile(targetApp, []byte("appimage"), 0755)

	opts := DesktopApplyOptions{
		TargetPath: targetApp,
		Format:     "appimage",
	}

	res, err := ApplyDesktopUpdate(context.Background(), bytes.NewReader([]byte("new")), opts)
	if !errors.Is(err, ErrManagedByPackageManager) {
		t.Fatalf("expected ErrManagedByPackageManager, got %v", err)
	}
	if res == nil || res.ManagedByPkgManager != "deb" {
		t.Fatalf("expected ManagedByPkgManager=deb, got %+v", res)
	}
}

func TestDetectPackageManager(t *testing.T) {
	t.Run("env override", func(t *testing.T) {
		t.Setenv("SENDBEAM_PACKAGE_MANAGER", "brew")
		if pm := DetectPackageManager("/some/random/path"); pm != "brew" {
			t.Errorf("expected brew, got %q", pm)
		}
	})

	t.Run("clean standalone", func(t *testing.T) {
		t.Setenv("SENDBEAM_PACKAGE_MANAGER", "")
		if pm := DetectPackageManager("/home/user/Downloads/SendBeam.AppImage"); pm != "" {
			t.Errorf("expected empty string for standalone AppImage, got %q", pm)
		}
	})
}
