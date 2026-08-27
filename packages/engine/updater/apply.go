// Package updater implements cross-platform update checks, signature verification, and atomic self-updates.
package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ApplyOptions configures the atomic binary replacement transaction.
type ApplyOptions struct {
	TargetPath     string
	TargetOS       string
	ExpectedSHA256 string
	ArchiveName    string
}

// DesktopApplyOptions configures the desktop application update transaction.
type DesktopApplyOptions struct {
	TargetPath     string // Path to running binary, .AppImage, or .app bundle
	TargetOS       string
	TargetArch     string
	Format         string // "appimage", "zip", "installer", "app"
	ExpectedSHA256 string
	ArchiveName    string
	InstallerArgs  []string // Arguments to pass to installer if installer format
}

// DesktopApplyResult describes the outcome of a desktop apply operation.
type DesktopApplyResult struct {
	Applied             bool
	NeedsRestart        bool
	InstallerPath       string
	InstallerArgs       []string
	ManagedByPkgManager string
}

// DetectPackageManager detects whether the application is managed by an OS package manager.
func DetectPackageManager(execPath string) string {
	if pm := os.Getenv("SENDBEAM_PACKAGE_MANAGER"); pm != "" {
		return strings.ToLower(strings.TrimSpace(pm))
	}

	cleanPath := filepath.Clean(execPath)

	// Check Debian package paths
	if runtime.GOOS == "linux" {
		if strings.HasPrefix(cleanPath, "/usr/bin/") ||
			strings.HasPrefix(cleanPath, "/usr/share/sendbeam-desktop") ||
			strings.HasPrefix(cleanPath, "/opt/sendbeam-desktop") {
			// If dpkg status directory exists, treat as deb managed
			if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
				return "deb"
			}
		}
	}

	// Check Homebrew paths on macOS
	if runtime.GOOS == "darwin" {
		if strings.Contains(cleanPath, "/Cellar/") ||
			strings.HasPrefix(cleanPath, "/opt/homebrew/") ||
			strings.HasPrefix(cleanPath, "/usr/local/Caskroom/") {
			return "brew"
		}
	}

	// Check Windows WinGet / Scoop paths
	if runtime.GOOS == "windows" {
		if strings.Contains(strings.ToLower(cleanPath), "winget") ||
			strings.Contains(strings.ToLower(cleanPath), "scoop") {
			return "winget"
		}
	}

	return ""
}

// ResolveDesktopTarget finds the active desktop container / executable to update.
func ResolveDesktopTarget() (targetPath, format string) {
	// 1. Check AppImage on Linux
	if appImg := os.Getenv("APPIMAGE"); appImg != "" {
		return appImg, "appimage"
	}

	execPath, err := os.Executable()
	if err != nil || execPath == "" {
		return "", ""
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}

	if runtime.GOOS == "linux" && strings.HasSuffix(execPath, ".AppImage") {
		return execPath, "appimage"
	}

	// 2. Check macOS .app bundle
	if runtime.GOOS == "darwin" {
		if idx := strings.Index(execPath, ".app/Contents/MacOS"); idx != -1 {
			appBundle := execPath[:idx+4]
			return appBundle, "app"
		}
	}

	// 3. Windows or standalone desktop binary
	if runtime.GOOS == "windows" {
		return execPath, "installer"
	}

	return execPath, "binary"
}

// ApplyDesktopUpdate applies an update to the desktop application with rollback safety.
func ApplyDesktopUpdate(ctx context.Context, r io.Reader, opts DesktopApplyOptions) (*DesktopApplyResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	targetPath := opts.TargetPath
	if targetPath == "" {
		var detectedFormat string
		targetPath, detectedFormat = ResolveDesktopTarget()
		if opts.Format == "" {
			opts.Format = detectedFormat
		}
	}

	if targetPath == "" {
		return nil, errors.New("cannot determine desktop application path for update")
	}

	// Package manager check
	if pm := DetectPackageManager(targetPath); pm != "" {
		return &DesktopApplyResult{
			Applied:             false,
			ManagedByPkgManager: pm,
		}, fmt.Errorf("%w (%s)", ErrManagedByPackageManager, pm)
	}

	// Buffer stream while verifying SHA-256
	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)
	payload, err := io.ReadAll(tee)
	if err != nil {
		return nil, fmt.Errorf("reading update stream: %w", err)
	}

	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if opts.ExpectedSHA256 != "" && !strings.EqualFold(actualSHA256, opts.ExpectedSHA256) {
		return nil, fmt.Errorf("%w: expected %s, computed %s", ErrChecksumMismatch, opts.ExpectedSHA256, actualSHA256)
	}

	switch opts.Format {
	case "installer":
		// Stage installer into temp directory
		tmpDir := os.TempDir()
		instName := fmt.Sprintf("sendbeam-setup-%x.exe", randomBytes(8))
		instPath := filepath.Join(tmpDir, instName)

		if err := os.WriteFile(instPath, payload, 0755); err != nil {
			return nil, fmt.Errorf("staging installer to %s: %w", instPath, err)
		}

		args := opts.InstallerArgs
		if len(args) == 0 {
			args = []string{"/S"} // Silent / automated install by default
		}

		return &DesktopApplyResult{
			Applied:       true,
			NeedsRestart:  true,
			InstallerPath: instPath,
			InstallerArgs: args,
		}, nil

	case "appimage", "binary":
		// In-place atomic swap
		return applyInPlaceFile(ctx, targetPath, payload)

	case "app":
		// macOS .app bundle directory swap
		return applyMacAppBundle(ctx, targetPath, payload, opts.ArchiveName)

	default:
		// Default to archive extraction / binary swap
		applyOpts := ApplyOptions{
			TargetPath:     targetPath,
			TargetOS:       opts.TargetOS,
			ExpectedSHA256: opts.ExpectedSHA256,
			ArchiveName:    opts.ArchiveName,
		}
		if err := ApplyUpdate(ctx, bytes.NewReader(payload), applyOpts); err != nil {
			return nil, err
		}
		return &DesktopApplyResult{
			Applied:      true,
			NeedsRestart: true,
		}, nil
	}
}

func applyInPlaceFile(_ context.Context, targetPath string, payload []byte) (*DesktopApplyResult, error) {
	targetDir := filepath.Dir(targetPath)
	stagingPath := filepath.Join(targetDir, fmt.Sprintf(".%s.tmp-%x", filepath.Base(targetPath), randomBytes(8)))
	backupPath := targetPath + ".old"

	if err := os.WriteFile(stagingPath, payload, 0755); err != nil {
		return nil, fmt.Errorf("writing staging binary %s: %w", stagingPath, err)
	}
	defer func() {
		_ = os.Remove(stagingPath)
	}()

	if err := os.Chmod(stagingPath, 0755); err != nil {
		return nil, fmt.Errorf("setting permissions on staging file: %w", err)
	}

	// Move existing file to backup
	_ = os.Remove(backupPath)
	if err := os.Rename(targetPath, backupPath); err != nil {
		return nil, fmt.Errorf("creating backup %s: %w", backupPath, err)
	}

	// Atomic swap
	if err := os.Rename(stagingPath, targetPath); err != nil {
		_ = os.Rename(backupPath, targetPath) // Rollback
		return nil, fmt.Errorf("atomic swap failed (rolled back): %w", err)
	}

	// Post-swap validation
	fi, err := os.Stat(targetPath)
	if err != nil || fi.Size() == 0 {
		_ = os.Rename(backupPath, targetPath) // Rollback
		return nil, fmt.Errorf("validation failed on updated binary (rolled back): %v", err)
	}

	_ = os.Remove(backupPath)

	return &DesktopApplyResult{
		Applied:      true,
		NeedsRestart: true,
	}, nil
}

func applyMacAppBundle(_ context.Context, targetAppPath string, payload []byte, _ string) (*DesktopApplyResult, error) {
	parentDir := filepath.Dir(targetAppPath)
	stagingDir := filepath.Join(parentDir, fmt.Sprintf(".%s.tmp-%x", filepath.Base(targetAppPath), randomBytes(8)))
	backupDir := targetAppPath + ".old"

	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return nil, fmt.Errorf("creating staging app bundle directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stagingDir)
	}()

	// Unpack zip into stagingDir
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("opening mac app zip payload: %w", err)
	}

	for _, f := range zr.File {
		cleanName := filepath.Clean(f.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			continue
		}

		destPath := filepath.Join(stagingDir, cleanName)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, f.Mode()); err != nil {
				return nil, fmt.Errorf("creating directory %s: %w", destPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return nil, fmt.Errorf("creating parent for %s: %w", destPath, err)
		}

		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("opening zip file %s: %w", f.Name, err)
		}

		dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, f.Mode())
		if err != nil {
			_ = rc.Close()
			return nil, fmt.Errorf("creating destination file %s: %w", destPath, err)
		}

		_, copyErr := io.Copy(dst, rc)
		_ = dst.Close()
		_ = rc.Close()
		if copyErr != nil {
			return nil, fmt.Errorf("extracting file %s: %w", destPath, copyErr)
		}
	}

	// Locate unpacked .app folder inside stagingDir
	extractedApp := stagingDir
	entries, err := os.ReadDir(stagingDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
				extractedApp = filepath.Join(stagingDir, e.Name())
				break
			}
		}
	}

	// Backup active bundle
	_ = os.RemoveAll(backupDir)
	if err := os.Rename(targetAppPath, backupDir); err != nil {
		return nil, fmt.Errorf("creating backup app bundle %s: %w", backupDir, err)
	}

	// Atomic swap
	if err := os.Rename(extractedApp, targetAppPath); err != nil {
		_ = os.Rename(backupDir, targetAppPath) // Rollback
		return nil, fmt.Errorf("atomic app bundle swap failed (rolled back): %w", err)
	}

	// Validate post-swap
	if _, err := os.Stat(targetAppPath); err != nil {
		_ = os.Rename(backupDir, targetAppPath) // Rollback
		return nil, fmt.Errorf("validation failed on updated app bundle (rolled back): %v", err)
	}

	_ = os.RemoveAll(backupDir)

	return &DesktopApplyResult{
		Applied:      true,
		NeedsRestart: true,
	}, nil
}

// ApplyUpdate downloads, verifies, and replaces the target executable file.
func ApplyUpdate(ctx context.Context, r io.Reader, opts ApplyOptions) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if opts.TargetPath == "" {
		return errors.New("target executable path is required")
	}

	targetDir := filepath.Dir(opts.TargetPath)
	stagingFile := filepath.Join(targetDir, fmt.Sprintf(".%s.tmp-%x", filepath.Base(opts.TargetPath), randomBytes(8)))
	backupFile := opts.TargetPath + ".old"

	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	payload, err := io.ReadAll(tee)
	if err != nil {
		return fmt.Errorf("reading update stream: %w", err)
	}

	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if opts.ExpectedSHA256 != "" && !strings.EqualFold(actualSHA256, opts.ExpectedSHA256) {
		return fmt.Errorf("%w: expected %s, computed %s", ErrChecksumMismatch, opts.ExpectedSHA256, actualSHA256)
	}

	expectedBinaryName := TargetCLIBinaryName(opts.TargetOS)
	if opts.TargetOS == "" {
		expectedBinaryName = TargetCLIBinaryName(runtime.GOOS)
	}

	binaryBytes, err := extractExecutable(payload, opts.ArchiveName, expectedBinaryName)
	if err != nil {
		return fmt.Errorf("extracting binary from update archive: %w", err)
	}

	if err := os.WriteFile(stagingFile, binaryBytes, 0755); err != nil {
		return fmt.Errorf("writing staging binary %s: %w", stagingFile, err)
	}
	defer func() {
		_ = os.Remove(stagingFile)
	}()

	if runtime.GOOS != "windows" {
		if err := os.Chmod(stagingFile, 0755); err != nil {
			return fmt.Errorf("setting permissions on staging file: %w", err)
		}
	}

	_ = os.Remove(backupFile)
	if err := os.Rename(opts.TargetPath, backupFile); err != nil {
		return fmt.Errorf("backing up active binary: %w", err)
	}

	if err := os.Rename(stagingFile, opts.TargetPath); err != nil {
		_ = os.Rename(backupFile, opts.TargetPath)
		return fmt.Errorf("atomic binary swap failed (rolled back): %w", err)
	}

	fi, err := os.Stat(opts.TargetPath)
	if err != nil || fi.Size() == 0 {
		_ = os.Rename(backupFile, opts.TargetPath)
		return fmt.Errorf("validation failed on updated binary (rolled back): %v", err)
	}

	_ = os.Remove(backupFile)

	return nil
}

func extractExecutable(payload []byte, archiveName, targetBinaryName string) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".tar.gz") || strings.HasSuffix(archiveName, ".tgz") {
		return extractFromTarGz(payload, targetBinaryName)
	}
	if strings.HasSuffix(archiveName, ".zip") {
		return extractFromZip(payload, targetBinaryName)
	}

	// Try tar.gz first, then zip
	if b, err := extractFromTarGz(payload, targetBinaryName); err == nil {
		return b, nil
	}
	if b, err := extractFromZip(payload, targetBinaryName); err == nil {
		return b, nil
	}

	// If direct binary without archive encapsulation
	if len(payload) > 4 {
		return payload, nil
	}

	return nil, fmt.Errorf("unsupported or corrupted archive format: %s", archiveName)
}

func extractFromTarGz(payload []byte, targetName string) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar reading: %w", err)
		}

		baseName := filepath.Base(hdr.Name)
		if hdr.Typeflag == tar.TypeReg && (baseName == targetName || strings.HasPrefix(baseName, "sendbeam")) {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("%w: %q in tar.gz archive", ErrBinaryNotFoundInArchive, targetName)
}

func extractFromZip(payload []byte, targetName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("zip reader: %w", err)
	}

	for _, f := range zr.File {
		baseName := filepath.Base(f.Name)
		if !f.FileInfo().IsDir() && (baseName == targetName || strings.HasPrefix(baseName, "sendbeam")) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			data, readErr := io.ReadAll(rc)
			_ = rc.Close()
			if readErr != nil {
				return nil, readErr
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("%w: %q in zip archive", ErrBinaryNotFoundInArchive, targetName)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
