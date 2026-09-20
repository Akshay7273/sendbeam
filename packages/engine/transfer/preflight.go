package transfer

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sendbeam/wire"
)

// freeSpaceFunc reports the bytes available to unprivileged callers on the
// filesystem containing path.
type freeSpaceFunc func(path string) (int64, error)

// freeSpaceForPreflight is the free-space probe used by receive preflight.
// It is a variable so tests can inject deterministic values; production code
// always uses the platform implementation (freeSpace).
var freeSpaceForPreflight freeSpaceFunc = freeSpace

// PreflightReceive validates that a receive can be staged in destDir before
// any byte flows or any staging state is created beyond the destination
// directory itself:
//
//  1. destDir is created when missing.
//  2. destDir is writable (probe file round-trip).
//  3. the filesystem holds at least totalSize bytes available.
//
// The check is conservative: on resume it still requires the full manifest
// size, since verified partial bytes are only known later. A failed
// preflight returns a descriptive error naming what is missing (FailQuota
// for disk space, FailSinkError for directory problems) so the transfer
// fails fast instead of dying mid-write with ENOSPC in a half-staged state.
func PreflightReceive(destDir string, totalSize int64) error {
	return preflightReceive(destDir, totalSize, freeSpaceForPreflight)
}

func preflightReceive(destDir string, totalSize int64, freeSpace freeSpaceFunc) error {
	if destDir == "" {
		return wire.NewTransferError(wire.FailSinkError, "receive preflight: no destination directory configured")
	}
	if totalSize < 0 {
		return wire.NewTransferError(wire.FailSinkError, "receive preflight: negative manifest size")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return wire.NewTransferError(wire.FailSinkError,
			fmt.Sprintf("receive preflight: cannot create destination directory %q: %v", destDir, err))
	}
	// Writability probe: a temp file must round-trip through the directory.
	probe, err := os.CreateTemp(destDir, ".sendbeam-write-probe-*")
	if err != nil {
		return wire.NewTransferError(wire.FailSinkError,
			fmt.Sprintf("receive preflight: destination directory %q is not writable: %v", destDir, err))
	}
	probeName := probe.Name()
	_, _ = probe.Write([]byte("probe"))
	_ = probe.Close()
	_ = os.Remove(probeName)

	avail, err := freeSpace(destDir)
	if err != nil {
		return wire.NewTransferError(wire.FailSinkError,
			fmt.Sprintf("receive preflight: cannot query free space for %q: %v", destDir, err))
	}
	if avail < totalSize {
		return wire.NewTransferError(wire.FailQuota,
			fmt.Sprintf("receive preflight: insufficient disk space in %q: need %s, have %s available",
				destDir, humanBytes(totalSize), humanBytes(avail)))
	}
	return nil
}

// PreflightSpaceAvailable is the read-only half of receive preflight,
// suitable for consent time (before the user or policy has decided): it
// checks disk space without creating directories or probing writability.
// destDir is resolved to its nearest existing ancestor for the statfs
// query. It fails open (nil) when there is nothing meaningful to check —
// empty dir, non-positive size, no existing ancestor, or an unqueryable
// filesystem — because the full PreflightReceive in Prepare remains the
// hard guarantee and will fail closed there.
func PreflightSpaceAvailable(destDir string, totalSize int64) error {
	return preflightSpaceAvailable(destDir, totalSize, freeSpaceForPreflight)
}

func preflightSpaceAvailable(destDir string, totalSize int64, freeSpace freeSpaceFunc) error {
	if destDir == "" || totalSize <= 0 {
		return nil
	}
	probe := destDir
	for {
		if st, err := os.Stat(probe); err == nil && st.IsDir() {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return nil
		}
		probe = parent
	}
	avail, err := freeSpace(probe)
	if err != nil {
		return nil
	}
	if avail < totalSize {
		return wire.NewTransferError(wire.FailQuota,
			fmt.Sprintf("insufficient disk space in %q: need %s, have %s available",
				destDir, humanBytes(totalSize), humanBytes(avail)))
	}
	return nil
}

// humanBytes formats a byte count for preflight error messages.
func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	v := float64(n) / 1024
	u := 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	return fmt.Sprintf("%.1f %s", v, units[u])
}
