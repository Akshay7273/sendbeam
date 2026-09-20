package transfer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendbeam/wire"
)

var errFakeIO = errors.New("fake i/o error")

// fakeFreeSpace returns a freeSpaceFunc reporting a fixed byte count.
func fakeFreeSpace(avail int64) func(string) (int64, error) {
	return func(string) (int64, error) { return avail, nil }
}

func TestPreflightReceiveRejectsEmptyDir(t *testing.T) {
	if err := PreflightReceive("", 100); err == nil {
		t.Fatal("empty dest dir should fail preflight")
	}
}

func TestPreflightReceiveCreatesAndProbesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dest")
	if err := PreflightReceive(dir, 1024); err != nil {
		t.Fatalf("preflight on fresh dir: %v", err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("preflight should create the dest dir: %v", err)
	}
}

func TestPreflightReceiveFailsWhenDirIsAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreflightReceive(f, 1024); err == nil {
		t.Fatal("dest dir that is a file should fail preflight")
	}
}

func TestPreflightReceiveChecksDiskSpace(t *testing.T) {
	dir := t.TempDir()
	if err := preflightReceive(dir, 10<<30, fakeFreeSpace(1<<30)); err == nil {
		t.Fatal("10GiB need with 1GiB free should fail preflight")
	} else if got := err.Error(); !strings.Contains(got, "insufficient disk space") {
		t.Fatalf("error should name disk space, got: %v", err)
	}
	if err := preflightReceive(dir, 1<<30, fakeFreeSpace(10<<30)); err != nil {
		t.Fatalf("1GiB need with 10GiB free should pass: %v", err)
	}
}

func TestPreflightReceiveZeroSizeManifest(t *testing.T) {
	// A zero-byte manifest still needs a writable directory.
	dir := filepath.Join(t.TempDir(), "empty-xfer")
	if err := preflightReceive(dir, 0, fakeFreeSpace(0)); err != nil {
		t.Fatalf("zero-size manifest with zero free should pass writability: %v", err)
	}
}

func TestPrepareRunsPreflight(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatalf("new destination: %v", err)
	}
	manifest := wire.Manifest{
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TotalSize:  10 << 30,
		Files: []wire.FileEntry{{
			Idx: 0, Name: "big.bin", Size: 10 << 30,
			BlockSize: 1 << 20, Blocks: 10 << 10,
			LastModified: 1,
		}},
	}
	old := freeSpaceForPreflight
	freeSpaceForPreflight = fakeFreeSpace(1 << 30)
	defer func() { freeSpaceForPreflight = old }()
	if err := d.Prepare(manifest); err == nil {
		t.Fatal("Prepare should fail preflight when disk space is short")
	} else if got := err.Error(); !strings.Contains(got, "insufficient disk space") {
		t.Fatalf("Prepare error should name disk space, got: %v", err)
	}
}

func TestPreflightSpaceAvailableResolvesAncestor(t *testing.T) {
	dir := t.TempDir()
	var probed string
	fake := func(p string) (int64, error) { probed = p; return 1 << 40, nil }
	missing := filepath.Join(dir, "no", "such", "dir")
	if err := preflightSpaceAvailable(missing, 100, fake); err != nil {
		t.Fatalf("should pass with ample space: %v", err)
	}
	if probed != dir {
		t.Fatalf("should statfs nearest existing ancestor %q, probed %q", dir, probed)
	}
}

func TestPreflightSpaceAvailableFailsOpen(t *testing.T) {
	// Unqueryable filesystem: fail open, the full preflight decides later.
	broken := func(string) (int64, error) { return 0, errFakeIO }
	if err := preflightSpaceAvailable(t.TempDir(), 100, broken); err != nil {
		t.Fatalf("unqueryable fs should fail open: %v", err)
	}
	// Empty dir and zero size: nothing to check.
	if err := preflightSpaceAvailable("", 100, fakeFreeSpace(0)); err != nil {
		t.Fatalf("empty dir should fail open: %v", err)
	}
	if err := preflightSpaceAvailable(t.TempDir(), 0, fakeFreeSpace(0)); err != nil {
		t.Fatalf("zero size should pass: %v", err)
	}
}

func TestPreflightSpaceAvailableDetectsShortage(t *testing.T) {
	dir := t.TempDir()
	err := preflightSpaceAvailable(dir, 10<<30, fakeFreeSpace(1<<30))
	if err == nil {
		t.Fatal("10GiB need with 1GiB free should fail")
	}
	te, ok := err.(*wire.TransferError)
	if !ok {
		t.Fatalf("should be a *wire.TransferError, got %T", err)
	}
	if te.Reason != wire.FailQuota {
		t.Fatalf("should be FailQuota, got %q", te.Reason)
	}
}
