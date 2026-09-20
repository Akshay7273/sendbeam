package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A second desktop instance launched with share paths must be able to hand
// them to the running instance instead of silently dropping them.
func TestForwardPathsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	info, ln, err := WriteForwardInfo(dir)
	if err != nil {
		t.Fatalf("WriteForwardInfo: %v", err)
	}
	defer func() { _ = ln.Close() }()

	got := make(chan []string, 1)
	go ServeForward(ln, info, func(paths []string) { got <- paths })

	want := []string{filepath.Join(dir, "a.txt"), filepath.Join(dir, "b folder")}
	if err := ForwardPaths(info, want); err != nil {
		t.Fatalf("ForwardPaths: %v", err)
	}
	select {
	case paths := <-got:
		if len(paths) != len(want) || paths[0] != want[0] || paths[1] != want[1] {
			t.Fatalf("forwarded paths = %v, want %v", paths, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not receive forwarded paths")
	}
}

func TestForwardPathsRejectsBadToken(t *testing.T) {
	dir := t.TempDir()
	info, ln, err := WriteForwardInfo(dir)
	if err != nil {
		t.Fatalf("WriteForwardInfo: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go ServeForward(ln, info, func([]string) {})

	info.Token = "wrong-token"
	if err := ForwardPaths(info, []string{"/tmp/x"}); err == nil {
		t.Fatal("ForwardPaths with wrong token succeeded, want error")
	}
}

func TestForwardInfoFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := WriteForwardInfo(dir); err != nil {
		t.Fatalf("WriteForwardInfo: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, ForwardInfoFileName))
	if err != nil {
		t.Fatalf("stat forward info: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("forward info mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestForwardPathsValidation(t *testing.T) {
	dir := t.TempDir()
	info, ln, err := WriteForwardInfo(dir)
	if err != nil {
		t.Fatalf("WriteForwardInfo: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go ServeForward(ln, info, func([]string) { t.Error("handler must not run for invalid request") })

	tooMany := make([]string, MaxForwardPaths+1)
	for i := range tooMany {
		tooMany[i] = "/tmp/x"
	}
	if err := ForwardPaths(info, tooMany); err == nil {
		t.Fatal("oversized forward request accepted, want error")
	}
	if err := ForwardPaths(info, []string{"/tmp/has\x00nul"}); err == nil {
		t.Fatal("NUL-byte path accepted, want error")
	}
}

func TestSharePathsFromArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"no args", []string{"sendbeam-desktop"}, nil},
		{"flags skipped", []string{"sendbeam-desktop", "--hidden", "/tmp/a.txt"}, []string{"/tmp/a.txt"}},
		{"double dash passthrough", []string{"sendbeam-desktop", "--", "--weird-name"}, []string{"--weird-name"}},
		{"file urls", []string{"sendbeam-desktop", "file:///tmp/a%20b.txt"}, []string{"/tmp/a b.txt"}},
		{"blank dropped", []string{"sendbeam-desktop", "  ", "/tmp/a"}, []string{"/tmp/a"}},
		{"multiple", []string{"sendbeam-desktop", "/a", "/b", "/c"}, []string{"/a", "/b", "/c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SharePathsFromArgs(tc.args)
			if len(got) != len(tc.want) {
				t.Fatalf("SharePathsFromArgs(%v) = %v, want %v", tc.args, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("SharePathsFromArgs(%v) = %v, want %v", tc.args, got, tc.want)
				}
			}
		})
	}
}
