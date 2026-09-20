package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sendbeam/wire"
)

// TestSaveHandoffTextValidation covers the deliberate-Save path guards: kind,
// size, UTF-8, destination, and no-overwrite collision naming.
func TestSaveHandoffTextValidation(t *testing.T) {
	s := &TransferService{}
	dir := t.TempDir()

	if _, err := s.SaveHandoffText("file", "hello", dir); err == nil {
		t.Fatal("expected kind validation error")
	}
	if _, err := s.SaveHandoffText(wire.ContentKindText, "", dir); err == nil {
		t.Fatal("expected empty payload error")
	}
	if _, err := s.SaveHandoffText(wire.ContentKindText, strings.Repeat("a", wire.MaxHandoffBytes+1), dir); err == nil {
		t.Fatal("expected oversize payload error")
	}
	if _, err := s.SaveHandoffText(wire.ContentKindText, "bad\xffutf8", dir); err == nil {
		t.Fatal("expected UTF-8 validation error")
	}
	if _, err := s.SaveHandoffText(wire.ContentKindText, "hello", ""); err == nil {
		t.Fatal("expected destination error")
	}

	got, err := s.SaveHandoffText(wire.ContentKindText, "hello world", dir)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if filepath.Base(got) != "text.txt" {
		t.Fatalf("expected text.txt, got %s", got)
	}
	data, err := os.ReadFile(got)
	if err != nil || string(data) != "hello world" {
		t.Fatalf("saved content mismatch: %q, %v", data, err)
	}

	// A second save must not overwrite the first file.
	got2, err := s.SaveHandoffText(wire.ContentKindText, "second", dir)
	if err != nil {
		t.Fatalf("second save: %v", err)
	}
	if got2 == got {
		t.Fatal("second save overwrote the first file")
	}
	data, err = os.ReadFile(got)
	if err != nil || string(data) != "hello world" {
		t.Fatalf("first file was modified: %q, %v", data, err)
	}

	got3, err := s.SaveHandoffText(wire.ContentKindLink, "https://example.com", dir)
	if err != nil {
		t.Fatalf("link save: %v", err)
	}
	if filepath.Base(got3) != "link.txt" {
		t.Fatalf("expected link.txt, got %s", got3)
	}
}

// TestOpenHandoffLinkValidation covers the backend re-validation gate. The
// happy path launches a browser and is intentionally not exercised here.
func TestOpenHandoffLinkValidation(t *testing.T) {
	s := &TransferService{}
	for _, raw := range []string{
		"",
		"   ",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"ftp://example.com/x",
		"https://exam ple.com",
		strings.Repeat("a", wire.MaxHandoffBytes+1),
	} {
		if err := s.OpenHandoffLink(raw); err == nil {
			t.Fatalf("expected rejection for %q", raw)
		}
	}
}

// TestSaveHandoffTextNeverOverwrites proves the save is atomic: an existing
// file keeps its bytes (O_EXCL create), and the handoff lands on a
// non-colliding name instead.
func TestSaveHandoffTextNeverOverwrites(t *testing.T) {
	s := &TransferService{}
	dir := t.TempDir()
	victim := filepath.Join(dir, "text.txt")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.SaveHandoffText(wire.ContentKindText, "handoff", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got == victim {
		t.Fatalf("save reused an existing path %q", victim)
	}
	if raw, err := os.ReadFile(victim); err != nil || string(raw) != "original" {
		t.Fatalf("existing file was modified: %q %v", raw, err)
	}
	if raw, err := os.ReadFile(got); err != nil || string(raw) != "handoff" {
		t.Fatalf("saved payload wrong: %q %v", raw, err)
	}
}

// TestSaveHandoffTextCollisionExhaustion proves the collision loop fails
// closed instead of overwriting when every candidate name is taken.
func TestSaveHandoffTextCollisionExhaustion(t *testing.T) {
	s := &TransferService{}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "text.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 1000; i++ {
		p := filepath.Join(dir, "text-"+itoa(i)+".txt")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SaveHandoffText(wire.ContentKindText, "handoff", dir); err == nil {
		t.Fatal("expected exhaustion error, got nil")
	}
}

// TestOpenHandoffLinkRejectsHostlessURL covers the net/url host gate: a bare
// "https://" has the right scheme but no host and must be refused.
func TestOpenHandoffLinkRejectsHostlessURL(t *testing.T) {
	s := &TransferService{}
	if err := s.OpenHandoffLink("https://"); err == nil {
		t.Fatal("expected rejection for hostless URL")
	}
	if err := s.OpenHandoffLink("http://?x=1"); err == nil {
		t.Fatal("expected rejection for hostless URL with query")
	}
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
