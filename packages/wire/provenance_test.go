package wire

import (
	"strings"
	"testing"
)

func validProvenance() *Provenance {
	return &Provenance{
		RoutineID:   "0123456789abcdef0123456789abcdef",
		RoutineName: "nightly backup",
		SenderLabel: "akshay-laptop",
		Trigger:     "watch",
	}
}

func TestValidateProvenance(t *testing.T) {
	if err := ValidateProvenance(nil); err != nil {
		t.Fatalf("nil provenance must be valid (one-off send), got %v", err)
	}
	if err := ValidateProvenance(validProvenance()); err != nil {
		t.Fatalf("valid provenance rejected: %v", err)
	}
	bad := []struct {
		name   string
		mutate func(*Provenance)
	}{
		{"short routine id", func(p *Provenance) { p.RoutineID = "abc" }},
		{"uppercase routine id", func(p *Provenance) { p.RoutineID = "0123456789ABCDEF0123456789ABCDEF" }},
		{"non-hex routine id", func(p *Provenance) { p.RoutineID = "0123456789abcdeg0123456789abcdef" }},
		{"empty routine name", func(p *Provenance) { p.RoutineName = "" }},
		{"empty sender label", func(p *Provenance) { p.SenderLabel = "" }},
		{"routine name too long", func(p *Provenance) { p.RoutineName = strings.Repeat("x", 257) }},
		{"sender label too long", func(p *Provenance) { p.SenderLabel = strings.Repeat("x", 257) }},
		{"unknown trigger", func(p *Provenance) { p.Trigger = "cron" }},
		{"empty trigger", func(p *Provenance) { p.Trigger = "" }},
	}
	for _, tc := range bad {
		p := validProvenance()
		tc.mutate(p)
		if err := ValidateProvenance(p); err == nil {
			t.Fatalf("%s: malformed provenance accepted", tc.name)
		}
	}
	for _, trigger := range ValidProvenanceTriggers {
		p := validProvenance()
		p.Trigger = trigger
		if err := ValidateProvenance(p); err != nil {
			t.Fatalf("trigger %q rejected: %v", trigger, err)
		}
	}
}

func TestProvenanceWireBytes(t *testing.T) {
	// Byte-exact vector: key order must match the TypeScript twin
	// (type, transferId?, contentKind?, provenance?, files, totalSize).
	m := NewManifest([]FileEntry{{
		Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
		LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
	}}, 10)
	m.Provenance = validProvenance()
	got, err := EncodeControl(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":2,"provenance":{"routineId":"0123456789abcdef0123456789abcdef","routineName":"nightly backup","senderLabel":"akshay-laptop","trigger":"watch"},"files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}`
	if string(got) != want {
		t.Fatalf("provenance manifest bytes mismatch:\n got: %s\nwant: %s", got, want)
	}
	// Round-trip: decode restores the provenance exactly.
	dec, err := DecodeControl(got)
	if err != nil {
		t.Fatal(err)
	}
	dm, ok := dec.(*Manifest)
	if !ok {
		t.Fatalf("decoded type %T, want *Manifest", dec)
	}
	if dm.Provenance == nil || *dm.Provenance != *validProvenance() {
		t.Fatalf("decoded provenance = %+v, want %+v", dm.Provenance, validProvenance())
	}
}

func TestProvenanceDecodeReencodeByteIdentical(t *testing.T) {
	// A manifest WITH provenance (what a v2.2 sender emits), decoded and
	// re-encoded, must keep byte-identical JSON: the field order and
	// optional-key placement are part of the wire contract and must match
	// the TypeScript twin in packages/protocol/src/provenance.test.ts.
	m := NewManifest([]FileEntry{{
		Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
		LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
	}}, 10)
	m.Provenance = validProvenance()
	original, err := EncodeControl(m)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeControl(original)
	if err != nil {
		t.Fatal(err)
	}
	dm, ok := dec.(*Manifest)
	if !ok {
		t.Fatalf("decoded type %T, want *Manifest", dec)
	}
	again, err := EncodeControl(dm)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(original) {
		t.Fatalf("re-encode changed manifest bytes:\n got: %s\nwant: %s", again, original)
	}
}

func TestProvenanceOmittedWhenNil(t *testing.T) {
	// A manifest without provenance must encode byte-identically to the
	// pre-provenance shape: no "provenance" key at all.
	m := NewManifest([]FileEntry{{
		Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
		LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
	}}, 10)
	got, err := EncodeControl(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "provenance") {
		t.Fatalf("nil provenance leaked into wire bytes: %s", got)
	}
	want := `{"type":2,"files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}`
	if string(got) != want {
		t.Fatalf("one-off manifest bytes changed:\n got: %s\nwant: %s", got, want)
	}
	// And it decodes with a nil provenance: an ordinary one-off send.
	dec, err := DecodeControl(got)
	if err != nil {
		t.Fatal(err)
	}
	if dm := dec.(*Manifest); dm.Provenance != nil {
		t.Fatalf("decoded provenance = %+v, want nil", dm.Provenance)
	}
}

func TestDecodeManifestRejectsBadProvenance(t *testing.T) {
	// A manifest carrying a malformed provenance fails closed at decode.
	raw := `{"type":2,"provenance":{"routineId":"not-hex","routineName":"x","senderLabel":"y","trigger":"watch"},"files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}`
	if _, err := DecodeControl([]byte(raw)); err == nil {
		t.Fatal("manifest with malformed provenance decoded without error")
	}
	raw = `{"type":2,"provenance":{"routineId":"0123456789abcdef0123456789abcdef","routineName":"x","senderLabel":"y","trigger":"cron"},"files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}`
	if _, err := DecodeControl([]byte(raw)); err == nil {
		t.Fatal("manifest with unknown provenance trigger decoded without error")
	}
}

func TestManifestFingerprintExcludesProvenance(t *testing.T) {
	files := []FileEntry{{
		Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
		LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
	}}
	plain := NewManifest(files, 10)
	labeled := NewManifest(files, 10)
	labeled.Provenance = validProvenance()
	other := NewManifest(files, 10)
	other.Provenance = &Provenance{
		RoutineID:   "ffffffffffffffffffffffffffffffff",
		RoutineName: "other routine",
		SenderLabel: "other-device",
		Trigger:     "schedule",
	}
	fpPlain, err := ManifestFingerprint(*plain)
	if err != nil {
		t.Fatal(err)
	}
	fpLabeled, err := ManifestFingerprint(*labeled)
	if err != nil {
		t.Fatal(err)
	}
	fpOther, err := ManifestFingerprint(*other)
	if err != nil {
		t.Fatal(err)
	}
	// The same bytes sent by a different routine (or by hand, with no
	// provenance at all) must fingerprint identically: provenance is a
	// display label, never file-set identity.
	if fpPlain != fpLabeled || fpLabeled != fpOther {
		t.Fatalf("fingerprint depends on provenance: %s vs %s vs %s", fpPlain, fpLabeled, fpOther)
	}
	// A malformed provenance still fails the fingerprint closed.
	bad := NewManifest(files, 10)
	bad.Provenance = &Provenance{RoutineID: "nope"}
	if _, err := ManifestFingerprint(*bad); err == nil {
		t.Fatal("fingerprint accepted a malformed provenance")
	}
}

func TestProvenanceDisplay(t *testing.T) {
	if got := validProvenance().Display(); got != "Routine: nightly backup (trigger: watch) from akshay-laptop" {
		t.Fatalf("display = %q", got)
	}
	var nilProv *Provenance
	if got := nilProv.Display(); got != "One-off send (not from a saved routine)" {
		t.Fatalf("nil display = %q", got)
	}
	if got := (&Provenance{}).Display(); got != "Routine: unnamed routine (trigger: manual) from unknown device" {
		t.Fatalf("zero display = %q", got)
	}
}
