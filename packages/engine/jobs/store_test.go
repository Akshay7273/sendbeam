package jobs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *JobStore {
	t.Helper()
	s, err := OpenJobStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenJobStore: %v", err)
	}
	fixed := testNow
	s.now = func() time.Time { return fixed }
	return s
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s := openTestStore(t)
	j := mustJob(t)
	j.Status = JobQueued
	if err := s.Save(j); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := s.Load(j.JobID)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if got.JobID != j.JobID || got.Status != JobQueued || len(got.Attempts) != 2 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.SourceFingerprint != j.SourceFingerprint {
		t.Fatal("fingerprint changed across round trip")
	}
	// File mode must be private.
	fi, err := os.Stat(s.Path(j.JobID))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("job file mode %o is group/other readable", fi.Mode().Perm())
	}
}

func TestLoadMissing(t *testing.T) {
	s := openTestStore(t)
	_, ok, err := s.Load(strings.Repeat("b", 32))
	if err != nil || ok {
		t.Fatalf("missing load: ok=%v err=%v", ok, err)
	}
}

func TestCorruptFailsClosed(t *testing.T) {
	s := openTestStore(t)
	j := mustJob(t)
	if err := s.Save(j); err != nil {
		t.Fatal(err)
	}
	path := s.Path(j.JobID)

	// Snapshot the pristine encoding once: every case mutates from the good
	// bytes, never from a previous case's corruption.
	pristine, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func([]byte) []byte{
		"torn":     func(b []byte) []byte { return b[:len(b)/2] },
		"tampered": func(b []byte) []byte { out := append([]byte(nil), b...); out[50] ^= 0xff; return out },
		"trailing": func(b []byte) []byte { return append(append([]byte(nil), b...), "{}"...) },
		"empty":    func(b []byte) []byte { return nil },
		"not-json": func(b []byte) []byte { return []byte("hello") },
		"bad-sum":  func(b []byte) []byte { return []byte(strings.Replace(string(b), `"checksum":"`, `"checksum":"0`, 1)) },
		"unknown":  func(b []byte) []byte { return []byte(strings.Replace(string(b), `"jobId":`, `"evil":1,"jobId":`, 1)) },
		"future": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"schemaVersion":1`, `"schemaVersion":99`, 1))
		},
		"mismatch": func(b []byte) []byte { return []byte(strings.Replace(string(b), j.JobID, strings.Repeat("c", 32), 1)) },
	}
	for name, mutate := range cases {
		if err := os.WriteFile(path, mutate(pristine), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Load(j.JobID); err == nil {
			t.Fatalf("%s: corrupt job loaded without error", name)
		}
		// The corrupt file must still exist: nothing is auto-deleted.
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: corrupt job file was deleted", name)
		}
	}

	// Restore a good file; List must show it again.
	if err := s.Save(j); err != nil {
		t.Fatal(err)
	}
	entries, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].JobOK {
		t.Fatalf("list after restore: %+v", entries)
	}
}

func TestListSurfacesBadJob(t *testing.T) {
	s := openTestStore(t)
	good := mustJob(t)
	if err := s.Save(good); err != nil {
		t.Fatal(err)
	}
	badID := strings.Repeat("d", 32)
	if err := os.WriteFile(filepath.Join(s.Dir(), badID+".json"), []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("list len = %d, want 2", len(entries))
	}
	// Sorted by job id; bad (dddd...) sorts after good (aaaa...).
	if entries[0].JobID != good.JobID || !entries[0].JobOK {
		t.Fatalf("good entry wrong: %+v", entries[0])
	}
	if entries[1].JobOK || entries[1].Err == "" {
		t.Fatalf("bad entry not surfaced: %+v", entries[1])
	}
}

func TestDiscardIdempotent(t *testing.T) {
	s := openTestStore(t)
	j := mustJob(t)
	if err := s.Save(j); err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(j.JobID); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if _, ok, _ := s.Load(j.JobID); ok {
		t.Fatal("job still present after discard")
	}
	if err := s.Discard(j.JobID); err != nil {
		t.Fatalf("second Discard: %v", err)
	}
	if err := s.Discard("nope"); err == nil {
		t.Fatal("invalid id discard accepted")
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	s := openTestStore(t)
	j := mustJob(t)
	j.Attempts[0].Status = AttemptStatus("bogus")
	if err := s.Save(j); err == nil {
		t.Fatal("invalid job saved")
	}
	// Nothing must have been written.
	if _, err := os.Stat(s.Path(j.JobID)); !os.IsNotExist(err) {
		t.Fatal("invalid job file exists")
	}
}

func TestJobStoreDirOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(jobsDirEnv, dir)
	got, err := JobStoreDir()
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(dir)
	if got != abs {
		t.Fatalf("dir = %q, want %q", got, abs)
	}
}
