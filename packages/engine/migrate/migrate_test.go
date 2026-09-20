package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

// TestFreshStateBootstrapsGeneration2 is the clean-install proof: an empty
// config dir migrates to the current generation with no user state harmed.
func TestFreshStateBootstrapsGeneration2(t *testing.T) {
	dir := t.TempDir()
	isolateJobsDir(t, dir)
	rep, err := Run(context.Background(), dir)
	if err != nil {
		t.Fatalf("Run on empty dir: %v", err)
	}
	if rep.ToVersion != CurrentVersion {
		t.Fatalf("ToVersion = %d, want %d", rep.ToVersion, CurrentVersion)
	}
	if len(rep.Applied) == 0 {
		t.Fatal("expected migrations to be applied on fresh state")
	}
	if got := readMarkerVersion(t, dir); got != CurrentVersion {
		t.Fatalf("marker version = %d, want %d", got, CurrentVersion)
	}
	// Trust store must have been initialized empty; jobs dir must exist.
	if _, err := os.Stat(filepath.Join(dir, "trust.json")); err != nil {
		t.Fatalf("trust.json not initialized: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "jobs")); err != nil || !fi.IsDir() {
		t.Fatalf("jobs dir not bootstrapped: %v", err)
	}
}

// TestRerunIsIdempotent proves a second startup performs no work.
func TestRerunIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	isolateJobsDir(t, dir)
	if _, err := Run(context.Background(), dir); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	rep, err := Run(context.Background(), dir)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !rep.AlreadyCurrent {
		t.Fatal("second Run should report AlreadyCurrent")
	}
	if len(rep.Applied) != 0 {
		t.Fatalf("second Run applied %v, want none", rep.Applied)
	}
}

// TestNewerStateIsQuarantined: state written by a newer generation must be
// refused without modification — older binaries never truncate it.
func TestNewerStateIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	isolateJobsDir(t, dir)
	writeTestMarker(t, dir, CurrentVersion+1)
	sentinel := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(sentinel, []byte(`{"version":2,"devices":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(sentinel)
	_, err := Run(context.Background(), dir)
	if !errors.Is(err, ErrNewerState) {
		t.Fatalf("Run err = %v, want ErrNewerState", err)
	}
	after, _ := os.ReadFile(sentinel)
	if string(before) != string(after) {
		t.Fatal("quarantined state was modified")
	}
}

// TestFailingMigrationRollsBack: a migration that fails after partially
// writing must restore the pre-migration backup and keep the old marker.
func TestFailingMigrationRollsBack(t *testing.T) {
	dir := t.TempDir()
	isolateJobsDir(t, dir)
	victim := filepath.Join(dir, "trust.json")
	original := []byte(`{"version":2,"updated_at":"2026-01-01T00:00:00Z","devices":[]}`)
	if err := os.WriteFile(victim, original, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := Migration{
		Name:    "poison",
		Touches: []string{"trust.json"},
		Apply: func(ctx context.Context, configDir string) error {
			if err := os.WriteFile(victim, []byte("torn-write"), 0o600); err != nil {
				return err
			}
			return errors.New("boom: simulated migration failure")
		},
	}
	_, err := runWithMigrations(context.Background(), dir, []Migration{bad})
	if err == nil {
		t.Fatal("expected migration failure")
	}
	restored, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("victim file missing after rollback: %v", rerr)
	}
	if string(restored) != string(original) {
		t.Fatalf("rollback did not restore original: got %q", restored)
	}
	if _, serr := os.Stat(markerPath(dir)); !os.IsNotExist(serr) {
		t.Fatal("marker must not be written when a migration fails")
	}
}

// TestLegacyTrustV1UpgradesToV2 proves the real v1.9 -> v2.0 trust store
// upgrade runs through the migration runner without data loss.
func TestLegacyTrustV1UpgradesToV2(t *testing.T) {
	dir := t.TempDir()
	isolateJobsDir(t, dir)
	// Build a genuine v1 payload: a valid trust record inside a version-1
	// envelope, exactly what a v1.9 install left on disk.
	id, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rec := wire.TrustRecord{
		DeviceID:          id.DeviceID,
		PublicKey:         id.PublicKeyHex(),
		LocalLabel:        "old-phone",
		PairCredentialRef: "cred-legacy",
		Capabilities:      []string{wire.CapTransferV2},
		FirstSeenAt:       now,
		LastSeenAt:        now,
	}
	legacy, err := json.Marshal(struct {
		Version   int                `json:"version"`
		UpdatedAt time.Time          `json:"updated_at"`
		Devices   []wire.TrustRecord `json:"devices"`
	}{Version: 1, UpdatedAt: now, Devices: []wire.TrustRecord{rec}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Applied) == 0 {
		t.Fatal("expected trust-store migration to apply")
	}
	data, err := os.ReadFile(filepath.Join(dir, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("upgraded trust.json unparsable: %v", err)
	}
	if payload.Version != 2 {
		t.Fatalf("trust.json version = %d, want 2", payload.Version)
	}
	if got := readMarkerVersion(t, dir); got != CurrentVersion {
		t.Fatalf("marker = %d, want %d", got, CurrentVersion)
	}
}

// TestCorruptTrustStoreFailsClosed: a corrupt trust.json must fail the
// migration without deleting or truncating the file.
func TestCorruptTrustStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	isolateJobsDir(t, dir)
	victim := filepath.Join(dir, "trust.json")
	original := []byte(`{"version":2,"devices":[{broken`)
	if err := os.WriteFile(victim, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), dir); err == nil {
		t.Fatal("expected failure on corrupt trust.json")
	}
	restored, _ := os.ReadFile(victim)
	if string(restored) != string(original) {
		t.Fatal("corrupt trust.json was modified instead of failing closed")
	}
}

// TestUnsupportedJobSchemaQuarantines: a job file from a newer schema
// generation must stop the migration rather than be silently dropped.
func TestUnsupportedJobSchemaQuarantines(t *testing.T) {
	dir := t.TempDir()
	isolateJobsDir(t, dir)
	jobsDir := filepath.Join(dir, "jobs")
	if err := os.MkdirAll(jobsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	jobID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	future := `{"schemaVersion":999,"jobId":"` + jobID + `","checksum":"x"}`
	if err := os.WriteFile(filepath.Join(jobsDir, jobID+".json"), []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), dir)
	if err == nil {
		t.Fatal("expected quarantine failure on future job schema")
	}
	if _, serr := os.Stat(filepath.Join(jobsDir, jobID+".json")); serr != nil {
		t.Fatal("quarantined job file must not be deleted")
	}
}

// isolateJobsDir points the jobs store at a temp dir so migration tests never
// touch the real user jobs directory.
func isolateJobsDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("SENDBEAM_JOBS_DIR", filepath.Join(dir, "jobs"))
}

func readMarkerVersion(t *testing.T, dir string) int {
	t.Helper()
	data, err := os.ReadFile(markerPath(dir))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	var m stateMarker
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse marker: %v", err)
	}
	return m.Version
}

func writeTestMarker(t *testing.T, dir string, v int) {
	t.Helper()
	data, _ := json.Marshal(stateMarker{Version: v})
	if err := os.WriteFile(markerPath(dir), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
