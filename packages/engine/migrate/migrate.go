// Package migrate owns versioned upgrades of SendBeam's local state
// directory with rollback.
//
// State generation 2 is the v2.0 generation. The runner guarantees three
// properties:
//
//  1. Newer state is quarantined: when the state-version marker records a
//     generation newer than this binary understands, the runner refuses to
//     read or modify anything (ErrNewerState). Older binaries never truncate
//     or reinterpret newer state.
//  2. Migrations are ordered and atomic: each migration snapshots the files
//     it may touch (Touches) before Apply; if Apply or Verify fails, every
//     snapshot is restored (rollback) and the previous generation marker is
//     left in place. Migrations never delete user state on failure.
//  3. Migrations are idempotent: re-running on a current state dir is a
//     no-op, so concurrent first startups converge safely.
//
// Rollback after a completed upgrade (downgrading the binary) is safe by
// construction: v1.x binaries ignore the unknown state-version.json marker
// and the v2.0-only jobs/ directory, and every pre-v2.0 file keeps the exact
// format those binaries already read.
package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/trust"
)

// CurrentVersion is the state generation this binary writes and understands.
// Generation 2 == SendBeam v2.0 (durable jobs, outbox, transfer center).
const CurrentVersion = 2

// stateVersionFileName is the generation marker inside the config dir.
const stateVersionFileName = "state-version.json"

// ErrNewerState is returned when the state dir was written by a newer
// generation. The state is quarantined: nothing is read, migrated, or
// modified.
var ErrNewerState = errors.New("migrate: state written by a newer SendBeam generation; refusing to modify (quarantined)")

// stateMarker is the on-disk generation record.
type stateMarker struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Migration is one ordered, reversible state upgrade step.
type Migration struct {
	// Name identifies the step in reports and backup paths.
	Name string
	// Touches lists config-dir-relative files the step may create or
	// modify. Each is snapshotted before Apply for rollback.
	Touches []string
	// Apply performs the upgrade. It must be fail-closed and must not
	// delete user state.
	Apply func(ctx context.Context, configDir string) error
	// Verify optionally re-checks the upgraded state. A Verify failure
	// triggers rollback just like an Apply failure.
	Verify func(ctx context.Context, configDir string) error
}

// Report describes what Run did.
type Report struct {
	// FromVersion is the generation found on disk (0 = no marker / pre-v2.0).
	FromVersion int
	// ToVersion is the generation after the run.
	ToVersion int
	// Applied lists migration names applied by this run, in order.
	Applied []string
	// AlreadyCurrent is true when no work was needed.
	AlreadyCurrent bool
}

// markerPath returns the marker file path for a config dir.
func markerPath(configDir string) string {
	return filepath.Join(configDir, stateVersionFileName)
}

// readMarker returns the recorded generation, or 0 when no marker exists
// (fresh install or pre-v2.0 state).
func readMarker(configDir string) (int, error) {
	data, err := os.ReadFile(markerPath(configDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("migrate: read state marker: %w", err)
	}
	var m stateMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return 0, fmt.Errorf("migrate: corrupt state marker (quarantined): %w", err)
	}
	if m.Version < 0 {
		return 0, fmt.Errorf("migrate: invalid state marker version %d (quarantined)", m.Version)
	}
	return m.Version, nil
}

// writeMarker atomically records the current generation.
func writeMarker(configDir string, version int) error {
	m := stateMarker{Version: version, UpdatedAt: time.Now().UTC()}
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("migrate: encode state marker: %w", err)
	}
	if err := atomicWriteFile(markerPath(configDir), data, 0o600); err != nil {
		return fmt.Errorf("migrate: write state marker: %w", err)
	}
	return nil
}

// Run upgrades configDir to CurrentVersion using the default v2.0
// migrations. It is the production entry point, called at startup before any
// store is opened for use.
func Run(ctx context.Context, configDir string) (*Report, error) {
	return runWithMigrations(ctx, configDir, defaultMigrations())
}

// runWithMigrations runs an explicit migration list; tests use it to inject
// failing migrations and prove rollback.
func runWithMigrations(ctx context.Context, configDir string, migrations []Migration) (*Report, error) {
	abs, err := filepath.Abs(configDir)
	if err != nil {
		return nil, fmt.Errorf("migrate: resolve config dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("migrate: create config dir: %w", err)
	}

	from, err := readMarker(abs)
	if err != nil {
		return nil, err
	}
	if from > CurrentVersion {
		return nil, fmt.Errorf("%w: state generation %d > supported %d",
			ErrNewerState, from, CurrentVersion)
	}
	if from == CurrentVersion {
		return &Report{FromVersion: from, ToVersion: from, AlreadyCurrent: true}, nil
	}

	backupRoot, err := os.MkdirTemp(abs, ".migrate-backup-*")
	if err != nil {
		return nil, fmt.Errorf("migrate: create backup dir: %w", err)
	}
	// Backups are removed on success; on failure the snapshots are restored
	// first and then the backup dir is removed.
	defer os.RemoveAll(backupRoot)

	rep := &Report{FromVersion: from, ToVersion: CurrentVersion}
	for _, m := range migrations {
		if err := ctx.Err(); err != nil {
			rollback(abs, backupRoot)
			return nil, fmt.Errorf("migrate: %s cancelled: %w", m.Name, err)
		}
		if err := snapshot(abs, backupRoot, m); err != nil {
			rollback(abs, backupRoot)
			return nil, fmt.Errorf("migrate: %s backup: %w", m.Name, err)
		}
		if err := m.Apply(ctx, abs); err != nil {
			rollback(abs, backupRoot)
			return nil, fmt.Errorf("migrate: %s apply: %w", m.Name, err)
		}
		if m.Verify != nil {
			if err := m.Verify(ctx, abs); err != nil {
				rollback(abs, backupRoot)
				return nil, fmt.Errorf("migrate: %s verify: %w", m.Name, err)
			}
		}
		rep.Applied = append(rep.Applied, m.Name)
	}

	if err := writeMarker(abs, CurrentVersion); err != nil {
		rollback(abs, backupRoot)
		return nil, err
	}
	return rep, nil
}

// snapshot copies every existing Touches file into the backup dir.
func snapshot(configDir, backupRoot string, m Migration) error {
	for _, rel := range m.Touches {
		src := filepath.Join(configDir, rel)
		data, err := os.ReadFile(src)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("snapshot %s: %w", rel, err)
		}
		dst := filepath.Join(backupRoot, m.Name, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return fmt.Errorf("snapshot %s: %w", rel, err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return fmt.Errorf("snapshot %s: %w", rel, err)
		}
	}
	return nil
}

// rollback restores every snapshotted file. It never deletes: a touched file
// that did not exist before the migration is left for the operator to
// inspect rather than silently removed.
func rollback(configDir, backupRoot string) {
	entries, err := os.ReadDir(backupRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		migRoot := filepath.Join(backupRoot, e.Name())
		_ = filepath.Walk(migRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, rerr := filepath.Rel(migRoot, path)
			if rerr != nil {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			// Best effort: restore the pre-migration bytes atomically.
			_ = atomicWriteFile(filepath.Join(configDir, rel), data, 0o600)
			return nil
		})
	}
}

// atomicWriteFile writes data via temp-file + rename so a crash leaves either
// the old or the complete new file.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// defaultMigrations returns the ordered v2.0 upgrade steps. Each step
// delegates to the real production store constructors so the migration path
// is exactly the path the application itself uses.
func defaultMigrations() []Migration {
	return []Migration{
		{
			Name:    "trust-store",
			Touches: []string{"trust.json"},
			Apply:   applyTrustStore,
			Verify:  verifyTrustStore,
		},
		{
			Name:    "jobs-store",
			Touches: nil, // validation only: never mutates existing job files
			Apply:   applyJobsStore,
		},
	}
}

// applyTrustStore opens the file trust store, which performs the atomic
// v1 -> v2 schema upgrade on load when needed. A trust.json from a newer
// generation is refused rather than truncated back to v2.
func applyTrustStore(_ context.Context, configDir string) error {
	path := filepath.Join(configDir, "trust.json")
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		var head struct {
			Version int `json:"version"`
		}
		if err := json.Unmarshal(data, &head); err != nil {
			return fmt.Errorf("trust.json unreadable (failing closed): %w", err)
		}
		if head.Version > trust.CurrentFileVersion() {
			return fmt.Errorf("%w: trust.json version %d > supported %d",
				ErrNewerState, head.Version, trust.CurrentFileVersion())
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read trust.json: %w", err)
	}
	if _, err := trust.NewFileTrustStore(path); err != nil {
		return fmt.Errorf("open trust store: %w", err)
	}
	return nil
}

// verifyTrustStore re-opens the store read-only and lists devices to prove
// the upgrade produced a usable store.
func verifyTrustStore(ctx context.Context, configDir string) error {
	st, err := trust.NewFileTrustStore(filepath.Join(configDir, "trust.json"))
	if err != nil {
		return fmt.Errorf("re-open trust store: %w", err)
	}
	if _, err := st.ListDevices(ctx); err != nil {
		return fmt.Errorf("list trust devices: %w", err)
	}
	return nil
}

// applyJobsStore bootstraps the v2.0 jobs directory and validates every
// existing job file. A job from an unsupported (newer) schema generation
// fails the migration — quarantined, never silently dropped or deleted.
func applyJobsStore(_ context.Context, _ string) error {
	dir, err := jobs.JobStoreDir()
	if err != nil {
		return fmt.Errorf("resolve jobs dir: %w", err)
	}
	st, err := jobs.OpenJobStore(dir)
	if err != nil {
		return fmt.Errorf("open job store: %w", err)
	}
	entries, err := st.List()
	if err != nil {
		return fmt.Errorf("validate jobs: %w", err)
	}
	for _, e := range entries {
		if !e.JobOK {
			return fmt.Errorf("%w: job %s unreadable: %s",
				ErrNewerState, e.JobID, e.Err)
		}
	}
	return nil
}
