package outbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/sendbeam/wire"
)

// sourcesFileVersion versions the sidecar schema independently of the Job
// schema. Older outbox binaries refuse unknown versions rather than guessing.
const sourcesFileVersion = 1

// sourcesRecord binds a job to the absolute source paths it was enqueued
// from. Dispatch re-expands these paths and re-fingerprints them; any
// mismatch fails the job instead of silently resending changed sources.
type sourcesRecord struct {
	Version int      `json:"version"`
	Paths   []string `json:"paths"`
}

// sourcesPath returns the sidecar path for a job. The jobID is validated so
// a corrupt store listing cannot escape the jobs directory. The ".sources"
// suffix (no ".json") keeps the jobs store's "*.json" listing from mistaking
// the sidecar for a job file.
func sourcesPath(dir, jobID string) (string, error) {
	if !isLowerHex32(jobID) {
		return "", wire.Errorf(wire.CodeStorage, "outbox: invalid job id %q", jobID)
	}
	return filepath.Join(dir, jobID+".sources"), nil
}

func isLowerHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// writeSourcesFile atomically records the source paths (mode 0600).
func writeSourcesFile(dir, jobID string, paths []string) (string, error) {
	p, err := sourcesPath(dir, jobID)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(sourcesRecord{Version: sourcesFileVersion, Paths: paths})
	if err != nil {
		return "", wire.Errorf(wire.CodeStorage, "outbox: cannot encode sources for job %q: %v", jobID, err)
	}
	tmp, err := os.CreateTemp(dir, ".sources-*")
	if err != nil {
		return "", wire.Errorf(wire.CodeStorage, "outbox: cannot stage sources for job %q: %v", jobID, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", wire.Errorf(wire.CodeStorage, "outbox: cannot write sources for job %q: %v", jobID, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", wire.Errorf(wire.CodeStorage, "outbox: cannot close sources for job %q: %v", jobID, err)
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		_ = os.Remove(tmpName)
		return "", wire.Errorf(wire.CodeStorage, "outbox: cannot protect sources for job %q: %v", jobID, err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		_ = os.Remove(tmpName)
		return "", wire.Errorf(wire.CodeStorage, "outbox: cannot install sources for job %q: %v", jobID, err)
	}
	syncOutboxDir(dir)
	return p, nil
}

// readSourcesFile loads and validates the recorded source paths.
func readSourcesFile(dir, jobID string) ([]string, error) {
	p, err := sourcesPath(dir, jobID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "outbox: cannot read sources for job %q: %v", jobID, err)
	}
	var rec sourcesRecord
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "outbox: corrupt sources for job %q: %v", jobID, err)
	}
	if rec.Version != sourcesFileVersion {
		return nil, wire.Errorf(wire.CodeStorage, "outbox: unsupported sources version %d for job %q", rec.Version, jobID)
	}
	if len(rec.Paths) == 0 {
		return nil, wire.Errorf(wire.CodeStorage, "outbox: empty sources for job %q", jobID)
	}
	return rec.Paths, nil
}

// syncOutboxDir fsyncs the directory so a rename survives a crash. Best
// effort: a sync failure is not fatal to the write itself.
func syncOutboxDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
