package jobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sendbeam/wire"
)

// jobsDirEnv overrides the jobs directory (tests).
const jobsDirEnv = "SENDBEAM_JOBS_DIR"

// JobStoreDir resolves the jobs directory: SENDBEAM_JOBS_DIR if set, else
// os.UserConfigDir()/sendbeam/jobs. Resolution failure fails closed.
func JobStoreDir() (string, error) {
	if dir := os.Getenv(jobsDirEnv); dir != "" {
		return filepath.Abs(dir)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", wire.Errorf(wire.CodeStorage, "jobs: resolve config dir: %v", err)
	}
	return filepath.Join(base, "sendbeam", "jobs"), nil
}

// JobStore owns the jobs directory: job load/save with atomic replace,
// listing, and the explicit discard operation.
type JobStore struct {
	dir string
	// now is the clock for timestamps; tests inject a fixed one.
	now func() time.Time
	// write writes a job atomically; tests inject failures (no sleeps).
	write func(path string, j Job) error
}

// OpenJobStore prepares (creating if needed) the jobs directory and resolves
// it absolutely so a later chdir cannot redirect writes.
func OpenJobStore(dir string) (*JobStore, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "jobs: resolve jobs dir: %v", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "jobs: create %s: %v", abs, err)
	}
	return &JobStore{
		dir:   abs,
		now:   time.Now,
		write: writeJobAtomic,
	}, nil
}

// Dir returns the resolved absolute jobs directory.
func (s *JobStore) Dir() string { return s.dir }

// Path returns the job file path for one job id.
func (s *JobStore) Path(jobID string) string {
	return filepath.Join(s.dir, jobID+".json")
}

// Load reads, decodes, validates, and checksum-verifies the job. It returns
// (job, false, nil) when no job exists, and fails closed (error) when the
// file exists but is corrupt, torn, tampered, or from an unsupported schema
// version. Nothing is deleted on a load error.
func (s *JobStore) Load(jobID string) (Job, bool, error) {
	if !isLowerHex32(jobID) {
		return Job{}, false, wire.Errorf(wire.CodeStorage, "jobs: invalid job id %q", jobID)
	}
	data, err := os.ReadFile(s.Path(jobID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Job{}, false, nil
		}
		return Job{}, true, wire.Errorf(wire.CodeStorage, "jobs: read job: %v", err)
	}
	j, err := decodeJob(data)
	if err != nil {
		return Job{}, true, err
	}
	if j.JobID != jobID {
		return Job{}, true, wire.Errorf(wire.CodeStorage,
			"jobs: job id mismatch: file %q holds %q (corrupt or tampered)", jobID, j.JobID)
	}
	return j, true, nil
}

// Save validates and writes a job atomically through the configured writer.
func (s *JobStore) Save(j Job) error {
	j.UpdatedAt = s.now().UTC()
	if err := ValidateJob(j); err != nil {
		return err
	}
	return s.write(s.Path(j.JobID), j)
}

// JobEntry is a list-view summary of one stored job.
type JobEntry struct {
	JobID       string
	JobOK       bool
	Err         string
	Status      JobStatus
	Files       int
	TotalSize   int64
	Recipients  int
	Completed   int
	Failed      int
	HasLease    bool
	LeaseOwner  string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Fingerprint string
}

// List scans the store and returns every job (valid or unreadable). A single
// bad job never hides the others and is never deleted.
func (s *JobStore) List() ([]JobEntry, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "jobs: list %s: %v", s.dir, err)
	}
	var out []JobEntry
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if id == "" {
			continue
		}
		j, ok, loadErr := s.Load(id)
		if loadErr != nil || !ok {
			msg := ""
			if loadErr != nil {
				msg = loadErr.Error()
			}
			out = append(out, JobEntry{JobID: id, JobOK: false, Err: msg})
			continue
		}
		var completed, failed int
		for _, a := range j.Attempts {
			switch a.Status {
			case AttemptCompleted, AttemptVerified:
				completed++
			case AttemptFailed:
				failed++
			}
		}
		e := JobEntry{
			JobID:       j.JobID,
			JobOK:       true,
			Status:      j.Status,
			Files:       len(j.Files),
			TotalSize:   j.TotalSize,
			Recipients:  len(j.Attempts),
			Completed:   completed,
			Failed:      failed,
			CreatedAt:   j.CreatedAt,
			UpdatedAt:   j.UpdatedAt,
			Fingerprint: j.SourceFingerprint,
		}
		if j.Lease != nil {
			e.HasLease = true
			e.LeaseOwner = j.Lease.Owner
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JobID < out[j].JobID })
	return out, nil
}

// Discard removes one job, idempotently and bounded to that job: it never
// touches other jobs. Only explicit user action calls this.
func (s *JobStore) Discard(jobID string) error {
	if !isLowerHex32(jobID) {
		return wire.Errorf(wire.CodeStorage, "jobs: invalid job id %q", jobID)
	}
	if err := os.Remove(s.Path(jobID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return wire.Errorf(wire.CodeStorage, "jobs: discard job: %v", err)
	}
	return nil
}

// DiscardAll discards every job. It is the explicit --all surface and never
// runs implicitly.
func (s *JobStore) DiscardAll() error {
	entries, err := s.List()
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if err := s.Discard(entry.JobID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// marshalJobJSON encodes with no HTML escaping and no trailing newline, so the
// encoding is byte-identical to the wire codec and journal conventions.
func marshalJobJSON(j Job) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(j); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// unmarshalStrictJob decodes exactly one JSON value, rejecting unknown fields
// and trailing data so an unexpected field or a torn tail fails closed.
func unmarshalStrictJob(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

// encodeJob produces the canonical file encoding: the checksum covers the
// exact bytes of every other field.
func encodeJob(j Job) ([]byte, error) {
	if err := ValidateJob(j); err != nil {
		return nil, err
	}
	j.Checksum = ""
	body, err := marshalJobJSON(j)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	j.Checksum = hex.EncodeToString(sum[:])
	return marshalJobJSON(j)
}

// decodeJob parses and verifies a stored job: strict schema, checksum over the
// exact body, and full structural validation. Schema versions other than the
// current one fail closed (quarantined, never migrated silently).
func decodeJob(data []byte) (Job, error) {
	// Peek the schema version with a lenient decoder (the strict decoder below
	// would reject the full document's other fields here).
	var head struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&head); err != nil {
		return Job{}, wire.Errorf(wire.CodeStorage, "jobs: malformed job: %v", err)
	}
	if head.SchemaVersion != jobSchemaVersion {
		return Job{}, wire.Errorf(wire.CodeStorage,
			"jobs: unsupported job schema version %d (quarantined; refusing to read)", head.SchemaVersion)
	}
	var j Job
	if err := unmarshalStrictJob(data, &j); err != nil {
		return Job{}, wire.Errorf(wire.CodeStorage, "jobs: decode job: %v", err)
	}
	stored := j.Checksum
	if !isLowerHex64(stored) {
		return Job{}, wire.Errorf(wire.CodeStorage, "jobs: malformed checksum")
	}
	j.Checksum = ""
	body, err := marshalJobJSON(j)
	if err != nil {
		return Job{}, wire.Errorf(wire.CodeStorage, "jobs: re-encode job: %v", err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != stored {
		return Job{}, wire.Errorf(wire.CodeStorage, "jobs: checksum mismatch (corrupt or tampered)")
	}
	j.Checksum = stored
	if err := ValidateJob(j); err != nil {
		return Job{}, err
	}
	return j, nil
}

// writeJobAtomic writes the canonical encoding through the atomic-replacement
// primitive: a temp file in the same directory, fsynced, closed, then renamed
// over the job, so a crash leaves either the old job or the complete new one.
// The temp file inherits CreateTemp's 0600 mode; the parent dir is fsynced
// afterwards (best effort).
func writeJobAtomic(path string, j Job) error {
	data, err := encodeJob(j)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return wire.Errorf(wire.CodeStorage, "jobs: create temp: %v", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "jobs: write temp: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "jobs: sync temp: %v", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "jobs: close temp: %v", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "jobs: replace: %v", err)
	}
	syncJobsDir(dir)
	return nil
}

// syncJobsDir fsyncs a directory so a rename inside it is durable. POSIX
// only; filesystems that reject directory sync are best-effort.
func syncJobsDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}
