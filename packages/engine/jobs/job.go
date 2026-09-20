package jobs

import (
	"sort"
	"time"

	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/wire"
)

// jobSchemaVersion is the current Job schema. Older binaries refuse (quarantine)
// records whose schema they do not understand rather than truncating them.
const jobSchemaVersion = 1

// JobStatus is the lifecycle state of a Job.
type JobStatus string

const (
	// JobDraft is a job being composed; it never dispatches.
	JobDraft JobStatus = "draft"
	// JobQueued waits for a dispatcher to pick it up.
	JobQueued JobStatus = "queued"
	// JobDispatching is actively being worked under a live lease.
	JobDispatching JobStatus = "dispatching"
	// JobPaused is suspended by the user; attempts keep their state.
	JobPaused JobStatus = "paused"
	// JobCompleted means every recipient attempt reached a terminal verified state.
	JobCompleted JobStatus = "completed"
	// JobFailed means the job is terminal with at least one failed attempt and no
	// remaining retry budget.
	JobFailed JobStatus = "failed"
	// JobCancelled was cancelled by the user; it never dispatches again.
	JobCancelled JobStatus = "cancelled"
)

// AttemptStatus is the lifecycle state of one recipient attempt.
type AttemptStatus string

const (
	// AttemptQueued waits for dispatch.
	AttemptQueued AttemptStatus = "queued"
	// AttemptActive is currently transferring under the job lease.
	AttemptActive AttemptStatus = "active"
	// AttemptInterrupted stopped before verification (crash, network loss,
	// revoked lease); it may be retried within policy.
	AttemptInterrupted AttemptStatus = "interrupted"
	// AttemptVerified completed transfer and digest verification, but the
	// receiver has not yet confirmed final save. NOT terminal: the job must
	// not report delivery until every attempt reaches completed.
	AttemptVerified AttemptStatus = "verified"
	// AttemptCompleted is verified and finalized (saved by the receiver and
	// acknowledged). Terminal: the only state that counts as delivered.
	AttemptCompleted AttemptStatus = "completed"
	// AttemptFailed is terminal for this attempt: refused, auth failure, or
	// retry budget exhausted.
	AttemptFailed AttemptStatus = "failed"
)

// JobFile binds one source file of a job: name, size, and digest. The job's
// SourceFingerprint is computed over the canonical serialization of these
// entries; if the files on disk no longer match, the job is stale and must
// not be silently resent.
type JobFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// RecipientAttempt is the per-target delivery state for one device.
type RecipientAttempt struct {
	DeviceID string `json:"deviceId"`
	Label    string `json:"label"`
	// Status is the attempt lifecycle state.
	Status AttemptStatus `json:"status"`
	// Attempts counts dispatch tries (including the in-flight one).
	Attempts int `json:"attempts"`
	// NextRetryAt is the earliest time a retry may start (RFC3339, UTC).
	// Zero means no retry scheduled.
	NextRetryAt time.Time `json:"nextRetryAt,omitempty"`
	// LastError is a human-readable, secret-free failure description.
	LastError string `json:"lastError,omitempty"`
	// BytesTransferred counts payload bytes acknowledged so far; it is
	// informational and never treated as proof of delivery.
	BytesTransferred int64 `json:"bytesTransferred,omitempty"`
	// VerifiedDigest is set once the whole-transfer digest verifies.
	VerifiedDigest string `json:"verifiedDigest,omitempty"`
	// UpdatedAt is the last state transition (RFC3339, UTC).
	UpdatedAt time.Time `json:"updatedAt"`
}

// RetryPolicy bounds redelivery of one attempt.
type RetryPolicy struct {
	// MaxAttempts caps total dispatch tries per recipient (>=1).
	MaxAttempts int `json:"maxAttempts"`
	// BaseBackoff is the delay before the first retry.
	BaseBackoff time.Duration `json:"baseBackoff"`
	// MaxBackoff caps the exponential backoff.
	MaxBackoff time.Duration `json:"maxBackoff"`
	// ExpiresAt, when non-zero, is the hard deadline: no dispatch starts after it.
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// Lease marks which process currently owns dispatch of a job.
type Lease struct {
	// Owner is "<hostname>:<pid>" of the dispatching process.
	Owner string `json:"owner"`
	// AcquiredAt and ExpiresAt bound the lease (RFC3339, UTC).
	AcquiredAt time.Time `json:"acquiredAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Job is one durable local transfer job.
type Job struct {
	SchemaVersion int    `json:"schemaVersion"`
	JobID         string `json:"jobId"`
	// CreatedAt / UpdatedAt are RFC3339 UTC timestamps.
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Status is the job lifecycle state.
	Status JobStatus `json:"status"`
	// Files is the canonical source file set.
	Files []JobFile `json:"files"`
	// SourceFingerprint binds the file set (see SourceFingerprint()).
	SourceFingerprint string `json:"sourceFingerprint"`
	// TotalSize is the sum of file sizes.
	TotalSize int64 `json:"totalSize"`
	// Attempts holds one entry per recipient device, keyed by device ID.
	Attempts []RecipientAttempt `json:"attempts"`
	// Policy bounds retries and expiry.
	Policy RetryPolicy `json:"policy"`
	// NetworkPolicy binds every attempt of this job to a network path
	// policy (V21-PR07). It is the canonical policy name ("online",
	// "prefer-local", "local-only"); empty means "online", the v2.0
	// default, so jobs written before this field existed keep their
	// semantics and their checksums (omitempty preserves the canonical
	// encoding). A job's network policy never changes implicitly: a
	// global policy change holds unsatisfiable jobs rather than
	// re-binding them, so local-only is never silently relaxed to
	// finish a transfer.
	//
	// Compatibility (no schema bump): old binaries quarantine a job that
	// carries this field because the strict store decoder rejects
	// unknown fields — a local-only job can never be silently
	// reinterpreted as online by an older reader. The checksum covers
	// this field, so flipping it after the fact also fails closed.
	NetworkPolicy string `json:"networkPolicy,omitempty"`
	// Provenance is the routine origin label (V22-PR06): which saved
	// recipe produced this job and what triggered it. Nil for ordinary
	// one-off sends. It is informational only — no secrets — and travels
	// on the wire manifest at dispatch time; the checksum covers this
	// field (omitempty preserves the canonical encoding of older jobs,
	// so no schema bump is needed and old records keep verifying).
	Provenance *wire.Provenance `json:"provenance,omitempty"`
	// Lease is non-nil while a dispatcher owns the job.
	Lease *Lease `json:"lease,omitempty"`
	// CancelledAt is set when the user cancels.
	CancelledAt time.Time `json:"cancelledAt,omitempty"`
	// Checksum covers the canonical encoding of every other field.
	Checksum string `json:"checksum"`
}

// DefaultRetryPolicy is the conservative out-of-the-box policy.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: 5,
		BaseBackoff: 30 * time.Second,
		MaxBackoff:  30 * time.Minute,
	}
}

// EffectiveNetworkPolicy returns the job's bound network policy. Empty
// (including every job written before V21-PR07) means Online, the v2.0
// behavior; the stored value is always a valid policy name because
// ValidateJob rejects anything else.
func (j Job) EffectiveNetworkPolicy() netpolicy.Policy {
	p, err := netpolicy.Parse(j.NetworkPolicy)
	if err != nil {
		return netpolicy.Online
	}
	return p
}

// ValidateJob checks structural invariants without touching the filesystem.
func ValidateJob(j Job) error {
	if j.SchemaVersion != jobSchemaVersion {
		return wire.Errorf(wire.CodeStorage, "jobs: unsupported schema version %d", j.SchemaVersion)
	}
	if !isLowerHex32(j.JobID) {
		return wire.Errorf(wire.CodeStorage, "jobs: jobId must be 32 lowercase hex characters")
	}
	switch j.Status {
	case JobDraft, JobQueued, JobDispatching, JobPaused, JobCompleted, JobFailed, JobCancelled:
	default:
		return wire.Errorf(wire.CodeStorage, "jobs: unknown job status %q", j.Status)
	}
	if len(j.Files) == 0 {
		return wire.Errorf(wire.CodeStorage, "jobs: job has no files")
	}
	seen := make(map[string]bool, len(j.Files))
	for i, f := range j.Files {
		if f.Name == "" || f.Size < 0 || f.Digest == "" {
			return wire.Errorf(wire.CodeStorage, "jobs: file %d has empty name/digest or negative size", i)
		}
		if seen[f.Name] {
			return wire.Errorf(wire.CodeStorage, "jobs: duplicate file name %q", f.Name)
		}
		seen[f.Name] = true
	}
	if j.SourceFingerprint == "" {
		return wire.Errorf(wire.CodeStorage, "jobs: missing source fingerprint")
	}
	if fp := SourceFingerprint(j.Files); fp != j.SourceFingerprint {
		return wire.Errorf(wire.CodeStorage, "jobs: source fingerprint does not match file set (corrupt or tampered)")
	}
	if len(j.Attempts) == 0 {
		return wire.Errorf(wire.CodeStorage, "jobs: job has no recipient attempts")
	}
	devSeen := make(map[string]bool, len(j.Attempts))
	for i := range j.Attempts {
		a := &j.Attempts[i]
		if a.DeviceID == "" {
			return wire.Errorf(wire.CodeStorage, "jobs: attempt %d has empty device id", i)
		}
		if devSeen[a.DeviceID] {
			return wire.Errorf(wire.CodeStorage, "jobs: duplicate attempt for device %q", a.DeviceID)
		}
		devSeen[a.DeviceID] = true
		if err := validateAttempt(*a); err != nil {
			return err
		}
	}
	if j.Policy.MaxAttempts < 1 {
		return wire.Errorf(wire.CodeStorage, "jobs: maxAttempts must be >= 1")
	}
	if _, err := netpolicy.Parse(j.NetworkPolicy); err != nil {
		return wire.Errorf(wire.CodeStorage, "jobs: invalid networkPolicy %q", j.NetworkPolicy)
	}
	if err := wire.ValidateProvenance(j.Provenance); err != nil {
		return wire.Errorf(wire.CodeStorage, "jobs: invalid provenance: %v", err)
	}
	if j.Policy.BaseBackoff < 0 || j.Policy.MaxBackoff < 0 || j.Policy.BaseBackoff > j.Policy.MaxBackoff {
		return wire.Errorf(wire.CodeStorage, "jobs: invalid backoff bounds")
	}
	if j.Lease != nil {
		if err := validateLease(*j.Lease); err != nil {
			return err
		}
	}
	// Terminal jobs must not hold a lease: a lease implies dispatch ownership,
	// which a terminal job can never have.
	switch j.Status {
	case JobCompleted, JobFailed, JobCancelled:
		if j.Lease != nil {
			return wire.Errorf(wire.CodeStorage, "jobs: terminal job must not hold a lease")
		}
	}
	if j.Status == JobCancelled && j.CancelledAt.IsZero() {
		return wire.Errorf(wire.CodeStorage, "jobs: cancelled job missing cancelledAt")
	}
	return nil
}

func validateAttempt(a RecipientAttempt) error {
	switch a.Status {
	case AttemptQueued, AttemptActive, AttemptInterrupted, AttemptVerified, AttemptCompleted, AttemptFailed:
	default:
		return wire.Errorf(wire.CodeStorage, "jobs: unknown attempt status %q for device %q", a.Status, a.DeviceID)
	}
	if a.Attempts < 0 {
		return wire.Errorf(wire.CodeStorage, "jobs: negative attempt count for device %q", a.DeviceID)
	}
	if a.Status == AttemptActive && a.Attempts < 1 {
		return wire.Errorf(wire.CodeStorage, "jobs: active attempt for device %q has no recorded try", a.DeviceID)
	}
	if a.VerifiedDigest != "" && !isLowerHex64(a.VerifiedDigest) {
		return wire.Errorf(wire.CodeStorage, "jobs: bad verified digest for device %q", a.DeviceID)
	}
	return nil
}

func validateLease(l Lease) error {
	if l.Owner == "" {
		return wire.Errorf(wire.CodeStorage, "jobs: lease missing owner")
	}
	if l.AcquiredAt.IsZero() || l.ExpiresAt.IsZero() {
		return wire.Errorf(wire.CodeStorage, "jobs: lease missing timestamps")
	}
	if !l.ExpiresAt.After(l.AcquiredAt) {
		return wire.Errorf(wire.CodeStorage, "jobs: lease expiry not after acquisition")
	}
	return nil
}

// SourceFingerprint is the canonical SHA-256 identity of a job's source file
// set: sorted by name, each entry "name\x00size\x00digest\x00", domain-separated.
// Byte-identical inputs always produce byte-identical fingerprints.
func SourceFingerprint(files []JobFile) string {
	cp := make([]JobFile, len(files))
	copy(cp, files)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Name < cp[j].Name })
	h := newJobHasher()
	for _, f := range cp {
		h.writeString(f.Name)
		h.writeInt64(f.Size)
		h.writeString(f.Digest)
	}
	return h.sum()
}

// BackoffForAttempt returns the delay before attempt number n (1-based):
// base * 2^(n-1), capped at max. n < 1 returns base.
func BackoffForAttempt(p RetryPolicy, n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := p.BaseBackoff
	for i := 1; i < n && d < p.MaxBackoff; i++ {
		d *= 2
		if d > p.MaxBackoff || d < 0 {
			d = p.MaxBackoff
			break
		}
	}
	if d > p.MaxBackoff {
		d = p.MaxBackoff
	}
	return d
}

// Retryable reports whether the attempt may be dispatched again at time now:
// not terminal, tries remain, backoff elapsed, and the job has not expired.
func (a RecipientAttempt) Retryable(p RetryPolicy, now time.Time) bool {
	switch a.Status {
	case AttemptQueued, AttemptInterrupted:
	default:
		return false
	}
	if a.Attempts >= p.MaxAttempts {
		return false
	}
	if !p.ExpiresAt.IsZero() && !now.Before(p.ExpiresAt) {
		return false
	}
	if !a.NextRetryAt.IsZero() && now.Before(a.NextRetryAt) {
		return false
	}
	return true
}

// terminalAttempt reports whether the attempt reached a final state.
// Verified is deliberately NOT terminal: the digest verified but the receiver
// has not yet finalized (saved) the transfer, so the crash window between
// receiver-commit and sender-ack must still be reconciled — never reported
// as delivered.
func terminalAttempt(s AttemptStatus) bool {
	return s == AttemptCompleted || s == AttemptFailed
}

// TransitionAttempt moves one attempt to a new status, enforcing the state
// machine. Invalid transitions fail closed with an error; the attempt is
// left unchanged.
func TransitionAttempt(a *RecipientAttempt, to AttemptStatus, now time.Time) error {
	allowed := map[AttemptStatus][]AttemptStatus{
		AttemptQueued:      {AttemptActive, AttemptFailed},
		AttemptActive:      {AttemptInterrupted, AttemptVerified, AttemptFailed},
		AttemptInterrupted: {AttemptQueued, AttemptFailed},
		AttemptVerified:    {AttemptCompleted, AttemptFailed},
		AttemptCompleted:   {},
		AttemptFailed:      {AttemptQueued}, // explicit operator re-queue only
	}
	ok := false
	for _, s := range allowed[a.Status] {
		if s == to {
			ok = true
			break
		}
	}
	if !ok {
		return wire.Errorf(wire.CodeStorage,
			"jobs: illegal attempt transition %q -> %q for device %q", a.Status, to, a.DeviceID)
	}
	a.Status = to
	a.UpdatedAt = now.UTC()
	return nil
}

// DeriveJobStatus recomputes the job status from its attempts.
//
// Delivery honesty: a job is JobCompleted only when every attempt reached
// AttemptCompleted. Attempts stuck at AttemptVerified (digest verified but
// receiver finalization unconfirmed) keep the job non-terminal — the
// receiver-commit/sender-ack crash window is reconciled or reported as
// uncertain, never invented as delivered.
func DeriveJobStatus(j *Job) JobStatus {
	if j.Status == JobCancelled || j.Status == JobDraft || j.Status == JobPaused {
		return j.Status
	}
	allDone := true
	allTerminal := true
	anyFailed := false
	anyProgress := false
	for i := range j.Attempts {
		a := &j.Attempts[i]
		if a.Status != AttemptCompleted {
			allDone = false
		}
		if !terminalAttempt(a.Status) {
			allTerminal = false
		}
		if a.Status == AttemptFailed {
			anyFailed = true
		}
		switch a.Status {
		case AttemptQueued, AttemptInterrupted, AttemptActive, AttemptVerified:
			anyProgress = true
		}
	}
	switch {
	case allDone:
		return JobCompleted
	case allTerminal && anyFailed:
		return JobFailed
	case anyProgress:
		if j.Status == JobDispatching {
			return JobDispatching
		}
		return JobQueued
	default:
		return j.Status
	}
}

// MarkInterruptedAfterCrash re-queues every attempt left active under a stale
// lease as interrupted. It never marks anything delivered: a crash window can
// only move active work back to interrupted, never forward.
func MarkInterruptedAfterCrash(j *Job, now time.Time) int {
	n := 0
	for i := range j.Attempts {
		a := &j.Attempts[i]
		if a.Status == AttemptActive {
			a.Status = AttemptInterrupted
			a.UpdatedAt = now.UTC()
			n++
		}
	}
	if n > 0 {
		j.Lease = nil
		j.UpdatedAt = now.UTC()
		j.Status = DeriveJobStatus(j)
	}
	return n
}

// QueueJob moves a draft job to queued so a dispatcher may pick it up. Only
// draft jobs may be queued; every other state fails closed. The outbox calls
// this exactly once at enqueue time — jobs never return to draft.
func QueueJob(j *Job, now time.Time) error {
	now = now.UTC()
	if j.Status != JobDraft {
		return wire.Errorf(wire.CodeStorage,
			"jobs: cannot queue job in status %q (only draft jobs may be queued)", j.Status)
	}
	j.Status = JobQueued
	j.UpdatedAt = now
	return nil
}

// NewJob constructs a validated job in draft state.
func NewJob(jobID string, files []JobFile, attempts []RecipientAttempt, policy RetryPolicy, now time.Time) (Job, error) {
	if !isLowerHex32(jobID) {
		return Job{}, wire.Errorf(wire.CodeStorage, "jobs: jobId must be 32 lowercase hex characters")
	}
	var total int64
	for _, f := range files {
		total += f.Size
	}
	now = now.UTC()
	j := Job{
		SchemaVersion:     jobSchemaVersion,
		JobID:             jobID,
		CreatedAt:         now,
		UpdatedAt:         now,
		Status:            JobDraft,
		Files:             files,
		SourceFingerprint: SourceFingerprint(files),
		TotalSize:         total,
		Attempts:          attempts,
		Policy:            policy,
	}
	for i := range j.Attempts {
		if j.Attempts[i].Status == "" {
			j.Attempts[i].Status = AttemptQueued
		}
		if j.Attempts[i].UpdatedAt.IsZero() {
			j.Attempts[i].UpdatedAt = now
		}
	}
	if err := ValidateJob(j); err != nil {
		return Job{}, err
	}
	return j, nil
}
