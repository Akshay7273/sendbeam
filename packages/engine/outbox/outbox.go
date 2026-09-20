package outbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

// RecipientRef identifies one trusted device to deliver to. The DeviceID is
// the trust-store device ID; the Label is human-readable and informational.
// Cryptographic binding to the intended peer happens at dispatch time, when
// the production sender re-resolves the trust record — never from this label.
type RecipientRef struct {
	DeviceID string
	Label    string
}

// SendOutcome is the sanitized result of one production send attempt. Error
// must be secret-free (no codes, paths, IPs, or key material).
type SendOutcome struct {
	Status           transfer.BroadcastStatus
	Error            string
	Digest           string // whole-transfer hex digest when Status is ok
	BytesTransferred int64
}

// SendFunc performs the real transfer for one due attempt. paths are the
// recorded absolute source paths, re-verified by the outbox before the call.
// The implementation must bind the attempt's DeviceID to the authenticated
// peer via the trust store; it must not trust job metadata for identity.
type SendFunc func(ctx context.Context, job jobs.Job, attempt jobs.RecipientAttempt, paths []string) SendOutcome

// DispatchOptions tunes one dispatch pass.
type DispatchOptions struct {
	// LeaseTTL bounds dispatch ownership of a job; zero selects jobs.DefaultLeaseTTL.
	LeaseTTL time.Duration
	// Concurrency bounds how many jobs dispatch in parallel; <=1 is
	// sequential. The SendFunc must be safe for concurrent use when >1.
	Concurrency int
}

// AttemptReport describes what one dispatch pass did to one attempt.
type AttemptReport struct {
	JobID    string
	DeviceID string
	Label    string
	From     jobs.AttemptStatus
	To       jobs.AttemptStatus
	Outcome  transfer.BroadcastStatus
	Error    string
}

// DispatchReport summarizes one DispatchOnce pass.
type DispatchReport struct {
	JobsSeen       int
	JobsDispatched int
	Results        []AttemptReport
	Skipped        []string // "jobID: reason" for jobs not dispatched this pass
}

// Outbox is the durable local outbox. The zero value is not usable; construct
// with New.
type Outbox struct {
	store *jobs.JobStore
	send  SendFunc
	now   func() time.Time
	newID func() string
}

// New builds an Outbox over store. send may be nil, in which case DispatchOnce
// fails closed — enqueue/list/cancel/retry still work.
func New(store *jobs.JobStore, send SendFunc) *Outbox {
	return &Outbox{
		store: store,
		send:  send,
		now:   func() time.Time { return time.Now().UTC() },
		newID: randomJobID,
	}
}

// clock returns the injected clock or wall time when none is set.
func (o *Outbox) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now().UTC()
}

// mintID returns the injected ID generator or a random job ID.
func (o *Outbox) mintID() string {
	if o.newID != nil {
		return o.newID()
	}
	return randomJobID()
}

// randomJobID mints a 32-lowercase-hex job ID (128 bits from crypto/rand).
func randomJobID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal: job IDs must be unpredictable.
		panic("outbox: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Enqueue records a new local outbox job: the source file set is expanded
// (folders, symlink rejection, path normalization — the production transfer
// semantics), fingerprinted, and bound to one queued attempt per recipient.
// The job starts dispatching only via DispatchOnce.
func (o *Outbox) Enqueue(ctx context.Context, paths []string, recipients []RecipientRef, policy jobs.RetryPolicy) (jobs.Job, error) {
	_ = ctx
	now := o.clock()
	if len(recipients) == 0 {
		return jobs.Job{}, wire.Errorf(wire.CodeStorage, "outbox: at least one recipient is required")
	}
	abs := make([]string, len(paths))
	for i, p := range paths {
		a, err := filepath.Abs(p)
		if err != nil {
			return jobs.Job{}, wire.Errorf(wire.CodeSourceIO, "outbox: cannot resolve source path %q: %v", p, err)
		}
		abs[i] = a
	}
	sources, _, err := transfer.NewOSFileSources(abs)
	if err != nil {
		return jobs.Job{}, wire.Errorf(wire.CodeSourceIO, "outbox: %v", err)
	}
	files := make([]jobs.JobFile, len(sources))
	for i, s := range sources {
		meta := s.Meta()
		digest, err := digestSource(s)
		if err != nil {
			return jobs.Job{}, wire.Errorf(wire.CodeSourceIO, "outbox: cannot digest %q: %v", meta.Name, err)
		}
		files[i] = jobs.JobFile{Name: meta.Name, Size: meta.Size, Digest: digest}
	}
	attempts := make([]jobs.RecipientAttempt, len(recipients))
	for i, r := range recipients {
		if r.DeviceID == "" {
			return jobs.Job{}, wire.Errorf(wire.CodeStorage, "outbox: recipient %d has an empty device id", i)
		}
		attempts[i] = jobs.RecipientAttempt{
			DeviceID:  r.DeviceID,
			Label:     r.Label,
			Status:    jobs.AttemptQueued,
			UpdatedAt: now,
		}
	}
	job, err := jobs.NewJob(o.mintID(), files, attempts, policy, now)
	if err != nil {
		return jobs.Job{}, err
	}
	if err := jobs.QueueJob(&job, now); err != nil {
		return jobs.Job{}, err
	}
	// Record the source paths before the job becomes visible: dispatch
	// re-expands these paths and refuses to send on any mismatch.
	sidecar, err := writeSourcesFile(o.store.Dir(), job.JobID, abs)
	if err != nil {
		return jobs.Job{}, err
	}
	if err := o.store.Save(job); err != nil {
		// The job never became visible: remove the orphan sidecar so a
		// half-enqueued job cannot linger in the store directory.
		_ = os.Remove(sidecar)
		return jobs.Job{}, err
	}
	return job, nil
}

// Get loads one job by ID.
func (o *Outbox) Get(jobID string) (jobs.Job, bool, error) {
	return o.store.Load(jobID)
}

// List returns the job index entries (including corrupt entries, flagged).
func (o *Outbox) List() ([]jobs.JobEntry, error) {
	return o.store.List()
}

// Cancel stops a job: it never dispatches again. Active attempts become
// interrupted; their cryptographic resume state stays in the transfer
// journals, but the scheduler will not touch them.
func (o *Outbox) Cancel(jobID string) error {
	job, ok, err := o.store.Load(jobID)
	if err != nil {
		return err
	}
	if !ok {
		return wire.Errorf(wire.CodeStorage, "outbox: unknown job %q", jobID)
	}
	if err := jobs.CancelJob(&job, o.clock()); err != nil {
		return err
	}
	return o.store.Save(job)
}

// RetryFailed explicitly re-queues failed attempts, granting a fresh retry
// budget (attempt counter reset, backoff cleared). deviceIDs filters by device;
// empty re-queues every failed attempt of the job. This is the operator's
// deliberate "try this target again" — automatic dispatch never revives a
// failed attempt on its own.
func (o *Outbox) RetryFailed(jobID string, deviceIDs []string) (int, error) {
	job, ok, err := o.store.Load(jobID)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, wire.Errorf(wire.CodeStorage, "outbox: unknown job %q", jobID)
	}
	now := o.clock()
	filter := make(map[string]bool, len(deviceIDs))
	for _, d := range deviceIDs {
		filter[d] = true
	}
	n := 0
	for i := range job.Attempts {
		a := &job.Attempts[i]
		if a.Status != jobs.AttemptFailed {
			continue
		}
		if len(filter) > 0 && !filter[a.DeviceID] {
			continue
		}
		if err := jobs.TransitionAttempt(a, jobs.AttemptQueued, now); err != nil {
			return n, err
		}
		a.Attempts = 0
		a.NextRetryAt = time.Time{}
		a.LastError = ""
		n++
	}
	if n > 0 {
		job.Status = jobs.DeriveJobStatus(&job)
		job.UpdatedAt = now
		if err := o.store.Save(job); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// DispatchOnce runs a single dispatch pass over every job: it acquires the
// dispatch lease per job, sends each due attempt via the production sender,
// records honest outcomes (completed only on digest-verified, receiver-
// finalized transfers), applies bounded backoff, enforces expiry, and fails
// jobs whose sources changed since enqueue instead of silently resending.
func (o *Outbox) DispatchOnce(ctx context.Context, opts DispatchOptions) (DispatchReport, error) {
	var rep DispatchReport
	if o.send == nil {
		return rep, wire.Errorf(wire.CodeStorage, "outbox: no production sender wired; dispatch refused")
	}
	ttl := opts.LeaseTTL
	if ttl <= 0 {
		ttl = jobs.DefaultLeaseTTL
	}
	owner := jobs.LeaseOwner()

	entries, err := o.store.List()
	if err != nil {
		return rep, err
	}
	rep.JobsSeen = len(entries)
	var ids []string
	for _, e := range entries {
		if !e.JobOK {
			rep.Skipped = append(rep.Skipped, e.JobID+": unreadable job file ("+e.Err+")")
			continue
		}
		job, ok, err := o.store.Load(e.JobID)
		if err != nil {
			rep.Skipped = append(rep.Skipped, e.JobID+": load error: "+err.Error())
			continue
		}
		if !ok {
			continue
		}
		switch job.Status {
		case jobs.JobCompleted, jobs.JobFailed, jobs.JobCancelled, jobs.JobDraft, jobs.JobPaused:
			continue // terminal, not yet released, or operator-suspended
		}
		ids = append(ids, job.JobID)
	}

	// Dispatch jobs with a bounded worker pool. Each worker owns one job at
	// a time, so a job's lease is never contended; attempts within a job
	// still run sequentially under that job's lease.
	n := opts.Concurrency
	if n < 1 {
		n = 1
	}
	if len(ids) > 0 && n > len(ids) {
		n = len(ids)
	}
	var mu sync.Mutex
	pending := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range pending {
				if ctx.Err() != nil {
					continue // drain; cancellation is reported below
				}
				job, ok, err := o.store.Load(id)
				if err != nil || !ok {
					msg := "reload error"
					if err != nil {
						msg += ": " + err.Error()
					}
					mu.Lock()
					rep.Skipped = append(rep.Skipped, id+": "+msg)
					mu.Unlock()
					continue
				}
				var sub DispatchReport
				o.dispatchJob(ctx, &job, owner, ttl, &sub)
				mu.Lock()
				rep.JobsDispatched += sub.JobsDispatched
				rep.Results = append(rep.Results, sub.Results...)
				rep.Skipped = append(rep.Skipped, sub.Skipped...)
				mu.Unlock()
			}
		}()
	}
	go func() {
		defer close(pending)
		for _, id := range ids {
			select {
			case <-ctx.Done():
				return
			case pending <- id:
			}
		}
	}()
	wg.Wait()
	if ctx.Err() != nil {
		return rep, ctx.Err()
	}
	return rep, nil
}

// dispatchJob runs one job's dispatch pass: lease, expiry, source
// verification, then each due attempt.
func (o *Outbox) dispatchJob(ctx context.Context, job *jobs.Job, owner string, ttl time.Duration, rep *DispatchReport) {
	now := o.clock()
	if err := jobs.AcquireLease(job, owner, ttl, now); err != nil {
		rep.Skipped = append(rep.Skipped, job.JobID+": "+err.Error())
		return
	}
	// Persist the lease (and any crash-interrupted re-queues) before sending.
	if err := o.store.Save(*job); err != nil {
		rep.Skipped = append(rep.Skipped, job.JobID+": cannot persist lease: "+err.Error())
		return
	}
	rep.JobsDispatched++

	finish := func() {
		jobs.FinalizeJob(job, o.clock())
		if job.Status != jobs.JobCompleted && job.Status != jobs.JobFailed {
			// Non-terminal: confirm we still own the stored job before
			// persisting; a concurrent cancel or adoption wins.
			if current, ok, err := o.store.Load(job.JobID); err == nil && ok &&
				(!leaseStillOurs(current, owner) || isTerminalJobStatus(current.Status)) {
				rep.Skipped = append(rep.Skipped, job.JobID+": not saving: job ownership changed during dispatch")
				return
			}
			_ = jobs.ReleaseLease(job, owner, o.clock())
		}
		_ = o.store.Save(*job)
	}

	// Expiry is terminal: no dispatch starts after the deadline, and the job
	// settles failed rather than lingering queued forever.
	if !job.Policy.ExpiresAt.IsZero() && !now.Before(job.Policy.ExpiresAt) {
		o.failJob(job, "job expired at "+job.Policy.ExpiresAt.Format(time.RFC3339)+"; no further dispatch", now)
		finish()
		return
	}

	// The sources must still be exactly what was enqueued. Anything else —
	// changed bytes, renamed or removed files — fails the job loudly; the
	// operator re-enqueues explicitly. Never silently resend.
	paths, stale, staleErr := o.verifySources(job)
	if staleErr != nil {
		rep.Skipped = append(rep.Skipped, job.JobID+": source verification unavailable: "+staleErr.Error())
		finish()
		return
	}
	if stale {
		o.failJob(job, "source files changed since enqueue (fingerprint mismatch); re-enqueue explicitly to resend", o.clock())
		finish()
		return
	}

	for i := range job.Attempts {
		if ctx.Err() != nil {
			break
		}
		a := &job.Attempts[i]
		if !a.Retryable(job.Policy, o.clock()) {
			continue
		}
		from := a.Status
		now = o.clock()
		// Interrupted attempts re-enter through queued: the state machine
		// requires it, and it keeps the retry visible as scheduled work.
		if a.Status == jobs.AttemptInterrupted {
			if err := jobs.TransitionAttempt(a, jobs.AttemptQueued, now); err != nil {
				rep.Skipped = append(rep.Skipped, job.JobID+"/"+a.DeviceID+": "+err.Error())
				continue
			}
		}
		if err := jobs.TransitionAttempt(a, jobs.AttemptActive, now); err != nil {
			rep.Skipped = append(rep.Skipped, job.JobID+"/"+a.DeviceID+": "+err.Error())
			continue
		}
		a.Attempts++
		a.NextRetryAt = time.Time{}
		a.LastError = ""
		if err := o.store.Save(*job); err != nil {
			// Attempt is recorded active; the next acquirer re-queues it as
			// interrupted. Do not send without a persisted record.
			rep.Skipped = append(rep.Skipped, job.JobID+"/"+a.DeviceID+": cannot persist active attempt: "+err.Error())
			break
		}
		// Best-effort heartbeat before a potentially long transfer.
		if err := jobs.RenewLease(job, owner, ttl, o.clock()); err != nil {
			a.Status = jobs.AttemptInterrupted
			a.UpdatedAt = o.clock()
			_ = o.store.Save(*job)
			rep.Skipped = append(rep.Skipped, job.JobID+": lease lost mid-dispatch")
			break
		}
		outcome := o.sendWithHeartbeat(ctx, job, a, paths, owner, ttl)

		// Re-read the job: the send may have taken a while. An operator
		// cancel, or a lease adopted after a crash, must not be
		// overwritten by this dispatch's stale copy.
		current, ok, err := o.store.Load(job.JobID)
		if err != nil || !ok {
			rep.Skipped = append(rep.Skipped, job.JobID+"/"+a.DeviceID+": reload after send failed")
			return
		}
		if !leaseStillOurs(current, owner) || isTerminalJobStatus(current.Status) {
			rep.Results = append(rep.Results, AttemptReport{
				JobID: job.JobID, DeviceID: a.DeviceID, Label: a.Label,
				From: from, To: attemptStatusIn(current, a.DeviceID),
				Outcome: outcome.Status,
				Error:   "in-flight result dropped: job ownership changed during send",
			})
			return
		}
		*job = current
		a = &job.Attempts[i]
		o.recordOutcome(job, i, outcome)
		ar := AttemptReport{
			JobID: job.JobID, DeviceID: a.DeviceID, Label: a.Label,
			From: from, To: a.Status, Outcome: outcome.Status, Error: a.LastError,
		}
		rep.Results = append(rep.Results, ar)
		if err := o.store.Save(*job); err != nil {
			rep.Skipped = append(rep.Skipped, job.JobID+"/"+a.DeviceID+": cannot persist outcome: "+err.Error())
			break
		}
	}
	finish()
}

// sendWithHeartbeat runs the send while a heartbeat keeps this dispatch's
// lease alive, so a long transfer is not mistaken for a crashed dispatcher
// and adopted (which would duplicate the send). The heartbeat only renews
// while the stored job still shows this owner and a dispatching status;
// a concurrent cancel stops the heartbeats.
func (o *Outbox) sendWithHeartbeat(ctx context.Context, job *jobs.Job, a *jobs.RecipientAttempt, paths []string, owner string, ttl time.Duration) SendOutcome {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		interval := ttl / 3
		if interval < time.Second {
			interval = time.Second
		}
		if interval > time.Minute {
			interval = time.Minute
		}
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				o.renewDispatchLease(job.JobID, owner, ttl)
			}
		}
	}()
	outcome := o.send(ctx, *job, *a, paths)
	close(stop)
	wg.Wait()
	return outcome
}

// renewDispatchLease extends this dispatch's lease on the stored job. It is
// a no-op when the job moved on (cancelled, finished, or adopted), so the
// heartbeat never resurrects work it no longer owns.
func (o *Outbox) renewDispatchLease(jobID, owner string, ttl time.Duration) {
	j, ok, err := o.store.Load(jobID)
	if err != nil || !ok {
		return
	}
	if j.Status != jobs.JobDispatching || j.Lease == nil || j.Lease.Owner != owner {
		return
	}
	if err := jobs.RenewLease(&j, owner, ttl, o.clock()); err != nil {
		return
	}
	_ = o.store.Save(j)
}

// leaseStillOurs reports whether the stored job is still owned by this dispatch.
func leaseStillOurs(j jobs.Job, owner string) bool {
	return j.Lease != nil && j.Lease.Owner == owner
}

func isTerminalJobStatus(st jobs.JobStatus) bool {
	switch st {
	case jobs.JobCompleted, jobs.JobFailed, jobs.JobCancelled:
		return true
	}
	return false
}

func attemptStatusIn(j jobs.Job, deviceID string) jobs.AttemptStatus {
	for _, a := range j.Attempts {
		if a.DeviceID == deviceID {
			return a.Status
		}
	}
	return jobs.AttemptQueued
}

// isHex64 reports whether s is a 64-character lowercase hex string, the
// shape of a SHA-256 digest as the transfer layer reports it.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

// recordOutcome applies one production send outcome to an attempt.
//
//   - ok: the transfer completed, the whole-transfer digest verified, and the
//     receiver finalized (saved) the output before acknowledging — the only
//     outcome that marks an attempt completed.
//   - offline: the recipient is unreachable right now — re-queue as
//     interrupted with exponential backoff. Never terminal on its own.
//   - refused / failed: terminal for this attempt. The operator may
//     explicitly re-queue via RetryFailed; automatic dispatch never revives it.
func (o *Outbox) recordOutcome(job *jobs.Job, idx int, outcome SendOutcome) {
	now := o.clock()
	a := &job.Attempts[idx]
	a.BytesTransferred = outcome.BytesTransferred
	errText := outcome.Error
	if errText == "" {
		errText = string(outcome.Status)
	}
	switch outcome.Status {
	case transfer.StatusOk:
		// Delivered counts only with a valid content digest: the digest is
		// the proof the bytes arrived intact. Without it the attempt fails
		// closed instead of recording a phantom delivery.
		if outcome.Digest == "" || !isHex64(outcome.Digest) {
			a.LastError = "transfer reported ok without a valid content digest; not marking delivered"
			_ = jobs.TransitionAttempt(a, jobs.AttemptFailed, now)
			break
		}
		a.VerifiedDigest = outcome.Digest
		a.LastError = ""
		_ = jobs.TransitionAttempt(a, jobs.AttemptVerified, now)
		_ = jobs.TransitionAttempt(a, jobs.AttemptCompleted, now)
	case transfer.StatusOffline, transfer.StatusFailed:
		// Transient: requeue with backoff while attempt budget remains.
		if a.Attempts >= job.Policy.MaxAttempts {
			a.LastError = fmt.Sprintf("%s; attempt %d of %d", errText, a.Attempts, job.Policy.MaxAttempts)
			_ = jobs.TransitionAttempt(a, jobs.AttemptFailed, now)
			break
		}
		if outcome.Status == transfer.StatusOffline {
			a.LastError = "recipient offline: " + errText
		} else {
			a.LastError = "transfer failed: " + errText
		}
		_ = jobs.TransitionAttempt(a, jobs.AttemptInterrupted, now)
		a.NextRetryAt = now.Add(jobs.BackoffForAttempt(job.Policy, a.Attempts))
	case transfer.StatusRefused:
		// Explicit refusal is terminal: the peer said no. The operator can
		// still requeue it deliberately with `outbox retry`.
		a.LastError = "recipient refused: " + errText
		_ = jobs.TransitionAttempt(a, jobs.AttemptFailed, now)
	default:
		// Unknown sender outcome: fail closed and terminal.
		a.LastError = "unknown sender outcome: " + errText
		_ = jobs.TransitionAttempt(a, jobs.AttemptFailed, now)
	}
	a.UpdatedAt = now
}

// failJob marks every non-terminal attempt failed with the given reason.
func (o *Outbox) failJob(job *jobs.Job, reason string, now time.Time) {
	for i := range job.Attempts {
		a := &job.Attempts[i]
		switch a.Status {
		case jobs.AttemptQueued, jobs.AttemptInterrupted, jobs.AttemptActive, jobs.AttemptVerified:
			_ = jobs.TransitionAttempt(a, jobs.AttemptFailed, now)
			a.LastError = reason
			a.UpdatedAt = now
		}
	}
}

// verifySources re-expands the recorded source paths and compares the
// fingerprint with the job's. stale=true means the source set changed (bytes,
// names, or membership) and the job must fail rather than resend. A transient
// read error returns err and the job is skipped this pass, not failed.
func (o *Outbox) verifySources(job *jobs.Job) (paths []string, stale bool, err error) {
	paths, err = readSourcesFile(o.store.Dir(), job.JobID)
	if err != nil {
		return nil, true, nil // no verifiable sources: fail closed as stale
	}
	for _, p := range paths {
		if _, err := os.Lstat(p); err != nil {
			return paths, true, nil // removed or replaced: stale
		}
	}
	sources, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return paths, true, nil // membership/shape changed: stale
	}
	files := make([]jobs.JobFile, len(sources))
	for i, s := range sources {
		meta := s.Meta()
		digest, derr := digestSource(s)
		if derr != nil {
			return paths, false, derr // transient read error: skip this pass
		}
		files[i] = jobs.JobFile{Name: meta.Name, Size: meta.Size, Digest: digest}
	}
	return paths, jobs.SourceFingerprint(files) != job.SourceFingerprint, nil
}

// digestSource streams a file source through SHA-256, matching the transfer
// layer's whole-file digest semantics (hex-encoded SHA-256 of the file bytes).
func digestSource(s wire.FileSource) (string, error) {
	h := sha256.New()
	if err := s.Stream(func(chunk []byte) error {
		_, _ = h.Write(chunk)
		return nil
	}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
