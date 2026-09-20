package transfercenter

import (
	"sort"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/wire"
)

// DisplayState is the user-facing transfer state shown in the transfer
// center. It is derived from the durable job/attempt state machine, never
// stored.
type DisplayState string

// User-facing states, in canonical display order.
const (
	StateQueued      DisplayState = "queued"
	StateActive      DisplayState = "active"
	StateInterrupted DisplayState = "interrupted"
	StateVerified    DisplayState = "verified"
	StateCompleted   DisplayState = "completed"
	StateFailed      DisplayState = "failed"
	StateCancelled   DisplayState = "cancelled"
	StatePaused      DisplayState = "paused"
	StateDraft       DisplayState = "draft"
	StateBroken      DisplayState = "broken"
)

// canonicalOrder fixes the group order of every snapshot.
var canonicalOrder = []DisplayState{
	StateQueued,
	StateActive,
	StateInterrupted,
	StateVerified,
	StateCompleted,
	StateFailed,
	StateCancelled,
	StatePaused,
	StateDraft,
	StateBroken,
}

// AttemptView is the per-target result of one job: one row per recipient
// device. Error text is the secret-free LastError already stored on the
// attempt; no cryptographic material is surfaced.
type AttemptView struct {
	DeviceID         string       `json:"deviceId"`
	ShortDeviceID    string       `json:"shortDeviceId"`
	Label            string       `json:"label"`
	State            DisplayState `json:"state"`
	Attempts         int          `json:"attempts"`
	MaxAttempts      int          `json:"maxAttempts"`
	LastError        string       `json:"lastError,omitempty"`
	BytesTransferred int64        `json:"bytesTransferred,omitempty"`
	NextRetryAt      *time.Time   `json:"nextRetryAt,omitempty"`
	UpdatedAt        time.Time    `json:"updatedAt"`
}

// JobView is one job as the transfer center shows it.
type JobView struct {
	JobID          string       `json:"jobId"`
	ShortJobID     string       `json:"shortJobId"`
	State          DisplayState `json:"state"`
	Files          int          `json:"files"`
	TotalSize      int64        `json:"totalSize"`
	Recipients     int          `json:"recipients"`
	Delivered      int          `json:"delivered"`
	Failed         int          `json:"failed"`
	Pending        int          `json:"pending"`
	HasLease       bool         `json:"hasLease"`
	NextRetryAt    *time.Time   `json:"nextRetryAt,omitempty"`
	LastError      string       `json:"lastError,omitempty"`
	ExpiresAt      *time.Time   `json:"expiresAt,omitempty"`
	CreatedAt      time.Time    `json:"createdAt"`
	UpdatedAt      time.Time    `json:"updatedAt"`
	NeedsAttention bool         `json:"needsAttention"`
}

// JobDetail is the full drill-down for one job: metadata plus every
// per-target result.
type JobDetail struct {
	JobView
	Attempts []AttemptView `json:"attempts"`
	// FileList names the source files. It is named FileList (not Files) so
	// the embedded JobView.Files count keeps its JSON name.
	FileList []JobFileView `json:"fileList"`
}

// JobFileView names one source file of a job (name and size only).
type JobFileView struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// StateGroup bundles the jobs currently in one display state.
type StateGroup struct {
	State DisplayState `json:"state"`
	Jobs  []JobView    `json:"jobs"`
}

// Summary counts jobs per display state.
type Summary struct {
	Total   int                  `json:"total"`
	ByState map[DisplayState]int `json:"byState"`
	Broken  int                  `json:"broken"`
}

// Snapshot is the whole transfer center at one instant.
type Snapshot struct {
	TakenAt time.Time    `json:"takenAt"`
	Groups  []StateGroup `json:"groups"`
	Summary Summary      `json:"summary"`
}

// Center is the transfer-center read model over a job store and the outbox.
// The zero value is not usable; construct with New.
type Center struct {
	store *jobs.JobStore
	ob    *outbox.Outbox
	now   func() time.Time
}

// New builds a Center. ob may carry a nil sender: dispatch is refused then,
// but list/show/cancel/retry/prune/forget keep working.
func New(store *jobs.JobStore, ob *outbox.Outbox) *Center {
	return &Center{store: store, ob: ob, now: func() time.Time { return time.Now().UTC() }}
}

// displayAttemptState maps one attempt to its user-facing state.
func displayAttemptState(a jobs.RecipientAttempt) DisplayState {
	switch a.Status {
	case jobs.AttemptQueued:
		return StateQueued
	case jobs.AttemptActive:
		return StateActive
	case jobs.AttemptInterrupted:
		return StateInterrupted
	case jobs.AttemptVerified:
		return StateVerified
	case jobs.AttemptCompleted:
		return StateCompleted
	case jobs.AttemptFailed:
		return StateFailed
	default:
		return StateQueued
	}
}

// displayJobState derives the headline state of a job.
//
// Terminal job statuses map directly. Non-terminal jobs resolve by attempt
// priority — active work first, then stalled work needing attention, then
// the uncertain verified window, then waiting work:
//
//	active > interrupted > verified > queued
//
// The per-attempt views always carry the full truth; the headline never
// hides a stalled or uncertain attempt behind a calmer label.
func displayJobState(j jobs.Job) DisplayState {
	switch j.Status {
	case jobs.JobCompleted:
		return StateCompleted
	case jobs.JobFailed:
		return StateFailed
	case jobs.JobCancelled:
		return StateCancelled
	case jobs.JobPaused:
		return StatePaused
	case jobs.JobDraft:
		return StateDraft
	}
	var active, interrupted, verified bool
	for _, a := range j.Attempts {
		switch a.Status {
		case jobs.AttemptActive:
			active = true
		case jobs.AttemptInterrupted:
			interrupted = true
		case jobs.AttemptVerified:
			verified = true
		}
	}
	switch {
	case active:
		return StateActive
	case interrupted:
		return StateInterrupted
	case verified:
		return StateVerified
	case j.Status == jobs.JobDispatching:
		return StateActive
	default:
		return StateQueued
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// attemptView renders one attempt. maxAttempts comes from the job policy.
func attemptView(a jobs.RecipientAttempt, maxAttempts int) AttemptView {
	v := AttemptView{
		DeviceID:         a.DeviceID,
		ShortDeviceID:    shortID(a.DeviceID),
		Label:            a.Label,
		State:            displayAttemptState(a),
		Attempts:         a.Attempts,
		MaxAttempts:      maxAttempts,
		LastError:        a.LastError,
		BytesTransferred: a.BytesTransferred,
		UpdatedAt:        a.UpdatedAt,
	}
	if !a.NextRetryAt.IsZero() {
		t := a.NextRetryAt
		v.NextRetryAt = &t
	}
	return v
}

// jobView renders one job's summary row.
func jobView(j jobs.Job) JobView {
	v := JobView{
		JobID:      j.JobID,
		ShortJobID: shortID(j.JobID),
		State:      displayJobState(j),
		Files:      len(j.Files),
		TotalSize:  j.TotalSize,
		Recipients: len(j.Attempts),
		HasLease:   j.Lease != nil,
		CreatedAt:  j.CreatedAt,
		UpdatedAt:  j.UpdatedAt,
	}
	if !j.Policy.ExpiresAt.IsZero() {
		t := j.Policy.ExpiresAt
		v.ExpiresAt = &t
	}
	for _, a := range j.Attempts {
		switch displayAttemptState(a) {
		case StateCompleted:
			v.Delivered++
		case StateFailed:
			v.Failed++
			if v.LastError == "" {
				v.LastError = a.LastError
			}
		default:
			v.Pending++
		}
		if a.Status == jobs.AttemptInterrupted || a.Status == jobs.AttemptFailed {
			v.NeedsAttention = true
		}
		if !a.NextRetryAt.IsZero() && (v.NextRetryAt == nil || a.NextRetryAt.Before(*v.NextRetryAt)) {
			t := a.NextRetryAt
			v.NextRetryAt = &t
		}
	}
	return v
}

// Snapshot renders the whole transfer center: every stored job grouped by
// display state in canonical order, plus summary counts. Unreadable job
// files surface under "broken" and are never hidden or deleted.
func (c *Center) Snapshot() (Snapshot, error) {
	entries, err := c.store.List()
	if err != nil {
		return Snapshot{}, err
	}
	byState := make(map[DisplayState][]JobView, len(canonicalOrder))
	for _, st := range canonicalOrder {
		byState[st] = []JobView{}
	}
	for _, e := range entries {
		if !e.JobOK {
			byState[StateBroken] = append(byState[StateBroken], JobView{
				JobID:      e.JobID,
				ShortJobID: shortID(e.JobID),
				State:      StateBroken,
				LastError:  e.Err,
			})
			continue
		}
		j, ok, err := c.store.Load(e.JobID)
		if err != nil || !ok {
			byState[StateBroken] = append(byState[StateBroken], JobView{
				JobID:      e.JobID,
				ShortJobID: shortID(e.JobID),
				State:      StateBroken,
				LastError:  "reload failed after listing",
			})
			continue
		}
		st := displayJobState(j)
		byState[st] = append(byState[st], jobView(j))
	}
	snap := Snapshot{TakenAt: c.now(), Summary: Summary{ByState: make(map[DisplayState]int)}}
	for _, st := range canonicalOrder {
		js := byState[st]
		sort.Slice(js, func(i, k int) bool { return js[i].UpdatedAt.After(js[k].UpdatedAt) })
		snap.Groups = append(snap.Groups, StateGroup{State: st, Jobs: js})
		snap.Summary.ByState[st] = len(js)
		snap.Summary.Total += len(js)
	}
	snap.Summary.Broken = len(byState[StateBroken])
	return snap, nil
}

// Get returns the full detail of one job: summary plus every per-target
// result and the file list.
func (c *Center) Get(jobID string) (JobDetail, error) {
	j, ok, err := c.store.Load(jobID)
	if err != nil {
		return JobDetail{}, err
	}
	if !ok {
		return JobDetail{}, wire.Errorf(wire.CodeStorage, "transfercenter: unknown job %q", jobID)
	}
	d := JobDetail{JobView: jobView(j)}
	for _, a := range j.Attempts {
		d.Attempts = append(d.Attempts, attemptView(a, j.Policy.MaxAttempts))
	}
	for _, f := range j.Files {
		d.FileList = append(d.FileList, JobFileView{Name: f.Name, Size: f.Size})
	}
	return d, nil
}

// Cancel stops a job via the outbox: it never dispatches again.
func (c *Center) Cancel(jobID string) error {
	if c.ob == nil {
		return wire.Errorf(wire.CodeStorage, "transfercenter: no outbox wired")
	}
	return c.ob.Cancel(jobID)
}

// RetryFailed re-queues failed attempts of one job with a fresh retry budget.
func (c *Center) RetryFailed(jobID string, deviceIDs []string) (int, error) {
	if c.ob == nil {
		return 0, wire.Errorf(wire.CodeStorage, "transfercenter: no outbox wired")
	}
	return c.ob.RetryFailed(jobID, deviceIDs)
}
