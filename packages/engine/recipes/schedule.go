// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sendbeam/wire"
)

// ScheduleOptions tunes a Scheduler. Now is the clock for due-time
// computation; tests inject a fixed one (defaults to time.Now).
// RescanInterval controls how often the store is re-scanned for newly
// created schedule-triggered recipes (documented default: one minute;
// zero means the default). OnEvent, when set, receives a ScheduleEvent
// for every notable scheduler transition and is the only observability
// surface — the scheduler never logs on its own.
type ScheduleOptions struct {
	Now            func() time.Time
	OnEvent        func(ScheduleEvent)
	RescanInterval time.Duration
}

// defaultScheduleRescanInterval is how often the scheduler re-scans the
// store: newly created schedule-triggered recipes are picked up without
// a restart, at most this late.
const defaultScheduleRescanInterval = time.Minute

// ScheduleEventKind names what happened inside a Scheduler.
type ScheduleEventKind string

const (
	// ScheduleEventDue means a scheduled occurrence time arrived and is
	// being handled. At is the occurrence time.
	ScheduleEventDue ScheduleEventKind = "due"
	// ScheduleEventDispatching means the scheduler is asking the runner
	// to dispatch the due occurrence now.
	ScheduleEventDispatching ScheduleEventKind = "dispatching"
	// ScheduleEventDispatched means the runner accepted the dispatch and
	// enqueued a job. JobID is the enqueued job.
	ScheduleEventDispatched ScheduleEventKind = "dispatched"
	// ScheduleEventRefused means the dispatch attempt was refused (or
	// failed): the Detail/Err carries the reason. The refusal is also in
	// the recipe's last-run ledger.
	ScheduleEventRefused ScheduleEventKind = "refused"
	// ScheduleEventSkipped means no dispatch happened for a benign
	// reason: the occurrence fell outside the dispatch window, or a
	// dispatch was already in flight.
	ScheduleEventSkipped ScheduleEventKind = "skipped"
	// ScheduleEventCatchup summarizes a bounded catch-up after downtime:
	// how many missed occurrences were dispatched, how many were skipped
	// by the cap. The summary is also the recipe's last-run ledger entry.
	ScheduleEventCatchup ScheduleEventKind = "catchup"
	// ScheduleEventError means the scheduler hit an unexpected error
	// (store failure, invalid params on a hosted recipe, ...). The
	// scheduler keeps running the other recipes.
	ScheduleEventError ScheduleEventKind = "scheduler-error"
)

// ScheduleEvent is one observable scheduler transition.
type ScheduleEvent struct {
	Kind     ScheduleEventKind
	RecipeID string
	Name     string
	// At is the scheduled occurrence time, for due/dispatching/
	// dispatched/skipped events.
	At     time.Time
	JobID  string
	Err    error
	Detail string
}

// scheduledHost is one schedule-triggered recipe hosted by the scheduler:
// its freshly parsed parameters and resolved timezone.
type scheduledHost struct {
	params ScheduleParams
	tz     *time.Location
}

// Scheduler is the native explicit-schedule trigger (V22-PR05): it hosts
// every schedule-triggered recipe in the store and asks the routine
// runner for one TriggerSchedule dispatch per occurrence.
//
// The scheduler NEVER sends files itself — each due occurrence goes
// through Runner.Dispatch with TriggerSchedule, which re-loads the
// recipe, re-validates the grant/status/trust, re-resolves the sources
// fresh, re-checks budgets, and enqueues one ordinary outbox job. A
// schedule without a valid automation grant dispatches nothing: the
// attempt is refused and recorded in the last-run ledger.
//
// Durable cursor: the recipe's ScheduleCursor is the last occurrence
// time that was dispatched or deliberately skipped, persisted in the
// 0600 store. It is advanced BEFORE each dispatch, so a crash, restart
// or rapid re-tick can never double-dispatch an occurrence, and a second
// scheduler tick racing the first finds the cursor already past.
//
// Catch-up is bounded, never a stampede: occurrences missed while the
// scheduler was down are dispatched at most max_catchup_runs at a time,
// sequentially through the runner (never parallel); the rest are marked
// skipped and the cursor advances past all of them. The catch-up decision
// is recorded in the last-run ledger ("caught up 2 of 5 missed runs; 3
// skipped by cap"). max_catchup_runs=0 means no catch-up at all: missed
// occurrences are skipped and the schedule simply resumes.
//
// Dispatch windows: an occurrence outside not_before/not_after is skipped
// (cursor advanced, skip recorded) — never dispatched outside the window.
//
// Hosting: disabled recipes are never hosted, and a recipe whose trigger
// stops being "schedule" is dropped. The store is re-scanned every
// rescan interval so newly created scheduled recipes are picked up
// without a restart; the grant is NOT checked at host time (it may be
// granted later) but at every dispatch, where a missing/invalid grant
// refuses fast with a ledger entry while the scheduler keeps running the
// other recipes.
//
// Lifecycle: Start begins hosting; starting an already-started scheduler
// is an error. Stop is idempotent and waits for the tick loop to exit, so
// no goroutine survives it; a dispatch already in flight runs to
// completion (the runner owns that bound).
type Scheduler struct {
	store          *RecipeStore
	runner         *Runner
	now            func() time.Time
	onEvent        func(ScheduleEvent)
	rescanInterval time.Duration

	mu         sync.Mutex
	started    bool
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	hosts      map[string]scheduledHost
	nextRescan time.Time
}

// NewScheduler builds a scheduler over the recipe store and the routine
// runner. It fails when the store or runner is nil.
func NewScheduler(store *RecipeStore, runner *Runner, opts ScheduleOptions) (*Scheduler, error) {
	if store == nil {
		return nil, wire.Errorf(wire.CodeInternal, "recipes: nil recipe store")
	}
	if runner == nil {
		return nil, wire.Errorf(wire.CodeInternal, "recipes: nil routine runner")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	rescan := opts.RescanInterval
	if rescan <= 0 {
		rescan = defaultScheduleRescanInterval
	}
	return &Scheduler{
		store:          store,
		runner:         runner,
		now:            now,
		onEvent:        opts.OnEvent,
		rescanInterval: rescan,
		hosts:          make(map[string]scheduledHost),
	}, nil
}

// Start begins hosting schedule-triggered recipes: it re-scans the store,
// Start runs the scheduler in the background. The first tick is
// synchronous: Start returns only after the store has been rescanned and
// any due occurrences processed, so an already-due recipe fires without
// waiting for the first sleep and callers (like the CLI's "hosting N
// recipes" line) see an accurate hosted set. After that the loop sleeps
// until the next occurrence or rescan. Starting an already-started
// scheduler is an error.
func (s *Scheduler) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return wire.Errorf(wire.CodeStorage, "recipes: scheduler is already started")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	s.started = true
	s.mu.Unlock()

	// Synchronous first tick. This runs outside s.mu: tick takes the
	// mutex itself, so holding it here would deadlock.
	s.tick()
	go s.loop()
	return nil
}

// Stop ends scheduling: the tick loop exits and is waited on, so no
// goroutine survives Stop. A dispatch already in flight is NOT
// interrupted — it runs to completion. Stop is idempotent and safe on a
// scheduler that never started.
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = false
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()
	cancel()
	<-done
	return nil
}

// Hosts returns a snapshot of the schedule-triggered recipes currently
// hosted: recipe ID to parsed schedule parameters.
func (s *Scheduler) Hosts() map[string]ScheduleParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]ScheduleParams, len(s.hosts))
	for id, h := range s.hosts {
		out[id] = h.params
	}
	return out
}

// Running reports whether the scheduler is currently started.
func (s *Scheduler) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// loop is the scheduler's tick loop. The first tick already ran in
// Start; the loop ticks again after each wake-up and runs until the
// scheduler context is done, then closes done.
func (s *Scheduler) loop() {
	defer close(s.done)
	for {
		wake := s.tick()
		wait := time.Until(wake)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-s.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// tick processes every hosted recipe once and returns the next wake-up
// time: the earliest upcoming occurrence across all hosted recipes, or
// the next store rescan, whichever is sooner. It never returns a time in
// the past (a one-second floor keeps a logic bug from hot-spinning).
func (s *Scheduler) tick() time.Time {
	now := s.now()
	if !now.Before(s.nextRescan) {
		s.rescan(now)
		s.nextRescan = now.Add(s.rescanInterval)
	}
	var earliest time.Time
	for id, host := range s.hosts {
		s.processRecipe(id, now)
		if next := s.nextWakeFor(id, host); !next.IsZero() && (earliest.IsZero() || next.Before(earliest)) {
			earliest = next
		}
	}
	wake := s.nextRescan
	if !earliest.IsZero() && earliest.Before(wake) {
		wake = earliest
	}
	if wake.Before(now) {
		wake = now.Add(time.Second)
	}
	return wake
}

// nextWakeFor returns the next occurrence after the recipe's persisted
// cursor, for sleep-time computation. A store failure yields the zero
// time (no wake-up from this recipe).
func (s *Scheduler) nextWakeFor(id string, host scheduledHost) time.Time {
	r, ok, err := s.store.Load(id)
	if err != nil || !ok || r.ScheduleCursor == nil {
		return time.Time{}
	}
	next, err := NextRun(host.params, host.tz, *r.ScheduleCursor)
	if err != nil {
		return time.Time{}
	}
	return next
}

// rescan reconciles the hosted set with the store: recipes whose trigger
// is "schedule" and which are not disabled are hosted (new ones start
// with no cursor — adoption happens on the next tick); everything else is
// dropped. A recipe with invalid schedule parameters is not hosted and
// surfaces an error event; the scheduler keeps running the others.
func (s *Scheduler) rescan(now time.Time) {
	_ = now
	entries, err := s.store.List()
	if err != nil {
		s.emit(ScheduleEvent{Kind: ScheduleEventError, Err: err, Detail: err.Error()})
		return
	}
	want := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.Trigger != string(TriggerSchedule) {
			continue
		}
		want[e.ID] = true
		if _, ok := s.hosts[e.ID]; ok {
			continue
		}
		r, ok, err := s.store.Load(e.ID)
		if err != nil {
			s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: e.ID, Err: err, Detail: err.Error()})
			continue
		}
		if !ok {
			continue
		}
		if r.Status == RecipeDisabled {
			// Disabled recipes are never hosted.
			continue
		}
		sp, err := ParseScheduleParams(r.Trigger.Schedule)
		if err != nil {
			s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: e.ID, Name: r.Name, Err: err, Detail: err.Error()})
			continue
		}
		tz := sp.TZ
		if tz == nil {
			tz = time.Local
		}
		s.hosts[e.ID] = scheduledHost{params: sp, tz: tz}
	}
	for id := range s.hosts {
		if !want[id] {
			delete(s.hosts, id)
		}
	}
}

// processRecipe handles one tick for one hosted recipe: adopt the cursor
// on first sight (no backfill), run bounded catch-up for missed
// occurrences, then dispatch the currently-due occurrence if any.
func (s *Scheduler) processRecipe(id string, now time.Time) {
	r, ok, err := s.store.Load(id)
	if err != nil {
		s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: id, Err: err, Detail: err.Error()})
		s.unhost(id)
		return
	}
	if !ok {
		s.unhost(id)
		return
	}
	if r.Status == RecipeDisabled || r.Trigger.Kind != TriggerSchedule {
		// Disabled recipes are never hosted; a recipe whose trigger
		// changed is dropped at once (not at the next rescan).
		s.unhost(id)
		return
	}
	// Re-parse from the fresh record: a re-granted edit may have changed
	// the parameters (which revoked and re-bound the grant via
	// ApplyUpdate). A recipe that became invalid is dropped with an
	// error event; the scheduler keeps running the others.
	sp, err := ParseScheduleParams(r.Trigger.Schedule)
	if err != nil {
		s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: id, Name: r.Name, Err: err, Detail: err.Error()})
		s.unhost(id)
		return
	}
	tz := sp.TZ
	if tz == nil {
		tz = time.Local
	}
	s.hosts[id] = scheduledHost{params: sp, tz: tz}

	cursor := r.ScheduleCursor
	if cursor == nil {
		// First adoption: the scheduler only ever fires occurrences
		// after it started hosting. Backfilling the whole history
		// would be a stampede by another name.
		c := now.UTC()
		if aerr := s.store.AdvanceScheduleCursor(id, c); aerr != nil {
			s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: id, Name: r.Name, Err: aerr, Detail: aerr.Error()})
			return
		}
		cursor = &c
	}
	latest := latestAtOrBefore(sp, tz, now)
	if latest.After(*cursor) {
		s.catchUp(id, r.Name, sp, tz, *cursor, latest, now)
		r, ok, err = s.store.Load(id)
		if err != nil || !ok || r.ScheduleCursor == nil {
			return
		}
		cursor = r.ScheduleCursor
	}
	// At most one occurrence can be due now (the cursor sits at or past
	// the latest occurrence <= now); the bounded loop is belt and braces
	// against clock weirdness.
	for i := 0; i < 8; i++ {
		next, err := NextRun(sp, tz, *cursor)
		if err != nil {
			s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: id, Name: r.Name, Err: err, Detail: err.Error()})
			return
		}
		if next.After(now) {
			return
		}
		s.dispatchOccurrence(id, r.Name, sp, next, now)
		r, ok, err = s.store.Load(id)
		if err != nil || !ok || r.ScheduleCursor == nil {
			return
		}
		cursor = r.ScheduleCursor
	}
}

// catchUp handles occurrences missed while the scheduler was down:
// scheduled times t with cursor < t <= latest. At most
// max_catchup_runs of them are dispatched, sequentially through the
// runner — never parallel, never a stampede. The rest are marked
// skipped, the cursor advances past ALL missed occurrences, and the
// catch-up decision is recorded as the recipe's last-run ledger entry
// (last write wins, so it survives the per-dispatch entries).
func (s *Scheduler) catchUp(id, name string, sp ScheduleParams, tz *time.Location, cursor, latest, now time.Time) {
	total := countMissed(sp, tz, cursor, latest)
	if total <= 0 {
		return
	}
	n := total
	if n > int64(sp.MaxCatchupRuns) {
		n = int64(sp.MaxCatchupRuns)
	}
	var caught, failed, windowSkipped int64
	var firstErr error
	ct := cursor
	for i := int64(0); i < n; i++ {
		next, err := NextRun(sp, tz, ct)
		if err != nil {
			s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: id, Name: name, Err: err, Detail: err.Error()})
			break
		}
		if next.After(latest) {
			break
		}
		ct = next
		if !sp.InWindow(ct) {
			if !s.advanceCursor(id, ct) {
				break
			}
			windowSkipped++
			s.emit(ScheduleEvent{
				Kind:     ScheduleEventSkipped,
				RecipeID: id,
				Name:     name,
				At:       ct,
				Detail:   fmt.Sprintf("scheduled occurrence at %s is outside the %s-%s window — skipped", ct.In(tz).Format("15:04"), sp.NotBefore, sp.NotAfter),
			})
			continue
		}
		// Advance the cursor BEFORE dispatching: a crash, restart or
		// rapid re-tick can never double-dispatch this occurrence, and
		// a racing tick sees the cursor already past it. If the cursor
		// cannot advance, the occurrence is not dispatched at all.
		if !s.advanceCursor(id, ct) {
			failed++
			break
		}
		s.emit(ScheduleEvent{Kind: ScheduleEventDue, RecipeID: id, Name: name, At: ct})
		if s.stopped() {
			return
		}
		s.emit(ScheduleEvent{Kind: ScheduleEventDispatching, RecipeID: id, Name: name, At: ct})
		job, err := s.runner.Dispatch(s.dispatchCtx(), id, TriggerSchedule)
		if err != nil {
			if errors.Is(err, ErrAlreadyRunning) {
				// A dispatch is already in flight covering this
				// occurrence: consume it, don't pile on.
				caught++
				s.emit(ScheduleEvent{Kind: ScheduleEventSkipped, RecipeID: id, Name: name, At: ct, Detail: "dispatch already in flight", Err: err})
			} else {
				failed++
				if firstErr == nil {
					firstErr = err
				}
				s.emit(ScheduleEvent{Kind: ScheduleEventRefused, RecipeID: id, Name: name, At: ct, Err: err, Detail: err.Error()})
			}
			continue
		}
		caught++
		s.emit(ScheduleEvent{Kind: ScheduleEventDispatched, RecipeID: id, Name: name, At: ct, JobID: job.JobID})
	}
	// Advance past ALL missed occurrences, including the ones skipped by
	// the cap: they were deliberately not run.
	s.advanceCursor(id, latest)
	detail := fmt.Sprintf("caught up %d of %d missed run(s); %d skipped by cap", caught, total, total-n)
	if windowSkipped > 0 {
		detail += fmt.Sprintf("; %d outside the %s-%s window", windowSkipped, sp.NotBefore, sp.NotAfter)
	}
	if failed > 0 {
		detail += fmt.Sprintf("; %d failed", failed)
		if firstErr != nil {
			detail += ": " + firstErr.Error()
		}
	}
	status := RunStatusSkipped
	switch {
	case caught > 0:
		status = RunStatusDispatched
	case failed > 0:
		status = RunStatusFailed
	}
	_ = s.store.RecordRun(id, RecipeRunInfo{
		At:      now.UTC(),
		Trigger: TriggerSchedule,
		Status:  status,
		Detail:  detail,
	})
	s.emit(ScheduleEvent{Kind: ScheduleEventCatchup, RecipeID: id, Name: name, Detail: detail})
}

// dispatchOccurrence dispatches (or window-skips) one currently-due
// occurrence. The cursor advances before the dispatch; a grant refusal
// lands in the last-run ledger via the runner.
func (s *Scheduler) dispatchOccurrence(id, name string, sp ScheduleParams, at, now time.Time) {
	tz := sp.TZ
	if tz == nil {
		tz = time.Local
	}
	if !sp.InWindow(at) {
		if !s.advanceCursor(id, at) {
			return
		}
		detail := fmt.Sprintf("scheduled occurrence at %s is outside the %s-%s window — skipped", at.In(tz).Format("15:04"), sp.NotBefore, sp.NotAfter)
		_ = s.store.RecordRun(id, RecipeRunInfo{
			At:      now.UTC(),
			Trigger: TriggerSchedule,
			Status:  RunStatusSkipped,
			Detail:  detail,
		})
		s.emit(ScheduleEvent{Kind: ScheduleEventSkipped, RecipeID: id, Name: name, At: at, Detail: detail})
		return
	}
	// The cursor advances before the dispatch; if it cannot advance,
	// the occurrence is not dispatched.
	if !s.advanceCursor(id, at) {
		return
	}
	s.emit(ScheduleEvent{Kind: ScheduleEventDue, RecipeID: id, Name: name, At: at})
	if s.stopped() {
		return
	}
	s.emit(ScheduleEvent{Kind: ScheduleEventDispatching, RecipeID: id, Name: name, At: at})
	job, err := s.runner.Dispatch(s.dispatchCtx(), id, TriggerSchedule)
	if err != nil {
		if errors.Is(err, ErrAlreadyRunning) {
			s.emit(ScheduleEvent{Kind: ScheduleEventSkipped, RecipeID: id, Name: name, At: at, Detail: "dispatch already in flight", Err: err})
			return
		}
		s.emit(ScheduleEvent{Kind: ScheduleEventRefused, RecipeID: id, Name: name, At: at, Err: err, Detail: err.Error()})
		return
	}
	s.emit(ScheduleEvent{Kind: ScheduleEventDispatched, RecipeID: id, Name: name, At: at, JobID: job.JobID})
}

// advanceCursor persists the schedule cursor and reports whether the
// write succeeded. A store failure surfaces an error event; the caller
// must NOT dispatch the occurrence, because cursor-before-dispatch is
// the deduplication guarantee.
func (s *Scheduler) advanceCursor(id string, t time.Time) bool {
	if err := s.store.AdvanceScheduleCursor(id, t); err != nil {
		s.emit(ScheduleEvent{Kind: ScheduleEventError, RecipeID: id, Err: err, Detail: err.Error()})
		return false
	}
	return true
}

// unhost drops a recipe from the hosted set.
func (s *Scheduler) unhost(id string) {
	delete(s.hosts, id)
}

// stopped reports whether the scheduler context is done. A nil context
// (a tick driven directly in tests without Start) never reports stopped.
func (s *Scheduler) stopped() bool {
	return s.ctx != nil && s.ctx.Err() != nil
}

// dispatchCtx returns the scheduler context for dispatches, or a
// background context when the tick is driven directly (tests without
// Start): Runner.Dispatch calls ctx.Err(), which panics on a nil
// context.
func (s *Scheduler) dispatchCtx() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// emit delivers one event to the OnEvent callback, if set. A panicking
// callback must not take the tick loop down with it.
func (s *Scheduler) emit(evt ScheduleEvent) {
	if s.onEvent == nil {
		return
	}
	defer func() { _ = recover() }()
	s.onEvent(evt)
}

// latestAtOrBefore returns the latest scheduled occurrence at or before
// t, evaluated in tz. It is the dual of NextRun and agrees with it: for
// the returned latest, NextRun(params, tz, latest) is strictly after t
// (up to the documented DST resolution).
func latestAtOrBefore(sp ScheduleParams, tz *time.Location, t time.Time) time.Time {
	switch sp.Kind {
	case ScheduleKindDaily:
		minutes, _ := parseScheduleHHMM(sp.At)
		lt := t.In(tz)
		cand := time.Date(lt.Year(), lt.Month(), lt.Day(), minutes/60, minutes%60, 0, 0, tz)
		if cand.After(t) {
			// Yesterday's wall time, re-resolved: adding 24h to the
			// instant would drift across a DST transition.
			cand = time.Date(lt.Year(), lt.Month(), lt.Day()-1, minutes/60, minutes%60, 0, 0, tz)
		}
		// Belt and braces: walk forward while the next occurrence is
		// still <= t (at most one step is ever needed).
		for i := 0; i < 4; i++ {
			nxt, err := NextRun(sp, tz, cand)
			if err != nil || nxt.After(t) {
				break
			}
			cand = nxt
		}
		return cand
	case ScheduleKindHourly:
		lt := t.In(tz)
		cand := time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour(), sp.Minute, 0, 0, tz)
		if cand.After(t) {
			cand = time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour()-1, sp.Minute, 0, 0, tz)
		}
		// Across a fall-back transition one wall hour holds two real
		// :MM instants; walk forward to the true latest <= t.
		for i := 0; i < 4; i++ {
			nxt, err := NextRun(sp, tz, cand)
			if err != nil || nxt.After(t) {
				break
			}
			cand = nxt
		}
		return cand
	case ScheduleKindInterval:
		n := int64(sp.EveryMinutes)
		m := floorDiv(t.Unix(), 60)
		return time.Unix(floorDiv(m, n)*n*60, 0).UTC()
	default:
		return time.Time{}
	}
}

// countMissed counts scheduled occurrences t with from < t <= to,
// evaluated in tz. from is exclusive (it is the cursor: already handled),
// to is inclusive. It is arithmetic, not iterative, so a month of
// downtime does not mean a month of iteration.
func countMissed(sp ScheduleParams, tz *time.Location, from, to time.Time) int64 {
	if !from.Before(to) {
		return 0
	}
	first, err := NextRun(sp, tz, from)
	if err != nil || first.After(to) {
		return 0
	}
	switch sp.Kind {
	case ScheduleKindInterval:
		n := int64(sp.EveryMinutes)
		fromMin := floorDiv(from.Unix(), 60)
		toMin := floorDiv(to.Unix(), 60)
		return floorDiv(toMin, n) - floorDiv(fromMin, n)
	case ScheduleKindDaily:
		lf := first.In(tz)
		lt := to.In(tz)
		return 1 + calendarDaysBetween(
			time.Date(lf.Year(), lf.Month(), lf.Day(), 12, 0, 0, 0, tz),
			time.Date(lt.Year(), lt.Month(), lt.Day(), 12, 0, 0, 0, tz))
	case ScheduleKindHourly:
		// Elapsed whole hours between the first and last occurrence.
		// This agrees with NextRun's elapsed-time advance, including
		// across DST transitions (each wall hour yields exactly one
		// occurrence instant there).
		return 1 + int64(to.Sub(first)/time.Hour)
	default:
		return 0
	}
}

// calendarDaysBetween returns whole calendar days from a to b (b >= a),
// anchored at noon so DST transitions cannot shift the count.
func calendarDaysBetween(a, b time.Time) int64 {
	if b.Before(a) {
		return 0
	}
	return int64(math.Round(b.Sub(a).Hours() / 24))
}
