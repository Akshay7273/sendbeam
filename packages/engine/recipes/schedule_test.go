// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/engine/trust"
)

// scheduleEventLog collects ScheduleEvents goroutine-safely.
type scheduleEventLog struct {
	mu     sync.Mutex
	events []ScheduleEvent
}

func (l *scheduleEventLog) handler() func(ScheduleEvent) {
	return func(evt ScheduleEvent) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.events = append(l.events, evt)
	}
}

func (l *scheduleEventLog) kinds() []ScheduleEventKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]ScheduleEventKind, len(l.events))
	for i, e := range l.events {
		out[i] = e.Kind
	}
	return out
}

func (l *scheduleEventLog) hasKind(k ScheduleEventKind) bool {
	for _, got := range l.kinds() {
		if got == k {
			return true
		}
	}
	return false
}

func (l *scheduleEventLog) countKind(k ScheduleEventKind) int {
	n := 0
	for _, got := range l.kinds() {
		if got == k {
			n++
		}
	}
	return n
}

// scheduleFixture is one fully-wired schedule test: trusted device,
// source root, granted schedule-trigger recipe, recording enqueuer,
// runner and a fixed clock. The scheduler is built per-test via
// fixture.scheduler so RescanInterval/Now stay deterministic.
type scheduleFixture struct {
	store  *RecipeStore
	ts     *trust.MemoryTrustStore
	recipe Recipe
	root   string
	eq     *watchEnqueuer
	runner *Runner
	log    *scheduleEventLog
	now    time.Time
}

// newScheduleFixture builds a manual-status, auto-send-granted
// schedule-trigger recipe over a fresh source root. now is the fixed
// clock for the recipe timestamps, the grant and the runner; the
// scheduler clock is injected per-test.
func newScheduleFixture(t *testing.T, schedParams map[string]any, now time.Time) *scheduleFixture {
	t.Helper()
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "seed.txt", "seed")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Scheduled exports", now)
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerSchedule
	r.Trigger.Schedule = schedParams
	r.Grant.ScopeHash = r.ScopeHash()
	if err := GrantAutomation(&r, now); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &watchEnqueuer{}
	nowFn := func() time.Time { return now }
	runner := NewRunner(RunDeps{Store: store, Trust: ts, Now: nowFn}, eq, RunnerOptions{Now: nowFn})
	log := &scheduleEventLog{}
	return &scheduleFixture{store: store, ts: ts, recipe: r, root: root, eq: eq, runner: runner, log: log, now: now}
}

// scheduler builds a scheduler over the fixture with the fixed clock and
// a long rescan interval (tests drive ticks directly or wait on the
// first immediate tick).
func (fx *scheduleFixture) scheduler(t *testing.T) *Scheduler {
	t.Helper()
	s, err := NewScheduler(fx.store, fx.runner, ScheduleOptions{
		Now:            func() time.Time { return fx.now },
		OnEvent:        fx.log.handler(),
		RescanInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return s
}

// backdateCursor moves the recipe's schedule cursor to now-d, so the next
// tick sees missed occurrences to catch up.
func (fx *scheduleFixture) backdateCursor(t *testing.T, d time.Duration) {
	t.Helper()
	if err := fx.store.AdvanceScheduleCursor(fx.recipe.ID, fx.now.Add(-d)); err != nil {
		t.Fatalf("AdvanceScheduleCursor: %v", err)
	}
}

// loadCursor reads the persisted schedule cursor.
func (fx *scheduleFixture) loadCursor(t *testing.T) *time.Time {
	t.Helper()
	r, ok, err := fx.store.Load(fx.recipe.ID)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	return r.ScheduleCursor
}

// lastRunDetail reads the recipe's last-run ledger detail.
func (fx *scheduleFixture) lastRunDetail(t *testing.T) (RunStatus, string) {
	t.Helper()
	r, ok, err := fx.store.Load(fx.recipe.ID)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if r.LastRun == nil {
		t.Fatalf("no last-run ledger entry recorded")
	}
	return r.LastRun.Status, r.LastRun.Detail
}

func TestParseScheduleParams(t *testing.T) {
	cases := []struct {
		name    string
		params  map[string]any
		wantErr bool
		check   func(t *testing.T, sp ScheduleParams)
	}{
		{"daily full", map[string]any{"kind": "daily", "at": "14:30", "tz": "Asia/Calcutta"}, false,
			func(t *testing.T, sp ScheduleParams) {
				if sp.Kind != "daily" || sp.At != "14:30" || sp.TZName != "Asia/Calcutta" || sp.MaxCatchupRuns != 3 {
					t.Errorf("unexpected parse: %+v", sp)
				}
			}},
		{"hourly minimal", map[string]any{"kind": "hourly", "minute": 15}, false,
			func(t *testing.T, sp ScheduleParams) {
				if sp.Kind != "hourly" || sp.Minute != 15 || sp.TZ == nil {
					t.Errorf("unexpected parse: %+v", sp)
				}
			}},
		{"interval with window and cap", map[string]any{
			"kind": "interval", "every_minutes": 30,
			"not_before": "09:00", "not_after": "17:00", "max_catchup_runs": 0,
		}, false, func(t *testing.T, sp ScheduleParams) {
			if sp.EveryMinutes != 30 || sp.NotBefore != "09:00" || sp.NotAfter != "17:00" || sp.MaxCatchupRuns != 0 {
				t.Errorf("unexpected parse: %+v", sp)
			}
		}},
		{"int values accepted", map[string]any{"kind": "hourly", "minute": 15}, false, nil},
		{"missing kind", map[string]any{"at": "14:30"}, true, nil},
		{"empty map", map[string]any{}, true, nil},
		{"nil map", nil, true, nil},
		{"bad kind", map[string]any{"kind": "cron"}, true, nil},
		{"non-string kind", map[string]any{"kind": 5}, true, nil},
		{"daily missing at", map[string]any{"kind": "daily"}, true, nil},
		{"daily bad at format", map[string]any{"kind": "daily", "at": "2:30pm"}, true, nil},
		{"daily at hour out of range", map[string]any{"kind": "daily", "at": "24:00"}, true, nil},
		{"daily at minute out of range", map[string]any{"kind": "daily", "at": "14:60"}, true, nil},
		{"daily with minute key", map[string]any{"kind": "daily", "at": "14:30", "minute": 15}, true, nil},
		{"hourly missing minute", map[string]any{"kind": "hourly"}, true, nil},
		{"hourly minute negative", map[string]any{"kind": "hourly", "minute": -1}, true, nil},
		{"hourly minute 60", map[string]any{"kind": "hourly", "minute": 60}, true, nil},
		{"hourly minute fractional", map[string]any{"kind": "hourly", "minute": 15.5}, true, nil},
		{"hourly minute string", map[string]any{"kind": "hourly", "minute": "15"}, true, nil},
		{"hourly with at key", map[string]any{"kind": "hourly", "minute": 15, "at": "14:30"}, true, nil},
		{"interval missing every_minutes", map[string]any{"kind": "interval"}, true, nil},
		{"interval zero", map[string]any{"kind": "interval", "every_minutes": 0}, true, nil},
		{"interval above max", map[string]any{"kind": "interval", "every_minutes": 1441}, true, nil},
		{"interval fractional", map[string]any{"kind": "interval", "every_minutes": 30.5}, true, nil},
		{"unknown tz", map[string]any{"kind": "daily", "at": "14:30", "tz": "Mars/Olympus"}, true, nil},
		{"non-string tz", map[string]any{"kind": "daily", "at": "14:30", "tz": 5}, true, nil},
		{"unknown key", map[string]any{"kind": "daily", "at": "14:30", "cron": "* * *"}, true, nil},
		{"bad not_before format", map[string]any{"kind": "interval", "every_minutes": 30, "not_before": "9am"}, true, nil},
		{"not_before after not_after", map[string]any{"kind": "interval", "every_minutes": 30, "not_before": "17:00", "not_after": "09:00"}, true, nil},
		{"not_before equal not_after", map[string]any{"kind": "interval", "every_minutes": 30, "not_before": "09:00", "not_after": "09:00"}, true, nil},
		{"max_catchup_runs above max", map[string]any{"kind": "interval", "every_minutes": 30, "max_catchup_runs": 11}, true, nil},
		{"max_catchup_runs negative", map[string]any{"kind": "interval", "every_minutes": 30, "max_catchup_runs": -1}, true, nil},
		{"max_catchup_runs fractional", map[string]any{"kind": "interval", "every_minutes": 30, "max_catchup_runs": 2.5}, true, nil},
		{"bounds inclusive", map[string]any{"kind": "hourly", "minute": 59, "tz": "UTC"}, false, nil},
		{"interval bounds inclusive", map[string]any{"kind": "interval", "every_minutes": 1440, "max_catchup_runs": 10}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := ParseScheduleParams(tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", sp)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, sp)
			}
		})
	}
}

func TestNextRun(t *testing.T) {
	kolkata, err := time.LoadLocation("Asia/Calcutta")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	mustParams := func(t *testing.T, m map[string]any) ScheduleParams {
		t.Helper()
		sp, err := ParseScheduleParams(m)
		if err != nil {
			t.Fatalf("ParseScheduleParams: %v", err)
		}
		return sp
	}

	t.Run("daily", func(t *testing.T) {
		sp := mustParams(t, map[string]any{"kind": "daily", "at": "14:30", "tz": "Asia/Calcutta"})
		// 2026-09-20 10:00 IST -> next 14:30 IST same day.
		after := time.Date(2026, 9, 20, 10, 0, 0, 0, kolkata)
		next, err := NextRun(sp, nil, after)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		want := time.Date(2026, 9, 20, 14, 30, 0, 0, kolkata)
		if !next.Equal(want) {
			t.Fatalf("got %s, want %s", next, want)
		}
		// Exactly at the occurrence -> strictly after, so next day.
		next, err = NextRun(sp, nil, want)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		wantNext := time.Date(2026, 9, 21, 14, 30, 0, 0, kolkata)
		if !next.Equal(wantNext) {
			t.Fatalf("got %s, want %s", next, wantNext)
		}
	})

	t.Run("hourly", func(t *testing.T) {
		sp := mustParams(t, map[string]any{"kind": "hourly", "minute": 15, "tz": "Asia/Calcutta"})
		after := time.Date(2026, 9, 20, 10, 20, 0, 0, kolkata)
		next, err := NextRun(sp, nil, after)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		want := time.Date(2026, 9, 20, 11, 15, 0, 0, kolkata)
		if !next.Equal(want) {
			t.Fatalf("got %s, want %s", next, want)
		}
		// Exactly on the minute -> next hour.
		next, err = NextRun(sp, nil, want)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		if want2 := time.Date(2026, 9, 20, 12, 15, 0, 0, kolkata); !next.Equal(want2) {
			t.Fatalf("got %s, want %s", next, want2)
		}
	})

	t.Run("interval epoch-anchored", func(t *testing.T) {
		sp := mustParams(t, map[string]any{"kind": "interval", "every_minutes": 30})
		after := time.Date(2026, 9, 20, 12, 0, 30, 0, time.UTC)
		next, err := NextRun(sp, nil, after)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		if want := time.Date(2026, 9, 20, 12, 30, 0, 0, time.UTC); !next.Equal(want) {
			t.Fatalf("got %s, want %s", next, want)
		}
		// Exactly on a boundary -> strictly after.
		next, err = NextRun(sp, nil, time.Date(2026, 9, 20, 12, 30, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		if want := time.Date(2026, 9, 20, 13, 0, 0, 0, time.UTC); !next.Equal(want) {
			t.Fatalf("got %s, want %s", next, want)
		}
		// Odd period still epoch-anchored: every 45 min from midnight.
		sp45 := mustParams(t, map[string]any{"kind": "interval", "every_minutes": 45})
		next, err = NextRun(sp45, nil, time.Date(2026, 9, 20, 0, 44, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		if want := time.Date(2026, 9, 20, 0, 45, 0, 0, time.UTC); !next.Equal(want) {
			t.Fatalf("got %s, want %s", next, want)
		}
	})

	t.Run("explicit tz overrides params tz", func(t *testing.T) {
		sp := mustParams(t, map[string]any{"kind": "daily", "at": "14:30", "tz": "Asia/Calcutta"})
		utc := time.UTC
		after := time.Date(2026, 9, 20, 10, 0, 0, 0, utc)
		next, err := NextRun(sp, utc, after)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		if want := time.Date(2026, 9, 20, 14, 30, 0, 0, utc); !next.Equal(want) {
			t.Fatalf("got %s, want %s", next, want)
		}
	})

	t.Run("unknown kind errors", func(t *testing.T) {
		if _, err := NextRun(ScheduleParams{Kind: "cron"}, nil, time.Now()); err == nil {
			t.Fatalf("expected error for unknown kind")
		}
	})
}

// TestNextRunDST locks the documented DST behavior (verified against Go's
// time package): a nonexistent wall time (spring-forward gap) is
// interpreted with the pre-transition offset, so the occurrence still
// fires exactly once; an ambiguous wall time (fall-back) takes the first
// occurrence.
func TestNextRunDST(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	mustParams := func(t *testing.T, m map[string]any) ScheduleParams {
		t.Helper()
		sp, err := ParseScheduleParams(m)
		if err != nil {
			t.Fatalf("ParseScheduleParams: %v", err)
		}
		return sp
	}

	t.Run("spring forward gap resolves once", func(t *testing.T) {
		// 2026-03-08: 02:00 -> 03:00, so 02:30 never happens.
		sp := mustParams(t, map[string]any{"kind": "daily", "at": "02:30", "tz": "America/New_York"})
		after := time.Date(2026, 3, 8, 0, 0, 0, 0, ny)
		next, err := NextRun(sp, nil, after)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		// Go interprets the nonexistent 02:30 with the pre-transition
		// (EST) offset: the instant that displays as 01:30 EST.
		want := time.Date(2026, 3, 8, 1, 30, 0, 0, ny)
		if !next.Equal(want) {
			t.Fatalf("got %s (%s), want %s", next, next.Format("15:04 MST"), want)
		}
		// The next day is back to a real 02:30 wall time: no drift.
		next2, err := NextRun(sp, nil, next)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		want2 := time.Date(2026, 3, 9, 2, 30, 0, 0, ny)
		if !next2.Equal(want2) {
			t.Fatalf("got %s, want %s", next2, want2)
		}
	})

	t.Run("fall back takes first occurrence", func(t *testing.T) {
		// 2026-11-01: 01:30 happens twice (EDT then EST).
		sp := mustParams(t, map[string]any{"kind": "daily", "at": "01:30", "tz": "America/New_York"})
		after := time.Date(2026, 11, 1, 0, 0, 0, 0, ny)
		next, err := NextRun(sp, nil, after)
		if err != nil {
			t.Fatalf("NextRun: %v", err)
		}
		want := time.Date(2026, 11, 1, 1, 30, 0, 0, ny)
		if !next.Equal(want) {
			t.Fatalf("got %s, want %s", next, want)
		}
		if got := next.Format("MST"); got != "EDT" {
			t.Fatalf("ambiguous time took %s, want the first occurrence (EDT)", got)
		}
	})

	t.Run("hourly across spring forward", func(t *testing.T) {
		sp := mustParams(t, map[string]any{"kind": "hourly", "minute": 30, "tz": "America/New_York"})
		after := time.Date(2026, 3, 8, 1, 0, 0, 0, ny) // 01:00 EST
		var seq []time.Time
		cur := after
		for i := 0; i < 3; i++ {
			nxt, err := NextRun(sp, nil, cur)
			if err != nil {
				t.Fatalf("NextRun: %v", err)
			}
			seq = append(seq, nxt)
			cur = nxt
		}
		// 01:30 EST, then the gap-hour occurrence (the instant that
		// displays as 01:30 EST under the old offset), then 04:30 EDT:
		// strictly increasing instants, one per iteration, no stall.
		for i := 1; i < len(seq); i++ {
			if !seq[i].After(seq[i-1]) {
				t.Fatalf("occurrence %d (%s) not after %d (%s)", i, seq[i], i-1, seq[i-1])
			}
		}
		if want := time.Date(2026, 3, 8, 1, 30, 0, 0, ny); !seq[0].Equal(want) {
			t.Fatalf("seq[0] = %s, want %s", seq[0], want)
		}
		if want := time.Date(2026, 3, 8, 4, 30, 0, 0, ny); !seq[2].Equal(want) {
			t.Fatalf("seq[2] = %s, want %s", seq[2], want)
		}
	})

	t.Run("hourly across fall back fires both", func(t *testing.T) {
		sp := mustParams(t, map[string]any{"kind": "hourly", "minute": 15, "tz": "America/New_York"})
		after := time.Date(2026, 11, 1, 0, 0, 0, 0, ny) // 00:00 EDT
		var seq []time.Time
		cur := after
		for i := 0; i < 4; i++ {
			nxt, err := NextRun(sp, nil, cur)
			if err != nil {
				t.Fatalf("NextRun: %v", err)
			}
			seq = append(seq, nxt)
			cur = nxt
		}
		// 00:15 EDT, 01:15 EDT, 01:15 EST, 02:15 EST — every real :15.
		zones := []string{"EDT", "EDT", "EST", "EST"}
		for i, z := range zones {
			if got := seq[i].Format("MST"); got != z {
				t.Fatalf("seq[%d] zone = %s, want %s (seq: %v)", i, got, z, seq)
			}
		}
	})
}

func TestScheduleParamsScopeHash(t *testing.T) {
	base := func() Recipe {
		r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
		return r
	}
	h0 := base().ScopeHash()
	mutations := []struct {
		name   string
		params map[string]any
	}{
		{"kind", map[string]any{"kind": "daily", "at": "14:30"}},
		{"every_minutes", map[string]any{"kind": "interval", "every_minutes": 60}},
		{"at", map[string]any{"kind": "daily", "at": "15:30"}},
		{"tz", map[string]any{"kind": "interval", "every_minutes": 30, "tz": "Asia/Calcutta"}},
		{"window", map[string]any{"kind": "interval", "every_minutes": 30, "not_before": "09:00", "not_after": "17:00"}},
		{"max_catchup_runs", map[string]any{"kind": "interval", "every_minutes": 30, "max_catchup_runs": 1}},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			r := scheduleTestRecipe(t, m.params)
			if r.ScopeHash() == h0 {
				t.Fatalf("scope hash unchanged after %s mutation", m.name)
			}
		})
	}
	t.Run("identical params identical hash", func(t *testing.T) {
		if h := base().ScopeHash(); h != h0 {
			t.Fatalf("identical params changed the hash")
		}
	})
	t.Run("cursor not material", func(t *testing.T) {
		r := base()
		h := r.ScopeHash()
		c := time.Now().UTC()
		r.ScheduleCursor = &c
		if r.ScopeHash() != h {
			t.Fatalf("advancing the schedule cursor changed the scope hash")
		}
	})
}

// scheduleTestRecipe builds a minimal schedule-trigger recipe for
// scope-hash tests (no store, no grant needed).
func scheduleTestRecipe(t *testing.T, params map[string]any) Recipe {
	t.Helper()
	r, err := NewRecipe("Sched", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: "/tmp/src", Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: "sb-dev-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Label: "x"}}
	r.Trigger.Kind = TriggerSchedule
	r.Trigger.Schedule = params
	if err := ValidateRecipe(r); err != nil {
		t.Fatalf("ValidateRecipe: %v", err)
	}
	return r
}

func TestScheduleTriggerValidation(t *testing.T) {
	t.Run("schedule params on watch trigger rejected", func(t *testing.T) {
		r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
		r.Trigger.Kind = TriggerWatch
		if err := ValidateRecipe(r); err == nil {
			t.Fatalf("expected error for schedule params on a watch trigger")
		}
	})
	t.Run("watch params on schedule trigger rejected", func(t *testing.T) {
		r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
		r.Trigger.Watch = map[string]any{"debounce_ms": 500}
		if err := ValidateRecipe(r); err == nil {
			t.Fatalf("expected error for watch params on a schedule trigger")
		}
	})
	t.Run("invalid schedule params rejected", func(t *testing.T) {
		r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
		r.Trigger.Schedule = map[string]any{"kind": "interval", "every_minutes": 0}
		if err := ValidateRecipe(r); err == nil {
			t.Fatalf("expected error for invalid schedule params")
		}
	})
	t.Run("empty schedule on schedule trigger rejected", func(t *testing.T) {
		r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
		r.Trigger.Schedule = nil
		if err := ValidateRecipe(r); err == nil {
			t.Fatalf("expected error for empty schedule params")
		}
	})
	t.Run("material change revokes grant", func(t *testing.T) {
		store := openTestRecipeStore(t)
		r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
		r.Status = RecipeManual
		r.Grant.ScopeHash = r.ScopeHash()
		if err := GrantAutomation(&r, time.Now().UTC()); err != nil {
			t.Fatalf("GrantAutomation: %v", err)
		}
		if err := store.Save(r); err != nil {
			t.Fatalf("Save: %v", err)
		}
		// Change the schedule: the grant must be revoked.
		r.Trigger.Schedule = map[string]any{"kind": "interval", "every_minutes": 60}
		updated, err := ApplyUpdate(store, r)
		if err != nil {
			t.Fatalf("ApplyUpdate: %v", err)
		}
		if updated.Grant.AutoSend {
			t.Fatalf("schedule change did not revoke the automation grant")
		}
		if updated.Status != RecipeApprovalRequired {
			t.Fatalf("status = %q, want approval-required", updated.Status)
		}
	})
}

// TestSchedulerCatchupBounded: cursor backdated 5 intervals with
// max_catchup_runs=2 -> exactly 2 catch-up dispatches, the cursor
// advanced past all missed occurrences, and the ledger names the cap.
func TestSchedulerCatchupBounded(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 1, "max_catchup_runs": 2,
	}, now)
	fx.backdateCursor(t, 5*time.Minute)

	sched := fx.scheduler(t)
	sched.tick()

	if got := fx.eq.numCalls(); got != 2 {
		t.Fatalf("dispatches = %d, want exactly 2", got)
	}
	cur := fx.loadCursor(t)
	if cur == nil || cur.Before(now) {
		t.Fatalf("cursor = %v, want advanced to at least %v", cur, now)
	}
	status, detail := fx.lastRunDetail(t)
	if status != RunStatusDispatched {
		t.Fatalf("ledger status = %q, want dispatched", status)
	}
	if !strings.Contains(detail, "caught up 2 of 5 missed run(s)") || !strings.Contains(detail, "3 skipped by cap") {
		t.Fatalf("ledger detail does not describe the bounded catch-up: %q", detail)
	}
	if !fx.log.hasKind(ScheduleEventCatchup) {
		t.Fatalf("no catchup event emitted (kinds: %v)", fx.log.kinds())
	}
	if n := fx.log.countKind(ScheduleEventDispatched); n != 2 {
		t.Fatalf("dispatched events = %d, want 2", n)
	}

	// A rapid second tick must not double-dispatch anything.
	sched.tick()
	if got := fx.eq.numCalls(); got != 2 {
		t.Fatalf("second tick dispatched again: calls = %d", got)
	}
}

// TestSchedulerCatchupZero: max_catchup_runs=0 -> no catch-up dispatches,
// the cursor still advances past everything missed, and the schedule
// simply resumes.
func TestSchedulerCatchupZero(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 1, "max_catchup_runs": 0,
	}, now)
	fx.backdateCursor(t, 5*time.Minute)

	sched := fx.scheduler(t)
	sched.tick()

	if got := fx.eq.numCalls(); got != 0 {
		t.Fatalf("dispatches = %d, want 0", got)
	}
	cur := fx.loadCursor(t)
	if cur == nil || cur.Before(now) {
		t.Fatalf("cursor = %v, want advanced to at least %v", cur, now)
	}
	status, detail := fx.lastRunDetail(t)
	if status != RunStatusSkipped {
		t.Fatalf("ledger status = %q, want skipped", status)
	}
	if !strings.Contains(detail, "0 of 5 missed run(s)") || !strings.Contains(detail, "5 skipped by cap") {
		t.Fatalf("ledger detail does not describe the zero catch-up: %q", detail)
	}
}

// TestSchedulerWindowSkip: every occurrence (missed and due) outside
// not_before/not_after is skipped — never dispatched — and the cursor
// advances.
func TestSchedulerWindowSkip(t *testing.T) {
	// 12:00 UTC, window 13:00-14:00 UTC: everything is outside.
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 30, "tz": "UTC",
		"not_before": "13:00", "not_after": "14:00",
	}, now)
	fx.backdateCursor(t, 90*time.Minute) // 3 missed occurrences

	sched := fx.scheduler(t)
	sched.tick()

	if got := fx.eq.numCalls(); got != 0 {
		t.Fatalf("dispatches = %d outside the window, want 0", got)
	}
	cur := fx.loadCursor(t)
	if cur == nil || cur.Before(now) {
		t.Fatalf("cursor = %v, want advanced to at least %v", cur, now)
	}
	status, detail := fx.lastRunDetail(t)
	if status != RunStatusSkipped {
		t.Fatalf("ledger status = %q, want skipped", status)
	}
	if !strings.Contains(detail, "outside the 13:00-14:00 window") {
		t.Fatalf("ledger detail does not name the window skip: %q", detail)
	}
	if !fx.log.hasKind(ScheduleEventSkipped) {
		t.Fatalf("no skipped event emitted (kinds: %v)", fx.log.kinds())
	}
}

// TestSchedulerGrantRevoked: a due occurrence with no valid grant is
// refused (recorded in the ledger); the scheduler keeps running.
func TestSchedulerGrantRevoked(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 30,
	}, now)
	// Revoke the grant after the fixture granted it.
	r, ok, err := fx.store.Load(fx.recipe.ID)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	RevokeAutomation(&r)
	if err := fx.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fx.backdateCursor(t, 30*time.Minute) // 1 missed occurrence

	sched := fx.scheduler(t)
	sched.tick()

	if got := fx.eq.numCalls(); got != 0 {
		t.Fatalf("dispatches = %d without a grant, want 0", got)
	}
	if !fx.log.hasKind(ScheduleEventRefused) {
		t.Fatalf("no refused event emitted (kinds: %v)", fx.log.kinds())
	}
	status, detail := fx.lastRunDetail(t)
	if status == RunStatusDispatched {
		t.Fatalf("ledger claims a dispatch without a grant: %q", detail)
	}
	if !strings.Contains(detail, "automation grant") {
		t.Fatalf("ledger detail does not name the missing grant: %q", detail)
	}
}

// TestSchedulerDisabledNeverHosted: a disabled schedule-triggered recipe
// is never dispatched and records nothing.
func TestSchedulerDisabledNeverHosted(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 1,
	}, now)
	r, ok, err := fx.store.Load(fx.recipe.ID)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	r.Status = RecipeDisabled
	if err := fx.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sched := fx.scheduler(t)
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sched.Stop() }()
	// The loop ticks immediately on Start; wait until the first tick has
	// run (nextRescan is set by tick), then assert the disabled recipe
	// was never hosted and nothing dispatched.
	waitFor(t, 5*time.Second, "first tick", func() bool {
		sched.mu.Lock()
		defer sched.mu.Unlock()
		return !sched.nextRescan.IsZero()
	})
	sched.mu.Lock()
	_, hosted := sched.hosts[fx.recipe.ID]
	sched.mu.Unlock()
	if hosted {
		t.Fatalf("disabled recipe is hosted")
	}
	time.Sleep(200 * time.Millisecond)
	if got := fx.eq.numCalls(); got != 0 {
		t.Fatalf("disabled recipe dispatched %d time(s)", got)
	}
	r, _, _ = fx.store.Load(fx.recipe.ID)
	if r.LastRun != nil {
		t.Fatalf("disabled recipe recorded a ledger entry: %+v", r.LastRun)
	}
}

// TestSchedulerDueDispatch: a currently-due occurrence dispatches once
// through the runner with TriggerSchedule.
func TestSchedulerDueDispatch(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "interval", "every_minutes": 30,
	}, now)
	// Cursor one interval back: exactly one missed occurrence, which is
	// also the current due.
	fx.backdateCursor(t, 30*time.Minute)

	sched := fx.scheduler(t)
	sched.tick()

	if got := fx.eq.numCalls(); got != 1 {
		t.Fatalf("dispatches = %d, want 1", got)
	}
	status, _ := fx.lastRunDetail(t)
	if status != RunStatusDispatched {
		t.Fatalf("ledger status = %q, want dispatched", status)
	}
	if !fx.log.hasKind(ScheduleEventDue) || !fx.log.hasKind(ScheduleEventDispatched) {
		t.Fatalf("missing due/dispatched events (kinds: %v)", fx.log.kinds())
	}
}

// TestSchedulerStartStop: Start twice is an error; Stop is idempotent;
// Stop during sleep returns promptly with no goroutine leak.
func TestSchedulerStartStop(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fx := newScheduleFixture(t, map[string]any{
		"kind": "daily", "at": "14:30", "tz": "UTC",
	}, now)
	// Adopt the cursor first so the loop's immediate tick sleeps until
	// the next occurrence (hours away), exercising Stop-during-sleep.
	if err := fx.store.AdvanceScheduleCursor(fx.recipe.ID, now); err != nil {
		t.Fatalf("AdvanceScheduleCursor: %v", err)
	}
	sched := fx.scheduler(t)
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := sched.Start(context.Background()); err == nil {
		t.Fatalf("second Start did not error")
	}
	if !sched.Running() {
		t.Fatalf("scheduler not running after Start")
	}
	done := make(chan struct{})
	go func() { _ = sched.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Stop did not return promptly")
	}
	if sched.Running() {
		t.Fatalf("scheduler still running after Stop")
	}
	// Idempotent.
	if err := sched.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if err := sched.Stop(); err != nil {
		t.Fatalf("Stop without Start: %v", err)
	}
}

func TestPreviewScheduleWords(t *testing.T) {
	r := scheduleTestRecipe(t, map[string]any{
		"kind": "daily", "at": "14:30", "tz": "Asia/Calcutta",
		"not_before": "09:00", "not_after": "17:00", "max_catchup_runs": 2,
	})
	p := Preview(r)
	for _, want := range []string{
		"daily at 14:30 Asia/Calcutta",
		"only between 09:00 and 17:00",
		"catch up at most 2 missed run(s)",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("preview missing %q:\n%s", want, p)
		}
	}
	r2 := scheduleTestRecipe(t, map[string]any{"kind": "hourly", "minute": 5})
	if p2 := Preview(r2); !strings.Contains(p2, "hourly at minute 5") {
		t.Fatalf("preview missing hourly words:\n%s", p2)
	}
	r3 := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 45})
	if p3 := Preview(r3); !strings.Contains(p3, "every 45 minute(s)") {
		t.Fatalf("preview missing interval words:\n%s", p3)
	}
}

// TestScheduleCursorChecksumCompat: a v1 record without the scheduleCursor
// key (written before V22-PR05) still loads and checksum-verifies, and the
// cursor round-trips once set.
func TestScheduleCursorChecksumCompat(t *testing.T) {
	store := openTestRecipeStore(t)
	r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
	r.Status = RecipeManual
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, ok, err := store.Load(r.ID)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if loaded.ScheduleCursor != nil {
		t.Fatalf("cursor should be nil for a pre-schedule record")
	}
	cur := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	if err := store.AdvanceScheduleCursor(r.ID, cur); err != nil {
		t.Fatalf("AdvanceScheduleCursor: %v", err)
	}
	loaded, ok, err = store.Load(r.ID)
	if err != nil || !ok {
		t.Fatalf("Load after cursor: ok=%v err=%v", ok, err)
	}
	if loaded.ScheduleCursor == nil || !loaded.ScheduleCursor.Equal(cur) {
		t.Fatalf("cursor did not round-trip: %v", loaded.ScheduleCursor)
	}
}

// TestImportClearsScheduleCursor: the schedule cursor is host-local
// history like the last-run ledger — an imported recipe adopts a fresh
// cursor on its first scheduler tick instead of inheriting the
// exporter's.
func TestImportClearsScheduleCursor(t *testing.T) {
	store := openTestRecipeStore(t)
	r := scheduleTestRecipe(t, map[string]any{"kind": "interval", "every_minutes": 30})
	r.Status = RecipeManual
	cur := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	r.ScheduleCursor = &cur
	r.LastRun = &RecipeRunInfo{At: cur, Trigger: TriggerSchedule, Status: RunStatusDispatched}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := Export(r)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	imported, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imported.ScheduleCursor != nil {
		t.Fatalf("import retained schedule cursor: %v", imported.ScheduleCursor)
	}
	if imported.LastRun != nil {
		t.Fatalf("import retained last-run ledger: %+v", imported.LastRun)
	}
	if imported.Status != RecipeDisabled {
		t.Fatalf("import status = %q, want disabled", imported.Status)
	}
}
