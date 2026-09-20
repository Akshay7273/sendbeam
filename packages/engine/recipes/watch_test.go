// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// watchEnqueuer is a goroutine-safe recording Enqueuer for watcher tests:
// the watcher's event loop dispatches from its own goroutine.
type watchEnqueuer struct {
	mu         sync.Mutex
	calls      int
	paths      []string
	recipients []EnqueueRecipient
}

func (f *watchEnqueuer) Enqueue(_ context.Context, paths []string, recipients []EnqueueRecipient, _ jobs.RetryPolicy, _ netpolicy.Policy, _ *wire.Provenance) (jobs.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.paths = append([]string{}, paths...)
	f.recipients = append([]EnqueueRecipient{}, recipients...)
	return jobs.Job{JobID: "watch-job-1"}, nil
}

func (f *watchEnqueuer) numCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *watchEnqueuer) lastPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.paths...)
}

// watchEventLog collects WatchEvents goroutine-safely.
type watchEventLog struct {
	mu     sync.Mutex
	events []WatchEvent
}

func (l *watchEventLog) handler() func(WatchEvent) {
	return func(evt WatchEvent) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.events = append(l.events, evt)
	}
}

func (l *watchEventLog) kinds() []WatchEventKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]WatchEventKind, len(l.events))
	for i, e := range l.events {
		out[i] = e.Kind
	}
	return out
}

func (l *watchEventLog) hasKind(k WatchEventKind) bool {
	for _, got := range l.kinds() {
		if got == k {
			return true
		}
	}
	return false
}

// watchFixture is one fully-wired watch test: trusted device, source
// root, granted watch-trigger recipe, recording enqueuer, runner and
// watcher with short debounce/cooldown overrides.
type watchFixture struct {
	store   *RecipeStore
	ts      *trust.MemoryTrustStore
	recipe  Recipe
	root    string
	eq      *watchEnqueuer
	runner  *Runner
	watcher *Watcher
	log     *watchEventLog
}

// newWatchFixture builds a manual-status, auto-send-granted watch recipe
// over a fresh source root. watchParams may be nil (defaults apply).
// Overrides give every watcher a 100ms debounce / 300ms cooldown unless
// overridden per-test afterwards — no, overrides are fixed here; tests
// needing other values construct their own watcher.
func newWatchFixture(t *testing.T, watchParams map[string]any) *watchFixture {
	t.Helper()
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "seed.txt", "seed")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Watched exports", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerWatch
	r.Trigger.Watch = watchParams
	r.Grant.ScopeHash = r.ScopeHash()
	// Grant at the fixed test clock and run the routine runner on the
	// real clock: the watcher's Start checks the grant against time.Now,
	// and a grant timestamped "now" would read as future-dated to a
	// runner pinned to the older fixed test clock.
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &watchEnqueuer{}
	runner := NewRunner(RunDeps{Store: store, Trust: ts, Now: time.Now}, eq, RunnerOptions{Now: time.Now})
	log := &watchEventLog{}
	w, err := NewWatcher(store, runner, r.ID, WatchOptions{
		Debounce: 100 * time.Millisecond,
		Cooldown: 300 * time.Millisecond,
		OnEvent:  log.handler(),
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	fx := &watchFixture{store: store, ts: ts, recipe: r, root: root, eq: eq, runner: runner, watcher: w, log: log}
	t.Cleanup(func() { _ = w.Stop() })
	return fx
}

func (fx *watchFixture) start(t *testing.T) {
	t.Helper()
	if err := fx.watcher.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// waitFor polls cond until it is true or the timeout elapses. Timeouts
// are generous (CI slowness); waits only end early on success.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestWatchParamsValidation(t *testing.T) {
	cases := []struct {
		name    string
		params  map[string]any
		wantErr bool
		check   func(t *testing.T, wp WatchParams)
	}{
		{"nil means defaults", nil, false, func(t *testing.T, wp WatchParams) {
			if wp.Debounce != DefaultWatchDebounce || wp.Cooldown != DefaultWatchCooldown || !wp.Recursive {
				t.Errorf("defaults not applied: %+v", wp)
			}
		}},
		{"empty means defaults", map[string]any{}, false, nil},
		{"custom values", map[string]any{"debounce_ms": 500.0, "cooldown_ms": 0.0, "recursive": false}, false,
			func(t *testing.T, wp WatchParams) {
				if wp.Debounce != 500*time.Millisecond || wp.Cooldown != 0 || wp.Recursive {
					t.Errorf("custom values not parsed: %+v", wp)
				}
			}},
		{"int values accepted", map[string]any{"debounce_ms": 500}, false, nil},
		{"unknown key rejected", map[string]any{"bogus": 1}, true, nil},
		{"string debounce rejected", map[string]any{"debounce_ms": "2s"}, true, nil},
		{"bool debounce rejected", map[string]any{"debounce_ms": true}, true, nil},
		{"fractional rejected", map[string]any{"debounce_ms": 500.5}, true, nil},
		{"debounce below min", map[string]any{"debounce_ms": 100}, true, nil},
		{"debounce above max", map[string]any{"debounce_ms": 60001}, true, nil},
		{"cooldown negative", map[string]any{"cooldown_ms": -1}, true, nil},
		{"cooldown above max", map[string]any{"cooldown_ms": 3600001}, true, nil},
		{"recursive non-bool", map[string]any{"recursive": "yes"}, true, nil},
		{"bounds inclusive", map[string]any{"debounce_ms": 250, "cooldown_ms": 3600000}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wp, err := ParseWatchParams(tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseWatchParams accepted %v", tc.params)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseWatchParams(%v): %v", tc.params, err)
			}
			if tc.check != nil {
				tc.check(t, wp)
			}
		})
	}
}

func TestWatcherDispatchesOnNewFile(t *testing.T) {
	fx := newWatchFixture(t, nil)
	fx.start(t)

	writeTestFile(t, fx.root, "new.txt", "fresh payload")
	// Wait for the dispatched event, not just the enqueue call: the
	// watcher emits it after Runner.Dispatch returns, so the event
	// implies the enqueue happened and the ledger was written.
	waitFor(t, 10*time.Second, "dispatch", func() bool { return fx.log.hasKind(WatchEventDispatched) })

	paths := fx.eq.lastPaths()
	found := false
	for _, p := range paths {
		if p == filepath.Join(fx.root, "new.txt") {
			found = true
		}
	}
	if !found {
		t.Errorf("dispatched job does not include the new file; paths=%v", paths)
	}
	if !fx.log.hasKind(WatchEventDispatched) {
		t.Errorf("no dispatched event; kinds=%v", fx.log.kinds())
	}
}

func TestWatcherDebounceCoalescesBurst(t *testing.T) {
	fx := newWatchFixture(t, nil)
	fx.start(t)

	// A rapid burst of writes must coalesce into exactly one dispatch.
	for i := 0; i < 10; i++ {
		writeTestFile(t, fx.root, "burst.txt", strings.Repeat("x", i+1))
	}
	waitFor(t, 10*time.Second, "coalesced dispatch", func() bool { return fx.eq.numCalls() == 1 })
	// Give the debounce window several more chances to (incorrectly) fire.
	time.Sleep(500 * time.Millisecond)
	if n := fx.eq.numCalls(); n != 1 {
		t.Errorf("burst produced %d dispatches, want exactly 1", n)
	}
}

func TestWatcherIgnoresOutOfScopeChanges(t *testing.T) {
	fx := newWatchFixture(t, nil)
	// Exclude filter via the recipe itself.
	r := fx.recipe
	r.Exclude = []string{"*.tmp"}
	r.Grant.ScopeHash = r.ScopeHash()
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := fx.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fx.start(t)

	// A file in a different directory is outside the watched scope.
	other := t.TempDir()
	writeTestFile(t, other, "elsewhere.txt", "not watched")
	// A file matching the exclude filter must not arm the debounce timer.
	writeTestFile(t, fx.root, "skip.tmp", "excluded")
	time.Sleep(600 * time.Millisecond) // > debounce several times over
	if n := fx.eq.numCalls(); n != 0 {
		t.Errorf("out-of-scope changes dispatched %d job(s), want 0", n)
	}
}

func TestWatcherSymlinkEscapeIgnored(t *testing.T) {
	fx := newWatchFixture(t, nil)
	// A symlink inside the root pointing at a file outside it.
	outside := t.TempDir()
	target := writeTestFile(t, outside, "secret.txt", "outside")
	fx.start(t)

	link := filepath.Join(fx.root, "escape-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// Touching the *target* outside the root generates no event under the
	// watched root (the OS reports it on the target's own directory).
	writeTestFile(t, outside, "secret.txt", "outside-changed")
	time.Sleep(600 * time.Millisecond)
	if n := fx.eq.numCalls(); n != 0 {
		t.Errorf("symlink-escape change dispatched %d job(s), want 0", n)
	}

	// Unit-level: the pre-filter itself must reject the escape path even
	// when an event names the link directly.
	tgt := watchTarget{root: fx.root, rootResolved: fx.root, include: nil, exclude: nil}
	if tgt.inScope(link) {
		t.Errorf("pre-filter accepted symlink escaping its root: %s", link)
	}
}

func TestWatcherStartRequiresGrant(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "a")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Ungranted", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerWatch
	r.Grant.ScopeHash = r.ScopeHash()
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &watchEnqueuer{}
	runner := newTestRunner(store, ts, eq, RunnerOptions{})
	w, err := NewWatcher(store, runner, r.ID, WatchOptions{})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := w.Start(ctx); err == nil {
		_ = w.Stop()
		t.Fatalf("Start without a grant succeeded")
	} else if wire.CodeOf(err) != wire.CodeAuth {
		t.Fatalf("Start without grant: got %v, want CodeAuth", err)
	}
}

func TestWatcherGrantRevokedMidWatch(t *testing.T) {
	fx := newWatchFixture(t, nil)
	fx.start(t)

	// Revoke the grant while the watcher runs: the next debounced change
	// must be refused and the refusal recorded in the ledger.
	r, ok, err := fx.store.Load(fx.recipe.ID)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", ok, err)
	}
	RevokeAutomation(&r)
	if err := fx.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	writeTestFile(t, fx.root, "after-revoke.txt", "nope")
	waitFor(t, 10*time.Second, "refusal ledger entry", func() bool {
		r, ok, err := fx.store.Load(fx.recipe.ID)
		if err != nil || !ok || r.LastRun == nil {
			return false
		}
		return r.LastRun.Status == RunStatusRefused
	})
	if n := fx.eq.numCalls(); n != 0 {
		t.Errorf("revoked grant dispatched %d job(s), want 0", n)
	}
	lr := loadLastRun(t, fx.store, fx.recipe.ID)
	if lr.Trigger != TriggerWatch {
		t.Errorf("ledger trigger = %q, want watch", lr.Trigger)
	}
}

func TestWatcherDisabledRecipeRefusesStart(t *testing.T) {
	fx := newWatchFixture(t, nil)
	r, ok, err := fx.store.Load(fx.recipe.ID)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", ok, err)
	}
	r.Status = RecipeDisabled
	if err := fx.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := fx.watcher.Start(context.Background()); err == nil {
		t.Fatalf("Start on disabled recipe succeeded")
	} else if wire.CodeOf(err) != wire.CodeAuth {
		t.Fatalf("Start on disabled recipe: got %v, want CodeAuth", err)
	}
}

func TestWatcherCooldown(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "a")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Cooldown", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerWatch
	r.Grant.ScopeHash = r.ScopeHash()
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &watchEnqueuer{}
	runner := NewRunner(RunDeps{Store: store, Trust: ts, Now: time.Now}, eq, RunnerOptions{Now: time.Now})
	w, err := NewWatcher(store, runner, r.ID, WatchOptions{Debounce: 100 * time.Millisecond, Cooldown: 1500 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	t.Cleanup(func() { _ = w.Stop() })
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeTestFile(t, root, "one.txt", "1")
	waitFor(t, 10*time.Second, "first dispatch", func() bool { return eq.numCalls() == 1 })

	// A second burst inside the cooldown window must not dispatch again.
	writeTestFile(t, root, "two.txt", "2")
	time.Sleep(500 * time.Millisecond) // debounce elapsed, cooldown not
	if n := eq.numCalls(); n != 1 {
		t.Fatalf("cooldown burst dispatched: %d calls, want 1", n)
	}

	// After the cooldown elapses, a new burst dispatches again.
	time.Sleep(1500 * time.Millisecond)
	writeTestFile(t, root, "three.txt", "3")
	waitFor(t, 10*time.Second, "second dispatch after cooldown", func() bool { return eq.numCalls() == 2 })
}

func TestWatcherStopDuringDebounce(t *testing.T) {
	before := runtime.NumGoroutine()
	fx := newWatchFixture(t, nil)
	fx.start(t)

	writeTestFile(t, fx.root, "doomed.txt", "never sent")
	if err := fx.watcher.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Stopping must be idempotent.
	if err := fx.watcher.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	// The pending debounce must never fire after the stop.
	time.Sleep(500 * time.Millisecond)
	if n := fx.eq.numCalls(); n != 0 {
		t.Errorf("dispatch happened after Stop: %d call(s)", n)
	}
	// No goroutine may survive the stop (fsnotify internals included).
	time.Sleep(300 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestWatcherStartTwiceFails(t *testing.T) {
	fx := newWatchFixture(t, nil)
	fx.start(t)
	if err := fx.watcher.Start(context.Background()); err == nil {
		t.Fatalf("second Start succeeded")
	}
}

func TestWatcherFileSource(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	watched := writeTestFile(t, root, "watched.txt", "v1")
	writeTestFile(t, root, "sibling.txt", "sibling")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("File watch", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	// A file source watches its parent directory but filters events to
	// the file itself.
	r.Sources = []RecipeSource{{Path: watched, Recursive: false}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerWatch
	r.Grant.ScopeHash = r.ScopeHash()
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &watchEnqueuer{}
	runner := NewRunner(RunDeps{Store: store, Trust: ts, Now: time.Now}, eq, RunnerOptions{Now: time.Now})
	w, err := NewWatcher(store, runner, r.ID, WatchOptions{Debounce: 100 * time.Millisecond, Cooldown: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	t.Cleanup(func() { _ = w.Stop() })
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// A change to a *sibling* file in the same directory must not dispatch.
	writeTestFile(t, root, "sibling.txt", "sibling-changed")
	time.Sleep(400 * time.Millisecond)
	if n := eq.numCalls(); n != 0 {
		t.Fatalf("sibling change dispatched %d job(s), want 0", n)
	}
	// A change to the watched file itself dispatches.
	writeTestFile(t, root, "watched.txt", "v2")
	waitFor(t, 10*time.Second, "file dispatch", func() bool { return eq.numCalls() == 1 })
}

func TestWatcherPicksUpNewSubdirectory(t *testing.T) {
	fx := newWatchFixture(t, nil)
	fx.start(t)

	// Directories created after Start join the watch set on the fly.
	if err := os.MkdirAll(filepath.Join(fx.root, "later"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // let the create event register the dir
	writeTestFile(t, fx.root, "later/nested.txt", "nested")
	waitFor(t, 10*time.Second, "nested dispatch", func() bool { return fx.eq.numCalls() == 1 })
}

func TestWatcherManualRunNeedsNoGrant(t *testing.T) {
	// A watch-trigger recipe stays manually runnable without any grant:
	// the human at the keyboard is the authorization.
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "a")
	store := openTestRecipeStore(t)

	r, err := NewRecipe("Watch manual", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
	r.Status = RecipeManual
	r.Trigger.Kind = TriggerWatch
	r.Trigger.Watch = map[string]any{"debounce_ms": 1000}
	r.Grant.ScopeHash = r.ScopeHash()
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	eq := &recordingEnqueuer{}
	if _, err := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID); err != nil {
		t.Fatalf("manual Run on watch recipe without grant: %v", err)
	}
	if eq.calls != 1 {
		t.Errorf("manual run enqueued %d jobs, want 1", eq.calls)
	}
}

func TestWatchParamsAreMaterialScope(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id := testIdentity(ctx, t, ts, "Studio laptop")
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "a")
	store := openTestRecipeStore(t)

	build := func(t *testing.T, params map[string]any) Recipe {
		t.Helper()
		r, err := NewRecipe("Scope", time.Now().UTC())
		if err != nil {
			t.Fatalf("NewRecipe: %v", err)
		}
		r.Sources = []RecipeSource{{Path: root, Recursive: true}}
		r.Recipients = []RecipeRecipient{{DeviceID: id, Label: "studio"}}
		r.Status = RecipeManual
		r.Trigger.Kind = TriggerWatch
		r.Trigger.Watch = params
		r.Grant.ScopeHash = r.ScopeHash()
		return r
	}

	a := build(t, nil)
	b := build(t, map[string]any{"debounce_ms": 5000})
	if a.ScopeHash() == b.ScopeHash() {
		t.Fatalf("watch param change did not change ScopeHash")
	}
	// Defaults are canonical: explicit defaults hash like the empty map.
	c := build(t, map[string]any{"debounce_ms": 2000, "cooldown_ms": 10000, "recursive": true})
	if a.ScopeHash() != c.ScopeHash() {
		t.Fatalf("explicit defaults hash differently than empty params")
	}

	// A watch param edit through ApplyUpdate revokes the automation grant
	// via the normal material-change rule.
	granted := build(t, nil)
	if err := GrantAutomation(&granted, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := store.Save(granted); err != nil {
		t.Fatalf("Save: %v", err)
	}
	updated := granted
	updated.Trigger.Watch = map[string]any{"debounce_ms": 5000}
	after, err := ApplyUpdate(store, updated)
	if err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if after.Grant.AutoSend {
		t.Errorf("watch param change did not revoke the grant")
	}
	if after.Status != RecipeApprovalRequired {
		t.Errorf("status after material change = %q, want approval-required", after.Status)
	}
}

func TestPreviewShowsWatchParams(t *testing.T) {
	r, err := NewRecipe("Prev", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Trigger.Kind = TriggerWatch
	r.Trigger.Watch = map[string]any{"debounce_ms": 5000, "cooldown_ms": 0, "recursive": false}
	out := Preview(r)
	for _, want := range []string{"watch", "debounce 5s", "cooldown 0s", "recursive subdirectories: false"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview missing %q:\n%s", want, out)
		}
	}
}

func TestNewWatcherRejectsBadInput(t *testing.T) {
	fx := newWatchFixture(t, nil)
	if _, err := NewWatcher(nil, fx.runner, fx.recipe.ID, WatchOptions{}); err == nil {
		t.Errorf("nil store accepted")
	}
	if _, err := NewWatcher(fx.store, nil, fx.recipe.ID, WatchOptions{}); err == nil {
		t.Errorf("nil runner accepted")
	}
	if _, err := NewWatcher(fx.store, fx.runner, "nope", WatchOptions{}); err == nil {
		t.Errorf("bad id accepted")
	}
	if _, err := NewWatcher(fx.store, fx.runner, strings.Repeat("0", 32), WatchOptions{}); err == nil {
		t.Errorf("unknown recipe accepted")
	}
	if _, err := NewWatcher(fx.store, fx.runner, fx.recipe.ID, WatchOptions{Debounce: -time.Second}); err == nil {
		t.Errorf("negative debounce accepted")
	}
	// A manual-trigger recipe cannot be watched.
	r := fx.recipe
	r.Trigger.Kind = TriggerManual
	r.Trigger.Watch = nil
	r.Grant.ScopeHash = r.ScopeHash()
	if err := fx.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := NewWatcher(fx.store, fx.runner, r.ID, WatchOptions{}); err == nil {
		t.Errorf("manual-trigger recipe accepted by NewWatcher")
	}
}
