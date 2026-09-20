// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sendbeam/wire"
)

// WatchOptions tunes a Watcher. Debounce and Cooldown override the
// recipe's watch parameters (zero means "take it from the recipe");
// negative values are rejected. OnEvent, when set, receives a
// WatchEvent for every notable watcher transition and is the only
// observability surface — the watcher never logs on its own.
type WatchOptions struct {
	Debounce time.Duration
	Cooldown time.Duration
	OnEvent  func(WatchEvent)
}

// WatchEventKind names what happened inside a Watcher.
type WatchEventKind string

const (
	// WatchEventChange means an in-scope filesystem change armed (or
	// re-armed) the debounce timer. Root is the source root the change
	// was seen under; Path is the changed path.
	WatchEventChange WatchEventKind = "change-detected"
	// WatchEventDispatching means the debounce window went quiet and the
	// watcher is asking the runner to dispatch now.
	WatchEventDispatching WatchEventKind = "dispatching"
	// WatchEventDispatched means the runner accepted the dispatch and
	// enqueued a job. JobID is the enqueued job.
	WatchEventDispatched WatchEventKind = "dispatched"
	// WatchEventRefused means the dispatch attempt was refused (or
	// failed): the Detail/Err carries the reason. The refusal is also in
	// the recipe's last-run ledger.
	WatchEventRefused WatchEventKind = "refused"
	// WatchEventSkipped means no dispatch happened for a benign reason:
	// the attempt fell inside the cooldown window or a dispatch was
	// already in flight.
	WatchEventSkipped WatchEventKind = "skipped"
	// WatchEventError means the underlying OS watcher reported an error.
	// The watcher keeps running; persistent errors surface here so the
	// host can surface them to the user.
	WatchEventError WatchEventKind = "watch-error"
)

// WatchEvent is one observable watcher transition.
type WatchEvent struct {
	Kind   WatchEventKind
	Root   string
	Path   string
	JobID  string
	Err    error
	Detail string
}

// watchTarget is one recipe source prepared for watching: the configured
// absolute root, its symlink-resolved form for confinement checks, whether
// it is a single file, and the recipe's include/exclude filters.
type watchTarget struct {
	root         string
	rootResolved string
	isFile       bool
	include      []string
	exclude      []string
}

// contains reports whether name (cleaned, absolute) is the target itself
// or lexically beneath it. This is the cheap lexical pre-check; inScope
// applies confinement and filters afterwards.
func (t watchTarget) contains(name string) bool {
	if t.isFile {
		return name == t.root
	}
	return name == t.root || withinRoot(name, t.root)
}

// inScope reports whether an event path may arm the debounce timer: it
// must resolve (through symlinks) inside the target's resolved root —
// symlink escapes are ignored — and it must pass the recipe's
// include/exclude filters with the same relative-path glob semantics the
// resolver uses.
func (t watchTarget) inScope(name string) bool {
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil {
		// The path vanished (or is unreadable) between the event and
		// this check: ignore it rather than dispatch on a guess. Remove
		// events are dropped before this point anyway.
		return false
	}
	if !withinRoot(resolved, t.rootResolved) {
		return false
	}
	return matchFilters(name, t.root, t.include, t.exclude)
}

// Watcher is the native watched-folder trigger (V22-PR04): it notices
// filesystem changes under a watch-trigger recipe's sources and asks the
// routine runner to dispatch, debounced and cooldown-bounded.
//
// The watcher NEVER sends files itself and never reads file contents —
// it only notices change. Each dispatch goes through
// Runner.Dispatch with TriggerWatch, which re-loads the recipe,
// re-validates the grant/status/trust, re-resolves the sources fresh
// (with symlink-escape protection), re-checks budgets, and enqueues one
// ordinary outbox job. A watch without a valid automation grant never
// starts: Start fails fast.
//
// Event semantics:
//
//   - Create, Write, Rename and Chmod on in-scope paths re-arm the
//     debounce timer. A Rename is treated as a create of the new name.
//     Remove events are ignored: the resolver runs fresh at dispatch
//     time anyway, and a deletion must never delete remote files.
//   - When the debounce window goes quiet, one dispatch is attempted —
//     unless the cooldown window since the last attempt has not elapsed,
//     in which case the burst is skipped (flap protection).
//   - Directories created after Start are watched on the fly (when the
//     recipe's recursive flag is on), still confined within the source
//     root. Symlinked directories are never followed for watching:
//     watching a symlinked directory would observe a tree the user did
//     not select.
//   - The watch-level recursive flag governs *detection* scope only. The
//     resolver's per-source Recursive flag still governs what a dispatch
//     *sends*.
//
// Lifecycle: NewWatcher snapshots the recipe and its sources; Start
// performs the dynamic checks (status, grant) and begins watching; Stop
// is idempotent and waits for the event loop to exit, so no goroutine
// survives it. Starting an already-started watcher is an error.
type Watcher struct {
	store    *RecipeStore
	runner   *Runner
	recipeID string
	name     string
	opts     WatchOptions

	mu           sync.Mutex
	started      bool
	ctx          context.Context
	cancel       context.CancelFunc
	fw           *fsnotify.Watcher
	done         chan struct{}
	debounce     time.Duration
	cooldown     time.Duration
	watchSubdirs bool
	targets      []watchTarget
	lastTry      time.Time
}

// NewWatcher builds a watcher for the watch-trigger recipe recipeID. It
// fails when the store or runner is nil, the id is malformed, the recipe
// does not exist, its trigger kind is not "watch", its watch parameters
// are invalid, a watch override is negative, or a source root is not
// accessible. Dynamic checks (recipe status, automation grant) happen in
// Start, because the grant may be revoked between construction and start;
// the watch configuration (parameters, sources, filters) is likewise
// re-resolved from the fresh record at Start.
func NewWatcher(store *RecipeStore, runner *Runner, recipeID string, opts WatchOptions) (*Watcher, error) {
	if store == nil {
		return nil, wire.Errorf(wire.CodeInternal, "recipes: nil recipe store")
	}
	if runner == nil {
		return nil, wire.Errorf(wire.CodeInternal, "recipes: nil routine runner")
	}
	if !isLowerHex32(recipeID) {
		return nil, wire.Errorf(wire.CodeStorage, "recipes: invalid recipe id %q", recipeID)
	}
	if opts.Debounce < 0 {
		return nil, wire.Errorf(wire.CodeStorage, "recipes: negative debounce override %s", opts.Debounce)
	}
	if opts.Cooldown < 0 {
		return nil, wire.Errorf(wire.CodeStorage, "recipes: negative cooldown override %s", opts.Cooldown)
	}
	r, ok, err := store.Load(recipeID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, wire.Errorf(wire.CodeStorage, "recipes: no recipe %q", recipeID)
	}
	if r.Trigger.Kind != TriggerWatch {
		return nil, wire.Errorf(wire.CodeStorage,
			"recipes: recipe %q trigger kind is %q, not watch — watching requires a watch trigger", r.Name, r.Trigger.Kind)
	}
	w := &Watcher{
		store:    store,
		runner:   runner,
		recipeID: recipeID,
		name:     r.Name,
		opts:     opts,
	}
	// Fail fast on invalid params or inaccessible sources; Start
	// re-resolves from the fresh record.
	if err := w.resolveConfig(r); err != nil {
		return nil, err
	}
	return w, nil
}

// resolveConfig derives the watcher's effective configuration from a
// recipe record: validated watch parameters (with WatchOptions overrides
// applied) and one watch target per source. It is called by NewWatcher
// for fail-fast validation and again by Start against the fresh record,
// so filter, source or parameter edits made between construction and
// start (followed by the explicit re-grant that material changes require)
// take effect.
func (w *Watcher) resolveConfig(r Recipe) error {
	wp, err := ParseWatchParams(r.Trigger.Watch)
	if err != nil {
		return err
	}
	debounce := wp.Debounce
	if w.opts.Debounce > 0 {
		debounce = w.opts.Debounce
	}
	cooldown := wp.Cooldown
	if w.opts.Cooldown > 0 {
		cooldown = w.opts.Cooldown
	}
	targets := make([]watchTarget, 0, len(r.Sources))
	for _, src := range r.Sources {
		t, err := newWatchTarget(src, r.Include, r.Exclude)
		if err != nil {
			return err
		}
		targets = append(targets, t)
	}
	w.debounce = debounce
	w.cooldown = cooldown
	w.watchSubdirs = wp.Recursive
	w.targets = targets
	return nil
}

// newWatchTarget prepares one recipe source for watching. The root must
// exist and be accessible; a missing or unreadable source root fails
// closed here rather than watching nothing and looking healthy.
func newWatchTarget(src RecipeSource, include, exclude []string) (watchTarget, error) {
	root := filepath.Clean(src.Path)
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return watchTarget{}, wire.Errorf(wire.CodeSourceIO,
			"recipes: watch source root %q is not accessible: %v", src.Path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return watchTarget{}, wire.Errorf(wire.CodeSourceIO,
			"recipes: watch source root %q is not accessible: %v", src.Path, err)
	}
	return watchTarget{
		root:         root,
		rootResolved: resolved,
		isFile:       !info.IsDir(),
		include:      include,
		exclude:      exclude,
	}, nil
}

// Start validates the recipe's dynamic state and begins watching. It
// fails fast — before any OS watch is installed — when the recipe is
// disabled, still needs approval, or has no valid automation grant: a
// watch without a grant never starts. Starting an already-started watcher
// is an error.
func (w *Watcher) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return wire.Errorf(wire.CodeStorage, "recipes: watcher for recipe %q is already started", w.name)
	}
	// Dynamic checks run against the fresh record: the grant or status
	// may have changed since NewWatcher.
	r, ok, err := w.store.Load(w.recipeID)
	if err != nil {
		return err
	}
	if !ok {
		return wire.Errorf(wire.CodeStorage, "recipes: no recipe %q", w.recipeID)
	}
	switch r.Status {
	case RecipeManual:
		// The only status automated dispatch may run under.
	case RecipeDisabled:
		return wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q is disabled — enable it before watching", r.Name)
	case RecipeApprovalRequired:
		return wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q requires approval before it can be watched — run `recipe approve %s` first", r.Name, r.ID)
	default:
		return wire.Errorf(wire.CodeStorage, "recipes: recipe %q has unknown status %q", r.Name, r.Status)
	}
	if !r.GrantValid(time.Now().UTC()) {
		return grantRefusal(r, TriggerWatch)
	}
	// Fresh configuration: filters, sources or watch parameters may have
	// changed (with a re-grant) since NewWatcher.
	if err := w.resolveConfig(r); err != nil {
		return err
	}

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return wire.Errorf(wire.CodeInternal, "recipes: create filesystem watcher: %v", err)
	}
	// If registration fails partway, close the watcher: a half-watched
	// recipe must not look healthy.
	registered := false
	defer func() {
		if !registered {
			_ = fw.Close()
		}
	}()
	for _, t := range w.targets {
		if err := w.addTarget(fw, t); err != nil {
			return err
		}
	}
	w.ctx, w.cancel = context.WithCancel(ctx)
	w.fw = fw
	w.done = make(chan struct{})
	w.started = true
	registered = true
	go w.loop()
	return nil
}

// Stop ends watching: the OS watcher is closed, timers are dropped and the
// event loop is waited on, so no goroutine survives Stop. It is safe to
// call Stop multiple times and on a watcher that never started.
func (w *Watcher) Stop() error {
	w.mu.Lock()
	if !w.started {
		w.mu.Unlock()
		return nil
	}
	w.started = false
	cancel := w.cancel
	done := w.done
	w.mu.Unlock()
	cancel()
	<-done
	return nil
}

// Started reports whether the watcher is currently running.
func (w *Watcher) Started() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.started
}

// addTarget installs OS watches for one target: a file source watches its
// parent directory (events are filtered to the file itself); a directory
// source watches the directory and, when subdirectory watching is on,
// every existing subdirectory. Symlinked directories are never followed —
// watching them would observe a tree outside the user's selection.
func (w *Watcher) addTarget(fw *fsnotify.Watcher, t watchTarget) error {
	if t.isFile {
		dir := filepath.Dir(t.rootResolved)
		if err := fw.Add(dir); err != nil {
			return wire.Errorf(wire.CodeSourceIO,
				"recipes: watch directory %q for source %q: %v", dir, t.root, err)
		}
		return nil
	}
	if !w.watchSubdirs {
		if err := fw.Add(t.rootResolved); err != nil {
			return wire.Errorf(wire.CodeSourceIO,
				"recipes: watch source root %q: %v", t.root, err)
		}
		return nil
	}
	return filepath.WalkDir(t.rootResolved, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return wire.Errorf(wire.CodeSourceIO, "recipes: scan source root %q: %v", t.root, err)
		}
		if !d.IsDir() {
			return nil
		}
		// Never follow symlinked directories while installing watches.
		if d.Type()&fs.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		if err := fw.Add(path); err != nil {
			return wire.Errorf(wire.CodeSourceIO, "recipes: watch directory %q: %v", path, err)
		}
		return nil
	})
}

// loop is the watcher's event loop. It runs until the watcher context is
// done or the OS watcher closes, then closes done.
func (w *Watcher) loop() {
	defer close(w.done)
	defer func() { _ = w.fw.Close() }()
	timer := time.NewTimer(w.debounce)
	if !timer.Stop() {
		<-timer.C
	}
	armed := false
	rearm := func() {
		if armed {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer.Reset(w.debounce)
		armed = true
	}
	for {
		select {
		case <-w.ctx.Done():
			return
		case err, ok := <-w.fw.Errors:
			if !ok {
				return
			}
			w.emit(WatchEvent{Kind: WatchEventError, Err: err, Detail: err.Error()})
		case ev, ok := <-w.fw.Events:
			if !ok {
				return
			}
			if w.handleEvent(ev) {
				rearm()
			}
		case <-timer.C:
			armed = false
			w.fire()
		}
	}
}

// handleEvent processes one OS event. It returns true when the event is
// an in-scope change that must re-arm the debounce timer. Remove events
// are ignored; everything else must pass the per-target scope check
// (lexical containment, symlink-escape confinement, include/exclude
// filters) before it counts.
func (w *Watcher) handleEvent(ev fsnotify.Event) bool {
	if ev.Op&fsnotify.Remove != 0 {
		return false
	}
	if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Chmod) == 0 {
		return false
	}
	name := filepath.Clean(ev.Name)
	var root string
	inScope := false
	for _, t := range w.targets {
		if !t.contains(name) {
			continue
		}
		if !t.inScope(name) {
			continue
		}
		root, inScope = t.root, true
		break
	}
	if !inScope {
		return false
	}
	// A newly created directory joins the watch set on the fly (still
	// confined within its source root); symlinked directories never do.
	if w.watchSubdirs && ev.Op&fsnotify.Create != 0 {
		w.maybeAddDir(name)
	}
	w.emit(WatchEvent{Kind: WatchEventChange, Root: root, Path: name})
	return true
}

// maybeAddDir installs an OS watch for a newly created directory, after
// confirming it is a real directory (not a symlink) confined within one
// of the watched roots. It runs on the event loop goroutine.
func (w *Watcher) maybeAddDir(name string) {
	linfo, err := os.Lstat(name)
	if err != nil {
		return
	}
	if linfo.Mode()&fs.ModeSymlink != 0 {
		return
	}
	if !linfo.IsDir() {
		return
	}
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil {
		return
	}
	for _, t := range w.targets {
		if t.isFile {
			continue
		}
		if withinRoot(resolved, t.rootResolved) {
			if err := w.fw.Add(name); err != nil {
				w.emit(WatchEvent{Kind: WatchEventError, Path: name, Err: err, Detail: err.Error()})
			}
			return
		}
	}
}

// fire runs when the debounce window goes quiet: unless the cooldown
// window since the last attempt has not elapsed, it asks the runner for
// one TriggerWatch dispatch. The runner re-validates everything (grant,
// status, trust, files, budgets) and enqueues one ordinary job — or
// refuses, which lands in the last-run ledger and in a Refused event.
func (w *Watcher) fire() {
	// The watcher may be stopping: a canceled context means the host
	// already asked us to end — do not start a dispatch that would be
	// recorded as a context-canceled failure.
	if err := w.ctx.Err(); err != nil {
		return
	}
	now := time.Now()
	if !w.lastTry.IsZero() && now.Sub(w.lastTry) < w.cooldown {
		w.emit(WatchEvent{
			Kind:   WatchEventSkipped,
			Detail: fmt.Sprintf("within cooldown (%s since last dispatch attempt)", now.Sub(w.lastTry).Round(time.Millisecond)),
		})
		return
	}
	w.lastTry = now
	w.emit(WatchEvent{Kind: WatchEventDispatching})
	job, err := w.runner.Dispatch(w.ctx, w.recipeID, TriggerWatch)
	if err != nil {
		if errors.Is(err, ErrAlreadyRunning) {
			w.emit(WatchEvent{Kind: WatchEventSkipped, Detail: "dispatch already in flight", Err: err})
			return
		}
		w.emit(WatchEvent{Kind: WatchEventRefused, Err: err, Detail: err.Error()})
		return
	}
	w.emit(WatchEvent{Kind: WatchEventDispatched, JobID: job.JobID})
}

// emit delivers one event to the OnEvent callback, if set. A panicking
// callback must not take the event loop down with it.
func (w *Watcher) emit(evt WatchEvent) {
	if w.opts.OnEvent == nil {
		return
	}
	defer func() { _ = recover() }()
	w.opts.OnEvent(evt)
}
