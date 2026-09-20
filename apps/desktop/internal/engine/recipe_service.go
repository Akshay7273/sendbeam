// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/recipes"
	"github.com/sendbeam/engine/trust"
)

// RecipeService is the Wails-bound service for saved handoff recipes
// (V22-PR02). It exposes the same engine operations the CLI uses —
// list/show, dry-run preview (human and machine-readable), explicit
// one-shot runs, and approval — over the desktop trust and job stores.
//
// NOTE (frontend scope): this repo carries no TypeScript source for the
// desktop frontend (apps/desktop/frontend holds only the built dist/),
// so there is no companion UI markup in this change. These bindings are
// the complete service surface; a future frontend PR can call them
// directly once TS source exists.

// RecipeService owns the recipe store and the production outbox used for
// one-shot runs. It never dispatches by itself: RunRecipe enqueues one
// ordinary outbox job; the existing transfer machinery sends it.
//
// Automated dispatch runs through the service's own routine runner:
// watched-folder triggers get one in-process Watcher per watched recipe
// (tracked in watchers), and schedule triggers get one in-process
// Scheduler (scheduler). Both are deliberately per-process: there is no
// daemon yet, so automated runs live only as long as the desktop process
// does — the CLI `recipe watch` / `recipe scheduler` foreground commands
// cover headless use, and a real background service is future work
// (V22-PR08 packaging).
type RecipeService struct {
	mu       sync.Mutex
	store    *recipes.RecipeStore
	trust    trust.Store
	jobs     *jobs.JobStore
	outbox   *outbox.Outbox
	runner   *recipes.Runner
	watchers map[string]*recipes.Watcher
	// scheduler hosts every enabled schedule-triggered recipe in this
	// process between StartScheduler and StopScheduler; nil when not
	// started. schedCancel stops the scheduler's context.
	scheduler   *recipes.Scheduler
	schedCancel context.CancelFunc
	nowFunc     func() time.Time
}

// NewRecipeService opens the recipe and job stores under customConfigDir
// (or the default desktop config dir) and binds them to the given trust
// store — normally the DeviceService's store, so recipe recipient checks
// see the same trust the rest of the desktop uses.
func NewRecipeService(customConfigDir string, trustStore trust.Store) (*RecipeService, error) {
	if trustStore == nil {
		return nil, fmt.Errorf("recipe service: nil trust store")
	}
	dir := customConfigDir
	if dir == "" {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			userConfig = "."
		}
		dir = filepath.Join(userConfig, config.AppDirName)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("recipe service: create config dir: %w", err)
	}
	recipeStore, err := recipes.OpenRecipeStore(filepath.Join(dir, "recipes"))
	if err != nil {
		return nil, fmt.Errorf("recipe service: open recipe store: %w", err)
	}
	jobStore, err := jobs.OpenJobStore(filepath.Join(dir, "jobs"))
	if err != nil {
		return nil, fmt.Errorf("recipe service: open job store: %w", err)
	}
	nowFunc := time.Now
	ob := outbox.New(jobStore, nil)
	svc := &RecipeService{
		store:    recipeStore,
		trust:    trustStore,
		jobs:     jobStore,
		outbox:   ob,
		watchers: make(map[string]*recipes.Watcher),
		nowFunc:  nowFunc,
	}
	svc.runner = recipes.NewRunner(
		recipes.RunDeps{Store: recipeStore, Trust: trustStore, Now: nowFunc},
		recipeOutboxEnqueuer{ob: ob},
		recipes.RunnerOptions{},
	)
	return svc, nil
}

// ListRecipes returns every loadable recipe summary.
func (s *RecipeService) ListRecipes() ([]recipes.RecipeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.List()
}

// GetRecipe returns the full stored recipe.
func (s *RecipeService) GetRecipe(id string) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe service: no recipe %q", id)
	}
	return r, nil
}

// PreviewRecipe renders the human-readable recipe summary plus a dry-run
// note. It sends nothing and creates no jobs.
func (s *RecipeService) PreviewRecipe(id string) (string, error) {
	r, err := s.GetRecipe(id)
	if err != nil {
		return "", err
	}
	return recipes.Preview(r) + "\nDry-run preview: this sends nothing and creates no jobs.\n", nil
}

// PlanRecipe resolves the recipe's current file plan and returns the
// versioned, secret-free plan DTO JSON (v1 contract: additive changes
// only). It sends nothing and creates no jobs.
func (s *RecipeService) PlanRecipe(id string) (string, error) {
	r, err := s.GetRecipe(id)
	if err != nil {
		return "", err
	}
	plan, err := recipes.Resolve(r, recipes.ResolveOptions{})
	if err != nil {
		return "", err
	}
	return string(recipes.PlanDTO(plan)), nil
}

// ApproveRecipe moves an approval-required recipe to manual. The person
// clicking Approve IS the approval; it never grants auto-send.
func (s *RecipeService) ApproveRecipe(id string) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe service: no recipe %q", id)
	}
	if r.Status == recipes.RecipeDisabled {
		return recipes.Recipe{}, fmt.Errorf("recipe service: recipe %q is disabled; edit it to re-enable before approving", r.Name)
	}
	r.Status = recipes.RecipeManual
	if err := s.store.Save(r); err != nil {
		return recipes.Recipe{}, err
	}
	return r, nil
}

// GrantAutomation records the user's explicit consent for automatic
// dispatch of the recipe by the native routine runner (V22-PR03). The
// person clicking Grant IS the authorization: consent is timestamped and
// bound to the recipe's current material scope, and any later material
// change revokes it. It grants nothing on the receiver side and it never
// runs anything itself — grant != run. Only manual-status recipes can be
// granted (approve first); the status is left untouched.
func (s *RecipeService) GrantAutomation(id string) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe service: no recipe %q", id)
	}
	if err := recipes.GrantAutomation(&r, s.nowFunc().UTC()); err != nil {
		return recipes.Recipe{}, err
	}
	if err := s.store.Save(r); err != nil {
		return recipes.Recipe{}, err
	}
	return r, nil
}

// RevokeAutomation withdraws the auto-send consent for the recipe.
// Automated dispatch is refused from then on; the status is unchanged, so
// manual runs keep working.
func (s *RecipeService) RevokeAutomation(id string) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe service: no recipe %q", id)
	}
	recipes.RevokeAutomation(&r)
	if err := s.store.Save(r); err != nil {
		return recipes.Recipe{}, err
	}
	return r, nil
}

// StartWatch begins watching the recipe's sources for filesystem changes
// in this process. Each quiet window ends in one TriggerWatch dispatch
// through the service's routine runner — one ordinary outbox job per
// dispatch, with the grant, trust, files and budgets re-validated every
// time. Starting an already-watched recipe is an error.
//
// Fail-fast, like the CLI: a recipe with no valid auto-send grant, a
// disabled recipe, or a non-watch trigger never starts watching.
func (s *RecipeService) StartWatch(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.watchers[id]; ok {
		return fmt.Errorf("recipe service: recipe %q is already being watched", id)
	}
	w, err := recipes.NewWatcher(s.store, s.runner, id, recipes.WatchOptions{})
	if err != nil {
		return err
	}
	if err := w.Start(context.Background()); err != nil {
		return err
	}
	s.watchers[id] = w
	return nil
}

// StopWatch ends watching for one recipe. It is idempotent: stopping a
// recipe that is not being watched succeeds silently.
func (s *RecipeService) StopWatch(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.watchers[id]
	if !ok {
		return nil
	}
	delete(s.watchers, id)
	return w.Stop()
}

// IsWatching reports whether the recipe currently has an active
// in-process watcher on this desktop instance.
func (s *RecipeService) IsWatching(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.watchers[id]
	return ok
}

// StopAllWatches ends every active watcher. Callers shutting the desktop
// process down should call this so no filesystem watcher outlives the
// service that owns it.
func (s *RecipeService) StopAllWatches() {
	s.mu.Lock()
	watchers := make([]*recipes.Watcher, 0, len(s.watchers))
	for id, w := range s.watchers {
		delete(s.watchers, id)
		watchers = append(watchers, w)
	}
	s.mu.Unlock()
	for _, w := range watchers {
		_ = w.Stop()
	}
}

// StartScheduler hosts every enabled schedule-triggered recipe in this
// desktop process and runs due occurrences (with bounded catch-up)
// until StopScheduler. The desktop app calls this once during startup;
// schedules are per-process and stop with it. Starting twice is an error.
func (s *RecipeService) StartScheduler() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scheduler != nil {
		return fmt.Errorf("recipe service: scheduler already started")
	}
	sched, err := recipes.NewScheduler(s.store, s.runner, recipes.ScheduleOptions{})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := sched.Start(ctx); err != nil {
		cancel()
		return err
	}
	s.scheduler = sched
	s.schedCancel = cancel
	return nil
}

// StopScheduler ends in-process schedule hosting: due occurrences stop
// firing and no scheduler goroutine survives. It is idempotent and safe
// on a service whose scheduler never started.
func (s *RecipeService) StopScheduler() error {
	s.mu.Lock()
	sched := s.scheduler
	cancel := s.schedCancel
	s.scheduler = nil
	s.schedCancel = nil
	s.mu.Unlock()
	if sched == nil {
		return nil
	}
	defer cancel()
	return sched.Stop()
}

// SchedulerRunning reports whether the in-process schedule scheduler is
// currently started.
func (s *RecipeService) SchedulerRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scheduler != nil
}

// LastRun returns the recipe's last-run ledger entry — the most recent
// dispatch attempt (any trigger, including refusals), written by the
// routine runner. It returns nil when no attempt has been recorded yet.
// The entry also rides on the Recipe DTO returned by GetRecipe.
func (s *RecipeService) LastRun(id string) (*recipes.RecipeRunInfo, error) {
	r, err := s.GetRecipe(id)
	if err != nil {
		return nil, err
	}
	return r.LastRun, nil
}

// RunRecipe performs the explicit one-shot run: revalidates status,
// expiry, trust, files and budgets at enqueue time, then enqueues exactly
// one job through the production outbox. It returns the job id.
func (s *RecipeService) RunRecipe(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := recipes.Run(context.Background(), recipes.RunDeps{
		Store: s.store,
		Trust: s.trust,
		Now:   s.nowFunc,
	}, recipeOutboxEnqueuer{ob: s.outbox}, id)
	if err != nil {
		return "", err
	}
	return job.JobID, nil
}

// DeleteRecipe removes one recipe explicitly.
func (s *RecipeService) DeleteRecipe(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Delete(id)
}

// recipeOutboxEnqueuer adapts the real *outbox.Outbox to the
// recipes.Enqueuer interface: one call, one job, one attempt per
// recipient. No second queue.
type recipeOutboxEnqueuer struct {
	ob *outbox.Outbox
}

func (a recipeOutboxEnqueuer) Enqueue(ctx context.Context, paths []string, recipients []recipes.EnqueueRecipient, policy jobs.RetryPolicy, np netpolicy.Policy) (jobs.Job, error) {
	refs := make([]outbox.RecipientRef, len(recipients))
	for i, r := range recipients {
		refs[i] = outbox.RecipientRef{DeviceID: r.DeviceID, Label: r.Label}
	}
	return a.ob.Enqueue(ctx, paths, refs, policy, np)
}
