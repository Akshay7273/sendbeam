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
type RecipeService struct {
	mu      sync.Mutex
	store   *recipes.RecipeStore
	trust   trust.Store
	jobs    *jobs.JobStore
	outbox  *outbox.Outbox
	nowFunc func() time.Time
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
	return &RecipeService{
		store:   recipeStore,
		trust:   trustStore,
		jobs:    jobStore,
		outbox:  outbox.New(jobStore, nil),
		nowFunc: time.Now,
	}, nil
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
