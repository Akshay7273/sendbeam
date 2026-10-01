// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/recipes"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
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
	// identity + secrets wire the PRODUCTION sender for dispatch (v2.3
	// correction C): identity is this device's Ed25519 identity, secrets
	// resolve pair credentials at dispatch time. Both come from the
	// DeviceService; nil identity/secrets keep dispatch nil (fail-closed).
	identity *trust.IdentityManager
	secrets  trust.CredentialStore
	// dispatchCancel stops the bounded dispatcher loop (per-process, no
	// daemon — lives only while the desktop app does).
	dispatchCancel context.CancelFunc
	// localPeerAddrs maps deviceId -> manual local endpoint (ip:port) the
	// dispatcher uses for local-only dispatch passes. Jobs whose recipient
	// lacks an entry are held with a clear skip reason (no online fallback).
	localPeerAddrs map[string]string
	// policyLookup returns the CURRENT desktop network policy (wired from
	// main.go's persisted-config accessor). Gap 4: recipe-bound policy +
	// current policy together govern routing.
	policyLookup func() netpolicy.Policy
	// onlineSender is the desktop's real online targeted-send engine call
	// (wired from the TransferService); nil keeps online dispatch
	// fail-closed.
	onlineSender func(ctx context.Context, req onlineSendRequest) (transfer.Outcome, error)
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
func NewRecipeService(customConfigDir string, trustStore trust.Store, identity *trust.IdentityManager, secrets trust.CredentialStore) (*RecipeService, error) {
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
		identity: identity,
		secrets:  secrets,
	}
	// v2.3 correction C (gap 2): the dispatcher starts WITH the service
	// (bound to the desktop process lifecycle) whenever the production
	// sender is wired — run/watch/schedule reach delivery without any
	// separate developer/dispatcher call.
	if identity != nil && secrets != nil {
		if err := svc.StartDispatcher(2 * time.Second); err != nil {
			return nil, fmt.Errorf("recipe service: start dispatcher: %w", err)
		}
	}
	svc.runner = recipes.NewRunner(
		recipes.RunDeps{Store: recipeStore, Trust: trustStore, Now: nowFunc, SenderLabel: desktopDeviceLabel()},
		recipeOutboxEnqueuer{ob: ob, senderLabel: desktopDeviceLabel()},
		recipes.RunnerOptions{},
	)
	return svc, nil
}

// desktopDeviceLabel is this device's own label for the routine origin
// stamp (V22-PR06): the hostname, falling back to "Desktop Device" when
// the hostname is unavailable.
func desktopDeviceLabel() string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return "Desktop Device"
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
		return recipes.Recipe{}, fmt.Errorf("recipe service: recipe %q is disabled; enable it before approving", r.Name)
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

// DisableRecipe switches the routine off (V22-PR06): status "disabled",
// so every future dispatch — watch, schedule, retry, and manual alike —
// is refused and the watcher's dynamic reload plus the scheduler's
// reconciliation drop it. A dispatch already admitted keeps running to
// completion: disable stops the NEXT send, never the one already moving
// bytes.
func (s *RecipeService) DisableRecipe(id string) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe service: no recipe %q", id)
	}
	recipes.Disable(&r)
	if err := s.store.Save(r); err != nil {
		return recipes.Recipe{}, err
	}
	return r, nil
}

// EnableRecipe returns a disabled routine to life through the safe
// default (V22-PR06): status "approval-required" and its automation
// consent revoked, even if it was granted before. Nothing dispatches
// until a person re-reviews: manual runs need ApproveRecipe first, and
// automated dispatch needs a fresh GrantAutomation after that.
func (s *RecipeService) EnableRecipe(id string) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe service: no recipe %q", id)
	}
	if r.Status != recipes.RecipeDisabled {
		return recipes.Recipe{}, fmt.Errorf("recipe service: recipe %q is not disabled (status %s)", r.Name, string(r.Status))
	}
	recipes.Enable(&r)
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
		// V22-PR06: this device's own label rides the job's provenance.
		SenderLabel: desktopDeviceLabel(),
	}, recipeOutboxEnqueuer{ob: s.outbox, senderLabel: desktopDeviceLabel()}, id)
	if err != nil {
		return "", err
	}
	return job.JobID, nil
}

// RecipeUpsert carries one save-handoff editor submission. Fields are the
// editor's explicit inputs; validation and consent live in the engine.
type RecipeUpsert struct {
	// ID non-empty = edit of an existing recipe; empty = create.
	ID string `json:"id"`
	Name string `json:"name"`
	Sources []RecipeSourceInput `json:"sources"`
	RecipientDeviceIDs []string `json:"recipientDeviceIDs"`
	NetworkPolicy string `json:"networkPolicy,omitempty"`
	RequirePadding bool `json:"requirePadding"`
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	TriggerKind string `json:"triggerKind"`
	ScheduleParams map[string]any `json:"scheduleParams,omitempty"`
	WatchParams map[string]any `json:"watchParams,omitempty"`
	MaxBytesPerRun int64 `json:"maxBytesPerRun,omitempty"`
	MaxFilesPerRun int64 `json:"maxFilesPerRun,omitempty"`
}

// RecipeSourceInput is one explicit source root from the editor.
type RecipeSourceInput struct {
	Path string `json:"path"`
	Recursive bool `json:"recursive"`
}

// CreateRecipe saves a NEW recipe from editor input. New recipes are inert:
// status approval-required, no automation grant. Invalid sources,
// untrusted recipients, or bad trigger parameters fail visibly; the caller
// (frontend) must surface the error literally.
func (s *RecipeService) CreateRecipe(in RecipeUpsert) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsertLocked(in, nil, true)
}

// DuplicateRecipe copies an existing recipe's material scope into a new,
// inert recipe under a new name. Grants are never copied.
func (s *RecipeService) DuplicateRecipe(id, name string) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe %q not found", id)
	}
	dup, err := s.upsertLocked(upsertFromRecipe(src, name), nil, true)
	if err != nil {
		return recipes.Recipe{}, err
	}
	return dup, nil
}

// EditRecipe applies editor input to an existing recipe. A material scope
// change revokes any prior automation grant and drops the recipe back to
// approval-required — implemented by re-hashing the scope on save (the
// store checksum path), plus an explicit grant reset here.
func (s *RecipeService) EditRecipe(id string, in RecipeUpsert) (recipes.Recipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok, err := s.store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("recipe %q not found", id)
	}
	// ApplyUpdate is the engine's canonical edit path: it reconciles the
	// grant (material scope change ⇒ consent revoked + status back to
	// approval-required), validates, and saves atomically. upsertLocked
	// prepares the edited recipe without saving (persist=false).
	in.ID = existing.ID
	in.Name = existing.Name
	edited, err := s.upsertLocked(in, &existing, false)
	if err != nil {
		return recipes.Recipe{}, err
	}
	return recipes.ApplyUpdate(s.store, edited)
}

// upsertLocked applies editor input onto a target recipe (create: fresh
// NewRecipe; edit: copy onto existing to preserve id/timestamps/ledger),
// validates recipients against the live trust store, and saves. For edit
// callers that use recipes.ApplyUpdate, the save is skipped (persist=false)
// because ApplyUpdate performs the reconciled save itself.
func (s *RecipeService) upsertLocked(in RecipeUpsert, existing *recipes.Recipe, persist bool) (recipes.Recipe, error) {
	var r recipes.Recipe
	if existing == nil {
		nr, err := recipes.NewRecipe(in.Name, s.nowFunc())
		if err != nil {
			return recipes.Recipe{}, err
		}
		r = nr
	} else {
		r = *existing
		// Name is a non-material field: rename in place, keep
		// id/timestamps/ledger; material-scope changes are handled below.
		if strings.TrimSpace(in.Name) != "" {
			r.Name = strings.TrimSpace(in.Name)
		}
	}

	if len(in.Sources) == 0 {
		return recipes.Recipe{}, fmt.Errorf("recipes: at least one source root is required")
	}
	r.Sources = nil
	for _, src := range in.Sources {
		abs, err := filepath.Abs(src.Path)
		if err != nil {
			return recipes.Recipe{}, fmt.Errorf("resolve source %q: %w", src.Path, err)
		}
		st, serr := os.Stat(abs)
		if serr != nil {
			return recipes.Recipe{}, fmt.Errorf("source %q is not accessible: %w", abs, serr)
		}
		if !st.IsDir() {
			return recipes.Recipe{}, fmt.Errorf("source %q is not a directory", abs)
		}
		r.Sources = append(r.Sources, recipes.RecipeSource{Path: filepath.Clean(abs), Recursive: src.Recursive})
	}

	r.Recipients = nil
	for _, devID := range in.RecipientDeviceIDs {
		rec, err := s.trust.GetDevice(context.Background(), devID)
		if err != nil || rec == nil {
			return recipes.Recipe{}, fmt.Errorf("recipient %q is not a trusted paired device", devID)
		}
		if rec.Revoked {
			return recipes.Recipe{}, fmt.Errorf("recipient %q is revoked", devID)
		}
		r.Recipients = append(r.Recipients, recipes.RecipeRecipient{DeviceID: devID, Label: rec.LocalLabel})
	}

	switch in.NetworkPolicy {
	case "", "online", "prefer-local", "local-only":
		r.NetworkPolicy = in.NetworkPolicy
	default:
		return recipes.Recipe{}, fmt.Errorf("unknown network policy %q", in.NetworkPolicy)
	}
	r.RequirePadding = in.RequirePadding
	r.Include = in.Include
	r.Exclude = in.Exclude

	switch in.TriggerKind {
	case "manual", "":
		r.Trigger = recipes.RecipeTrigger{Kind: recipes.TriggerManual}
	case "watch":
		r.Trigger = recipes.RecipeTrigger{Kind: recipes.TriggerWatch, Watch: in.WatchParams}
	case "schedule":
		if in.ScheduleParams == nil {
			return recipes.Recipe{}, fmt.Errorf("schedule trigger requires schedule parameters")
		}
		r.Trigger = recipes.RecipeTrigger{Kind: recipes.TriggerSchedule, Schedule: in.ScheduleParams}
	default:
		return recipes.Recipe{}, fmt.Errorf("unknown trigger kind %q", in.TriggerKind)
	}
	if in.TriggerKind == "schedule" && in.ScheduleParams != nil {
		if _, err := recipes.ParseScheduleParams(in.ScheduleParams); err != nil {
			return recipes.Recipe{}, err
		}
	}

	if in.MaxBytesPerRun > 0 {
		r.Budgets.MaxBytesPerRun = in.MaxBytesPerRun
	}
	if in.MaxFilesPerRun > 0 {
		r.Budgets.MaxFilesPerRun = in.MaxFilesPerRun
	}

	r.Grant.ScopeHash = r.ScopeHash()

	if err := recipes.ValidateRecipients(context.Background(), s.trust, r); err != nil {
		return recipes.Recipe{}, err
	}
	if persist {
		if err := s.store.Save(r); err != nil {
			return recipes.Recipe{}, err
		}
	}
	return r, nil
}

// upsertFromRecipe converts an existing recipe into editor input for
// duplication (name overridden; grant/status intentionally dropped —
// duplicates start inert).
func upsertFromRecipe(src recipes.Recipe, name string) RecipeUpsert {
	in := RecipeUpsert{
		ID: "", // new id
		Name: name,
		NetworkPolicy: src.NetworkPolicy,
		RequirePadding: src.RequirePadding,
		Include: append([]string(nil), src.Include...),
		Exclude: append([]string(nil), src.Exclude...),
		TriggerKind: string(src.Trigger.Kind),
		ScheduleParams: src.Trigger.Schedule,
		WatchParams: src.Trigger.Watch,
		MaxBytesPerRun: src.Budgets.MaxBytesPerRun,
		MaxFilesPerRun: src.Budgets.MaxFilesPerRun,
	}
	for _, s := range src.Sources {
		in.Sources = append(in.Sources, RecipeSourceInput{Path: s.Path, Recursive: s.Recursive})
	}
	for _, r := range src.Recipients {
		in.RecipientDeviceIDs = append(in.RecipientDeviceIDs, r.DeviceID)
	}
	return in
}

// RecipeDeliveryStatus is the recipe → job → recipient-attempt → outcome
// chain for one run, read from the REAL production stores. Queue success is
// never presented as delivered: per-recipient verified/completed states are
// the only delivery proof.
type RecipeDeliveryStatus struct {
	RecipeID string `json:"recipeId"`
	// LastRun ledger entry (dispatch attempt): nil when no attempt ever
	// recorded. A refusal/failure here is NOT a delivery.
	LastRun *recipes.RecipeRunInfo `json:"lastRun,omitempty"`
	// Job mirrors the production job record when one exists for the last
	// dispatched run.
	Job *DeliveryJobView `json:"job,omitempty"`
}

// DeliveryJobView is the outbox job as the status surface needs it.
type DeliveryJobView struct {
	JobID     string                  `json:"jobId"`
	Status    string                  `json:"status"`
	TotalSize int64                   `json:"totalSize"`
	Attempts  []DeliveryAttemptView   `json:"attempts"`
}

// DeliveryAttemptView is one recipient attempt: queue/active/verified/
// completed/failed states stay distinct — a queued attempt never appears
// as delivered.
type DeliveryAttemptView struct {
	DeviceID         string `json:"deviceId"`
	Label            string `json:"label"`
	Status           string `json:"status"`
	Attempts         int    `json:"attempts"`
	NextRetryAt      string `json:"nextRetryAt,omitempty"`
	LastError        string `json:"lastError,omitempty"`
	BytesTransferred int64  `json:"bytesTransferred,omitempty"`
	VerifiedDigest   string `json:"verifiedDigest,omitempty"`
	UpdatedAt        string `json:"updatedAt"`
}

// RecipeDeliveryStatus resolves the delivery chain for a recipe's most recent run:
// the ledger entry (what was dispatched and how it ended) plus the real job
// record (per-recipient attempt states from the outbox store). A job that
// was never dispatched (refused/failed/skipped run) carries no job view.
func (s *RecipeService) RecipeDeliveryStatus(id string) (RecipeDeliveryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := RecipeDeliveryStatus{RecipeID: id}

	r, ok, err := s.store.Load(id)
	if err != nil {
		return out, err
	}
	if !ok {
		return out, fmt.Errorf("recipe %q not found", id)
	}
	out.LastRun = r.LastRun
	if out.LastRun == nil || out.LastRun.JobID == "" {
		// No dispatched run yet (inert/approval-required, refused, failed,
		// or skipped) — honest shape: lastRun may still explain why.
		return out, nil
	}

	job, found, err := s.jobs.Load(out.LastRun.JobID)
	if err != nil || !found {
		// Ledger says dispatched but the job record is gone (expired/
		// discarded): surface that honestly rather than inventing an outcome.
		return out, nil
	}
	view := DeliveryJobView{
		JobID:     job.JobID,
		Status:    string(job.Status),
		TotalSize: job.TotalSize,
	}
	for _, a := range job.Attempts {
		view.Attempts = append(view.Attempts, DeliveryAttemptView{
			DeviceID:         a.DeviceID,
			Label:            a.Label,
			Status:           string(a.Status),
			Attempts:         a.Attempts,
			LastError:        a.LastError,
			BytesTransferred: a.BytesTransferred,
			VerifiedDigest:   a.VerifiedDigest,
			UpdatedAt:        a.UpdatedAt.UTC().Format(time.RFC3339),
		})
		if !a.NextRetryAt.IsZero() {
			view.Attempts[len(view.Attempts)-1].NextRetryAt = a.NextRetryAt.UTC().Format(time.RFC3339)
		}
	}
	out.Job = &view
	return out, nil
}

// DeleteRecipe removes one recipe explicitly.
func (s *RecipeService) DeleteRecipe(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Delete(id)
}

// SetPolicyLookup wires the current-desktop-policy accessor (called once
// from main.go after the config store exists).
func (s *RecipeService) SetPolicyLookup(fn func() netpolicy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyLookup = fn
}

// SetOnlineSender wires the desktop's real online targeted-send engine call.
func (s *RecipeService) SetOnlineSender(fn func(ctx context.Context, req onlineSendRequest) (transfer.Outcome, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onlineSender = fn
}

// SetLocalPeerAddr records the manual local endpoint for a paired device
// (the desktop equivalent of the CLI's --peer-addr at dispatch time).
func (s *RecipeService) SetLocalPeerAddr(deviceID, addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.localPeerAddrs == nil {
		s.localPeerAddrs = make(map[string]string)
	}
	if addr == "" {
		delete(s.localPeerAddrs, deviceID)
		return
	}
	s.localPeerAddrs[deviceID] = addr
}

// DispatcherRunning reports whether the bounded dispatcher loop is active.
func (s *RecipeService) DispatcherRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dispatchCancel != nil
}

// StartDispatcher runs the bounded dispatch loop for this process: every
// interval it performs one DispatchOnce pass (concurrency 2, bounded lease)
// over the production outbox. No daemon: the loop lives only while the
// desktop process does (stated in the UI, V23-PR05).
func (s *RecipeService) StartDispatcher(interval time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dispatchCancel != nil {
		return fmt.Errorf("recipe service: dispatcher already running")
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.dispatchCancel = cancel
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.DispatchOnceNow(ctx); err != nil {
					log.Printf("recipe dispatcher pass: %v", err)
				}
			}
		}
	}()
	return nil
}

// StopDispatcher stops the bounded dispatch loop.
func (s *RecipeService) StopDispatcher() {
	s.mu.Lock()
	cancel := s.dispatchCancel
	s.dispatchCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Shutdown implements the lifecycle coordinator's Shutdownable: stops the
// dispatcher loop (in-flight passes finish under the bounded lease; the
// lease expires naturally on crash). Called on app quit — the dispatcher's
// lifecycle IS the desktop process lifecycle (v2.3 correction C, gap 2).
func (s *RecipeService) Shutdown(_ time.Duration) error {
	s.StopDispatcher()
	return nil
}

// DispatchOnceNow performs ONE dispatch pass now (also the immediate kick
// after RunRecipe/watch/schedule enqueue). Returns the dispatch report.
func (s *RecipeService) DispatchOnceNow(ctx context.Context) (outbox.DispatchReport, error) {
	s.mu.Lock()
	identity, secrets, peerAddrs := s.identity, s.secrets, s.localPeerAddrs
	s.mu.Unlock()
	if identity == nil || secrets == nil {
		return outbox.DispatchReport{}, fmt.Errorf("production sender not wired: identity/secrets unavailable")
	}
	localID, err := identity.GetOrCreateIdentity()
	if err != nil {
		return outbox.DispatchReport{}, err
	}
	// Gap 4 (routing): the CURRENT desktop policy gates the pass (the CLI's
	// dispatch-time effective policy equivalent); each job's OWN recipe-bound
	// policy is checked against it by the outbox's per-job gate below. An
	// online-policy recipe under a local-only desktop (or vice versa where
	// unsatisfiable) is HELD with a clear reason — never sent on a silent
	// fallback route.
	effective := netpolicy.LocalOnly
	if s.policyLookup != nil {
		effective = s.policyLookup()
	}
	// Production sender: one attempt per call. Local-only route via the
	// recorded manual endpoint; the outbox's own policy gate holds
	// unsatisfiable jobs with a clear skip reason (no silent online
	// fallback). A fresh Outbox over the SAME shared job store keeps lease
	// and attempt state in one place; only the sender closure is per-call.
	// livePolicy re-reads the CURRENT desktop policy at every decision
	// point (route selection AND immediately before each online call) —
	// policy changes between enqueue/send/fallback govern immediately;
	// the snapshot never does.
	livePolicy := func() netpolicy.Policy {
		if s.policyLookup != nil {
			return s.policyLookup()
		}
		return netpolicy.LocalOnly
	}
	onlineAllowedNow := func() bool {
		cur := livePolicy()
		return cur == netpolicy.Online || cur == netpolicy.PreferLocal
	}
	sender := func(ctx context.Context, job jobs.Job, attempt jobs.RecipientAttempt, paths []string) outbox.SendOutcome {
		// STOP-SHIP INVARIANT: the job-bound policy AND the CURRENT desktop
		// policy are both checked here and again immediately before every
		// online invocation — a prefer-local job under LocalOnly must NEVER
		// reach the online sender (missing endpoint OR local failure).
		jobPolicy := job.EffectiveNetworkPolicy()
		curPolicy := livePolicy()
		if !jobPolicy.DispatchableUnder(curPolicy) {
			return outbox.SendOutcome{Status: transfer.StatusFailed,
				Error: fmt.Sprintf("job policy %q is not dispatchable under the current desktop policy %q; HELD — no fallback", jobPolicy, curPolicy)}
		}
		// Gap 1: the job's PERSISTED padding policy governs; routine jobs
		// missing the field fail closed (privacy never guessed).
		padding, perr := job.EffectiveRequirePadding(job.Provenance != nil)
		if perr != nil {
			return outbox.SendOutcome{Status: transfer.StatusFailed, Error: perr.Error()}
		}
		addr := peerAddrs[attempt.DeviceID]
		switch jobPolicy {
		case netpolicy.LocalOnly:
			if addr == "" {
				// HELD (no attempt, budget untouched — the endpoint gate
				// below already skips it; this backstop is for races).
				return outbox.SendOutcome{Status: transfer.StatusFailed,
					Error: fmt.Sprintf("no local endpoint recorded for %q; HELD — local-only never falls back online", attempt.DeviceID)}
			}
			return s.productionLocalSend(ctx, job, attempt, paths, addr, padding, false)
		case netpolicy.PreferLocal:
			if addr != "" {
				out := s.productionLocalSend(ctx, job, attempt, paths, addr, padding, false)
				if out.Status == transfer.StatusOk {
					return out
				}
				// Online fallback — only if the CURRENT policy (re-read
				// NOW, after local failure) permits online sends.
				if !onlineAllowedNow() {
					return outbox.SendOutcome{Status: transfer.StatusFailed,
						Error: "local: " + out.Error + "; policy changed — online fallback refused (no silent downgrade)"}
				}
				fb := s.productionOnlineSend(ctx, job, attempt, paths, localID, padding)
				if fb.Status == transfer.StatusOk {
					return outbox.SendOutcome{Status: transfer.StatusOk, Digest: fb.Digest, BytesTransferred: fb.BytesTransferred}
				}
				return outbox.SendOutcome{Status: transfer.StatusFailed,
					Error: "local: " + out.Error + "; online fallback: " + fb.Error}
			}
			if !onlineAllowedNow() {
				return outbox.SendOutcome{Status: transfer.StatusFailed,
					Error: fmt.Sprintf("no local endpoint for %q and the current policy %q forbids online; HELD", attempt.DeviceID, curPolicy)}
			}
			return s.productionOnlineSend(ctx, job, attempt, paths, localID, padding)
		default:
			if !onlineAllowedNow() {
				return outbox.SendOutcome{Status: transfer.StatusFailed,
					Error: fmt.Sprintf("online job under current policy %q; HELD — no fallback", curPolicy)}
			}
			return s.productionOnlineSend(ctx, job, attempt, paths, localID, padding)
		}
	}
	ob := outbox.New(s.jobs, sender)
	// Gap 3 (real HELD): recipients without a configured endpoint are held
	// BEFORE any attempt mutates — zero send attempts, retry budget
	// untouched, honest skip reason.
	ob.SetEndpointGate(func(deviceID string) bool {
		return peerAddrs[deviceID] != ""
	})
	return ob.DispatchOnce(ctx, outbox.DispatchOptions{
		Concurrency:     2,
		LeaseTTL:        jobs.DefaultLeaseTTL,
		EffectivePolicy: effective,
	})
}

// productionLocalSend is the desktop production sender for one dispatch
// attempt over the local-only route: the same engine path the CLI outbox
// local dispatch uses (localtransfer.Transfer) — trust re-resolution and
// device binding here (the job label is never trusted), route validation
// against the interface-derived policy, source revalidation, and a
// digest-verified outcome. No online fallback exists on this path.
func (s *RecipeService) productionLocalSend(ctx context.Context, job jobs.Job, attempt jobs.RecipientAttempt, paths []string, peerAddr string, requirePadding, privateMode bool) outbox.SendOutcome {
	fail := func(format string, args ...any) outbox.SendOutcome {
		return outbox.SendOutcome{Status: transfer.StatusFailed, Error: fmt.Sprintf(format, args...)}
	}
	if s.identity == nil || s.secrets == nil {
		return fail("production sender not wired: identity/secrets unavailable; dispatch refused")
	}
	resolved, err := s.resolveSendTarget(ctx, attempt.DeviceID)
	if err != nil {
		return fail("resolve recipient: %v", err)
	}
	identity, err := s.identity.GetOrCreateIdentity()
	if err != nil {
		return fail("identity: %v", err)
	}
	table := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	if _, err := table.AddManual(attempt.DeviceID, peerAddr); err != nil {
		return fail("--peer-addr %q rejected: %v", peerAddr, err)
	}
	sources, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return fail("read sources: %v", err)
	}
	kPair, err := s.secrets.ResolvePairSecret(ctx, resolved.record.DeviceID, resolved.record.PairCredentialRef)
	if err != nil || len(kPair) == 0 {
		return fail("resolve pair secret for %q: %v", attempt.DeviceID, err)
	}
	peerPub, err := hex.DecodeString(resolved.record.PublicKey)
	if err != nil || len(peerPub) == 0 {
		return fail("invalid trust record public key for %q", attempt.DeviceID)
	}
	var handle [16]byte
	if _, err := rand.Read(handle[:]); err != nil {
		return fail("mint handle: %v", err)
	}
	var sentBytes int64
	out, err := localtransfer.Transfer(ctx, localtransfer.Options{
		Identity:     identity,
		Store:        s.trust,
		Resolver:     s.secrets,
		Table:        table,
		PeerDeviceID: attempt.DeviceID,
		PeerLabel:    resolved.record.LocalLabel,
		Role:         rendezvous.RoleOfferer,
		Sources:      sources,
		DestDir:      "", // receiver chooses
		Private:      privateMode,
		RequirePadding: requirePadding,
		TransferID:   job.JobID,
		Provenance:   job.Provenance,
		OnProgress: func(n int64) { sentBytes = n },
	})
	if err != nil {
		return fail("local transfer: %v", err)
	}
	digest := out.Digest
	if digest == "" {
		return fail("local transfer reported success without a content digest; not marking delivered")
	}
	return outbox.SendOutcome{Status: transfer.StatusOk, Digest: digest, BytesTransferred: sentBytes}
}

// productionOnlineSend is the production ONLINE sender: one targeted
// transfer through the desktop engine's real rendezvous path (the same
// machinery TransferService.Send drives), honoring the persisted padding
// decision. No silent policy change: called only for online-policy jobs or
// the visible prefer-local fallback.
func (s *RecipeService) productionOnlineSend(ctx context.Context, job jobs.Job, attempt jobs.RecipientAttempt, paths []string, localID *wire.DeviceIdentity, padding bool) outbox.SendOutcome {
	fail := func(format string, args ...any) outbox.SendOutcome {
		return outbox.SendOutcome{Status: transfer.StatusFailed, Error: fmt.Sprintf(format, args...)}
	}
	if s.onlineSender == nil {
		return fail("online sender not wired; refusing to send")
	}
	resolved, err := s.resolveSendTarget(ctx, attempt.DeviceID)
	if err != nil {
		return fail("resolve recipient: %v", err)
	}
	sources, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return fail("read sources: %v", err)
	}
	var sentBytes int64
	out, err := s.onlineSender(ctx, onlineSendRequest{
		Attempt:        attempt,
		Paths:          paths,
		Sources:        sources,
		Peer:           resolved.record,
		LocalID:        localID,
		RequirePadding: padding,
		Provenance:     job.Provenance,
		OnProgress:     func(n int64) { sentBytes = n },
	})
	if err != nil {
		return fail("online transfer: %v", err)
	}
	if out.Digest == "" {
		return fail("online transfer reported success without a content digest; not marking delivered")
	}
	return outbox.SendOutcome{Status: transfer.StatusOk, Digest: out.Digest, BytesTransferred: sentBytes}
}

// onlineSendRequest carries one production online-send invocation.
type onlineSendRequest struct {
	Attempt        jobs.RecipientAttempt
	Paths          []string
	Sources        []wire.FileSource
	Peer           *wire.TrustRecord
	LocalID        *wire.DeviceIdentity
	RequirePadding bool
	Provenance     *wire.Provenance
	OnProgress     func(int64)
}

// resolveSendTarget loads the trust record for a device and fails closed on
// unknown/revoked devices.
func (s *RecipeService) resolveSendTarget(ctx context.Context, deviceID string) (resolvedSendTarget, error) {
	rec, err := s.trust.GetDevice(ctx, deviceID)
	if err != nil {
		return resolvedSendTarget{}, fmt.Errorf("trust lookup: %w", err)
	}
	if rec == nil {
		return resolvedSendTarget{}, fmt.Errorf("device %q is not a trusted paired device", deviceID)
	}
	if rec.Revoked {
		return resolvedSendTarget{}, fmt.Errorf("device %q is revoked", deviceID)
	}
	return resolvedSendTarget{record: rec}, nil
}

type resolvedSendTarget struct {
	record *wire.TrustRecord
}

// recipeOutboxEnqueuer adapts the real *outbox.Outbox to the
// recipes.Enqueuer interface: one call, one job, one attempt per
// recipient. No second queue. The routine origin label (V22-PR06) is
// stamped on the job via EnqueueWithProvenance; senderLabel backstops an
// empty engine-built label so the job's provenance is never blank.
type recipeOutboxEnqueuer struct {
	ob          *outbox.Outbox
	senderLabel string
}

func (a recipeOutboxEnqueuer) EnqueueWithPrivacy(ctx context.Context, paths []string, recipients []recipes.EnqueueRecipient, policy jobs.RetryPolicy, np netpolicy.Policy, provenance *wire.Provenance, requirePadding bool) (jobs.Job, error) {
	refs := make([]outbox.RecipientRef, len(recipients))
	for i, r := range recipients {
		refs[i] = outbox.RecipientRef{DeviceID: r.DeviceID, Label: r.Label}
	}
	return a.ob.EnqueueWithPrivacy(ctx, paths, refs, policy, np, provenance, requirePadding)
}

func (a recipeOutboxEnqueuer) Enqueue(ctx context.Context, paths []string, recipients []recipes.EnqueueRecipient, policy jobs.RetryPolicy, np netpolicy.Policy, provenance *wire.Provenance) (jobs.Job, error) {
	return a.EnqueueWithPrivacy(ctx, paths, recipients, policy, np, provenance, false)
}

