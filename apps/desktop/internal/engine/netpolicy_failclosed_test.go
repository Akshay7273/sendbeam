// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/receiver"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestConfigStore returns a config.Store over a fresh temporary
// directory (no config file written yet — first-launch state).
func newTestConfigStore(t *testing.T) *config.Store {
	t.Helper()
	store, err := config.NewStore(t.TempDir(), config.NewMemorySecretStore())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// writeFile creates parent directories and writes data.
func writeFile(t *testing.T, path string, data []byte) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// failClosedGetPolicy mirrors main.go's SB-R05 retrieval closure exactly.
// main.go is package main and cannot be imported; the decision logic is
// duplicated here so the tests exercise the production pattern. Both cite
// this comment — a change to one must be mirrored in the other.
func failClosedGetPolicy(store *config.Store) func() netpolicy.Policy {
	return func() netpolicy.Policy {
		cfg, err := store.Load()
		if err != nil {
			return netpolicy.LocalOnly
		}
		p, err := netpolicy.Parse(cfg.NetworkPolicy)
		if err != nil {
			return netpolicy.LocalOnly
		}
		return p
	}
}

// newDispatchableRecipeService builds a RecipeService with real
// identity/secrets (dispatch requires them) and a stopped dispatcher, so
// each test controls exactly when dispatch passes run.
func newDispatchableRecipeService(t *testing.T) (*RecipeService, string) {
	t.Helper()
	dir := t.TempDir()
	idm, err := trust.NewIdentityManager(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatalf("IdentityManager: %v", err)
	}
	secrets, err := trust.NewFileSecretStore(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatalf("FileSecretStore: %v", err)
	}
	ts := trust.NewMemoryTrustStore()
	deviceID := seedRecipeTrust(t, ts)
	svc, err := NewRecipeService(dir, ts, idm, secrets)
	if err != nil {
		t.Fatalf("NewRecipeService: %v", err)
	}
	svc.StopDispatcher() // deterministic dispatch: only explicit passes run
	t.Cleanup(func() { _ = svc.Shutdown(5 * time.Second) })
	return svc, deviceID
}

// lastRunJobID returns the job ID recorded on the recipe's last run.
func lastRunJobID(t *testing.T, svc *RecipeService, recipeID string) string {
	t.Helper()
	rec, err := svc.GetRecipe(recipeID)
	if err != nil {
		t.Fatalf("GetRecipe: %v", err)
	}
	if rec.LastRun == nil {
		t.Fatal("recipe has no LastRun")
	}
	return rec.LastRun.JobID
}

// ---------------------------------------------------------------------------
// 1. Runtime retrieval: an unusable config must never select Online
// ---------------------------------------------------------------------------

func TestGetPolicyFailsClosedOnUnreadableConfig(t *testing.T) {
	dir := t.TempDir()
	// A config directory nested under a regular file can never be read.
	blocker := filepath.Join(dir, "blocker")
	if err := writeFile(t, blocker, []byte("x")); err != nil {
		t.Fatal(err)
	}
	store, err := config.NewStore(filepath.Join(blocker, "cfg"), config.NewMemorySecretStore())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("test setup: expected unreadable config to fail Load")
	}
	if got := failClosedGetPolicy(store)(); got != netpolicy.LocalOnly {
		t.Fatalf("getPolicy with unreadable config = %v, want local-only (fail closed)", got)
	}
}

func TestGetPolicyFailsClosedOnCorruptConfig(t *testing.T) {
	store := newTestConfigStore(t)
	if err := writeFile(t, store.ConfigPath(), []byte("{ corrupt json ...")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("test setup: expected corrupt config to fail Load")
	}
	if got := failClosedGetPolicy(store)(); got != netpolicy.LocalOnly {
		t.Fatalf("getPolicy with corrupt config = %v, want local-only", got)
	}
}

func TestGetPolicyFailsClosedOnInvalidPolicyValue(t *testing.T) {
	store := newTestConfigStore(t)
	// A hand-edited config with an unrecognized policy value: Load fails
	// validation, and the fail-closed closure must degrade — not select
	// Online.
	if err := writeFile(t, store.ConfigPath(), []byte(`{"networkPolicy":"mesh"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("test setup: expected invalid policy value to fail Load validation")
	}
	if got := failClosedGetPolicy(store)(); got != netpolicy.LocalOnly {
		t.Fatalf("getPolicy with invalid stored policy = %v, want local-only", got)
	}
}

// TestGetPolicyFirstLaunchOnlineMissingFile preserves the verified
// first-launch behavior: a MISSING config file is not a failure. Load
// returns defaults (NetworkPolicy "online") and the closure selects Online.
// Only genuinely unusable configs degrade.
func TestGetPolicyFirstLaunchOnlineMissingFile(t *testing.T) {
	store := newTestConfigStore(t)
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load on missing file should succeed with defaults: %v", err)
	}
	if cfg.NetworkPolicy != "online" {
		t.Fatalf("default NetworkPolicy = %q, want online", cfg.NetworkPolicy)
	}
	if got := failClosedGetPolicy(store)(); got != netpolicy.Online {
		t.Fatalf("first-launch getPolicy = %v, want online (missing file is not a failure)", got)
	}
}

func TestGetPolicyHonorsStoredLocalOnly(t *testing.T) {
	store := newTestConfigStore(t)
	cfg, _ := store.Load()
	cfg.NetworkPolicy = "local-only"
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := failClosedGetPolicy(store)(); got != netpolicy.LocalOnly {
		t.Fatalf("getPolicy = %v, want local-only", got)
	}
}

// ---------------------------------------------------------------------------
// 2. Receiver policy application: the second retrieval seam
// ---------------------------------------------------------------------------

// newPolicyTestTransferService builds a TransferService plus a receiver
// base config carrying a public signaling server and a custom dialer, so
// the LocalOnly adjustment (Server="", Dialer=nil) is observable without
// any network activity: an empty server never schedules a dial and a nil
// dialer can never dial. LAN discovery is disabled (Port 0).
func newPolicyTestTransferService(t *testing.T) (*TransferService, receiver.Config) {
	t.Helper()
	svc := NewTransferService(nil, nil)

	dir := t.TempDir()
	idm, err := trust.NewIdentityManager(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatalf("IdentityManager: %v", err)
	}
	localID, err := idm.GetOrCreateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	trustStore, err := trust.NewFileTrustStore(filepath.Join(dir, "trust.json"))
	if err != nil {
		t.Fatalf("trust store: %v", err)
	}

	base := receiver.Config{
		Server: "wss://signaling.example.invalid/ws",
		Dialer: func(_ context.Context, _ string) (transfer.Signal, error) {
			return nil, errors.New("dialer must be stripped under local-only policy")
		},
		DestDir:    filepath.Join(dir, "out"),
		Identity:   localID,
		TrustStore: trustStore,
		Secrets:    trust.NewMemoryCredentialStore(),
		Port:       0, // LAN discovery off in this test
	}
	t.Cleanup(func() { _ = svc.StopNativeReceiver() })
	return svc, base
}

func TestApplyNetworkPolicyFailsClosedOnUnusableConfig(t *testing.T) {
	svc, base := newPolicyTestTransferService(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := writeFile(t, blocker, []byte("x")); err != nil {
		t.Fatal(err)
	}
	store, err := config.NewStore(filepath.Join(blocker, "cfg"), config.NewMemorySecretStore())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	svc.SetConfigStore(store)

	if err := svc.StartNativeReceiverWithPolicy(base); err != nil {
		t.Fatalf("StartNativeReceiverWithPolicy: %v", err)
	}
	l := svc.NativeReceiver()
	if l == nil {
		t.Fatal("receiver should be running")
	}
	if got := l.Config().Server; got != "" {
		t.Fatalf("fail-closed receiver Server = %q, want empty (no public rendezvous)", got)
	}
}

// TestApplyNetworkPolicyFailsClosedOnInvalidPolicyValue: the same seam must
// degrade when the stored policy value is unparseable.
func TestApplyNetworkPolicyFailsClosedOnInvalidPolicyValue(t *testing.T) {
	svc, base := newPolicyTestTransferService(t)
	store := newTestConfigStore(t)
	if err := writeFile(t, store.ConfigPath(), []byte(`{"networkPolicy":"mesh"}`)); err != nil {
		t.Fatal(err)
	}
	svc.SetConfigStore(store)

	if err := svc.StartNativeReceiverWithPolicy(base); err != nil {
		t.Fatalf("StartNativeReceiverWithPolicy: %v", err)
	}
	l := svc.NativeReceiver()
	if l == nil {
		t.Fatal("receiver should be running")
	}
	if got := l.Config().Server; got != "" {
		t.Fatalf("receiver Server = %q under invalid stored policy, want empty", got)
	}
}

// TestApplyNetworkPolicyFirstLaunchKeepsOnline proves the first-launch
// default is preserved: a missing config file is not a failure, so the
// receiver keeps its configured signaling server.
func TestApplyNetworkPolicyFirstLaunchKeepsOnline(t *testing.T) {
	svc, base := newPolicyTestTransferService(t)
	store := newTestConfigStore(t) // fresh dir, no file
	svc.SetConfigStore(store)

	if err := svc.StartNativeReceiverWithPolicy(base); err != nil {
		t.Fatalf("StartNativeReceiverWithPolicy: %v", err)
	}
	l := svc.NativeReceiver()
	if l == nil {
		t.Fatal("receiver should be running")
	}
	if got := l.Config().Server; got == "" {
		t.Fatal("first-launch receiver should keep its signaling server config")
	}
}

// TestApplyNetworkPolicyHonorsLocalOnly pins the pre-existing correct
// behavior that the fail-closed degradation reuses.
func TestApplyNetworkPolicyHonorsLocalOnly(t *testing.T) {
	svc, base := newPolicyTestTransferService(t)
	store := newTestConfigStore(t)
	cfg, _ := store.Load()
	cfg.NetworkPolicy = "local-only"
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	svc.SetConfigStore(store)

	if err := svc.StartNativeReceiverWithPolicy(base); err != nil {
		t.Fatalf("StartNativeReceiverWithPolicy: %v", err)
	}
	l := svc.NativeReceiver()
	if l == nil {
		t.Fatal("receiver should be running")
	}
	if got := l.Config().Server; got != "" {
		t.Fatalf("local-only receiver Server = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// 3. Dispatcher: end-to-end no-egress proofs
// ---------------------------------------------------------------------------

// enqueueRecipe creates, approves and runs a recipe so its job sits in the
// outbox queue.
func enqueueRecipe(t *testing.T, svc *RecipeService, deviceID, root, policy string) string {
	t.Helper()
	in := newEditorInput("nightly", root, deviceID)
	in.NetworkPolicy = policy
	r, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatalf("CreateRecipe: %v", err)
	}
	if _, err := svc.ApproveRecipe(r.ID); err != nil {
		t.Fatalf("ApproveRecipe: %v", err)
	}
	if _, err := svc.RunRecipe(r.ID); err != nil {
		t.Fatalf("RunRecipe: %v", err)
	}
	return r.ID
}

// TestRecipeDispatchHeldWhenPolicyLookupFails proves the dispatcher holds
// Online jobs when policy retrieval is unusable — the central SB-R05
// no-egress assertion.
func TestRecipeDispatchHeldWhenPolicyLookupFails(t *testing.T) {
	svc, deviceID := newDispatchableRecipeService(t)
	root := t.TempDir()
	if err := writeFile(t, filepath.Join(root, "f.bin"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recipeID := enqueueRecipe(t, svc, deviceID, root, "online")

	var onlineCalls int
	var onlineMu sync.Mutex
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		onlineMu.Lock()
		onlineCalls++
		onlineMu.Unlock()
		return transfer.Outcome{}, errors.New("online sender must never be reached under a failing policy lookup")
	})
	// The lookup fails exactly like main.go's fail-closed closure with an
	// unusable config: it degrades to LocalOnly, never Online.
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })
	// A local endpoint exists, but an Online job may only use online egress.
	svc.SetLocalPeerAddr(deviceID, "127.0.0.1:1")

	rep, err := svc.DispatchOnceNow(context.Background())
	if err != nil {
		t.Fatalf("dispatch pass returned an unexpected error: %v", err)
	}
	onlineMu.Lock()
	calls := onlineCalls
	onlineMu.Unlock()
	if calls != 0 {
		t.Fatalf("online sender invoked %d time(s) under failed policy retrieval; want 0", calls)
	}
	// The job must be HELD with a clear policy reason, attempts untouched.
	held := false
	for _, skip := range rep.Skipped {
		if strings.Contains(strings.ToLower(skip), "policy") {
			held = true
		}
	}
	if !held {
		t.Fatalf("expected the online job to be held for policy reasons; skipped=%v results=%v", rep.Skipped, rep.Results)
	}
	jobID := lastRunJobID(t, svc, recipeID)
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != deviceID {
			continue
		}
		if a.Status != jobs.AttemptQueued {
			t.Fatalf("held attempt status = %q, want queued (budget untouched)", a.Status)
		}
		if a.LastError != "" {
			t.Fatalf("held attempt should record no error, got %q", a.LastError)
		}
	}
}

// TestRecipeDispatchNoOnlineFallbackAfterPolicyDegradation proves the
// fallback decision point honors the degraded policy: a prefer-local job
// with a recorded endpoint whose local send fails must NOT fall back online
// when the current policy is LocalOnly — the online sender is never reached
// and the attempt records an honest failure.
func TestRecipeDispatchNoOnlineFallbackAfterPolicyDegradation(t *testing.T) {
	svc, deviceID := newDispatchableRecipeService(t)
	root := t.TempDir()
	if err := writeFile(t, filepath.Join(root, "f.bin"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recipeID := enqueueRecipe(t, svc, deviceID, root, "prefer-local")

	var onlineCalls int
	var onlineMu sync.Mutex
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		onlineMu.Lock()
		onlineCalls++
		onlineMu.Unlock()
		return transfer.Outcome{}, errors.New("online fallback attempted after policy degradation")
	})
	svc.SetLocalPeerAddr(deviceID, "127.0.0.1:1")
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.LocalOnly })

	if _, err := svc.DispatchOnceNow(context.Background()); err != nil {
		t.Fatalf("dispatch pass error: %v", err)
	}
	onlineMu.Lock()
	calls := onlineCalls
	onlineMu.Unlock()
	if calls != 0 {
		t.Fatalf("online sender invoked %d time(s) after policy degradation; want 0", calls)
	}
	jobID := lastRunJobID(t, svc, recipeID)
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	for _, a := range job.Attempts {
		if a.DeviceID != deviceID {
			continue
		}
		if a.Status == jobs.AttemptCompleted || a.Status == jobs.AttemptVerified {
			t.Fatalf("attempt marked %q despite degraded policy; want failed/held", a.Status)
		}
		if a.LastError == "" {
			t.Fatal("attempt should record an honest error after refused fallback")
		}
	}
}

// TestRecipeDispatchUnwiredLookupHoldsOnlineJobs proves the ResolveEffective
// nil-lookup contract end-to-end: with no policy lookup wired at all, the
// pass gate degrades to LocalOnly and online jobs are held — never
// dispatched on an assumed-online pass.
func TestRecipeDispatchUnwiredLookupHoldsOnlineJobs(t *testing.T) {
	svc, deviceID := newDispatchableRecipeService(t)
	root := t.TempDir()
	if err := writeFile(t, filepath.Join(root, "f.bin"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recipeID := enqueueRecipe(t, svc, deviceID, root, "online")

	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		return transfer.Outcome{}, errors.New("unwired lookup must not dispatch online jobs")
	})
	// NOTE: SetPolicyLookup deliberately NOT called — unconfigured case.

	rep, err := svc.DispatchOnceNow(context.Background())
	if err != nil {
		t.Fatalf("dispatch pass error: %v", err)
	}
	held := false
	for _, skip := range rep.Skipped {
		if strings.Contains(strings.ToLower(skip), "policy") {
			held = true
		}
	}
	if !held {
		t.Fatalf("expected the online job to be held with an unwired lookup; skipped=%v results=%v", rep.Skipped, rep.Results)
	}
	jobID := lastRunJobID(t, svc, recipeID)
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	if len(job.Attempts) == 0 {
		t.Fatal("job should carry a recipient attempt record")
	}
	for _, a := range job.Attempts {
		if a.Status != jobs.AttemptQueued {
			t.Fatalf("unwired-lookup attempt status = %q, want queued (held before any attempt)", a.Status)
		}
	}
}

// TestPolicyResolutionNoticeSurfaced pins the observable-degradation
// contract at the engine boundary: ResolveEffective reports exactly one
// actionable notice when no lookup is wired, and still selects LocalOnly.
func TestPolicyResolutionNoticeSurfaced(t *testing.T) {
	var notices []string
	var mu sync.Mutex
	p := netpolicy.ResolveEffective(nil, func(msg string) {
		mu.Lock()
		notices = append(notices, msg)
		mu.Unlock()
	})
	if p != netpolicy.LocalOnly {
		t.Fatalf("unwired lookup policy = %v, want local-only", p)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one", notices)
	}
}

// TestGetPolicyFailsClosedOnPermissionDenied covers the blueprint's
// filesystem-permission-denial case: a config file that exists but cannot
// be read (mode 000, non-root) must degrade to LocalOnly, never Online.
func TestGetPolicyFailsClosedOnPermissionDenied(t *testing.T) {
	store := newTestConfigStore(t)
	cfg, err := store.Load() // first-launch defaults; creates nothing
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Running as root would defeat this check; skip honestly if so.
	if os.Geteuid() == 0 {
		t.Skip("permission-denial scenario requires a non-root user")
	}
	if err := os.Chmod(store.ConfigPath(), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.ConfigPath(), 0o600) })

	if _, err := store.Load(); err == nil {
		t.Fatal("test setup: expected permission-denied config to fail Load")
	} else if !errors.Is(err, config.ErrUnreadable) {
		t.Fatalf("Load error = %v, want ErrUnreadable", err)
	}
	if got := failClosedGetPolicy(store)(); got != netpolicy.LocalOnly {
		t.Fatalf("getPolicy with permission-denied config = %v, want local-only", got)
	}
}

// TestLoadErrorClassification pins the errors.Is contract the fail-closed
// callers rely on: unreadable vs corrupt are distinguishable, missing file
// is neither.
func TestLoadErrorClassification(t *testing.T) {
	// Missing file: no error at all.
	missing := newTestConfigStore(t)
	if _, err := missing.Load(); err != nil {
		t.Fatalf("missing file: Load = %v, want nil error", err)
	}

	// Corrupt JSON: ErrCorrupt, not ErrUnreadable.
	corrupt := newTestConfigStore(t)
	if err := writeFile(t, corrupt.ConfigPath(), []byte("{ nope")); err != nil {
		t.Fatal(err)
	}
	_, err := corrupt.Load()
	if !errors.Is(err, config.ErrCorrupt) || errors.Is(err, config.ErrUnreadable) {
		t.Fatalf("corrupt file: err = %v, want ErrCorrupt only", err)
	}

	// Invalid validated value: ErrCorrupt as well (file exists, unusable).
	invalid := newTestConfigStore(t)
	if err := writeFile(t, invalid.ConfigPath(), []byte(`{"networkPolicy":"mesh"}`)); err != nil {
		t.Fatal(err)
	}
	_, err = invalid.Load()
	if !errors.Is(err, config.ErrCorrupt) {
		t.Fatalf("invalid value: err = %v, want ErrCorrupt", err)
	}
}
