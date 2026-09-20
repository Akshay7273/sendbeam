// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/recipes"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// seedRecipeTrust registers one trusted device and returns its device id.
func seedRecipeTrust(t *testing.T, ts *trust.MemoryTrustStore) string {
	t.Helper()
	gen, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	now := time.Now().UTC()
	if err := ts.AddOrUpdateDevice(context.Background(), &wire.TrustRecord{
		DeviceID:          gen.DeviceID,
		PublicKey:         gen.PublicKeyHex(),
		LocalLabel:        "studio",
		PairCredentialRef: "cred-test",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	}); err != nil {
		t.Fatalf("AddOrUpdateDevice: %v", err)
	}
	return gen.DeviceID
}

// storeRecipe composes and saves a manual-status recipe over root.
func storeRecipe(t *testing.T, svc *RecipeService, root, name, deviceID string) string {
	t.Helper()
	r, err := recipes.NewRecipe(name, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []recipes.RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []recipes.RecipeRecipient{{DeviceID: deviceID, Label: "studio"}}
	r.Status = recipes.RecipeManual
	r.Grant.ScopeHash = r.ScopeHash()
	if err := svc.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return r.ID
}

func TestRecipeServiceRoundTrip(t *testing.T) {
	ctx := context.Background()
	_ = ctx
	dir := t.TempDir()
	ts := trust.NewMemoryTrustStore()
	devID := seedRecipeTrust(t, ts)

	svc, err := NewRecipeService(dir, ts)
	if err != nil {
		t.Fatalf("NewRecipeService: %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	id := storeRecipe(t, svc, root, "Exports", devID)

	entries, err := svc.ListRecipes()
	if err != nil {
		t.Fatalf("ListRecipes: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != id {
		t.Fatalf("ListRecipes: %v", entries)
	}

	got, err := svc.GetRecipe(id)
	if err != nil {
		t.Fatalf("GetRecipe: %v", err)
	}
	if got.Name != "Exports" {
		t.Fatalf("GetRecipe name: %q", got.Name)
	}

	preview, err := svc.PreviewRecipe(id)
	if err != nil {
		t.Fatalf("PreviewRecipe: %v", err)
	}
	if !strings.Contains(preview, "sends nothing") {
		t.Fatalf("preview does not state it sends nothing")
	}

	planJSON, err := svc.PlanRecipe(id)
	if err != nil {
		t.Fatalf("PlanRecipe: %v", err)
	}
	if !strings.Contains(planJSON, `"version":1`) {
		t.Fatalf("plan DTO missing version: %s", planJSON)
	}

	jobID, err := svc.RunRecipe(id)
	if err != nil {
		t.Fatalf("RunRecipe: %v", err)
	}
	if jobID == "" {
		t.Fatalf("RunRecipe returned empty job id")
	}
	listed, err := svc.jobs.List()
	if err != nil {
		t.Fatalf("jobs List: %v", err)
	}
	if len(listed) != 1 || listed[0].JobID != jobID {
		t.Fatalf("want exactly the one enqueued job, got %v", listed)
	}
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("job load: %v %v", err, ok)
	}
	if len(job.Attempts) != 1 || job.Attempts[0].DeviceID != devID {
		t.Fatalf("job attempts: %+v", job.Attempts)
	}

	if err := svc.DeleteRecipe(id); err != nil {
		t.Fatalf("DeleteRecipe: %v", err)
	}
	entries, err = svc.ListRecipes()
	if err != nil {
		t.Fatalf("ListRecipes: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("recipe not deleted: %v", entries)
	}
}

func TestRecipeServiceRunGates(t *testing.T) {
	dir := t.TempDir()
	ts := trust.NewMemoryTrustStore()
	devID := seedRecipeTrust(t, ts)

	svc, err := NewRecipeService(dir, ts)
	if err != nil {
		t.Fatalf("NewRecipeService: %v", err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	// approval-required run refuses.
	r, err := recipes.NewRecipe("Needs approval", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []recipes.RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []recipes.RecipeRecipient{{DeviceID: devID, Label: "studio"}}
	r.Grant.ScopeHash = r.ScopeHash()
	if err := svc.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := svc.RunRecipe(r.ID); err == nil {
		t.Fatalf("approval-required run accepted")
	} else if !strings.Contains(err.Error(), "requires approval") {
		t.Fatalf("error %q not actionable", err)
	}

	// ApproveRecipe flips it to manual; then it runs.
	approved, err := svc.ApproveRecipe(r.ID)
	if err != nil {
		t.Fatalf("ApproveRecipe: %v", err)
	}
	if approved.Status != recipes.RecipeManual {
		t.Fatalf("status after approve: %q", approved.Status)
	}
	jobID, err := svc.RunRecipe(r.ID)
	if err != nil {
		t.Fatalf("RunRecipe after approve: %v", err)
	}
	if jobID == "" {
		t.Fatalf("empty job id")
	}

	// Revoked recipient fails at run, naming the device.
	if err := ts.RevokeDevice(context.Background(), devID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, err := svc.RunRecipe(r.ID); err == nil {
		t.Fatalf("run with revoked recipient accepted")
	} else if !strings.Contains(err.Error(), devID) {
		t.Fatalf("error %q does not name the device", err)
	}
}

func TestRecipeServiceNilTrust(t *testing.T) {
	if _, err := NewRecipeService(t.TempDir(), nil); err == nil {
		t.Fatalf("nil trust store accepted")
	}
}

// TestRecipeServiceUsesProductionOutbox asserts the service enqueues real
// jobs.Job values through the production outbox type (no mock queue).
func TestRecipeServiceUsesProductionOutbox(t *testing.T) {
	dir := t.TempDir()
	ts := trust.NewMemoryTrustStore()
	devID := seedRecipeTrust(t, ts)
	svc, err := NewRecipeService(dir, ts)
	if err != nil {
		t.Fatalf("NewRecipeService: %v", err)
	}
	if svc.outbox == nil {
		t.Fatalf("service has no outbox")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	id := storeRecipe(t, svc, root, "Real job", devID)
	var _ jobs.Job
	jobID, err := svc.RunRecipe(id)
	if err != nil {
		t.Fatalf("RunRecipe: %v", err)
	}
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("enqueued job not found in the jobs store: %v %v", err, ok)
	}
	if len(job.Files) != 1 || job.TotalSize != 4 {
		t.Fatalf("job files: %+v", job.Files)
	}
}

// TestRecipeServiceWatch exercises the desktop-hosted watcher lifecycle:
// start, change, dispatch through the real outbox, stop. Watches are
// per-process by design (see RecipeService).
func TestRecipeServiceWatch(t *testing.T) {
	dir := t.TempDir()
	ts := trust.NewMemoryTrustStore()
	devID := seedRecipeTrust(t, ts)

	svc, err := NewRecipeService(dir, ts)
	if err != nil {
		t.Fatalf("NewRecipeService: %v", err)
	}
	t.Cleanup(svc.StopAllWatches)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	id := storeRecipe(t, svc, root, "Exports", devID)

	// No grant yet: StartWatch must fail fast.
	if err := svc.StartWatch(id); err == nil {
		t.Fatalf("StartWatch without grant succeeded")
	}
	if svc.IsWatching(id) {
		t.Fatalf("IsWatching true after failed start")
	}

	// Flip to a watch trigger (material change), approve and grant.
	r, ok, err := svc.store.Load(id)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", ok, err)
	}
	r.Trigger.Kind = recipes.TriggerWatch
	r.Trigger.Watch = map[string]any{"debounce_ms": 250, "cooldown_ms": 300}
	if _, err := recipes.ApplyUpdate(svc.store, r); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if _, err := svc.ApproveRecipe(id); err != nil {
		t.Fatalf("ApproveRecipe: %v", err)
	}
	if _, err := svc.GrantAutomation(id); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}

	if err := svc.StartWatch(id); err != nil {
		t.Fatalf("StartWatch: %v", err)
	}
	if !svc.IsWatching(id) {
		t.Fatalf("IsWatching false after start")
	}
	if err := svc.StartWatch(id); err == nil {
		t.Fatalf("second StartWatch succeeded")
	}

	// A change dispatches one ordinary outbox job through the real outbox.
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("more"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, gerr := svc.LastRun(id)
		if gerr == nil && got != nil && got.Status == recipes.RunStatusDispatched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no dispatched last-run entry after change")
		}
		time.Sleep(20 * time.Millisecond)
	}
	listed, err := svc.outbox.List()
	if err != nil {
		t.Fatalf("outbox List: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("outbox has %d jobs, want 1", len(listed))
	}

	if err := svc.StopWatch(id); err != nil {
		t.Fatalf("StopWatch: %v", err)
	}
	if svc.IsWatching(id) {
		t.Fatalf("IsWatching true after stop")
	}
	// StopWatch is idempotent.
	if err := svc.StopWatch(id); err != nil {
		t.Fatalf("second StopWatch: %v", err)
	}
	// Stopping an unknown id is not an error either.
	if err := svc.StopWatch(strings.Repeat("0", 32)); err != nil {
		t.Fatalf("StopWatch unknown id: %v", err)
	}
}
