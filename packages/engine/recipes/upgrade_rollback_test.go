// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

// Upgrade (v2.1 -> v2.2) and rollback (v2.2 -> v2.1) evidence for the
// Repeatable Handoffs release (V22-PR08).
//
// The recipe system is new in v2.2: a separate store directory and a new
// optional wire manifest field. These tests prove the upgrade is purely
// additive and that a rollback cannot be confused by recipe state.
//
// The "v2.1 reader" in these tests is the jobs/outbox/trust code surface
// as it existed before v2.2: those packages never import the recipes
// package (verified by `go list -deps` in the release notes), so
// exercising recipes cannot change what they read.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// snapshotFiles records the exact bytes of every regular file under root,
// keyed by slash-separated relative path.
func snapshotFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return out
}

// assertSnapshotsEqual fails if any pre-existing file changed bytes or
// vanished, or any unexpected file appeared outside the named new dirs.
func assertSnapshotsEqual(t *testing.T, before, after map[string][]byte, newDirs ...string) {
	t.Helper()
	for rel, data := range before {
		got, ok := after[rel]
		if !ok {
			t.Fatalf("file %q vanished after v2.2 init", rel)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("file %q changed bytes after v2.2 init", rel)
		}
	}
	for rel := range after {
		if _, ok := before[rel]; ok {
			continue
		}
		underNew := false
		for _, d := range newDirs {
			if rel == d || strings.HasPrefix(rel, d+"/") {
				underNew = true
				break
			}
		}
		if !underNew {
			t.Fatalf("unexpected new file %q outside %v after v2.2 init", rel, newDirs)
		}
	}
}

const upgradeTestJobID = "0123456789abcdef0123456789abcdef"

// openV21Surface builds the v2.1-era on-disk state: a jobs store holding
// one ordinary queued job and an initialized trust database.
func openV21Surface(t *testing.T, root string) (*jobs.JobStore, string, string) {
	t.Helper()
	jobsDir := filepath.Join(root, "jobs")
	trustFile := filepath.Join(root, "trust", "trust.json")

	js, err := jobs.OpenJobStore(jobsDir)
	if err != nil {
		t.Fatalf("OpenJobStore: %v", err)
	}
	j, err := jobs.NewJob(upgradeTestJobID,
		[]jobs.JobFile{{Name: "a.txt", Size: 3, Digest: "deadbeef"}},
		[]jobs.RecipientAttempt{{DeviceID: "ffffffffffffffffffffffffffffffff", Label: "peer"}},
		jobs.DefaultRetryPolicy(), testNow)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	if err := jobs.QueueJob(&j, testNow); err != nil {
		t.Fatalf("QueueJob: %v", err)
	}
	if err := js.Save(j); err != nil {
		t.Fatalf("Save job: %v", err)
	}
	if _, err := trust.NewFileTrustStore(trustFile); err != nil {
		t.Fatalf("NewFileTrustStore: %v", err)
	}
	return js, jobsDir, trustFile
}

func TestUpgradeV22InitLeavesV21StateUntouched(t *testing.T) {
	root := t.TempDir()
	js, jobsDir, trustFile := openV21Surface(t, root)
	before := snapshotFiles(t, root)

	// v2.2 init: open the recipe store in the same profile root and use it.
	rs, err := OpenRecipeStore(filepath.Join(root, "recipes"))
	if err != nil {
		t.Fatalf("OpenRecipeStore: %v", err)
	}
	r := validRecipe(t, testDeviceIDs(t, 1)[0])
	if err := rs.Save(r); err != nil {
		t.Fatalf("Save recipe: %v", err)
	}

	after := snapshotFiles(t, root)
	// (a) every v2.1 file still decodes and is byte-identical; the recipe
	// store created only new files.
	assertSnapshotsEqual(t, before, after, "recipes")

	// (b) the v2.1 reader's view of its own files is unaffected: re-open
	// the stores fresh (as a v2.1 binary would) and compare.
	js2, err := jobs.OpenJobStore(jobsDir)
	if err != nil {
		t.Fatalf("re-open JobStore: %v", err)
	}
	orig, ok, err := js.Load(upgradeTestJobID)
	if err != nil || !ok {
		t.Fatalf("Load original job: %v %v", orig, err)
	}
	reloaded, ok, err := js2.Load(upgradeTestJobID)
	if err != nil || !ok {
		t.Fatalf("Load job after v2.2 init: %v %v", reloaded, err)
	}
	if !reflect.DeepEqual(orig, reloaded) {
		t.Fatalf("job changed across v2.2 init:\nbefore: %+v\nafter:  %+v", orig, reloaded)
	}
	// The outbox view (v2.1 queue semantics) is unchanged too.
	ob := outbox.New(js2, nil)
	entries, err := ob.List()
	if err != nil {
		t.Fatalf("Outbox.List: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.JobID == upgradeTestJobID {
			found = true
		}
	}
	if !found {
		t.Fatalf("v2.1 job %q missing from outbox view after v2.2 init", upgradeTestJobID)
	}
	// Trust database reloads identically.
	ts2, err := trust.NewFileTrustStore(trustFile)
	if err != nil {
		t.Fatalf("re-open trust store: %v", err)
	}
	devices, err := ts2.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("trust devices changed across v2.2 init: %d", len(devices))
	}
}

// TestUpgradeV22GrantsDoNotTouchV21Stores exercises the full recipe
// lifecycle (create, approve, grant, run, disable) and asserts the v2.1-era
// stores never see recipe-shaped state: only ordinary jobs and ordinary
// trust files.
func TestUpgradeV22GrantsDoNotTouchV21Stores(t *testing.T) {
	root := t.TempDir()
	_, _, _ = openV21Surface(t, root)
	before := snapshotFiles(t, root)

	rs, err := OpenRecipeStore(filepath.Join(root, "recipes"))
	if err != nil {
		t.Fatalf("OpenRecipeStore: %v", err)
	}
	r := validRecipe(t, testDeviceIDs(t, 1)[0])
	r.Status = RecipeManual // what `recipe approve` does in the CLI
	if err := rs.Save(r); err != nil {
		t.Fatalf("Save recipe: %v", err)
	}
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := rs.Save(r); err != nil {
		t.Fatalf("Save granted recipe: %v", err)
	}
	if err := rs.RecordRun(r.ID, RecipeRunInfo{At: testNow, Trigger: TriggerManual, Status: RunStatusDispatched, JobID: "job-1"}); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}
	Disable(&r)
	if err := rs.Save(r); err != nil {
		t.Fatalf("Save disabled recipe: %v", err)
	}

	after := snapshotFiles(t, root)
	// Granting, running, and disabling touched only the recipes directory.
	assertSnapshotsEqual(t, before, after, "recipes")
}

// TestRollbackRecipesLeaveNoResidueInV21Stores enqueues a job through the
// exact production path a recipe run uses (outbox.EnqueueWithProvenance,
// which stamps the advisory routine label), then proves the resulting job
// record is an ordinary job: no recipe-specific fields, and the provenance
// label is optional metadata an older reader ignores without changing its
// view of the job.
func TestRollbackRecipesLeaveNoResidueInV21Stores(t *testing.T) {
	root := t.TempDir()
	rs, err := OpenRecipeStore(filepath.Join(root, "recipes"))
	if err != nil {
		t.Fatalf("OpenRecipeStore: %v", err)
	}
	js, err := jobs.OpenJobStore(filepath.Join(root, "jobs"))
	if err != nil {
		t.Fatalf("OpenJobStore: %v", err)
	}

	// Exercise recipes: create, approve, grant, dispatch one job, disable.
	r := validRecipe(t, testDeviceIDs(t, 1)[0])
	r.Status = RecipeManual
	if err := rs.Save(r); err != nil {
		t.Fatalf("Save recipe: %v", err)
	}
	if err := GrantAutomation(&r, testNow); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	if err := rs.Save(r); err != nil {
		t.Fatalf("Save granted recipe: %v", err)
	}

	src := filepath.Join(t.TempDir(), "export.bin")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	prov := &wire.Provenance{
		RoutineID:   r.ID,
		RoutineName: r.Name,
		SenderLabel: "test-device",
		Trigger:     "manual",
	}
	ob := outbox.New(js, nil)
	enqueued, err := ob.EnqueueWithProvenance(context.Background(),
		[]string{src},
		[]outbox.RecipientRef{{DeviceID: testDeviceIDs(t, 1)[0], Label: "peer"}},
		jobs.DefaultRetryPolicy(), netpolicy.Online, prov)
	if err != nil {
		t.Fatalf("EnqueueWithProvenance: %v", err)
	}
	Disable(&r)
	if err := rs.Save(r); err != nil {
		t.Fatalf("Save disabled recipe: %v", err)
	}

	// (a) the jobs directory holds only ordinary job files — no recipe,
	// ledger, or run-history residue.
	names, err := filepath.Glob(filepath.Join(js.Dir(), "*.json"))
	if err != nil {
		t.Fatalf("glob jobs dir: %v", err)
	}
	if len(names) != 1 { // only the job the recipe run enqueued
		t.Fatalf("jobs dir holds %d files, want exactly the 1 recipe-enqueued job record: %v", len(names), names)
	}
	sort.Strings(names)

	// (b) every job in the store loads and validates as an ordinary job.
	for _, path := range names {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		j, ok, err := js.Load(id)
		if err != nil || !ok {
			t.Fatalf("Load %s: %v %v", id, j, err)
		}
		if err := jobs.ValidateJob(j); err != nil {
			t.Fatalf("ValidateJob %s: %v", id, err)
		}
	}

	// (c) the provenance on the recipe job is advisory-only: stripping the
	// key leaves an identical job for every other field, which is exactly
	// what an older reader that ignores the unknown field sees.
	j, ok, err := js.Load(enqueued.JobID)
	if err != nil || !ok {
		t.Fatalf("Load recipe job: %v %v", j, err)
	}
	if j.Provenance == nil {
		t.Fatalf("recipe job lost its provenance label")
	}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal job map: %v", err)
	}
	delete(asMap, "provenance")
	strippedRaw, err := json.Marshal(asMap)
	if err != nil {
		t.Fatalf("remarshal stripped job: %v", err)
	}
	var stripped jobs.Job
	if err := json.Unmarshal(strippedRaw, &stripped); err != nil {
		t.Fatalf("unmarshal stripped job: %v", err)
	}
	j.Provenance = nil
	if !reflect.DeepEqual(j, stripped) {
		t.Fatalf("job differs beyond the advisory provenance label:\nfull:     %+v\nstripped: %+v", j, stripped)
	}
	if err := jobs.ValidateJob(stripped); err != nil {
		t.Fatalf("stripped (v2.1-view) job fails validation: %v", err)
	}
	// (d) a nil provenance is a valid one-off, so downgraded readers that
	// drop the label still have a coherent job.
	if err := wire.ValidateProvenance(nil); err != nil {
		t.Fatalf("nil provenance invalid: %v", err)
	}
}
