// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// testDeviceIDFake returns a canonically-formed device id that is not in
// any trust store: fine for resolve-only tests where recipients never hit
// the trust store.
func testDeviceIDFake() string {
	return "sb-dev-" + strings.Repeat("a1", 32)
}

// writeTestFile writes content to dir/name (creating parents) and returns
// the absolute path.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// testIdentity registers one trusted device in ts and returns its device id.
func testIdentity(ctx context.Context, t *testing.T, ts *trust.MemoryTrustStore, label string) string {
	t.Helper()
	gen, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	rec := &wire.TrustRecord{
		DeviceID:          gen.DeviceID,
		PublicKey:         gen.PublicKeyHex(),
		LocalLabel:        label,
		PairCredentialRef: "cred-test",
		FirstSeenAt:       testNow,
		LastSeenAt:        testNow,
		Policy:            wire.DefaultTrustPolicy(),
	}
	if err := ts.AddOrUpdateDevice(ctx, rec); err != nil {
		t.Fatalf("AddOrUpdateDevice: %v", err)
	}
	return gen.DeviceID
}

// composableRecipe builds a saved, manual-status recipe over root with two
// trusted recipients.
func composableRecipe(t *testing.T, store *RecipeStore, root, name string, ids ...string) Recipe {
	t.Helper()
	r, err := NewRecipe(name, testNow)
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	for _, id := range ids {
		r.Recipients = append(r.Recipients, RecipeRecipient{DeviceID: id, Label: "dev-" + id[:8]})
	}
	r.Status = RecipeManual
	r.Grant.ScopeHash = r.ScopeHash()
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return r
}

func TestResolveRecursive(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "alpha")
	writeTestFile(t, root, "sub/b.txt", "bravo")
	writeTestFile(t, root, "sub/deep/c.txt", "charlie")
	writeTestFile(t, root, "sub/deep/d.bin", "delta-bytes")

	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Include = nil

	plan, err := Resolve(r, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Files) != 4 {
		t.Fatalf("got %d files, want 4", len(plan.Files))
	}
	// Deterministic order: sorted by path.
	for i := 1; i < len(plan.Files); i++ {
		if plan.Files[i-1].Path >= plan.Files[i].Path {
			t.Fatalf("files not sorted: %q then %q", plan.Files[i-1].Path, plan.Files[i].Path)
		}
	}
	want := map[string]string{
		filepath.Join(root, "a.txt"):          sha256Hex("alpha"),
		filepath.Join(root, "sub/b.txt"):      sha256Hex("bravo"),
		filepath.Join(root, "sub/deep/c.txt"): sha256Hex("charlie"),
		filepath.Join(root, "sub/deep/d.bin"): sha256Hex("delta-bytes"),
	}
	var total int64
	for _, f := range plan.Files {
		wantDigest, ok := want[f.Path]
		if !ok {
			t.Fatalf("unexpected file %q", f.Path)
		}
		if f.Digest != wantDigest {
			t.Fatalf("digest mismatch for %q", f.Path)
		}
		total += f.Size
	}
	if plan.TotalBytes != total {
		t.Fatalf("TotalBytes %d, want %d", plan.TotalBytes, total)
	}
	if len(plan.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", plan.Warnings)
	}
}

func TestResolveNonRecursive(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "top.txt", "top")
	writeTestFile(t, root, "sub/nested.txt", "nested")

	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: root, Recursive: false}}
	r.Include = nil

	plan, err := Resolve(r, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Files) != 1 || !strings.HasSuffix(plan.Files[0].Path, "top.txt") {
		t.Fatalf("non-recursive resolve got %v", plan.Files)
	}
}

func TestResolveFileSource(t *testing.T) {
	root := t.TempDir()
	single := writeTestFile(t, root, "one.txt", "just me")

	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: single, Recursive: false}}
	r.Include = nil

	plan, err := Resolve(r, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Files) != 1 || plan.Files[0].Path != single {
		t.Fatalf("file source got %v", plan.Files)
	}
	if plan.Files[0].Digest != sha256Hex("just me") {
		t.Fatalf("bad digest")
	}
}

func TestResolveFilters(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "keep.txt", "a")
	writeTestFile(t, root, "skip.log", "b")
	writeTestFile(t, root, "sub/keep2.txt", "c")
	writeTestFile(t, root, "sub/skip2.log", "d")

	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Include = []string{"*.txt"}
	r.Exclude = []string{"sub/*"}

	plan, err := Resolve(r, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// "*.txt" matches only top-level *.txt (no ** semantics); "sub/*"
	// excludes everything under sub/.
	if len(plan.Files) != 1 || !strings.HasSuffix(plan.Files[0].Path, "keep.txt") {
		t.Fatalf("filter resolve got %v", plan.Files)
	}
}

func TestResolveRejectsDoubleStar(t *testing.T) {
	r := validRecipe(t, testDeviceIDFake())
	r.Include = []string{"**.txt"}
	if _, err := Resolve(r, ResolveOptions{}); err == nil {
		t.Fatalf("** glob accepted")
	} else if !strings.Contains(err.Error(), "**") {
		t.Fatalf("error %q does not name the unsupported glob", err)
	}
}

func TestResolveOverlappingRootsDedup(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "a")
	writeTestFile(t, root, "sub/b.txt", "b")

	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{
		{Path: root, Recursive: true},
		{Path: filepath.Join(root, "sub"), Recursive: true},
	}
	r.Include = nil

	plan, err := Resolve(r, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Files) != 2 {
		t.Fatalf("overlapping roots produced %d entries, want 2 (deduped)", len(plan.Files))
	}
}

func TestResolveSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeTestFile(t, root, "inner.txt", "inside")
	writeTestFile(t, outside, "secret.txt", "outside-secret")
	writeTestFile(t, outside, "whole/evil.bin", "dir-secret")

	// File symlink escaping the root.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "leak.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// Directory symlink escaping the root (followed: must not descend).
	if err := os.Symlink(filepath.Join(outside, "whole"), filepath.Join(root, "leakdir")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// Benign symlink inside the root: still resolved.
	if err := os.Symlink(filepath.Join(root, "inner.txt"), filepath.Join(root, "alias.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Include = nil

	plan, err := Resolve(r, ResolveOptions{FollowDirSymlinks: true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, f := range plan.Files {
		if strings.HasSuffix(f.Path, "leak.txt") || strings.Contains(f.Path, "leakdir") {
			t.Fatalf("escaped symlink produced an entry: %q", f.Path)
		}
		if f.Digest == sha256Hex("outside-secret") || f.Digest == sha256Hex("dir-secret") {
			t.Fatalf("outside content leaked into plan digest")
		}
	}
	if len(plan.Warnings) != 2 {
		t.Fatalf("want 2 escape warnings, got %v", plan.Warnings)
	}
	for _, w := range plan.Warnings {
		if !strings.Contains(w, "escaping its source root") {
			t.Fatalf("warning %q is not a deterministic escape warning", w)
		}
	}
	// Deterministic: same warning text across runs.
	plan2, err := Resolve(r, ResolveOptions{FollowDirSymlinks: true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan2.Warnings) != 2 || plan2.Warnings[0] != plan.Warnings[0] || plan2.Warnings[1] != plan.Warnings[1] {
		t.Fatalf("warnings not deterministic: %v vs %v", plan.Warnings, plan2.Warnings)
	}
	// The benign alias resolves to the same content as inner.txt.
	found := false
	for _, f := range plan.Files {
		if strings.HasSuffix(f.Path, "alias.txt") && f.Digest == sha256Hex("inside") {
			found = true
		}
	}
	if !found {
		t.Fatalf("in-root symlink not resolved: %v", plan.Files)
	}
}

func TestResolveDanglingSymlinkHardError(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "ok.txt", "ok")
	if err := os.Symlink(filepath.Join(root, "nope.txt"), filepath.Join(root, "dangling.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Include = nil
	if _, err := Resolve(r, ResolveOptions{}); err == nil {
		t.Fatalf("dangling symlink silently accepted")
	} else if !strings.Contains(err.Error(), "dangling.txt") {
		t.Fatalf("error %q does not name the dangling path", err)
	}
}

func TestResolvePermissionDeniedHardError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not apply to root; CI runs this as non-root")
	}
	root := t.TempDir()
	writeTestFile(t, root, "ok.txt", "ok")
	locked := writeTestFile(t, root, "locked.txt", "nope")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer func() { _ = os.Chmod(locked, 0o644) }()

	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Include = nil
	_, err := Resolve(r, ResolveOptions{})
	if err == nil {
		t.Fatalf("unreadable file silently skipped")
	}
	if !strings.Contains(err.Error(), "locked.txt") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error %q does not name the path with permission denied", err)
	}
}

func TestResolveMissingRootHardError(t *testing.T) {
	r := validRecipe(t, testDeviceIDFake())
	r.Sources = []RecipeSource{{Path: filepath.Join(t.TempDir(), "no-such-root"), Recursive: true}}
	r.Include = nil
	if _, err := Resolve(r, ResolveOptions{}); err == nil {
		t.Fatalf("missing root silently accepted")
	}
}

// recordingEnqueuer is a test Enqueuer that records calls and fails the
// test if it is called when it should not be.
type recordingEnqueuer struct {
	calls      int
	paths      []string
	recipients []EnqueueRecipient
	// provenance records the routine origin label the dispatch passed
	// (V22-PR06); nil for one-off-style calls.
	provenance *wire.Provenance
	job        jobs.Job
	failIfCall bool
}

func (f *recordingEnqueuer) Enqueue(_ context.Context, paths []string, recipients []EnqueueRecipient, _ jobs.RetryPolicy, _ netpolicy.Policy, provenance *wire.Provenance) (jobs.Job, error) {
	f.calls++
	if f.failIfCall {
		panic("Enqueue called during dry-run")
	}
	f.paths = append([]string{}, paths...)
	f.recipients = append([]EnqueueRecipient{}, recipients...)
	f.provenance = provenance
	if f.job.JobID == "" {
		f.job = jobs.Job{JobID: "test-job-1"}
	}
	return f.job, nil
}

func openTestRecipeStore(t *testing.T) *RecipeStore {
	t.Helper()
	store, err := OpenRecipeStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenRecipeStore: %v", err)
	}
	return store
}

func TestRunHappyPath(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")
	id2 := testIdentity(ctx, t, ts, "Phone")

	root := t.TempDir()
	f1 := writeTestFile(t, root, "a.txt", "alpha")
	f2 := writeTestFile(t, root, "sub/b.txt", "bravo")

	store := openTestRecipeStore(t)
	r := composableRecipe(t, store, root, "Export folder", id1, id2)

	eq := &recordingEnqueuer{}
	job, err := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if eq.calls != 1 {
		t.Fatalf("Enqueue called %d times, want exactly 1", eq.calls)
	}
	if len(eq.paths) != 2 || eq.paths[0] != f1 || eq.paths[1] != f2 {
		t.Fatalf("enqueued paths %v, want [%s %s]", eq.paths, f1, f2)
	}
	if len(eq.recipients) != 2 {
		t.Fatalf("want one attempt per recipient, got %v", eq.recipients)
	}
	got := map[string]bool{}
	for _, c := range eq.recipients {
		got[c.DeviceID] = true
	}
	if !got[id1] || !got[id2] {
		t.Fatalf("recipients not preserved: %v", eq.recipients)
	}
	if job.JobID != "test-job-1" {
		t.Fatalf("Run did not return the enqueued job")
	}
}

func TestDryRunCreatesNoJobs(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")

	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "alpha")

	store := openTestRecipeStore(t)
	r := composableRecipe(t, store, root, "Dry run", id1)

	// The dry-run surface (Resolve, PlanDTO, Preview) takes no Enqueuer
	// and no jobs store — a job cannot be created by construction. Run the
	// whole dry-run surface against a live jobs store and assert it stays
	// empty.
	jobStore, err := jobs.OpenJobStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenJobStore: %v", err)
	}
	eq := &recordingEnqueuer{failIfCall: true}

	loaded, ok, err := store.Load(r.ID)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", err, ok)
	}
	plan, err := Resolve(loaded, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	_ = PlanDTO(plan)
	_ = Preview(loaded)

	if eq.calls != 0 {
		t.Fatalf("dry-run called the enqueuer %d times", eq.calls)
	}
	listed, err := jobStore.List()
	if err != nil {
		t.Fatalf("jobs List: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("dry-run created %d jobs", len(listed))
	}
}

func TestRunReResolvesAfterPreview(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")

	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "alpha")

	store := openTestRecipeStore(t)
	r := composableRecipe(t, store, root, "Reresolve", id1)

	loaded, _, _ := store.Load(r.ID)
	before, err := Resolve(loaded, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(before.Files) != 1 {
		t.Fatalf("preview got %d files", len(before.Files))
	}

	// Source changes between preview and run.
	writeTestFile(t, root, "b.txt", "bravo")

	eq := &recordingEnqueuer{}
	if _, err := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(eq.paths) != 2 {
		t.Fatalf("run did not re-resolve: enqueued %v", eq.paths)
	}
}

func TestRunRevokedRecipient(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")

	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "alpha")

	store := openTestRecipeStore(t)
	r := composableRecipe(t, store, root, "Revoked", id1)
	if err := ts.RevokeDevice(ctx, id1); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	eq := &recordingEnqueuer{}
	_, err := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID)
	if err == nil {
		t.Fatalf("run accepted a revoked recipient")
	}
	if !strings.Contains(err.Error(), id1) {
		t.Fatalf("error %q does not name the revoked device", err)
	}
	if eq.calls != 0 {
		t.Fatalf("failed run still enqueued")
	}
}

func TestRunStatusGates(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")

	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "alpha")
	store := openTestRecipeStore(t)

	for _, tc := range []struct {
		status RecipeStatus
		want   string
	}{
		{RecipeDisabled, "is disabled"},
		{RecipeApprovalRequired, "requires approval"},
	} {
		r, err := NewRecipe("Gate", testNow)
		if err != nil {
			t.Fatalf("NewRecipe: %v", err)
		}
		r.Sources = []RecipeSource{{Path: root, Recursive: true}}
		r.Recipients = []RecipeRecipient{{DeviceID: id1, Label: "laptop"}}
		r.Status = tc.status
		r.Grant.ScopeHash = r.ScopeHash()
		if err := store.Save(r); err != nil {
			t.Fatalf("Save: %v", err)
		}
		eq := &recordingEnqueuer{}
		_, err = Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID)
		if err == nil {
			t.Fatalf("status %q run accepted", tc.status)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("status %q error %q is not actionable (want %q)", tc.status, err, tc.want)
		}
		if tc.status == RecipeApprovalRequired && !strings.Contains(err.Error(), "recipe approve") {
			t.Fatalf("approval error %q does not point at the fix", err)
		}
		if eq.calls != 0 {
			t.Fatalf("gated run still enqueued")
		}
	}
}

func TestRunExpired(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")

	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "alpha")
	store := openTestRecipeStore(t)

	r := composableRecipe(t, store, root, "Expired", id1)
	r.ExpiresAt = testNow.Add(-time.Hour)
	r.Grant.ScopeHash = r.ScopeHash()
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &recordingEnqueuer{}
	_, err := Run(ctx, RunDeps{Store: store, Trust: ts, Now: func() time.Time { return testNow }}, eq, r.ID)
	if err == nil {
		t.Fatalf("expired recipe ran")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error %q does not say expired", err)
	}
	if eq.calls != 0 {
		t.Fatalf("expired run still enqueued")
	}
}

func TestRunBudgets(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")

	root := t.TempDir()
	writeTestFile(t, root, "a.txt", "0123456789") // 10 bytes
	writeTestFile(t, root, "b.txt", "0123456789")

	for _, tc := range []struct {
		name    string
		budgets RecipeBudgets
		want    string
	}{
		{"bytes", RecipeBudgets{MaxBytesPerRun: 5, MaxFilesPerRun: 100, MaxConcurrentRuns: 1}, "byte"},
		{"files", RecipeBudgets{MaxBytesPerRun: 1 << 20, MaxFilesPerRun: 1, MaxConcurrentRuns: 1}, "file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestRecipeStore(t)
			r := composableRecipe(t, store, root, "Budget "+tc.name, id1)
			r.Budgets = tc.budgets
			r.Grant.ScopeHash = r.ScopeHash()
			if err := store.Save(r); err != nil {
				t.Fatalf("Save: %v", err)
			}
			eq := &recordingEnqueuer{}
			_, err := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID)
			if err == nil {
				t.Fatalf("over-budget run accepted")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "budget") {
				t.Fatalf("error %q does not name the exceeded budget", err)
			}
			if eq.calls != 0 {
				t.Fatalf("over-budget run still enqueued")
			}
		})
	}
}

func TestRunZeroFiles(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	id1 := testIdentity(ctx, t, ts, "Studio laptop")

	root := t.TempDir()
	writeTestFile(t, root, "a.log", "logs only")

	store := openTestRecipeStore(t)
	r := composableRecipe(t, store, root, "Zero files", id1)
	r.Include = []string{"*.txt"}
	r.Grant.ScopeHash = r.ScopeHash()
	if err := store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eq := &recordingEnqueuer{}
	_, err := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, r.ID)
	if err == nil {
		t.Fatalf("zero-file run accepted")
	}
	if !strings.Contains(err.Error(), "no files matched") {
		t.Fatalf("error %q does not say no files matched", err)
	}
}

func TestRunNotFound(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()
	store := openTestRecipeStore(t)
	eq := &recordingEnqueuer{}
	_, err := Run(ctx, RunDeps{Store: store, Trust: ts}, eq, "00000000000000000000000000000000")
	if err == nil {
		t.Fatalf("unknown recipe ran")
	}
}

func TestPlanDTOContract(t *testing.T) {
	root := t.TempDir()
	f1 := writeTestFile(t, root, "a.txt", "alpha")

	r := validRecipe(t, testDeviceIDFake())
	r.Name = `Tricky <script>alert("x&y")</script> "name"`
	r.Sources = []RecipeSource{{Path: root, Recursive: true}}
	r.Include = nil
	r.Recipients = []RecipeRecipient{{DeviceID: testDeviceIDFake(), Label: `l<e>g"end`}}

	plan, err := Resolve(r, ResolveOptions{Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	raw := PlanDTO(plan)

	var dto map[string]any
	if err := json.Unmarshal(raw, &dto); err != nil {
		t.Fatalf("DTO is not JSON: %v", err)
	}
	if dto["version"] != float64(1) {
		t.Fatalf("DTO version %v, want 1", dto["version"])
	}
	if dto["status"] != "dry-run" {
		t.Fatalf("DTO status %v, want dry-run", dto["status"])
	}
	if dto["recipeName"] != r.Name {
		t.Fatalf("tricky name mangled: %v", dto["recipeName"])
	}
	files, _ := dto["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("files: %v", dto["files"])
	}
	f0 := files[0].(map[string]any)
	if f0["path"] != f1 || f0["digest"] != sha256Hex("alpha") {
		t.Fatalf("file entry: %v", f0)
	}
	recipients, _ := dto["recipients"].([]any)
	r0 := recipients[0].(map[string]any)
	if r0["label"] != `l<e>g"end` {
		t.Fatalf("tricky label mangled: %v", r0["label"])
	}
	// Secret-free: no key material may appear anywhere, even if a future
	// field is added. Scan the raw bytes for credential-shaped words.
	lower := strings.ToLower(string(raw))
	for _, bad := range []string{"privatekey", "private_key", "secret", "credential", "password", "token", "seed"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("DTO contains credential-shaped word %q", bad)
		}
	}
	// HTML must not be escaped: < and > appear verbatim in the raw bytes
	// (the " is backslash-escaped, which is required JSON syntax).
	if !strings.Contains(string(raw), `l<e>g\"end`) {
		t.Fatalf("DTO HTML-escaped the label")
	}
	// resolvedAt is RFC3339.
	if _, err := time.Parse(time.RFC3339, dto["resolvedAt"].(string)); err != nil {
		t.Fatalf("resolvedAt not RFC3339: %v", dto["resolvedAt"])
	}
}
