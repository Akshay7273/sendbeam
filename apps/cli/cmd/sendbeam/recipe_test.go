package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/recipes"
)

// recipeTestSetup builds an isolated CLI environment with one trusted
// device and one source tree, and returns the config dir, the device id,
// and a source file path.
func recipeTestSetup(t *testing.T) (cfgDir, devID, srcDir string) {
	t.Helper()
	cfgDir = t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	devID = seedOutboxDevice(t, env, "studio")
	srcDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "export.txt"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return cfgDir, devID, srcDir
}

// recipeIDInStore reads the single recipe id stored under cfgDir.
func recipeIDInStore(t *testing.T, cfgDir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(cfgDir, "recipes", "*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("want exactly 1 recipe file, got %v (err %v)", matches, err)
	}
	return strings.TrimSuffix(filepath.Base(matches[0]), ".json")
}

func runRecipeCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runRecipe(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestRecipeRoundTrip exercises the full one-shot workflow:
// create → preview → approve → run → show, in an isolated config dir.
func TestRecipeRoundTrip(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	// create
	code, out, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Exports", "--source", srcDir, "--to", devID)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "approval-required") {
		t.Fatalf("new recipe should start approval-required, got: %s", out)
	}
	id := recipeIDInStore(t, cfgDir)

	// run before approval must refuse with an actionable message.
	code, _, errOut = runRecipeCmd(t, "run", "--config-dir", cfgDir, id)
	if code == 0 {
		t.Fatalf("run before approval succeeded")
	}
	if !strings.Contains(errOut, "requires approval") || !strings.Contains(errOut, "recipe approve") {
		t.Fatalf("run refusal not actionable: %s", errOut)
	}

	// preview --json: versioned DTO, and no jobs exist afterwards.
	code, out, errOut = runRecipeCmd(t, "preview", "--config-dir", cfgDir, id, "--json")
	if code != 0 {
		t.Fatalf("preview exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, `"version":1`) || !strings.Contains(out, `"status":"dry-run"`) {
		t.Fatalf("preview JSON missing version/status: %s", out)
	}
	if !strings.Contains(out, `"path"`) {
		t.Fatalf("preview JSON missing files: %s", out)
	}

	// preview (human) states it sends nothing.
	code, out, _ = runRecipeCmd(t, "preview", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("preview exit %d", code)
	}
	if !strings.Contains(out, "sends nothing") {
		t.Fatalf("preview does not state it sends nothing: %s", out)
	}

	jobStore, err := jobs.OpenJobStore(filepath.Join(cfgDir, "jobs"))
	if err != nil {
		t.Fatalf("open jobs: %v", err)
	}
	listed, err := jobStore.List()
	if err != nil {
		t.Fatalf("jobs list: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("preview created %d jobs", len(listed))
	}

	// approve, then run: exactly one job, one attempt per recipient.
	code, out, errOut = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Approved") {
		t.Fatalf("approve output: %s", out)
	}

	code, out, errOut = runRecipeCmd(t, "run", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("run exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Enqueued") {
		t.Fatalf("run output: %s", out)
	}
	listed, err = jobStore.List()
	if err != nil {
		t.Fatalf("jobs list: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("run created %d jobs, want exactly 1", len(listed))
	}
	job, ok, err := jobStore.Load(listed[0].JobID)
	if err != nil || !ok {
		t.Fatalf("job load: %v %v", err, ok)
	}
	if len(job.Files) != 1 || len(job.Attempts) != 1 {
		t.Fatalf("job has %d files and %d attempts, want 1 and 1", len(job.Files), len(job.Attempts))
	}
	if job.Attempts[0].DeviceID != devID {
		t.Fatalf("job attempt for wrong device: %v", job.Attempts[0].DeviceID)
	}

	// show renders the human preview.
	code, out, errOut = runRecipeCmd(t, "show", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("show exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Exports") {
		t.Fatalf("show output: %s", out)
	}

	// edit rename (non-material) keeps manual status.
	code, out, errOut = runRecipeCmd(t, "edit", "--config-dir", cfgDir, id, "--name", "Exports v2")
	if code != 0 {
		t.Fatalf("edit exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "manual") {
		t.Fatalf("non-material edit should keep manual status: %s", out)
	}

	// duplicate: fresh id, approval-required, no auto-send.
	code, out, errOut = runRecipeCmd(t, "duplicate", "--config-dir", cfgDir, id, "--name", "Exports copy")
	if code != 0 {
		t.Fatalf("duplicate exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "approval-required") {
		t.Fatalf("duplicate should start approval-required: %s", out)
	}
	matches, _ := filepath.Glob(filepath.Join(cfgDir, "recipes", "*.json"))
	if len(matches) != 2 {
		t.Fatalf("want 2 recipes after duplicate, got %d", len(matches))
	}

	// delete the duplicate (keep the original for export/import below).
	dupID := ""
	for _, m := range matches {
		cand := strings.TrimSuffix(filepath.Base(m), ".json")
		if cand != id {
			dupID = cand
		}
	}
	code, _, errOut = runRecipeCmd(t, "delete", "--config-dir", cfgDir, dupID)
	if code != 0 {
		t.Fatalf("delete exit %d: %s", code, errOut)
	}
	matches, _ = filepath.Glob(filepath.Join(cfgDir, "recipes", "*.json"))
	if len(matches) != 1 {
		t.Fatalf("want 1 recipe after delete, got %d", len(matches))
	}
}

// TestRecipeExportImport verifies the export/import round-trip: the
// imported copy keeps the content but starts disabled with no grant.
func TestRecipeExportImport(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Backup", "--source", srcDir, "--to", devID)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)

	exportPath := filepath.Join(t.TempDir(), "recipe.json")
	code, _, errOut = runRecipeCmd(t, "export", "--config-dir", cfgDir, id, "--out", exportPath)
	if code != 0 {
		t.Fatalf("export exit %d: %s", code, errOut)
	}
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !strings.Contains(string(data), "Backup") {
		t.Fatalf("export missing recipe name")
	}

	// Delete the original, then import: the copy must start disabled.
	code, _, errOut = runRecipeCmd(t, "delete", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("delete exit %d: %s", code, errOut)
	}
	code, out, errOut := runRecipeCmd(t, "import", "--config-dir", cfgDir, exportPath)
	if code != 0 {
		t.Fatalf("import exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "disabled") {
		t.Fatalf("imported recipe should start disabled: %s", out)
	}
	newID := recipeIDInStore(t, cfgDir)

	// A disabled recipe refuses to run.
	code, _, errOut = runRecipeCmd(t, "run", "--config-dir", cfgDir, newID)
	if code == 0 {
		t.Fatalf("disabled imported recipe ran")
	}
	if !strings.Contains(errOut, "disabled") {
		t.Fatalf("run refusal: %s", errOut)
	}

	// list shows it.
	code, out, errOut = runRecipeCmd(t, "list", "--config-dir", cfgDir)
	if code != 0 {
		t.Fatalf("list exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Backup") || !strings.Contains(out, "disabled") {
		t.Fatalf("list output: %s", out)
	}
}

// TestRecipeCreateValidatesTrust ensures an unknown device id is rejected
// at create time.
func TestRecipeCreateValidatesTrust(t *testing.T) {
	cfgDir, _, srcDir := recipeTestSetup(t)
	code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Bad", "--source", srcDir, "--to", "sb-dev-"+strings.Repeat("0", 64))
	if code == 0 {
		t.Fatalf("create with untrusted device succeeded")
	}
	if errOut == "" {
		t.Fatalf("expected an error message")
	}
}

// TestRecipeGrantRevokeShow exercises the auto-send grant lifecycle:
// approve → grant → show (grant state + empty ledger) → revoke → show,
// plus the grant gates (approval-required and disabled cannot be granted)
// and the material-change revocation through the real edit path.
func TestRecipeGrantRevokeShow(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Exports", "--source", srcDir, "--to", devID)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)

	// Grant before approval is refused with an actionable error.
	code, _, errOut = runRecipeCmd(t, "grant", "--config-dir", cfgDir, id)
	if code == 0 {
		t.Fatalf("grant on approval-required recipe succeeded")
	}
	if !strings.Contains(errOut, "recipe approve") {
		t.Fatalf("grant refusal does not point at approval: %s", errOut)
	}

	code, _, errOut = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}

	// Grant: explicit consent, material-change warning, no run.
	code, out, errOut := runRecipeCmd(t, "grant", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("grant exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Granted") || !strings.Contains(out, "Consent v1") {
		t.Fatalf("grant output: %s", out)
	}
	if !strings.Contains(out, "material change") || !strings.Contains(out, "revokes") {
		t.Fatalf("grant must warn that material changes revoke it: %s", out)
	}

	// Show: grant state, scope hash match, empty last-run ledger.
	code, out, errOut = runRecipeCmd(t, "show", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("show exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "auto-send ENABLED") {
		t.Fatalf("show does not report the grant: %s", out)
	}
	if !strings.Contains(out, "Grant scope:") || !strings.Contains(out, "matches the current scope") {
		t.Fatalf("show does not report scope hash match: %s", out)
	}
	if !strings.Contains(out, "Last run: none recorded") {
		t.Fatalf("show does not report the empty ledger: %s", out)
	}

	// JSON show carries the machine-readable grant.
	code, out, errOut = runRecipeCmd(t, "show", "--config-dir", cfgDir, id, "--json")
	if code != 0 {
		t.Fatalf("show --json exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, `"autoSend": true`) {
		t.Fatalf("show --json missing the grant: %s", out)
	}

	// Non-material edit keeps the grant.
	code, _, errOut = runRecipeCmd(t, "edit", "--config-dir", cfgDir, id, "--name", "Exports v2")
	if code != 0 {
		t.Fatalf("edit exit %d: %s", code, errOut)
	}
	code, out, errOut = runRecipeCmd(t, "show", "--config-dir", cfgDir, id, "--json")
	if code != 0 {
		t.Fatalf("show --json exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, `"autoSend": true`) {
		t.Fatalf("non-material edit dropped the grant: %s", out)
	}

	// Material edit revokes the grant and forces re-approval (the V22-PR01
	// material-change rule, through the real CLI edit path).
	code, _, errOut = runRecipeCmd(t, "edit", "--config-dir", cfgDir, id, "--budget-bytes", "123")
	if code != 0 {
		t.Fatalf("edit exit %d: %s", code, errOut)
	}
	code, out, errOut = runRecipeCmd(t, "show", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("show exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "approval-required") {
		t.Fatalf("material edit did not force re-approval: %s", out)
	}
	if strings.Contains(out, "auto-send ENABLED") {
		t.Fatalf("material edit did not revoke the grant: %s", out)
	}
	if !strings.Contains(out, "was revoked") {
		t.Fatalf("show does not explain the revoked consent: %s", out)
	}

	// Revoke on a grant-less recipe is a no-op with a clear message;
	// status is unchanged.
	code, out, errOut = runRecipeCmd(t, "revoke", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("revoke exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "no active auto-send grant") {
		t.Fatalf("revoke output: %s", out)
	}
}

// TestRecipeGrantRevokeRoundTrip grants and then revokes, verifying the
// stored record at each step.
func TestRecipeGrantRevokeRoundTrip(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Exports", "--source", srcDir, "--to", devID)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)
	if code, _, errOut = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "grant", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("grant exit %d: %s", code, errOut)
	}

	code, out, errOut := runRecipeCmd(t, "revoke", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("revoke exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Revoked") {
		t.Fatalf("revoke output: %s", out)
	}
	if !strings.Contains(out, "manual runs still work") {
		t.Fatalf("revoke must say manual runs keep working: %s", out)
	}

	code, out, errOut = runRecipeCmd(t, "show", "--config-dir", cfgDir, id, "--json")
	if code != 0 {
		t.Fatalf("show --json exit %d: %s", code, errOut)
	}
	if strings.Contains(out, `"autoSend": true`) {
		t.Fatalf("revoke did not clear autoSend: %s", out)
	}
}

// TestRecipeImportNeverRestoresGrant verifies that importing an export of
// a granted recipe starts disabled with no grant and no last-run ledger.
func TestRecipeImportNeverRestoresGrant(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Exports", "--source", srcDir, "--to", devID)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)
	if code, _, errOut = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "grant", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("grant exit %d: %s", code, errOut)
	}

	exportPath := filepath.Join(t.TempDir(), "recipe.json")
	if code, _, errOut = runRecipeCmd(t, "export", "--config-dir", cfgDir, id, "--out", exportPath); code != 0 {
		t.Fatalf("export exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "delete", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("delete exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "import", "--config-dir", cfgDir, exportPath); code != 0 {
		t.Fatalf("import exit %d: %s", code, errOut)
	}
	newID := recipeIDInStore(t, cfgDir)

	code, out, errOut := runRecipeCmd(t, "show", "--config-dir", cfgDir, newID, "--json")
	if code != 0 {
		t.Fatalf("show --json exit %d: %s", code, errOut)
	}
	if strings.Contains(out, `"autoSend": true`) {
		t.Fatalf("import restored the auto-send grant")
	}
	if strings.Contains(out, `"lastRun"`) {
		t.Fatalf("import restored the last-run ledger")
	}
	if !strings.Contains(out, `"status": "disabled"`) {
		t.Fatalf("imported recipe is not disabled: %s", out)
	}

	// A disabled import cannot be granted: enable (edit) and approve first.
	if code, _, _ = runRecipeCmd(t, "grant", "--config-dir", cfgDir, newID); code == 0 {
		t.Fatalf("grant on disabled import succeeded")
	}
}

// lockedBuffer is a goroutine-safe bytes.Buffer: the watcher's event
// callback writes from the watcher's goroutine while the test polls.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func waitForOutput(t *testing.T, timeout time.Duration, buf *lockedBuffer, what, substr string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in output:\n%s", what, buf.String())
}

// TestRecipeWatchForeground drives `recipe watch` end to end: the watcher
// starts, a touched file produces a "dispatched job" line, and cancelling
// the context stops the watcher cleanly with exit 0.
func TestRecipeWatchForeground(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	if code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Watched", "--source", srcDir, "--to", devID); code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)

	// Flip the trigger to watch through the store (material change), then
	// approve and grant through the real CLI path.
	store, err := openRecipeStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	r, err := loadRecipe(store, id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r.Trigger.Kind = recipes.TriggerWatch
	if _, err := recipes.ApplyUpdate(store, r); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if code, _, errOut := runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	if code, _, errOut := runRecipeCmd(t, "grant", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("grant exit %d: %s", code, errOut)
	}

	// show displays the trigger type and watch params.
	if code, out, errOut := runRecipeCmd(t, "show", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("show exit %d: %s", code, errOut)
	} else if !strings.Contains(out, "watch (debounce") {
		t.Fatalf("show does not display watch params:\n%s", out)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr lockedBuffer
	done := make(chan int, 1)
	go func() { done <- watchRecipe(ctx, id, cfgDir, &stdout, &stderr) }()

	waitForOutput(t, 10*time.Second, &stdout, "watch banner", "Watching recipe")
	if err := os.WriteFile(filepath.Join(srcDir, "live.txt"), []byte("live"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitForOutput(t, 10*time.Second, &stdout, "change line", "change detected in")
	waitForOutput(t, 10*time.Second, &stdout, "dispatch line", "dispatched job")

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("watchRecipe exit %d, stderr:\n%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("watchRecipe did not stop after cancel")
	}
	if !strings.Contains(stdout.String(), "Watch stopped.") {
		t.Fatalf("no clean-stop line in output:\n%s", stdout.String())
	}
}

// TestRecipeWatchRefusesWithoutGrant checks the fail-fast path: watching
// a recipe with no auto-send grant exits non-zero before watching.
func TestRecipeWatchRefusesWithoutGrant(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)
	if code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Watched", "--source", srcDir, "--to", devID); code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)
	if code, _, errOut := runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	store, err := openRecipeStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	r, err := loadRecipe(store, id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r.Trigger.Kind = recipes.TriggerWatch
	if _, err := recipes.ApplyUpdate(store, r); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if code, _, errOut := runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}

	// No grant: watch must fail fast with the refusal on stderr.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr lockedBuffer
	if code := watchRecipe(ctx, id, cfgDir, &stdout, &stderr); code == 0 {
		t.Fatalf("watch without grant exited 0")
	}
	if !strings.Contains(stderr.String(), "automation grant") {
		t.Fatalf("stderr does not name the missing grant:\n%s", stderr.String())
	}
}
