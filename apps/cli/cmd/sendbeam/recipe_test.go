package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendbeam/engine/jobs"
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
