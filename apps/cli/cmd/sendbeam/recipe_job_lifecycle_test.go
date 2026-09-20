// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A job already admitted when its recipe is disabled runs to completion
// semantics: disable touches the recipe, never the job. The full job id
// from `recipe show` cancels the job through the ordinary outbox path.
func TestRecipeJobSurvivesDisable_ThenCancels(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	if code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Exports", "--source", srcDir, "--to", devID); code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)
	if code, _, errOut := runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}

	// Run enqueues the job; capture the FULL job id from JSON output.
	code, out, errOut := runRecipeCmd(t, "run", "--config-dir", cfgDir, id, "--json")
	if code != 0 {
		t.Fatalf("run exit %d: %s", code, errOut)
	}
	var job struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal([]byte(out), &job); err != nil || job.JobID == "" {
		t.Fatalf("run --json did not yield a job id: %s (err %v)", out, err)
	}

	// `recipe show` must print the full job id and the exact cancel
	// command — the last-run line is the human's way to find it.
	code, out, _ = runRecipeCmd(t, "show", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("show exit %d", code)
	}
	if !strings.Contains(out, job.JobID) {
		t.Fatalf("show output missing full job id %q", job.JobID)
	}
	if !strings.Contains(out, "sendbeam outbox cancel "+job.JobID) {
		t.Fatalf("show output missing the cancel command for the full job id: %s", out)
	}
	if !strings.Contains(out, "Last run sent") {
		t.Fatalf("show output missing last-run bytes line: %s", out)
	}

	// Disable the recipe: the queued job is untouched.
	if code, _, errOut := runRecipeCmd(t, "disable", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("disable exit %d: %s", code, errOut)
	}
	var stdout, stderr strings.Builder
	if code := runOutbox([]string{"show", "--config-dir", cfgDir, "--json", job.JobID}, &stdout, &stderr); code != 0 {
		t.Fatalf("outbox show exit %d: %s", code, stderr.String())
	}
	var shown struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &shown); err != nil {
		t.Fatalf("outbox show --json: %v", err)
	}
	if shown.State != "queued" {
		t.Fatalf("job status after disable = %q, want queued", shown.State)
	}

	// Cancel the recipe job by its full id through the ordinary path.
	stdout.Reset()
	stderr.Reset()
	if code := runOutbox([]string{"cancel", "--config-dir", cfgDir, job.JobID}, &stdout, &stderr); code != 0 {
		t.Fatalf("outbox cancel exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(strings.ToLower(stdout.String()), "cancelled") {
		t.Fatalf("cancel output not confirming: %s", stdout.String())
	}
}
