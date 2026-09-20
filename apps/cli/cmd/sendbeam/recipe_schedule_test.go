package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/recipes"
)

// scheduleTriggerParams builds a schedule-params JSON flag value.
func scheduleTriggerParams(kind string) string {
	switch kind {
	case "daily":
		return `{"kind":"daily","at":"14:30","tz":"Asia/Calcutta"}`
	case "interval":
		return `{"kind":"interval","every_minutes":1}`
	default:
		return `{"kind":"hourly","minute":15}`
	}
}

// createScheduleRecipe creates an approved+granted schedule-triggered
// recipe and returns its id.
func createScheduleRecipe(t *testing.T, cfgDir, devID, srcDir, params string) string {
	t.Helper()
	if code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Scheduled", "--source", srcDir, "--to", devID,
		"--trigger", "schedule", "--schedule-params", params); code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)
	if code, _, errOut := runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	if code, _, errOut := runRecipeCmd(t, "grant", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("grant exit %d: %s", code, errOut)
	}
	return id
}

// TestRecipeScheduleCreateAndShow: create with --trigger schedule and
// JSON params, then show displays the human schedule words, the next run
// and the (absent) cursor.
func TestRecipeScheduleCreateAndShow(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)
	if code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Daily exports", "--source", srcDir, "--to", devID,
		"--trigger", "schedule", "--schedule-params", scheduleTriggerParams("daily")); code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)

	code, out, errOut := runRecipeCmd(t, "show", "--config-dir", cfgDir, id)
	if code != 0 {
		t.Fatalf("show exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"daily at 14:30 Asia/Calcutta",
		"Next run:",
		"Cursor: none yet",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("show missing %q:\n%s", want, out)
		}
	}
}

// TestRecipeScheduleParamsValidation: the CLI fails closed on bad
// schedule inputs (exit 2, message on stderr).
func TestRecipeScheduleParamsValidation(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad JSON", []string{"--trigger", "schedule", "--schedule-params", "{nope"}, "invalid --schedule-params JSON"},
		{"unknown kind", []string{"--trigger", "schedule", "--schedule-params", `{"kind":"cron"}`}, "kind must be one of"},
		{"bad at", []string{"--trigger", "schedule", "--schedule-params", `{"kind":"daily","at":"2:30pm"}`}, `want "HH:MM"`},
		{"unknown tz", []string{"--trigger", "schedule", "--schedule-params", `{"kind":"daily","at":"14:30","tz":"Mars/Olympus"}`}, "unknown time zone"},
		{"params without trigger", []string{"--schedule-params", scheduleTriggerParams("daily")}, "needs --trigger schedule"},
		{"schedule without params", []string{"--trigger", "schedule"}, "needs --schedule-params JSON"},
		{"bad trigger", []string{"--trigger", "cron"}, "unknown --trigger"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"create", "--config-dir", cfgDir,
				"--name", "Bad", "--source", srcDir, "--to", devID}, tc.args...)
			code, _, errOut := runRecipeCmd(t, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errOut)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Fatalf("stderr missing %q:\n%s", tc.want, errOut)
			}
		})
	}
}

// TestRecipeScheduleEditRevokesGrant: changing the schedule parameters
// is a material scope change — the automation grant is revoked and the
// recipe drops back to approval-required.
func TestRecipeScheduleEditRevokesGrant(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)
	id := createScheduleRecipe(t, cfgDir, devID, srcDir, scheduleTriggerParams("daily"))

	if code, _, errOut := runRecipeCmd(t, "edit", "--config-dir", cfgDir, id,
		"--schedule-params", `{"kind":"daily","at":"15:30","tz":"Asia/Calcutta"}`); code != 0 {
		t.Fatalf("edit exit %d: %s", code, errOut)
	}
	store, err := openRecipeStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	r, err := loadRecipe(store, id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if r.Grant.AutoSend {
		t.Fatalf("schedule change did not revoke the automation grant")
	}
	if r.Status != recipes.RecipeApprovalRequired {
		t.Fatalf("status = %q, want approval-required", r.Status)
	}
	if code, out, errOut := runRecipeCmd(t, "show", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("show exit %d: %s", code, errOut)
	} else if !strings.Contains(out, "daily at 15:30 Asia/Calcutta") {
		t.Fatalf("show does not display the edited schedule:\n%s", out)
	}
}

// TestRecipeSchedulerForeground: a backdated cursor (two missed
// occurrences) is caught up on scheduler start, the due run dispatches
// through the real runner, and Ctrl+C (ctx cancel) stops cleanly with
// exit 0.
func TestRecipeSchedulerForeground(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)
	id := createScheduleRecipe(t, cfgDir, devID, srcDir, scheduleTriggerParams("interval"))

	// Two missed one-minute occurrences: backdate the durable cursor.
	store, err := openRecipeStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.AdvanceScheduleCursor(id, time.Now().Add(-2*time.Minute).UTC()); err != nil {
		t.Fatalf("backdate cursor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr lockedBuffer
	done := make(chan int, 1)
	go func() { done <- scheduleRecipes(ctx, cfgDir, &stdout, &stderr) }()

	waitForOutput(t, 30*time.Second, &stdout, "hosting line", "Scheduler running,")
	waitForOutput(t, 30*time.Second, &stdout, "catch-up dispatch", "dispatched:")
	waitForOutput(t, 30*time.Second, &stdout, "second dispatch", "caught up 2 of 2")

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("scheduleRecipes exit %d, stderr:\n%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("scheduleRecipes did not stop after cancel")
	}
	if !strings.Contains(stdout.String(), "Scheduler stopped.") {
		t.Fatalf("no clean-stop line in output:\n%s", stdout.String())
	}

	// The cursor advanced past the missed occurrences and the ledger
	// describes the bounded catch-up.
	r, err := loadRecipe(store, id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if r.ScheduleCursor == nil || r.ScheduleCursor.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("cursor did not advance: %v", r.ScheduleCursor)
	}
	if r.LastRun == nil || !strings.Contains(r.LastRun.Detail, "caught up 2 of 2 missed run(s)") {
		t.Fatalf("ledger does not describe the catch-up: %+v", r.LastRun)
	}
}

// TestRecipeSchedulerNoGrantRefuses: without an automation grant the
// scheduler refuses due occurrences instead of dispatching them.
func TestRecipeSchedulerNoGrantRefuses(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)
	if code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Scheduled", "--source", srcDir, "--to", devID,
		"--trigger", "schedule", "--schedule-params", scheduleTriggerParams("interval")); code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)
	if code, _, errOut := runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	// No grant.
	store, err := openRecipeStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.AdvanceScheduleCursor(id, time.Now().Add(-time.Minute).UTC()); err != nil {
		t.Fatalf("backdate cursor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr lockedBuffer
	done := make(chan int, 1)
	go func() { done <- scheduleRecipes(ctx, cfgDir, &stdout, &stderr) }()

	waitForOutput(t, 30*time.Second, &stdout, "refusal line", "refused:")
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("scheduleRecipes exit %d, stderr:\n%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("scheduleRecipes did not stop after cancel")
	}
	if strings.Contains(stdout.String(), "dispatched:") {
		t.Fatalf("dispatched without a grant:\n%s", stdout.String())
	}
}
