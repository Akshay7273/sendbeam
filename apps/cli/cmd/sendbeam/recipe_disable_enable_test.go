// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
)

// Disabling a recipe switches it off for every trigger; enabling returns
// it to approval-required and revokes its automation consent, so nothing
// dispatches until a person re-reviews.
func TestRecipeDisableEnable(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	code, out, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Exports", "--source", srcDir, "--to", devID)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "approval-required") {
		t.Fatalf("new recipe should start approval-required, got: %s", out)
	}
	id := recipeIDInStore(t, cfgDir)

	// approve then grant: the routine is armed.
	if code, _, errOut = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "grant", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("grant exit %d: %s", code, errOut)
	}

	// disable: even manual runs are refused now.
	if code, out, errOut = runRecipeCmd(t, "disable", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("disable exit %d: %s", code, errOut)
	}
	if !strings.Contains(strings.ToLower(out), "disabled") {
		t.Fatalf("disable output not confirming: %s", out)
	}
	code, _, errOut = runRecipeCmd(t, "run", "--config-dir", cfgDir, id)
	if code == 0 {
		t.Fatal("run on disabled recipe succeeded")
	}
	if !strings.Contains(errOut, "disabled") || !strings.Contains(errOut, "recipe enable") {
		t.Fatalf("disable refusal not actionable: %s", errOut)
	}

	// enable: back to approval-required, grant revoked — nothing
	// dispatches until a person re-reviews.
	if code, out, errOut = runRecipeCmd(t, "enable", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("enable exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "approval-required") {
		t.Fatalf("enable output missing new status: %s", out)
	}
	code, _, errOut = runRecipeCmd(t, "run", "--config-dir", cfgDir, id)
	if code == 0 {
		t.Fatal("run after enable without re-approval succeeded")
	}
	if !strings.Contains(errOut, "requires approval") {
		t.Fatalf("enable refusal not asking for approval: %s", errOut)
	}

	// approve re-arms manual runs only; automation needs a fresh grant.
	if code, _, errOut = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("re-approve exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "run", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("run after re-approve exit %d: %s", code, errOut)
	}
}

// Disabling a recipe twice, or enabling a recipe that was never
// disabled, is a no-op — the commands never error on current state.
func TestRecipeDisableEnable_Idempotent(t *testing.T) {
	cfgDir, devID, srcDir := recipeTestSetup(t)

	code, _, errOut := runRecipeCmd(t, "create", "--config-dir", cfgDir,
		"--name", "Exports", "--source", srcDir, "--to", devID)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, errOut)
	}
	id := recipeIDInStore(t, cfgDir)

	if code, _, errOut = runRecipeCmd(t, "disable", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("first disable exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "disable", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("second disable exit %d: %s", code, errOut)
	}
	// Enabling a disabled recipe is a no-op-safe path back to
	// approval-required; approving a disabled recipe stays refused.
	if code, _, _ = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code == 0 {
		t.Fatal("approve on disabled recipe succeeded")
	}
	if code, _, errOut = runRecipeCmd(t, "enable", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("enable exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "approve", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("approve exit %d: %s", code, errOut)
	}
	if code, _, errOut = runRecipeCmd(t, "run", "--config-dir", cfgDir, id); code != 0 {
		t.Fatalf("run after enable+approve exit %d: %s", code, errOut)
	}
}
