// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/recipes"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// DisableRecipe switches the routine off for every trigger; EnableRecipe
// returns it to approval-required and revokes its automation consent, so
// nothing dispatches until a person re-reviews.
func TestRecipeServiceDisableEnable(t *testing.T) {
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
	r, err := recipes.NewRecipe("Studio exports", time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []recipes.RecipeSource{{Path: root, Recursive: true}}
	r.Recipients = []recipes.RecipeRecipient{{DeviceID: devID, Label: "studio"}}
	r.Grant.ScopeHash = r.ScopeHash()
	if err := svc.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := svc.ApproveRecipe(r.ID); err != nil {
		t.Fatalf("ApproveRecipe: %v", err)
	}
	if _, err := svc.GrantAutomation(r.ID); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}

	// Disable: runs refuse with an actionable error.
	disabled, err := svc.DisableRecipe(r.ID)
	if err != nil {
		t.Fatalf("DisableRecipe: %v", err)
	}
	if disabled.Status != recipes.RecipeDisabled {
		t.Fatalf("status = %q, want disabled", disabled.Status)
	}
	if _, err := svc.RunRecipe(r.ID); err == nil {
		t.Fatal("run on disabled recipe accepted")
	} else if !strings.Contains(err.Error(), "disabled") || !strings.Contains(err.Error(), "enable") {
		t.Fatalf("disable error %q not actionable", err)
	}

	// Enable: approval-required, grant revoked — runs refuse until
	// a person re-approves.
	enabled, err := svc.EnableRecipe(r.ID)
	if err != nil {
		t.Fatalf("EnableRecipe: %v", err)
	}
	if enabled.Status != recipes.RecipeApprovalRequired {
		t.Fatalf("status = %q, want approval-required", enabled.Status)
	}
	if enabled.Grant.AutoSend {
		t.Fatal("enable must revoke the automation consent")
	}
	if _, err := svc.RunRecipe(r.ID); err == nil {
		t.Fatal("run after enable without re-approval accepted")
	}
	if _, err := svc.ApproveRecipe(r.ID); err != nil {
		t.Fatalf("ApproveRecipe after enable: %v", err)
	}
	if _, err := svc.RunRecipe(r.ID); err != nil {
		t.Fatalf("RunRecipe after re-approve: %v", err)
	}
}

// The local consent event renders the routine origin label (nil for
// ordinary one-off sends) so the UI can show where the transfer came
// from — never a blank or misleading line.
func TestProvenanceEvent(t *testing.T) {
	if got := provenanceEvent(nil); got != nil {
		t.Fatalf("nil provenance rendered as %+v, want nil", got)
	}
	got := provenanceEvent(&wire.Provenance{
		RoutineID:   "0123456789abcdef0123456789abcdef",
		RoutineName: "nightly backup",
		SenderLabel: "akshay-laptop",
		Trigger:     "watch",
	})
	if got["routineId"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("routineId = %v", got["routineId"])
	}
	if got["routineName"] != "nightly backup" || got["senderLabel"] != "akshay-laptop" || got["trigger"] != "watch" {
		t.Fatalf("event = %+v", got)
	}
	if got["display"] != "Routine: nightly backup (trigger: watch) from akshay-laptop" {
		t.Fatalf("display = %v", got["display"])
	}
}
