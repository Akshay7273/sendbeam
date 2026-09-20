// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

var testNow = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

// testDeviceIDs generates n valid device identities for fixtures.
func testDeviceIDs(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id, err := wire.GenerateDeviceIdentity()
		if err != nil {
			t.Fatalf("GenerateDeviceIdentity: %v", err)
		}
		out = append(out, id.DeviceID)
	}
	return out
}

// validRecipe returns a structurally valid recipe with one source and one
// recipient, ready to save.
func validRecipe(t *testing.T, deviceID string) Recipe {
	t.Helper()
	r, err := NewRecipe("Nightly exports", testNow)
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	r.Sources = []RecipeSource{{Path: "/data/exports", Recursive: true}}
	r.Recipients = []RecipeRecipient{{DeviceID: deviceID, Label: "Studio laptop"}}
	r.NetworkPolicy = "prefer-local"
	r.Include = []string{"*.mp4"}
	r.Grant.ScopeHash = r.ScopeHash()
	if err := ValidateRecipe(r); err != nil {
		t.Fatalf("ValidateRecipe(fixture): %v", err)
	}
	return r
}

// approveGrant simulates an explicit user approval of auto-send on r.
func approveGrant(r *Recipe) {
	r.Grant = RecipeGrant{
		AutoSend:       true,
		ConsentVersion: r.Grant.ConsentVersion + 1,
		GrantedAt:      testNow,
		ScopeHash:      r.ScopeHash(),
	}
}

func openTestStore(t *testing.T) *RecipeStore {
	t.Helper()
	s, err := OpenRecipeStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenRecipeStore: %v", err)
	}
	return s
}

func TestNewRecipeDefaults(t *testing.T) {
	r, err := NewRecipe("Demo", testNow)
	if err != nil {
		t.Fatalf("NewRecipe: %v", err)
	}
	if r.SchemaVersion != RecipeSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", r.SchemaVersion, RecipeSchemaVersion)
	}
	if !isLowerHex32(r.ID) {
		t.Errorf("ID = %q, want 32 lowercase hex", r.ID)
	}
	if r.Status != RecipeApprovalRequired {
		t.Errorf("Status = %q, want %q (new recipes must never auto-run)", r.Status, RecipeApprovalRequired)
	}
	if r.Grant.AutoSend {
		t.Errorf("new recipe must not have AutoSend granted")
	}
	if !r.Grant.GrantedAt.IsZero() {
		t.Errorf("new recipe must have zero GrantedAt")
	}
	if r.Trigger.Kind != TriggerManual {
		t.Errorf("Trigger.Kind = %q, want manual", r.Trigger.Kind)
	}
	b := DefaultBudgets()
	if r.Budgets != b {
		t.Errorf("Budgets = %+v, want defaults %+v", r.Budgets, b)
	}
	if r.Grant.ScopeHash != r.ScopeHash() {
		t.Errorf("new recipe grant ScopeHash does not match ScopeHash()")
	}
	if _, err := NewRecipe("  ", testNow); err == nil {
		t.Errorf("NewRecipe with empty name must fail")
	}
}

func TestDefaultBudgetsSane(t *testing.T) {
	b := DefaultBudgets()
	if b.MaxBytesPerRun <= 0 || b.MaxFilesPerRun <= 0 || b.MaxConcurrentRuns <= 0 {
		t.Errorf("DefaultBudgets must be all > 0, got %+v", b)
	}
}

func TestScopeHashOrderIndependent(t *testing.T) {
	devs := testDeviceIDs(t, 2)
	a := validRecipe(t, devs[0])
	b := validRecipe(t, devs[0])
	// Same scope, different order / different name / different status.
	b.Sources = []RecipeSource{{Path: "/data/exports", Recursive: true}}
	b.Name = "Renamed"
	b.Status = RecipeManual
	if a.ScopeHash() != b.ScopeHash() {
		t.Errorf("ScopeHash differs for identical material scope")
	}
	c := validRecipe(t, devs[0])
	c.Sources = []RecipeSource{
		{Path: "/data/exports", Recursive: true},
		{Path: "/data/other", Recursive: false},
	}
	if c.ScopeHash() == a.ScopeHash() {
		t.Errorf("ScopeHash unchanged after widening sources")
	}
	d := validRecipe(t, devs[1])
	if d.ScopeHash() == a.ScopeHash() {
		t.Errorf("ScopeHash unchanged after changing recipient")
	}
}

func TestApplyUpdateMaterialChangesRevokeGrant(t *testing.T) {
	devs := testDeviceIDs(t, 2)

	material := []struct {
		name   string
		mutate func(*Recipe)
	}{
		{"add recipient", func(u *Recipe) {
			u.Recipients = append(u.Recipients, RecipeRecipient{DeviceID: devs[1], Label: "Spare"})
		}},
		{"widen source", func(u *Recipe) {
			u.Sources = append(u.Sources, RecipeSource{Path: "/data/more", Recursive: true})
		}},
		{"loosen budget", func(u *Recipe) {
			u.Budgets.MaxBytesPerRun *= 10
		}},
		{"tighten budget", func(u *Recipe) {
			u.Budgets.MaxBytesPerRun /= 2
		}},
		{"change network policy", func(u *Recipe) {
			u.NetworkPolicy = "local-only"
		}},
		{"change trigger kind", func(u *Recipe) {
			u.Trigger.Kind = TriggerWatch
		}},
		{"toggle padding", func(u *Recipe) {
			u.RequirePadding = !u.RequirePadding
		}},
		{"change filters", func(u *Recipe) {
			u.Exclude = []string{"*.tmp"}
		}},
		{"set expiry", func(u *Recipe) {
			u.ExpiresAt = testNow.Add(24 * time.Hour)
		}},
	}
	for _, tc := range material {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			r := validRecipe(t, devs[0])
			approveGrant(&r)
			if err := s.Save(r); err != nil {
				t.Fatalf("Save: %v", err)
			}
			stored, ok, err := s.Load(r.ID)
			if err != nil || !ok {
				t.Fatalf("Load: %v %v", ok, err)
			}
			if !stored.Grant.AutoSend {
				t.Fatalf("precondition: stored grant should be active")
			}
			updated := stored
			tc.mutate(&updated)
			// Grant smuggling: even if the caller forges a fully valid
			// grant for the NEW scope (matching scope hash, fresh
			// timestamp), a material change must still revoke it —
			// ApplyUpdate ignores caller-supplied grant fields.
			updated.Grant = RecipeGrant{
				AutoSend:       true,
				ConsentVersion: 99,
				GrantedAt:      testNow,
				ScopeHash:      updated.ScopeHash(),
			}
			got, err := ApplyUpdate(s, updated)
			if err != nil {
				t.Fatalf("ApplyUpdate: %v", err)
			}
			if got.Grant.AutoSend {
				t.Errorf("material change %q did not revoke AutoSend", tc.name)
			}
			if !got.Grant.GrantedAt.IsZero() {
				t.Errorf("material change %q did not zero GrantedAt", tc.name)
			}
			if got.Grant.ConsentVersion != stored.Grant.ConsentVersion+1 {
				t.Errorf("ConsentVersion = %d, want %d (bump on revocation)",
					got.Grant.ConsentVersion, stored.Grant.ConsentVersion+1)
			}
			if got.Status != RecipeApprovalRequired {
				t.Errorf("Status = %q, want approval-required after material change", got.Status)
			}
			if got.Grant.ScopeHash != got.ScopeHash() {
				t.Errorf("grant ScopeHash not refreshed to current scope")
			}
			// Grant smuggling: a caller cannot re-enable AutoSend through
			// the edit path without a matching scope hash.
			if err := ValidateRecipe(got); err != nil {
				t.Fatalf("stored recipe invalid after ApplyUpdate: %v", err)
			}
		})
	}
}

func TestApplyUpdateNonMaterialPreservesGrant(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	s := openTestStore(t)
	r := validRecipe(t, devs[0])
	approveGrant(&r)
	if err := s.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	stored, _, _ := s.Load(r.ID)

	updated := stored
	updated.Name = "Renamed exports"
	got, err := ApplyUpdate(s, updated)
	if err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if !got.Grant.AutoSend {
		t.Errorf("rename must not revoke AutoSend")
	}
	if got.Grant.ConsentVersion != stored.Grant.ConsentVersion {
		t.Errorf("rename must not bump ConsentVersion")
	}
	if !got.Grant.GrantedAt.Equal(stored.Grant.GrantedAt) {
		t.Errorf("rename must preserve GrantedAt")
	}
	if got.Name != "Renamed exports" {
		t.Errorf("rename not applied")
	}
	if got.Status != stored.Status {
		t.Errorf("rename changed status %q -> %q", stored.Status, got.Status)
	}
}

func TestApplyUpdateDisabledStaysDisabled(t *testing.T) {
	devs := testDeviceIDs(t, 2)
	s := openTestStore(t)
	r := validRecipe(t, devs[0])
	r.Status = RecipeDisabled
	if err := s.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	stored, _, _ := s.Load(r.ID)
	updated := stored
	updated.Sources = append(updated.Sources, RecipeSource{Path: "/data/more"})
	got, err := ApplyUpdate(s, updated)
	if err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	// Documented deviation from the bare "force approval-required" rule: a
	// recipe the user explicitly disabled must never be broadened by a
	// material change.
	if got.Status != RecipeDisabled {
		t.Errorf("Status = %q, want disabled (a material change must never broaden an explicitly disabled recipe)", got.Status)
	}
	if got.Grant.AutoSend {
		t.Errorf("AutoSend must stay off")
	}
}

func TestApplyUpdateUnknownRecipe(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	s := openTestStore(t)
	r := validRecipe(t, devs[0])
	if _, err := ApplyUpdate(s, r); err == nil {
		t.Errorf("ApplyUpdate on unknown recipe must fail")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	s := openTestStore(t)
	r := validRecipe(t, devs[0])
	if err := s.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// 0600 permissions.
	fi, err := os.Stat(s.Path(r.ID))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("recipe file mode = %o, want 600", fi.Mode().Perm())
	}
	got, ok, err := s.Load(r.ID)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", ok, err)
	}
	if got.Name != r.Name || got.Checksum == "" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != r.ID || entries[0].Name != r.Name {
		t.Errorf("List = %+v, want the one saved recipe", entries)
	}
	q, err := s.Quarantined()
	if err != nil {
		t.Fatalf("Quarantined: %v", err)
	}
	if len(q) != 0 {
		t.Errorf("Quarantined = %+v, want empty", q)
	}
	if err := s.Delete(r.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, err := s.Load(r.ID); err != nil || ok {
		t.Errorf("Load after Delete: ok=%v err=%v, want not found", ok, err)
	}
	if err := s.Delete(r.ID); err != nil {
		t.Errorf("Delete must be idempotent: %v", err)
	}
	if err := s.Save(r); err != nil {
		t.Fatalf("re-Save: %v", err)
	}
	if err := s.Save(Recipe{}); err == nil {
		t.Errorf("Save of invalid recipe must fail")
	}
}

func TestRecipeStoreDirEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENDBEAM_RECIPES_DIR", dir)
	got, err := RecipeStoreDir()
	if err != nil {
		t.Fatalf("RecipeStoreDir: %v", err)
	}
	abs, _ := filepath.Abs(dir)
	if got != abs {
		t.Errorf("RecipeStoreDir = %q, want %q", got, abs)
	}
	s, err := OpenRecipeStore(got)
	if err != nil {
		t.Fatalf("OpenRecipeStore: %v", err)
	}
	if s.Dir() != abs {
		t.Errorf("store dir = %q, want %q", s.Dir(), abs)
	}
}

func TestUnknownSchemaVersionQuarantined(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	s := openTestStore(t)
	r := validRecipe(t, devs[0])
	data, err := Export(r)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	// Bump only the version; the peek must reject it before the checksum
	// check could misreport it as tampering.
	bad := strings.Replace(string(data), `"schemaVersion":1`, `"schemaVersion":99`, 1)
	if bad == string(data) {
		t.Fatalf("could not rewrite schema version in fixture")
	}
	path := s.Path(r.ID)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := s.Load(r.ID); err == nil {
		t.Errorf("Load of unknown schema version: want failure, got nil error")
	} else if !strings.Contains(err.Error(), "schema version 99") {
		t.Errorf("Load error = %q, want it to name schema version 99", err)
	}
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List must not include quarantined recipes, got %+v", entries)
	}
	q, err := s.Quarantined()
	if err != nil {
		t.Fatalf("Quarantined: %v", err)
	}
	if len(q) != 1 {
		t.Fatalf("Quarantined = %+v, want exactly one entry", q)
	}
	if q[0].Path != path {
		t.Errorf("quarantine path = %q, want %q", q[0].Path, path)
	}
	if !strings.Contains(q[0].Reason, "schema version 99") {
		t.Errorf("quarantine reason = %q, want it to name schema version 99", q[0].Reason)
	}
	// Never deleted.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("quarantined file must not be deleted: %v", err)
	}
}

func TestCorruptJSONQuarantined(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	s := openTestStore(t)
	r := validRecipe(t, devs[0])
	path := s.Path(r.ID)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	q, err := s.Quarantined()
	if err != nil {
		t.Fatalf("Quarantined: %v", err)
	}
	if len(q) != 1 || !strings.Contains(q[0].Reason, "malformed") {
		t.Errorf("Quarantined = %+v, want one malformed entry", q)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("corrupt file must not be deleted: %v", err)
	}
	// A bad file never hides the good ones.
	r2 := validRecipe(t, devs[0])
	if err := s.Save(r2); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != r2.ID {
		t.Errorf("List = %+v, want only the good recipe", entries)
	}
}

func TestChecksumTamperFails(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	r := validRecipe(t, devs[0])
	data, err := Export(r)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	tampered := strings.Replace(string(data), "Studio laptop", "Studio laptob", 1)
	if tampered == string(data) {
		t.Fatalf("could not tamper fixture")
	}
	if _, err := decodeRecipe([]byte(tampered)); err == nil {
		t.Errorf("decodeRecipe accepted tampered bytes")
	} else if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("tamper error = %q, want checksum mismatch", err)
	}
	if _, err := Import([]byte(tampered)); err == nil {
		t.Errorf("Import accepted tampered bytes")
	}
}

func TestValidateRecipients(t *testing.T) {
	ctx := context.Background()
	ts := trust.NewMemoryTrustStore()

	// GenerateDeviceIdentity gives (DeviceID, public key) pairs where the id
	// is derived from the key, which TrustRecord.Validate requires — so
	// records must be built from fresh identities, not arbitrary ids.
	ids := make([]struct {
		deviceID string
		pubHex   string
	}, 0, 3)
	for i := 0; i < 3; i++ {
		gen, err := wire.GenerateDeviceIdentity()
		if err != nil {
			t.Fatalf("GenerateDeviceIdentity: %v", err)
		}
		ids = append(ids, struct {
			deviceID string
			pubHex   string
		}{gen.DeviceID, gen.PublicKeyHex()})
	}
	addDevice := func(i int, label string) {
		rec := &wire.TrustRecord{
			DeviceID:          ids[i].deviceID,
			PublicKey:         ids[i].pubHex,
			LocalLabel:        label,
			PairCredentialRef: "cred-test",
			FirstSeenAt:       testNow,
			LastSeenAt:        testNow,
			Policy:            wire.DefaultTrustPolicy(),
		}
		if err := ts.AddOrUpdateDevice(ctx, rec); err != nil {
			t.Fatalf("AddOrUpdateDevice: %v", err)
		}
	}
	addDevice(0, "Studio laptop")
	addDevice(1, "Phone")

	recipeWith := func(deviceIDs ...string) Recipe {
		r := validRecipe(t, ids[0].deviceID)
		r.Recipients = nil
		for _, d := range deviceIDs {
			r.Recipients = append(r.Recipients, RecipeRecipient{DeviceID: d, Label: "dev"})
		}
		r.Grant.ScopeHash = r.ScopeHash()
		return r
	}

	if err := ValidateRecipients(ctx, ts, recipeWith(ids[0].deviceID, ids[1].deviceID)); err != nil {
		t.Errorf("trusted recipients rejected: %v", err)
	}
	// Unknown (never paired) device.
	err := ValidateRecipients(ctx, ts, recipeWith(ids[0].deviceID, ids[2].deviceID))
	if err == nil {
		t.Errorf("untrusted recipient accepted")
	} else if !strings.Contains(err.Error(), ids[2].deviceID) {
		t.Errorf("error %q does not name the untrusted device", err)
	}
	// Revoked device.
	if err := ts.RevokeDevice(ctx, ids[1].deviceID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	err = ValidateRecipients(ctx, ts, recipeWith(ids[0].deviceID, ids[1].deviceID))
	if err == nil {
		t.Errorf("revoked recipient accepted")
	} else if !strings.Contains(err.Error(), ids[1].deviceID) {
		t.Errorf("error %q does not name the revoked device", err)
	}
}

func TestImportExportSecretFreeRoundTrip(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	r := validRecipe(t, devs[0])
	// Tricky labels: words that naive secret-scanners flag must survive as
	// plain labels, while no actual secret keys may exist.
	r.Recipients = []RecipeRecipient{
		{DeviceID: devs[0], Label: "studio secret token admin"},
	}
	r.Name = "password vault privateKey seed backup"
	r.Grant.ScopeHash = r.ScopeHash()
	approveGrant(&r)

	data, err := Export(r)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal export: %v", err)
	}
	var keys, vals []string
	var walk func(x any)
	walk = func(x any) {
		switch n := x.(type) {
		case map[string]any:
			for k, vv := range n {
				keys = append(keys, k)
				walk(vv)
			}
		case []any:
			for _, e := range n {
				walk(e)
			}
		case string:
			vals = append(vals, n)
		}
	}
	walk(v)

	bannedKey := []string{"secret", "token", "password", "privatekey", "seed"}
	for _, k := range keys {
		lk := strings.ToLower(k)
		for _, b := range bannedKey {
			if strings.Contains(lk, b) {
				t.Errorf("export contains suspicious key %q", k)
			}
		}
	}
	hexBlob := regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)
	// The allowed blobs are the sealed recipe's own integrity fields —
	// take them from the decoded export, not the pre-export value (whose
	// Checksum is not yet computed).
	sealed, err := decodeRecipe(data)
	if err != nil {
		t.Fatalf("decodeRecipe(export): %v", err)
	}
	allowed := map[string]bool{sealed.ID: true, sealed.Checksum: true, sealed.Grant.ScopeHash: true}
	for _, s := range vals {
		if hexBlob.MatchString(s) && !allowed[s] {
			t.Errorf("export contains unexplained hex/blob value %q", s)
		}
	}
	// Labels survive verbatim as plain labels.
	joined := strings.Join(vals, "\n")
	if !strings.Contains(joined, "studio secret token admin") {
		t.Errorf("recipient label did not survive export as a plain label")
	}
	if !strings.Contains(joined, "password vault privateKey seed backup") {
		t.Errorf("recipe name did not survive export as a plain label")
	}

	// Import: never runs automatically.
	imp, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imp.Status != RecipeDisabled {
		t.Errorf("imported Status = %q, want disabled", imp.Status)
	}
	if imp.Grant.AutoSend {
		t.Errorf("imported recipe must not have AutoSend")
	}
	if !imp.Grant.GrantedAt.IsZero() {
		t.Errorf("imported recipe must have zero GrantedAt")
	}
	if imp.ID != r.ID {
		t.Errorf("imported ID = %q, want preserved %q", imp.ID, r.ID)
	}
	if err := ValidateRecipe(imp); err != nil {
		t.Errorf("imported recipe invalid: %v", err)
	}
	// Re-export is stable and still secret-free.
	data2, err := Export(imp)
	if err != nil {
		t.Fatalf("re-Export: %v", err)
	}
	if _, err := Import(data2); err != nil {
		t.Errorf("second import failed: %v", err)
	}
}

func TestPreview(t *testing.T) {
	devs := testDeviceIDs(t, 1)
	r := validRecipe(t, devs[0])
	r.RequirePadding = true
	r.Exclude = []string{"*.tmp"}
	r.ExpiresAt = testNow.Add(48 * time.Hour)
	r.Grant.ScopeHash = r.ScopeHash()
	approveGrant(&r)
	// Preview what the store would actually hand back (sealed record).
	data, err := Export(r)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	sealed, err := decodeRecipe(data)
	if err != nil {
		t.Fatalf("decodeRecipe: %v", err)
	}

	out := Preview(sealed)
	for _, want := range []string{
		"/data/exports",
		"Studio laptop",
		devs[0],
		"prefer-local",
		"manual",
		"*.mp4",
		"*.tmp",
		"strict", // padding
		"auto-send ENABLED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("preview missing %q:\n%s", want, out)
		}
	}
	// Budget numbers are shown.
	if !strings.Contains(out, "10000") {
		t.Errorf("preview missing budget numbers:\n%s", out)
	}
	// No raw hashes leak into the human-readable preview: the recipe id and
	// device ids are operational identifiers shown intentionally, but the
	// checksum and grant scope hash must never appear.
	if sealed.Checksum != "" && strings.Contains(out, sealed.Checksum) {
		t.Errorf("preview leaks checksum material:\n%s", out)
	}
	if strings.Contains(out, sealed.Grant.ScopeHash) {
		t.Errorf("preview leaks scope-hash material:\n%s", out)
	}
	// A disabled, never-approved recipe previews honestly.
	r2 := validRecipe(t, devs[0])
	r2.Status = RecipeDisabled
	out2 := Preview(r2)
	if !strings.Contains(out2, "manual runs only") {
		t.Errorf("disabled preview missing grant state:\n%s", out2)
	}
}

func TestValidateRecipeRejects(t *testing.T) {
	devs := testDeviceIDs(t, 2)
	base := func() Recipe { return validRecipe(t, devs[0]) }
	cases := []struct {
		name   string
		mutate func(*Recipe)
	}{
		{"bad status", func(r *Recipe) { r.Status = "flying" }},
		{"relative source", func(r *Recipe) { r.Sources[0].Path = "data/exports" }},
		{"unclean source", func(r *Recipe) { r.Sources[0].Path = "/data/../data/exports" }},
		{"empty sources", func(r *Recipe) { r.Sources = nil }},
		{"empty recipients", func(r *Recipe) { r.Recipients = nil }},
		{"bad device id", func(r *Recipe) { r.Recipients[0].DeviceID = "nope" }},
		{"empty label", func(r *Recipe) { r.Recipients[0].Label = " " }},
		{"duplicate recipient", func(r *Recipe) {
			r.Recipients = append(r.Recipients, r.Recipients[0])
		}},
		{"bad network policy", func(r *Recipe) { r.NetworkPolicy = "carrier-pigeon" }},
		{"bad trigger kind", func(r *Recipe) { r.Trigger.Kind = "cron" }},
		{"non-empty watch map", func(r *Recipe) {
			r.Trigger.Kind = TriggerWatch
			r.Trigger.Watch = map[string]any{"debounceMs": 500}
		}},
		{"non-empty schedule map", func(r *Recipe) {
			r.Trigger.Kind = TriggerSchedule
			r.Trigger.Schedule = map[string]any{"every": "1h"}
		}},
		{"zero budgets", func(r *Recipe) { r.Budgets = RecipeBudgets{} }},
		{"negative budget", func(r *Recipe) { r.Budgets.MaxFilesPerRun = -5 }},
		{"autosend without grantedAt", func(r *Recipe) {
			r.Grant = RecipeGrant{AutoSend: true, ConsentVersion: 1, ScopeHash: r.ScopeHash()}
		}},
		{"autosend with stale scope", func(r *Recipe) {
			r.Grant = RecipeGrant{AutoSend: true, ConsentVersion: 1, GrantedAt: testNow, ScopeHash: "00"}
		}},
		{"bad schema version", func(r *Recipe) { r.SchemaVersion = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.mutate(&r)
			if err := ValidateRecipe(r); err == nil {
				t.Errorf("ValidateRecipe accepted %s", tc.name)
			}
		})
	}
	// Empty watch/schedule maps are fine (watch/schedule kinds reserved).
	r := base()
	r.Trigger.Kind = TriggerSchedule
	if err := ValidateRecipe(r); err != nil {
		t.Errorf("empty reserved schedule map must validate: %v", err)
	}
	// Strict decode rejects unknown fields.
	data, err := Export(base())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	withExtra := strings.Replace(string(data), `"checksum"`, `"checksum","smuggled":1`, 1)
	if _, err := decodeRecipe([]byte(withExtra)); err == nil {
		t.Errorf("decodeRecipe accepted unknown field")
	}
}

func TestImportRejectsGarbage(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(""),
		[]byte("{]"),
		[]byte(`{"schemaVersion":1}`),
	} {
		if _, err := Import(data); err == nil {
			t.Errorf("Import accepted %q", data)
		}
	}
}
