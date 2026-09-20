package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type onboardJSON struct {
	NewIdentity   bool   `json:"new_identity"`
	DeviceID      string `json:"device_id"`
	Fingerprint   string `json:"fingerprint"`
	ConfigDir     string `json:"config_dir"`
	PairedDevices int    `json:"paired_devices"`
	StateVersion  int    `json:"state_version"`
}

func runOnboardJSON(t *testing.T, cfgDir string, extra ...string) (int, onboardJSON) {
	t.Helper()
	args := append([]string{"--config-dir", cfgDir, "--json"}, extra...)
	var stdout, stderr bytes.Buffer
	code := runOnboard(args, &stdout, &stderr)
	var res onboardJSON
	if code == 0 {
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("onboard --json output not JSON: %v\n%s", err, stdout.String())
		}
	}
	return code, res
}

// TestOnboardCleanInstall is the clean-install proof: onboarding a fresh
// config dir creates the identity, runs v2.0 migrations, and reports itself
// as a new identity.
func TestOnboardCleanInstall(t *testing.T) {
	cfgDir := t.TempDir()
	// Point jobs state at the temp dir so the test never touches real state.
	t.Setenv("SENDBEAM_JOBS_DIR", filepath.Join(cfgDir, "jobs"))

	code, res := runOnboardJSON(t, cfgDir)
	if code != 0 {
		t.Fatalf("onboard exit code = %d, want 0", code)
	}
	if !res.NewIdentity {
		t.Error("new_identity = false on clean install, want true")
	}
	if res.DeviceID == "" || res.Fingerprint == "" {
		t.Error("onboard must report device_id and fingerprint")
	}
	if res.StateVersion != 2 {
		t.Errorf("state_version = %d, want 2", res.StateVersion)
	}
	// identity.key must exist with owner-only permissions.
	fi, err := os.Stat(filepath.Join(cfgDir, "identity.key"))
	if err != nil {
		t.Fatalf("identity.key not created: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("identity.key perms = %o, want 600", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "state-version.json")); err != nil {
		t.Errorf("state-version.json not written: %v", err)
	}
}

// TestOnboardExistingIdentityDoesNotRegenerate proves a second onboarding
// keeps the same identity instead of silently rotating it.
func TestOnboardExistingIdentityDoesNotRegenerate(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("SENDBEAM_JOBS_DIR", filepath.Join(cfgDir, "jobs"))

	code1, res1 := runOnboardJSON(t, cfgDir)
	code2, res2 := runOnboardJSON(t, cfgDir)
	if code1 != 0 || code2 != 0 {
		t.Fatalf("codes = %d, %d; want 0, 0", code1, code2)
	}
	if res2.NewIdentity {
		t.Error("second onboard reports new_identity = true, want false")
	}
	if res1.DeviceID != res2.DeviceID {
		t.Errorf("identity rotated: %q -> %q", res1.DeviceID, res2.DeviceID)
	}
}

// TestOnboardCorruptIdentityFailsClosed proves onboarding refuses to start
// with a corrupt identity file instead of silently generating a new one.
func TestOnboardCorruptIdentityFailsClosed(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("SENDBEAM_JOBS_DIR", filepath.Join(cfgDir, "jobs"))

	if code, _ := runOnboardJSON(t, cfgDir); code != 0 {
		t.Fatalf("first onboard exit = %d, want 0", code)
	}
	idPath := filepath.Join(cfgDir, "identity.key")
	corrupt := []byte("not-a-valid-identity")
	if err := os.WriteFile(idPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runOnboard([]string{"--config-dir", cfgDir, "--json"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("onboard with corrupt identity.key succeeded, want failure")
	}
	after, _ := os.ReadFile(idPath)
	if string(after) != string(corrupt) {
		t.Fatal("corrupt identity.key was replaced instead of failing closed")
	}
	if !strings.Contains(stderr.String(), "identity") {
		t.Errorf("stderr should explain the identity failure, got: %q", stderr.String())
	}
}

// TestOnboardHumanOutput is a smoke check that the default (non-JSON)
// onboarding prints actionable next steps.
func TestOnboardHumanOutput(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("SENDBEAM_JOBS_DIR", filepath.Join(cfgDir, "jobs"))

	var stdout, stderr bytes.Buffer
	code := runOnboard([]string{"--config-dir", cfgDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("onboard exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"pair", "listen", "send"} {
		if !strings.Contains(strings.ToLower(out), want) {
			t.Errorf("onboard output missing next-step %q:\n%s", want, out)
		}
	}
}
