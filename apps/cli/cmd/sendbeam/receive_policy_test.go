// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runReceivePolicyCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runReceivePolicy(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// The routine auto-accept policy starts off, persists across processes,
// and is written with the config file locked to the owner's eyes.
func TestReceivePolicy_SetShowRoundTrip(t *testing.T) {
	cfgDir := t.TempDir()
	devID := "0123456789abcdef0123456789abcdef"

	code, _, stderr := runReceivePolicyCmd(t, "set", "--config-dir", cfgDir, "--enable", "--allow-device", devID)
	if code != 0 {
		t.Fatalf("set: code=%d stderr=%s", code, stderr)
	}
	// Fresh enable also allows routine transfers by default.
	code, out, stderr := runReceivePolicyCmd(t, "show", "--config-dir", cfgDir)
	if code != 0 {
		t.Fatalf("show: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(out, "on") || !strings.Contains(out, "Allow routine transfers: true") {
		t.Fatalf("show output missing enabled state: %q", out)
	}
	if !strings.Contains(out, devID) {
		t.Fatalf("show output missing allowlisted device: %q", out)
	}

	// JSON output carries the machine-readable fields.
	code, out, stderr = runReceivePolicyCmd(t, "show", "--config-dir", cfgDir, "--json")
	if code != 0 {
		t.Fatalf("show --json: code=%d stderr=%s", code, stderr)
	}
	var decoded struct {
		Enabled               bool     `json:"enabled"`
		AllowRoutineTransfers bool     `json:"allowRoutineTransfers"`
		AllowedDevices        []string `json:"allowedDevices"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if !decoded.Enabled || !decoded.AllowRoutineTransfers || len(decoded.AllowedDevices) != 1 || decoded.AllowedDevices[0] != devID {
		t.Fatalf("json policy = %+v", decoded)
	}

	// The config file must be owner-only (0600).
	fi, err := os.Stat(filepath.Join(cfgDir, cliConfigFileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config perms = %o, want 0600", fi.Mode().Perm())
	}

	// Disable turns it off again.
	code, _, stderr = runReceivePolicyCmd(t, "set", "--config-dir", cfgDir, "--disable")
	if code != 0 {
		t.Fatalf("disable: code=%d stderr=%s", code, stderr)
	}
	if p := effectiveAutoAcceptPolicy(cfgDir); p.Enabled {
		t.Fatal("policy still enabled after --disable")
	}
}

// Setting the policy on a brand-new config dir creates the dir first.
func TestReceivePolicy_SetCreatesConfigDir(t *testing.T) {
	cfgDir := filepath.Join(t.TempDir(), "nested", "config")
	code, _, stderr := runReceivePolicyCmd(t, "set", "--config-dir", cfgDir, "--enable",
		"--allow-device", "0123456789abcdef0123456789abcdef")
	if code != 0 {
		t.Fatalf("set on fresh dir: code=%d stderr=%s", code, stderr)
	}
	if p := effectiveAutoAcceptPolicy(cfgDir); !p.Enabled {
		t.Fatal("policy not persisted on fresh dir")
	}
}

// A stored policy that fails validation is treated as absent — the
// receiver fails closed rather than trusting a malformed allowlist.
func TestReceivePolicy_MalformedStoredFailsClosed(t *testing.T) {
	cfgDir := t.TempDir()
	// Hand-write a config whose allowlist carries an empty entry — the
	// stored policy fails validation and must be treated as absent.
	data := `{"auto_accept_policy":{"enabled":true,"allowRoutineTransfers":true,"allowedDevices":[""]}}`
	if err := os.WriteFile(filepath.Join(cfgDir, cliConfigFileName), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := effectiveAutoAcceptPolicy(cfgDir); p.Enabled || len(p.AllowedDevices) != 0 {
		t.Fatalf("malformed stored policy not failed closed: %+v", p)
	}
}
