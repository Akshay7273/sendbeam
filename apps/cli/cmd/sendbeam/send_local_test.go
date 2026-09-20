// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunLocalOnlySendRejectsNonLocalPolicy verifies the local-only send
// path refuses to run unless the persisted network policy is local-only —
// it must never silently fall back to the online path.
func TestRunLocalOnlySendRejectsNonLocalPolicy(t *testing.T) {
	dir := t.TempDir()
	env, err := InitCLIEnvironment(dir)
	if err != nil {
		t.Fatalf("InitCLIEnvironment: %v", err)
	}
	var stdout, stderr bytes.Buffer
	// Default policy is online: the local-only send must refuse.
	rc := runLocalOnlySend(env, []string{"/tmp/nonexistent-file"}, handoffPayload{}, "device-1", "192.168.1.9:53317", false, false, false, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("runLocalOnlySend should fail when policy is not local-only")
	}
	if !strings.Contains(stderr.String(), "local-only") {
		t.Fatalf("expected local-only policy error, stderr=%q", stderr.String())
	}
}

// TestRunLocalOnlySendRejectsHandoffs verifies text/link handoffs are
// rejected on the local-only path in this release.
func TestRunLocalOnlySendRejectsHandoffs(t *testing.T) {
	dir := t.TempDir()
	var cfgOut, cfgErr bytes.Buffer
	if rc := executeConfig([]string{"--set-network-policy", "local-only", "--config-dir", dir}, &cfgOut, &cfgErr); rc != 0 {
		t.Fatalf("set policy: rc=%d stderr=%s", rc, cfgErr.String())
	}
	env, err := InitCLIEnvironment(dir)
	if err != nil {
		t.Fatalf("InitCLIEnvironment: %v", err)
	}
	var stdout, stderr bytes.Buffer
	rc := runLocalOnlySend(env, nil, handoffPayload{Kind: "text", Text: "hello"}, "device-1", "192.168.1.9:53317", false, false, false, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("runLocalOnlySend should reject handoffs")
	}
	if !strings.Contains(stderr.String(), "not supported") {
		t.Fatalf("expected handoff rejection, stderr=%q", stderr.String())
	}
}

// TestRunLocalOnlySendRequiresTarget verifies the target device and peer
// address are mandatory (no silent broadcast, no default peer).
func TestRunLocalOnlySendRequiresTarget(t *testing.T) {
	dir := t.TempDir()
	var cfgOut, cfgErr bytes.Buffer
	if rc := executeConfig([]string{"--set-network-policy", "local-only", "--config-dir", dir}, &cfgOut, &cfgErr); rc != 0 {
		t.Fatalf("set policy: rc=%d stderr=%s", rc, cfgErr.String())
	}
	env, err := InitCLIEnvironment(dir)
	if err != nil {
		t.Fatalf("InitCLIEnvironment: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if rc := runLocalOnlySend(env, []string{"/tmp/x"}, handoffPayload{}, "", "192.168.1.9:53317", false, false, false, &stdout, &stderr); rc == 0 {
		t.Fatal("missing --to device should fail")
	}
	stdout.Reset()
	stderr.Reset()
	if rc := runLocalOnlySend(env, []string{"/tmp/x"}, handoffPayload{}, "device-1", "", false, false, false, &stdout, &stderr); rc == 0 {
		t.Fatal("missing --peer-addr should fail")
	}
	if !strings.Contains(stderr.String(), "--peer-addr") {
		t.Fatalf("expected --peer-addr error, stderr=%q", stderr.String())
	}
}
