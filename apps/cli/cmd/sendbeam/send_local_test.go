// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sendbeam/engine/netpolicy"
)

// TestRunLocalOnlySendRejectsNonLocalPolicy verifies the local-only send
// path refuses to run when the caller's effective policy is not local-only
// — it must never silently fall back to the online path. (V21-PR07 moved
// policy resolution to the dispatcher; the path takes the resolved policy
// as a parameter and re-verifies it.)
func TestRunLocalOnlySendRejectsNonLocalPolicy(t *testing.T) {
	dir := t.TempDir()
	env, err := InitCLIEnvironment(dir)
	if err != nil {
		t.Fatalf("InitCLIEnvironment: %v", err)
	}
	var stdout, stderr bytes.Buffer
	// Effective policy is online: the local-only send must refuse, even
	// with an otherwise valid request shape.
	rc := runLocalOnlySend(env, []string{"/tmp/nonexistent-file"}, handoffPayload{}, "device-1", "192.168.1.9:53317", false, false, false, netpolicy.Online, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("runLocalOnlySend should fail when policy is not local-only")
	}
	if !strings.Contains(stderr.String(), "refusing to fall back to online") {
		t.Fatalf("expected no-fallback error, stderr=%q", stderr.String())
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
	rc := runLocalOnlySend(env, nil, handoffPayload{Kind: "text", Text: "hello"}, "device-1", "192.168.1.9:53317", false, false, false, netpolicy.LocalOnly, &stdout, &stderr)
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
	if rc := runLocalOnlySend(env, []string{"/tmp/x"}, handoffPayload{}, "", "192.168.1.9:53317", false, false, false, netpolicy.LocalOnly, &stdout, &stderr); rc == 0 {
		t.Fatal("missing --to device should fail")
	}
	stdout.Reset()
	stderr.Reset()
	if rc := runLocalOnlySend(env, []string{"/tmp/x"}, handoffPayload{}, "device-1", "", false, false, false, netpolicy.LocalOnly, &stdout, &stderr); rc == 0 {
		t.Fatal("missing --peer-addr should fail")
	}
	if !strings.Contains(stderr.String(), "--peer-addr") {
		t.Fatalf("expected --peer-addr error, stderr=%q", stderr.String())
	}
}
