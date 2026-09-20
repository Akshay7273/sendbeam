// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sendbeam/engine/netpolicy"
)

func TestNetpolicyParse(t *testing.T) {
	cases := []struct {
		in   string
		want netpolicy.Policy
	}{
		{"online", netpolicy.Online},
		{"", netpolicy.Online},
		{"automatic", netpolicy.Online},
		{"prefer-local", netpolicy.PreferLocal},
		{"local-only", netpolicy.LocalOnly},
		{"local", netpolicy.LocalOnly},
	}
	for _, c := range cases {
		got, err := netpolicy.Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("Parse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := netpolicy.Parse("bogus"); err == nil {
		t.Fatal("expected error for bogus policy")
	}
}

func TestConfigSetAndGetPolicy(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	// Set to local-only.
	if rc := executeConfig([]string{"--set-network-policy", "local-only", "--config-dir", dir}, &stdout, &stderr); rc != 0 {
		t.Fatalf("set: rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "local-only") {
		t.Fatalf("set output: %s", stdout.String())
	}

	// Get shows the persisted value.
	stdout.Reset()
	stderr.Reset()
	if rc := executeConfig([]string{"--config-dir", dir}, &stdout, &stderr); rc != 0 {
		t.Fatalf("get: rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "network-policy: local-only") {
		t.Fatalf("get output: %s", stdout.String())
	}

	// Invalid policy rejected.
	stdout.Reset()
	stderr.Reset()
	if rc := executeConfig([]string{"--set-network-policy", "bogus", "--config-dir", dir}, &stdout, &stderr); rc == 0 {
		t.Fatal("expected non-zero for bogus policy")
	}
}

func TestPairLocalJoinRejectsBadInvitation(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	// The invitation arrives on stdin (it carries the pairing secret, so it
	// is never accepted as an argv argument).
	rc := executePairLocalJoinStdin([]string{"--config-dir", dir}, strings.NewReader("not-an-invitation"), &stdout, &stderr)
	if rc == 0 {
		t.Fatal("expected non-zero for bad invitation")
	}
	if !strings.Contains(stderr.String(), "invalid invitation") {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

// TestPairLocalJoinRejectsArgvInvitation verifies the invitation secret is
// never read from the command line (argv is visible to other processes).
func TestPairLocalJoinRejectsArgvInvitation(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	rc := executePairLocal([]string{"join", "--config-dir", dir, "not-an-invitation"}, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("expected non-zero for argv invitation")
	}
	if !strings.Contains(stderr.String(), "stdin") {
		t.Fatalf("expected stdin hint, stderr: %s", stderr.String())
	}
}

func TestPairLocalRequiresSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := executePairLocal([]string{}, &stdout, &stderr); rc != 2 {
		t.Fatalf("rc=%d, want 2", rc)
	}
}
