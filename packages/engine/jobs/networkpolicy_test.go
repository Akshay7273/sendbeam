// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package jobs

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/sendbeam/engine/netpolicy"
)

// TestNetworkPolicyValidation verifies V21-PR07 job policy binding: empty
// means Online, known policies are accepted, unknown values fail closed.
func TestNetworkPolicyValidation(t *testing.T) {
	now := time.Now().UTC()
	mk := func(np string) Job {
		j, err := NewJob("abcdef0123456789abcdef0123456789",
			[]JobFile{{Name: "a.txt", Size: 1, Digest: "aa"}},
			[]RecipientAttempt{{DeviceID: "dev1", Status: AttemptQueued}},
			DefaultRetryPolicy(), now)
		if err != nil {
			t.Fatalf("NewJob: %v", err)
		}
		j.NetworkPolicy = np
		return j
	}
	for _, np := range []string{"", "online", "prefer-local", "local-only"} {
		if err := ValidateJob(mk(np)); err != nil {
			t.Errorf("ValidateJob(%q): unexpected error: %v", np, err)
		}
	}
	if err := ValidateJob(mk("mesh")); err == nil {
		t.Error("ValidateJob(\"mesh\"): expected error, got nil")
	}
}

// TestEffectiveNetworkPolicyDefaultsOnline proves pre-V21-PR07 jobs (no
// stored policy) keep v2.0 semantics.
func TestEffectiveNetworkPolicyDefaultsOnline(t *testing.T) {
	var j Job
	if got := j.EffectiveNetworkPolicy(); got != netpolicy.Online {
		t.Errorf("zero Job: got %v, want online", got)
	}
	j.NetworkPolicy = "local-only"
	if got := j.EffectiveNetworkPolicy(); got != netpolicy.LocalOnly {
		t.Errorf("local-only Job: got %v, want local-only", got)
	}
}

// TestLegacyJobWithoutNetworkPolicyDecodes verifies checksum stability:
// a job encoded before the networkPolicy field existed (field absent)
// still decodes and verifies under the new code.
func TestLegacyJobWithoutNetworkPolicyDecodes(t *testing.T) {
	now := time.Now().UTC()
	j, err := NewJob("abcdef0123456789abcdef0123456789",
		[]JobFile{{Name: "a.txt", Size: 1, Digest: "aa"}},
		[]RecipientAttempt{{DeviceID: "dev1", Status: AttemptQueued}},
		DefaultRetryPolicy(), now)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	// Encode with the field explicitly absent, as v2.0 wrote it.
	j.NetworkPolicy = ""
	raw, err := encodeJob(j)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := decodeJob(raw)
	if err != nil {
		t.Fatalf("decodeJob(legacy encoding): %v", err)
	}
	if dec.EffectiveNetworkPolicy() != netpolicy.Online {
		t.Errorf("legacy job: effective policy = %v, want online", dec.EffectiveNetworkPolicy())
	}
}

// TestNetworkPolicyTamperFailsClosed proves the checksum covers the bound
// policy: flipping networkPolicy in the stored file quarantines the job
// instead of silently re-binding it to a weaker path.
func TestNetworkPolicyTamperFailsClosed(t *testing.T) {
	s := openTestStore(t)
	j := mustJob(t)
	j.NetworkPolicy = "local-only"
	j.Status = JobQueued
	if err := s.Save(j); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(s.Path(j.JobID))
	if err != nil {
		t.Fatalf("read job file: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"networkPolicy":"local-only"`), []byte(`"networkPolicy":"online"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: expected the canonical encoding to contain the policy field")
	}
	if err := os.WriteFile(s.Path(j.JobID), tampered, 0600); err != nil {
		t.Fatalf("write tampered job: %v", err)
	}
	if _, _, err := s.Load(j.JobID); err == nil {
		t.Fatal("tampered job must be quarantined (load must fail)")
	}
}
