// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package netpolicy

import (
	"errors"
	"strings"
	"testing"
)

// TestParseRejectsUnknownFailingClosed verifies the SB-R05 contract: an
// unknown stored policy returns an error AND the least-permissive policy
// (LocalOnly), so a caller that ignores the error can never silently run
// with the most permissive behavior.
func TestParseRejectsUnknownFailingClosed(t *testing.T) {
	p, err := Parse("mesh")
	if err == nil {
		t.Fatal("Parse(\"mesh\"): expected error, got nil")
	}
	var perr *PolicyParseError
	if !errors.As(err, &perr) {
		t.Fatalf("error type = %T, want *PolicyParseError", err)
	}
	if perr.Input != "mesh" {
		t.Fatalf("PolicyParseError.Input = %q, want mesh", perr.Input)
	}
	if p != LocalOnly {
		t.Fatalf("Parse(\"mesh\") policy = %v, want local-only (fail closed)", p)
	}
	// The empty string remains the documented Online alias.
	if p, err := Parse(""); err != nil || p != Online {
		t.Fatalf("Parse(\"\") = %v, %v; want online, nil", p, err)
	}
}

// TestPolicyParseErrorMessage verifies the error is actionable.
func TestPolicyParseErrorMessage(t *testing.T) {
	_, err := Parse("bogus")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{"bogus", "online", "prefer-local", "local-only"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message %q does not mention %q", msg, want)
		}
	}
}

// TestParseKnownValuesStillAccepted guards the happy path after the
// fail-closed change.
func TestParseKnownValuesStillAccepted(t *testing.T) {
	for in, want := range map[string]Policy{
		"online": Online, "automatic": Online,
		"prefer-local": PreferLocal, "prefer_local": PreferLocal,
		"local-only": LocalOnly, "local": LocalOnly,
	} {
		p, err := Parse(in)
		if err != nil || p != want {
			t.Errorf("Parse(%q) = %v, %v; want %v, nil", in, p, err, want)
		}
	}
}
