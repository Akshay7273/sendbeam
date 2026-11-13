// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package netpolicy

import (
	"strings"
	"testing"
)

// TestResolveEffectiveNilLookupFailsClosed: an engine component without a
// wired policy lookup must never assume the most permissive policy.
func TestResolveEffectiveNilLookupFailsClosed(t *testing.T) {
	var notices []string
	p := ResolveEffective(nil, func(msg string) { notices = append(notices, msg) })
	if p != LocalOnly {
		t.Fatalf("nil lookup: policy = %v, want local-only", p)
	}
	if len(notices) != 1 {
		t.Fatalf("nil lookup: expected exactly one surfaced notice, got %v", notices)
	}
	if !strings.Contains(notices[0], "policy lookup unavailable") {
		t.Fatalf("notice %q does not explain the degradation", notices[0])
	}
}

// TestResolveEffectiveNilLookupSilent pins the existing call convention:
// a nil reporter is legal and suppresses only the message, never the
// fail-closed selection.
func TestResolveEffectiveNilLookupSilent(t *testing.T) {
	if p := ResolveEffective(nil, nil); p != LocalOnly {
		t.Fatalf("nil lookup, nil reporter: policy = %v, want local-only", p)
	}
}

// TestResolveEffectiveLiveReadIsAuthoritative: a healthy lookup's value is
// returned verbatim, read exactly once, with no notices.
func TestResolveEffectiveLiveReadIsAuthoritative(t *testing.T) {
	for _, want := range []Policy{Online, PreferLocal, LocalOnly} {
		calls := 0
		p := ResolveEffective(func() Policy { calls++; return want }, func(string) {
			t.Fatal("healthy lookup must not produce a notice")
		})
		if p != want {
			t.Fatalf("policy = %v, want %v", p, want)
		}
		if calls != 1 {
			t.Fatalf("lookup calls = %d, want 1 (exactly-once read)", calls)
		}
	}
}

// TestResolveEffectivePanickingLookupFailsClosed: a crashing config path is
// indistinguishable from an unreadable one at this layer — the dispatcher
// must survive it and degrade, not propagate a panic into dispatch.
func TestResolveEffectivePanickingLookupFailsClosed(t *testing.T) {
	var notices []string
	p := ResolveEffective(func() Policy { panic("config backend exploded") }, func(msg string) {
		notices = append(notices, msg)
	})
	if p != LocalOnly {
		t.Fatalf("panicking lookup: policy = %v, want local-only", p)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "policy lookup failed") {
		t.Fatalf("notice = %v, want one 'policy lookup failed' message", notices)
	}
}
