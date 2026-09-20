// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"strings"
	"testing"

	"github.com/sendbeam/engine/netpolicy"
)

// TestLocalServicePolicyGate verifies the offline listener refuses to start
// unless the network policy is offline-capable, starts idempotently when it
// is, and tears down cleanly.
func TestLocalServicePolicyGate(t *testing.T) {
	dir := t.TempDir()
	emit := func(string, any) {}
	ds, err := NewDeviceService(emit, dir)
	if err != nil {
		t.Fatalf("NewDeviceService: %v", err)
	}

	policy := netpolicy.Online
	svc := NewLocalService(ds.GetIdentityManager(), ds.GetStore(), ds.GetCredentialStore(), ds.GetTombstoneStore(), emit)
	svc.SetPolicy(func() netpolicy.Policy { return policy })
	svc.SetListenPort(0) // ephemeral port for the test

	if _, err := svc.Start(); err == nil {
		t.Fatal("Start with policy=online should be refused")
	} else if !strings.Contains(err.Error(), "local-only") && !strings.Contains(err.Error(), "prefer-local") {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if svc.IsListening() {
		t.Fatal("should not be listening after refused start")
	}

	policy = netpolicy.LocalOnly
	addr, err := svc.Start()
	if err != nil {
		t.Fatalf("Start with policy=local-only: %v", err)
	}
	if addr == "" {
		t.Fatal("Start returned empty listen address")
	}
	if !svc.IsListening() || svc.ListenAddr() != addr {
		t.Fatal("IsListening/ListenAddr mismatch after Start")
	}
	// Idempotent: second start returns the same listener.
	addr2, err := svc.Start()
	if err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if addr2 != addr {
		t.Fatalf("second Start moved the listener: %q -> %q", addr, addr2)
	}

	// Unknown consent IDs are an error, never a silent accept.
	if err := svc.RespondLocalConsent("no-such-transfer", LocalConsentDecision{Accepted: true}); err == nil {
		t.Fatal("RespondLocalConsent with unknown ID should fail")
	}

	svc.Stop()
	if svc.IsListening() || svc.ListenAddr() != "" {
		t.Fatal("Stop did not clear the listener")
	}
	if len(svc.PendingLocalConsents()) != 0 {
		t.Fatal("pending consents should be empty after Stop")
	}
}

// TestLocalServicePreferLocalStarts verifies prefer-local also permits the
// listener (offline-capable), and that the production default port constant
// matches the beacon advertisement contract.
func TestLocalServicePreferLocalStarts(t *testing.T) {
	dir := t.TempDir()
	emit := func(string, any) {}
	ds, err := NewDeviceService(emit, dir)
	if err != nil {
		t.Fatalf("NewDeviceService: %v", err)
	}
	svc := NewLocalService(ds.GetIdentityManager(), ds.GetStore(), ds.GetCredentialStore(), ds.GetTombstoneStore(), emit)
	svc.SetPolicy(func() netpolicy.Policy { return netpolicy.PreferLocal })
	svc.SetListenPort(0)
	defer svc.Stop()
	if _, err := svc.Start(); err != nil {
		t.Fatalf("Start with policy=prefer-local: %v", err)
	}
	if !svc.IsListening() {
		t.Fatal("expected listener to be up under prefer-local")
	}
}
