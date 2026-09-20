// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/trust"
)

func newTestLocalPairingService(t *testing.T) *LocalPairingService {
	t.Helper()
	dir := t.TempDir()
	idMgr, err := trust.NewIdentityManager(dir + "/identity.key")
	if err != nil {
		t.Fatal(err)
	}
	store := trust.NewMemoryTrustStore()
	return NewLocalPairingService(idMgr, store)
}

func TestLocalPairingServiceCreateAndCancel(t *testing.T) {
	svc := newTestLocalPairingService(t)
	view, err := svc.CreateInvitation(60, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if view.Invitation == "" || view.Address == "" || view.Fingerprint == "" {
		t.Fatalf("incomplete invitation view: %+v", view)
	}
	// Second invitation while one is active fails.
	if _, err := svc.CreateInvitation(60, "127.0.0.1:0"); err == nil {
		t.Fatal("expected error for duplicate invitation")
	}
	svc.CancelInvitation()
	// After cancel, a new invitation works.
	if _, err := svc.CreateInvitation(60, "127.0.0.1:0"); err != nil {
		t.Fatalf("after cancel: %v", err)
	}
	svc.CancelInvitation()
}

func TestLocalPairingServiceJoinBadInvitation(t *testing.T) {
	svc := newTestLocalPairingService(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := svc.JoinPairing(ctx, "not-an-invitation", "test"); err == nil {
		t.Fatal("expected error for bad invitation")
	}
}

func TestNetworkPolicyService(t *testing.T) {
	var current = netpolicy.Online
	svc := NewNetworkPolicyService(
		func() netpolicy.Policy { return current },
		func(p netpolicy.Policy) error { current = p; return nil },
	)
	if got := svc.GetPolicy(); got != "online" {
		t.Fatalf("got %q, want online", got)
	}
	if err := svc.SetPolicy("local-only"); err != nil {
		t.Fatal(err)
	}
	if got := svc.GetPolicy(); got != "local-only" {
		t.Fatalf("got %q, want local-only", got)
	}
	if err := svc.SetPolicy("bogus"); err == nil {
		t.Fatal("expected error for bogus policy")
	}
}
