// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"testing"

	"github.com/sendbeam/engine/netpolicy"
)

// TestUpdateServiceSkipsInLocalOnly verifies that in local-only mode the
// updater reports an honest skip instead of attempting any network egress.
func TestUpdateServiceSkipsInLocalOnly(t *testing.T) {
	svc := NewUpdateService(nil, nil)
	svc.SetNetworkPolicyProvider(func() netpolicy.Policy { return netpolicy.LocalOnly })

	st, err := svc.CheckUpdate("")
	if err != nil {
		t.Fatalf("CheckUpdate in local-only: %v", err)
	}
	if st.State != "skipped_local_only" {
		t.Fatalf("expected status skipped_local_only, got %q", st.State)
	}
	if st.Message == "" {
		t.Fatal("expected a human-readable skip message")
	}
}

// TestUpdateServiceOnlineByDefault verifies that with no policy provider the
// updater behaves as before (attempts the check; may fail without network,
// but must not report a local-only skip).
func TestUpdateServiceOnlineByDefault(t *testing.T) {
	svc := NewUpdateService(nil, nil)
	if svc.localOnly() {
		t.Fatal("no policy provider must not mean local-only")
	}
}
