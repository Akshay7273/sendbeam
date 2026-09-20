// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDesktopFrontend_OfflineUI asserts the shipped desktop UI exposes the
// V21-PR06 offline controls: the network policy selector, the offline
// listener toggle, the offline pairing card, the local-only consent routing
// marker, and bindings for the three offline backend services.
func TestDesktopFrontend_OfflineUI(t *testing.T) {
	path := filepath.Join("..", "..", "frontend", "dist", "index.html")
	contentBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read desktop index.html at %s: %v", path, err)
	}
	content := string(contentBytes)

	for _, id := range []string{
		"cfg-network-policy",   // network policy selector in settings
		"local-listener-state", // offline listener status readout
		"local-listener-toggle",
		"card-offline", // offline pairing card
		"offline-invite-btn",
		"offline-invite-view",
		"offline-join-inv",
		"offline-join-btn",
		"policy-banner",   // local-only banner in the send panel
		"recv-local-note", // local-only note in the receive panel
		"card-handoff",    // handoff card (hidden in local-only)
	} {
		if !strings.Contains(content, `id="`+id+`"`) {
			t.Errorf("desktop index.html is missing element id %q", id)
		}
	}

	// Backend service bindings the new UI calls into.
	for _, svc := range []string{
		"github.com/sendbeam/desktop/internal/engine.NetworkPolicyService",
		"github.com/sendbeam/desktop/internal/engine.LocalPairingService",
		"github.com/sendbeam/desktop/internal/engine.LocalService",
	} {
		if strings.Count(content, svc) < 1 {
			t.Errorf("desktop index.html does not bind service %q", svc)
		}
	}

	// Local-only send route and local consent routing marker.
	for _, marker := range []string{
		"SendToDeviceLocal",
		"SendToDevicePreferLocal", // V21-PR07: prefer-local LAN-first with explicit online fallback
		"RespondLocalConsent",
		"pendingConsentLocal",
		"skipped_local_only",
	} {
		if !strings.Contains(content, marker) {
			t.Errorf("desktop index.html is missing offline marker %q", marker)
		}
	}

	// V21-PR07: the settings page must save via the merge-patch binding so
	// one section never wipes fields managed elsewhere (theme, update
	// channel, network policy).
	if !strings.Contains(content, "SaveConfigPatch") {
		t.Error("desktop index.html does not use the SaveConfigPatch binding")
	}
	// V21-PR07: the updater status check must read the backend's `state`
	// field (not `status`) for the local-only skip.
	if !strings.Contains(content, `st.state === "skipped_local_only"`) {
		t.Error("desktop index.html checks the wrong updater status field")
	}
}
