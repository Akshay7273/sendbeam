// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package receiver

import (
	"context"
	"testing"

	"github.com/sendbeam/wire"
)

func routineManifest() wire.Manifest {
	return wire.Manifest{
		TransferID: "t-routine",
		Files: []wire.FileEntry{
			{Idx: 0, Name: "doc.pdf", Size: 500, Mime: "application/pdf"},
		},
		TotalSize: 500,
		Provenance: &wire.Provenance{
			RoutineID:   "0123456789abcdef0123456789abcdef",
			RoutineName: "nightly backup",
			SenderLabel: "alice-laptop",
			Trigger:     "watch",
		},
	}
}

// The routine auto-accept policy matrix (V22-PR06): the policy is OFF by
// default and, when enabled, accepts ONLY provenance-carrying transfers
// from explicitly allowlisted sender devices. Trust and tombstone
// validation always run first and cannot be bypassed.
func TestRoutineAutoAcceptPolicyMatrix(t *testing.T) {
	tmpDir := t.TempDir()
	idAlice, _, _, storeBob, _, tombstonesBob := setupPairedPeers(t, tmpDir)
	ctx := context.Background()

	evaluate := func(policy AutoAcceptPolicy, global bool, peerID string, manifest wire.Manifest) (ConsentDecision, error) {
		handlerCalled := false
		dec, err := EvaluateConsent(ctx, storeBob, tombstonesBob, global, policy, tmpDir, peerID, manifest,
			func(_ context.Context, _ ConsentRequest) (ConsentDecision, error) {
				handlerCalled = true
				return ConsentDecision{Accepted: false, Reason: "manual consent"}, nil
			})
		if handlerCalled {
			dec.Reason = "manual:" + dec.Reason
		}
		return dec, err
	}

	full := AutoAcceptPolicy{Enabled: true, AllowRoutineTransfers: true, AllowedDevices: []string{idAlice.DeviceID}}
	routine := routineManifest()
	oneOff := wire.Manifest{
		TransferID: "t-oneoff",
		Files:      []wire.FileEntry{{Idx: 0, Name: "doc.pdf", Size: 500, Mime: "application/pdf"}},
		TotalSize:  500,
	}

	cases := []struct {
		name     string
		policy   AutoAcceptPolicy
		global   bool
		peerID   string
		manifest wire.Manifest
		// want: "accept" | "manual"
		want string
	}{
		{"default off: routine transfer goes to manual", AutoAcceptPolicy{}, false, idAlice.DeviceID, routine, "manual"},
		{"default off: one-off goes to manual", AutoAcceptPolicy{}, false, idAlice.DeviceID, oneOff, "manual"},
		{"enabled, empty allowlist: routine goes to manual", AutoAcceptPolicy{Enabled: true, AllowRoutineTransfers: true}, false, idAlice.DeviceID, routine, "manual"},
		{"enabled but routine scope off: routine goes to manual", AutoAcceptPolicy{Enabled: true, AllowedDevices: []string{idAlice.DeviceID}}, false, idAlice.DeviceID, routine, "manual"},
		{"enabled: one-off (no provenance) goes to manual", full, false, idAlice.DeviceID, oneOff, "manual"},
		{"enabled: routine from allowlisted sender accepted", full, false, idAlice.DeviceID, routine, "accept"},
		{"enabled: malformed provenance goes to manual", full, false, idAlice.DeviceID, func() wire.Manifest {
			m := routineManifest()
			m.Provenance.Trigger = "cron"
			return m
		}(), "manual"},
		{"legacy global auto-accept still accepts one-off sends", AutoAcceptPolicy{}, true, idAlice.DeviceID, oneOff, "accept"},
		{"legacy global auto-accept still accepts routine sends", AutoAcceptPolicy{}, true, idAlice.DeviceID, routine, "accept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := evaluate(tc.policy, tc.global, tc.peerID, tc.manifest)
			if err != nil {
				t.Fatalf("EvaluateConsent: %v", err)
			}
			switch tc.want {
			case "accept":
				if !dec.Accepted {
					t.Fatalf("expected auto-accept, got %+v", dec)
				}
			case "manual":
				if dec.Accepted {
					t.Fatalf("expected manual consent, got auto-accept %+v", dec)
				}
			}
		})
	}
}

// A stranger device fails closed at the trust check — an error, never
// manual consent and never acceptance.
func TestRoutineAutoAccept_UnknownSenderFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	_, _, _, storeBob, _, tombstonesBob := setupPairedPeers(t, tmpDir)
	ctx := context.Background()

	policy := AutoAcceptPolicy{Enabled: true, AllowRoutineTransfers: true, AllowedDevices: []string{"unknown-device-id"}}
	dec, err := EvaluateConsent(ctx, storeBob, tombstonesBob, false, policy, tmpDir, "unknown-device-id", routineManifest(), nil)
	if err == nil {
		t.Fatal("unknown sender should produce a trust error")
	}
	if dec.Accepted {
		t.Fatalf("unknown sender auto-accepted: %+v", dec)
	}
}

// A revoked sender is declined even when allowlisted with a valid routine
// provenance: trust and tombstone validation run before the policy.
func TestRoutineAutoAccept_RevokedSenderDeclined(t *testing.T) {
	tmpDir := t.TempDir()
	idAlice, _, _, storeBob, _, tombstonesBob := setupPairedPeers(t, tmpDir)
	ctx := context.Background()

	if err := storeBob.RevokeDevice(ctx, idAlice.DeviceID); err != nil {
		t.Fatal(err)
	}
	policy := AutoAcceptPolicy{Enabled: true, AllowRoutineTransfers: true, AllowedDevices: []string{idAlice.DeviceID}}
	dec, err := EvaluateConsent(ctx, storeBob, tombstonesBob, false, policy, tmpDir, idAlice.DeviceID, routineManifest(), nil)
	if err == nil {
		t.Fatal("revoked sender should produce an error")
	}
	if dec.Accepted {
		t.Fatalf("revoked sender auto-accepted: %+v", dec)
	}
}

// The manual-consent handler sees the full provenance on the request.
func TestRoutineAutoAccept_HandlerSeesProvenance(t *testing.T) {
	tmpDir := t.TempDir()
	idAlice, _, _, storeBob, _, tombstonesBob := setupPairedPeers(t, tmpDir)
	ctx := context.Background()

	var got *wire.Provenance
	_, err := EvaluateConsent(ctx, storeBob, tombstonesBob, false, AutoAcceptPolicy{}, tmpDir, idAlice.DeviceID, routineManifest(),
		func(_ context.Context, req ConsentRequest) (ConsentDecision, error) {
			got = req.Provenance
			return ConsentDecision{Accepted: false, Reason: "declined"}, nil
		})
	if err != nil {
		t.Fatalf("EvaluateConsent: %v", err)
	}
	if got == nil || got.RoutineName != "nightly backup" || got.Trigger != "watch" || got.SenderLabel != "alice-laptop" {
		t.Fatalf("handler provenance = %+v", got)
	}
}

// Policy validation fails closed on empty allowlist entries.
func TestValidateAutoAcceptPolicy(t *testing.T) {
	if err := ValidateAutoAcceptPolicy(AutoAcceptPolicy{}); err != nil {
		t.Fatalf("zero policy rejected: %v", err)
	}
	if err := ValidateAutoAcceptPolicy(AutoAcceptPolicy{Enabled: true, AllowRoutineTransfers: true, AllowedDevices: []string{"a", "b"}}); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if err := ValidateAutoAcceptPolicy(AutoAcceptPolicy{AllowedDevices: []string{""}}); err == nil {
		t.Fatal("empty allowlist entry accepted")
	}
}
