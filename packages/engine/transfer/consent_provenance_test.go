// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"context"
	"testing"

	"github.com/sendbeam/wire"
)

// The routine origin label stamped on the wire manifest reaches the
// consent handler unchanged — and a manifest without one arrives as an
// explicit nil, so the consent UI can show the one-off marker.
func TestConsentDestination_CarriesProvenance(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		provenance *wire.Provenance
	}{
		{"routine transfer", &wire.Provenance{
			RoutineID:   "0123456789abcdef0123456789abcdef",
			RoutineName: "nightly backup",
			SenderLabel: "akshay-laptop",
			Trigger:     "watch",
		}},
		{"one-off send", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got *wire.Provenance
			dest := &consentDestination{
				ctx:         ctx,
				specDestDir: t.TempDir(),
				consent: func(_ context.Context, req ConsentRequest) (ConsentDecision, error) {
					got = req.Provenance
					return ConsentDecision{Accepted: true}, nil
				},
				peerDeviceID: "dev-alice-0000000000000001",
				peerLabel:    "alice",
			}
			manifest := wire.Manifest{
				TransferID: "0123456789abcdef0123456789abcdef",
				Files: []wire.FileEntry{{
					Idx: 0, Name: "doc.pdf", Size: 100, Mime: "application/pdf",
					LastModified: 5, BlockSize: 64, Blocks: 2, FileDigest: "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
				}},
				TotalSize:  100,
				Provenance: tc.provenance,
			}
			if err := dest.Prepare(manifest); err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			if tc.provenance == nil {
				if got != nil {
					t.Fatalf("one-off consent request carried provenance %+v", got)
				}
				return
			}
			if got == nil || *got != *tc.provenance {
				t.Fatalf("consent provenance = %+v, want %+v", got, tc.provenance)
			}
		})
	}
}
