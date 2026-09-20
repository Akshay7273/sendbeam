// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"testing"

	"github.com/sendbeam/wire"
)

// TestTransferRunResetLeg verifies the prefer-local fallback starts its
// online leg with clean per-attempt state (V21-PR07): progress counters,
// transport reports, and failure flags from the failed local attempt must
// not leak into the fallback leg, while the file list and totals survive.
func TestTransferRunResetLeg(t *testing.T) {
	svc := NewTransferService(nil, nil)
	r := svc.newRun("test-run", wire.RoleOfferer)

	r.files = []FileInfo{{Name: "a.bin", Size: 100}}
	r.totalBytes = 100
	r.doneBytes = 64
	r.reused = 10
	r.fileIdx = 1
	r.fileBytes = 32
	r.fileSize = 100
	r.filesDone = 0
	r.failed = true
	r.transport = "direct"
	r.fingerprint = "abc123"
	r.samples = []progressSample{{bytes: 64}}

	r.resetLeg()

	if r.doneBytes != 0 || r.reused != 0 || r.fileIdx != 0 || r.fileBytes != 0 ||
		r.fileSize != 0 || r.filesDone != 0 {
		t.Fatal("resetLeg left stale progress counters")
	}
	if r.failed || r.transport != "" || r.fingerprint != "" || len(r.samples) != 0 {
		t.Fatal("resetLeg left stale attempt state")
	}
	if len(r.files) != 1 || r.files[0].Name != "a.bin" || r.totalBytes != 100 {
		t.Fatal("resetLeg dropped the file list or totals")
	}
}
