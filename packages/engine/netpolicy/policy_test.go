// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package netpolicy

import "testing"

// TestDispatchableUnder verifies the V21-PR07 attempt-binding matrix: a
// job is dispatched only when its bound policy is satisfiable under the
// dispatcher's effective policy, never by silently broadening it.
func TestDispatchableUnder(t *testing.T) {
	cases := []struct {
		job, effective Policy
		want           bool
	}{
		// Local-only jobs: only when a local route is available.
		{LocalOnly, LocalOnly, true},
		{LocalOnly, PreferLocal, true},
		{LocalOnly, Online, false},
		// Online jobs: only when an online route is permitted.
		{Online, Online, true},
		{Online, PreferLocal, true},
		{Online, LocalOnly, false},
		// Prefer-local jobs: dispatch under any effective policy; the
		// route is chosen at send time within what is allowed.
		{PreferLocal, Online, true},
		{PreferLocal, PreferLocal, true},
		{PreferLocal, LocalOnly, true},
	}
	for _, c := range cases {
		if got := c.job.DispatchableUnder(c.effective); got != c.want {
			t.Errorf("job %q under effective %q: got %v, want %v",
				c.job, c.effective, got, c.want)
		}
	}
}
