// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"testing"
	"time"
)

// A recipe disabled while its watcher is running stops dispatching: the
// watcher reloads the recipe's status before every dispatch, so the next
// quiet window after the disable refuses instead of enqueueing.
func TestWatcherDynamicDisableStopsDispatch(t *testing.T) {
	fx := newWatchFixture(t, nil)
	fx.start(t)

	// First file dispatches while the routine is armed.
	writeTestFile(t, fx.root, "first.txt", "first payload")
	waitFor(t, 10*time.Second, "first dispatch", func() bool { return fx.eq.numCalls() >= 1 })
	if got := fx.eq.numCalls(); got != 1 {
		t.Fatalf("enqueue calls = %d, want 1", got)
	}

	// Disable mid-watch.
	r, ok, err := fx.store.Load(fx.recipe.ID)
	if err != nil || !ok {
		t.Fatalf("Load: %v %v", ok, err)
	}
	Disable(&r)
	if err := fx.store.Save(r); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A new file after the disable must NOT dispatch: the watcher sees
	// the disabled status on its reload and refuses.
	writeTestFile(t, fx.root, "second.txt", "second payload")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fx.eq.numCalls() > 1 {
			t.Fatalf("watcher dispatched after disable (calls=%d)", fx.eq.numCalls())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := fx.eq.numCalls(); got != 1 {
		t.Fatalf("enqueue calls = %d, want exactly 1 after disable", got)
	}
}
