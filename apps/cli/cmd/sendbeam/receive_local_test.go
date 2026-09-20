// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestRunLocalOnlyReceiveCancellation verifies the local receive loop
// stops promptly on context cancellation: the listener shuts down, no
// session is left dangling, and the command reports cancellation instead
// of hanging (V21-PR07 lifecycle).
func TestRunLocalOnlyReceiveCancellation(t *testing.T) {
	dir := t.TempDir()
	env, err := InitCLIEnvironment(dir)
	if err != nil {
		t.Fatalf("InitCLIEnvironment: %v", err)
	}
	outDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		// Loopback bind: same-machine test only.
		done <- runLocalOnlyReceiveWithContext(ctx, env, outDir, "127.0.0.1:0", false, false, &stdout, &stderr)
	}()

	// Give the listener a moment to start, then cancel.
	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case rc := <-done:
		if rc == 0 {
			t.Fatal("cancelled receive must not report success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("receive did not stop within 10s of cancellation (hang/leak)")
	}
}

// TestRunLocalOnlyReceiveBindsLANByDefault verifies the default bind is a
// usable LAN address: the printed listen address must not be loopback.
func TestRunLocalOnlyReceiveBindsLANByDefault(t *testing.T) {
	dir := t.TempDir()
	env, err := InitCLIEnvironment(dir)
	if err != nil {
		t.Fatalf("InitCLIEnvironment: %v", err)
	}
	outDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runLocalOnlyReceiveWithContext(ctx, env, outDir, "", false, false, &stdout, &stderr)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("receive did not stop after cancellation")
	}

	out := stdout.String()
	if !strings.Contains(out, "listening on ") {
		t.Fatalf("expected listen address in output, got: %q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "listening on ") {
			if strings.Contains(line, "127.0.0.1") || strings.Contains(line, "[::1]") {
				t.Fatalf("default bind must be a LAN address, got: %q", line)
			}
		}
	}
}
