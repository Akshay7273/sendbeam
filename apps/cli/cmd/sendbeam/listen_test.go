package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestListenCommand_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	code := executeListenWithContext(ctx, []string{"--config-dir", tmpDir, "--once", "--dest", tmpDir}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("listen exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "SendBeam Trusted Listener") {
		t.Errorf("expected header, got: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Destination:") {
		t.Errorf("expected Destination in output, got: %s", stdout.String())
	}
}

func TestListenCommand_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	code := executeListenWithContext(ctx, []string{"--config-dir", tmpDir, "--once", "--json", "--dest", tmpDir}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("listen --json exit code %d, stderr: %s", code, stderr.String())
	}
	// In JSON mode, human header should not be printed
	if strings.Contains(stdout.String(), "SendBeam Trusted Listener") {
		t.Errorf("expected no plain text header in JSON mode, got: %s", stdout.String())
	}
}

func TestListenCommand_InvalidArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := executeListenWithContext(context.Background(), []string{"--unknown-flag"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flags, got %d", code)
	}
}

func TestListenCommand_AutoAcceptFlag(t *testing.T) {
	tmpDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	code := executeListenWithContext(ctx, []string{"--config-dir", tmpDir, "--auto-accept", "--dest", tmpDir}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("listen exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Auto-Accept: Enabled") {
		t.Errorf("expected Auto-Accept: Enabled, got: %s", stdout.String())
	}
}

func TestListenCommand_RequirePaddingFlag(t *testing.T) {
	tmpDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	code := executeListenWithContext(ctx, []string{
		"--config-dir", tmpDir,
		"--dest", tmpDir,
		"--require-padding",
		"--private",
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("listen exit code %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("flag error: %s", stderr.String())
	}
}
