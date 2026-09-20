package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

// seedOutboxDevice adds one trusted device to a fresh CLI environment.
func seedOutboxDevice(t *testing.T, env *CLIEnvironment, label string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	devID := wire.DeriveDeviceID(pub)
	now := time.Now().UTC()
	if err := env.TrustStore.AddOrUpdateDevice(context.Background(), &wire.TrustRecord{
		DeviceID:          devID,
		PublicKey:         hex.EncodeToString(pub),
		LocalLabel:        label,
		PairCredentialRef: "cred-1",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	}); err != nil {
		t.Fatal(err)
	}
	return devID
}

func writeOutboxFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOutboxEnqueueListShow(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "hello outbox")

	var stdout, stderr bytes.Buffer
	code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Queued") {
		t.Fatalf("expected 'Queued' in stdout, got: %s", stdout.String())
	}

	stdout.Reset()
	code = runOutbox([]string{"list", "--config-dir", cfgDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("list exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "queued") {
		t.Fatalf("expected job in list output, got: %s", stdout.String())
	}

	// Extract the job id from the list output (first 12-hex token).
	var jobID string
	for _, field := range strings.Fields(stdout.String()) {
		if len(field) == 12 {
			if _, err := hex.DecodeString(field); err == nil {
				jobID = field
				break
			}
		}
	}
	_ = jobID

	stdout.Reset()
	code = runOutbox([]string{"show", "--config-dir", cfgDir, "--json", "bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("show of unknown job should exit 1, got %d", code)
	}
}

func TestOutboxEnqueueJSON(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "hello")

	var stdout, stderr bytes.Buffer
	code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, "--json", payload, "--to", "@laptop"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{`"job_id"`, `"status": "queued"`, `"label": "laptop"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %s in JSON output, got: %s", want, out)
		}
	}
}

func TestOutboxEnqueue_UnknownDevice(t *testing.T) {
	cfgDir := t.TempDir()
	if _, err := InitCLIEnvironment(cfgDir); err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	payload := writeOutboxFile(t, "hello")

	var stdout, stderr bytes.Buffer
	code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@ghost"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 for unknown device, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not found in trust store") {
		t.Fatalf("expected trust error, got: %s", stderr.String())
	}
}

func TestOutboxEnqueue_NeedsFileAndRecipient(t *testing.T) {
	cfgDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
	payload := writeOutboxFile(t, "hello")
	stderr.Reset()
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 for missing --to, got %d", code)
	}
}

func TestOutboxCancel(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "hello")

	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, "--json", payload, "--to", "@laptop"}, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}
	// Pull the full job id out of the JSON output.
	var jobID string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.Contains(line, `"job_id"`) {
			parts := strings.Split(line, `"`)
			if len(parts) >= 4 {
				jobID = parts[3]
			}
		}
	}
	if jobID == "" {
		t.Fatalf("could not parse job id from: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runOutbox([]string{"cancel", "--config-dir", cfgDir, jobID}, &stdout, &stderr); code != 0 {
		t.Fatalf("cancel exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Cancelled") {
		t.Fatalf("expected 'Cancelled', got: %s", stdout.String())
	}

	stdout.Reset()
	if code := runOutbox([]string{"show", "--config-dir", cfgDir, jobID}, &stdout, &stderr); code != 0 {
		t.Fatalf("show exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cancelled") {
		t.Fatalf("expected cancelled status, got: %s", stdout.String())
	}
}

func TestOutboxDispatch_NothingDue(t *testing.T) {
	cfgDir := t.TempDir()
	if _, err := InitCLIEnvironment(cfgDir); err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runOutbox([]string{"dispatch", "--config-dir", cfgDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Nothing due") {
		t.Fatalf("expected 'Nothing due', got: %s", stdout.String())
	}
}

func TestOutbox_UnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"frobnicate"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if code := runOutbox(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 for no args, got %d", code)
	}
}
