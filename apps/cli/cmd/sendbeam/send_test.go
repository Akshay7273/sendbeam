package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

func TestExecuteSend_MissingFileArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := executeSend([]string{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing file, got %d", code)
	}
	if !strings.Contains(stderr.String(), "a file to send is required") {
		t.Fatalf("expected error message in stderr, got: %s", stderr.String())
	}
}

func TestExecuteSend_TargetDeviceResolutionError(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		testFile,
		"@nonexistent",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for unresolvable device, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not found in trust store") {
		t.Fatalf("expected 'not found in trust store' in stderr, got: %s", stderr.String())
	}
}

func TestExecuteSend_RevokedDeviceRejection(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	devID := wire.DeriveDeviceID(pub)
	now := time.Now().UTC()

	ctx := context.Background()
	_ = env.TrustStore.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devID,
		PublicKey:         hex.EncodeToString(pub),
		LocalLabel:        "OldLaptop",
		PairCredentialRef: "cred-1",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Revoked:           true,
		Policy:            wire.DefaultTrustPolicy(),
	})

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		testFile,
		"@OldLaptop",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for revoked device, got %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "is revoked") {
		t.Fatalf("expected 'is revoked' in stderr, got: %s", stderr.String())
	}
}

func TestExecuteSend_MultipleTargetArgParsing(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	dev1 := wire.DeriveDeviceID(pub1)
	dev2 := wire.DeriveDeviceID(pub2)
	now := time.Now().UTC()

	ctx := context.Background()
	_ = env.TrustStore.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          dev1,
		PublicKey:         hex.EncodeToString(pub1),
		LocalLabel:        "laptop",
		PairCredentialRef: "cred-1",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = env.TrustStore.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          dev2,
		PublicKey:         hex.EncodeToString(pub2),
		LocalLabel:        "phone",
		PairCredentialRef: "cred-2",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	testFile := filepath.Join(tmpDir, "report.pdf")
	if err := os.WriteFile(testFile, []byte("fake-pdf-content"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	// Invalid server URL triggers offline status for targets
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		"--server", "ws://127.0.0.1:1/nonexistent",
		"--json",
		testFile,
		"@laptop",
		"@phone",
	}, &stdout, &stderr)

	// Since dialing 127.0.0.1:1 fails, all targets fail/offline -> exit code 1
	if code != 1 {
		t.Fatalf("expected exit code 1 on failed targets, got %d", code)
	}

	var res transfer.BroadcastResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("stdout was not valid json (%v): %s", err, stdout.String())
	}

	if res.AllOk {
		t.Fatal("expected AllOk=false")
	}
	if len(res.Results) != 2 {
		t.Fatalf("expected 2 target results, got %d", len(res.Results))
	}
	for _, r := range res.Results {
		if r.Status != transfer.StatusOffline && r.Status != transfer.StatusFailed {
			t.Errorf("target %s status = %s, want offline/failed", r.Label, r.Status)
		}
	}
}

func TestRenderBroadcastTable(t *testing.T) {
	results := []transfer.TargetResult{
		{
			TargetID:   "dev-1",
			Label:      "laptop",
			Status:     transfer.StatusOk,
			Digest:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			DurationMs: 450,
		},
		{
			TargetID:   "dev-2",
			Label:      "phone",
			Status:     transfer.StatusOffline,
			DurationMs: 1200,
			Error:      "peer offline",
		},
		{
			TargetID:   "dev-3",
			Label:      "workstation",
			Status:     transfer.StatusRefused,
			DurationMs: 300,
			Error:      "peer refused",
		},
	}

	var buf bytes.Buffer
	renderBroadcastTable(&buf, results, 1024*1024)
	out := buf.String()

	if !strings.Contains(out, "Broadcast Transfer Summary") {
		t.Errorf("missing header in table output: %s", out)
	}
	if !strings.Contains(out, "@laptop") || !strings.Contains(out, "@phone") || !strings.Contains(out, "@workstation") {
		t.Errorf("missing device labels in table output: %s", out)
	}
	if !strings.Contains(out, "1 succeeded, 2 failed") {
		t.Errorf("missing summary counts in table output: %s", out)
	}
}

func TestExecuteSend_PrivateFlag(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	// With an offline or fake server, executeSend should accept --private without flag error (code 1 for failed dial, not code 2 for flag parse error)
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		"--server", "wss://127.0.0.1:65530/ws",
		"--private",
		testFile,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for failed dial with --private flag, got %d. stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("--private flag was not recognized: %s", stderr.String())
	}
}
