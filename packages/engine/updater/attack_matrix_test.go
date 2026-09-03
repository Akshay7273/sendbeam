package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAttackMatrix_Vector15_UpdateManifestReplay exercises adversarial update rollback:
// An attacker replays a validly-signed older stable.json release manifest to coerce
// the updater into applying a known-vulnerable older version (ADR 0005 / V18-PR04).
func TestAttackMatrix_Vector15_UpdateManifestReplay(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam")

	// Current binary running v1.8.0
	currentBinary := []byte("sendbeam-v1.8.0")
	if err := os.WriteFile(targetBinary, currentBinary, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := DefaultMinisignPublicKey
	archiveName := "sendbeam-cli-linux-amd64.tar.gz"

	// Attacker replays a genuine, validly-signed older manifest (v1.6.0)
	oldPayload := []byte("sendbeam-v1.6.0-replayed-older-build")
	oldTarData := createTestTarGz(t, "sendbeam", oldPayload)
	oldTarHash := sha256Hex(oldTarData)

	olderManifest := ChannelManifest{
		SchemaVersion: 1,
		Version:       "1.6.0", // Older than active v1.8.0!
		Channel:       "stable",
		PublishedAt:   time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		ReleaseNotes:  "SendBeam v1.6.0 release notes",
		Assets: map[string]ReleaseAsset{
			"linux-amd64": {
				Name:   archiveName,
				SHA256: oldTarHash,
				Size:   int64(len(oldTarData)),
			},
		},
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		olderManifest.Assets["linux-amd64"] = ReleaseAsset{
			Name:        archiveName,
			DownloadURL: srv.URL + "/download/" + archiveName,
			SHA256:      oldTarHash,
			Size:        int64(len(oldTarData)),
		}
		data, _ := json.Marshal(olderManifest)
		// Cryptographically genuine Minisign signature
		sig, _ := SignMinisign(data, testSeed, testPub, "stable.json")

		switch r.URL.Path {
		case "/stable.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		case "/stable.json.minisig":
			_, _ = w.Write([]byte(sig))
		case "/download/" + archiveName:
			_, _ = w.Write(oldTarData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Initialized with current version 1.8.0
	u, err := New(
		"1.8.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetBinary),
		WithMinisignPublicKey(testPub),
		WithHTTPClient(srv.Client()),
	)
	if err != nil {
		t.Fatalf("New updater: %v", err)
	}

	ctx := context.Background()

	// 1. Check: Even though signature is 100% genuine and valid, update must NOT be available
	check, err := u.Check(ctx)
	if err != nil {
		t.Fatalf("Check unexpectedly errored on valid signature: %v", err)
	}
	if check.UpdateAvailable {
		t.Fatalf("downgrade coercion succeeded: replayed v1.6.0 manifest was accepted as update for active v1.8.0")
	}

	// 2. Apply: Attempting to apply the replayed older check result MUST fail closed
	err = u.Apply(ctx, check)
	if err == nil {
		t.Fatal("expected Apply to reject downgrade / replayed older version")
	}

	// 3. Verify file on disk was NEVER replaced with older binary
	afterContent, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile targetBinary: %v", err)
	}
	if string(afterContent) != string(currentBinary) {
		t.Fatalf("target binary was tampered: expected %q, got %q", currentBinary, afterContent)
	}
}
