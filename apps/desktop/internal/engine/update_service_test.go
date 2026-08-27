package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/updater"
)

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestUpdateService_CheckAndApply_AppImage(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")

	oldContent := []byte("AppImage-v1.4.0")
	if err := os.WriteFile(targetAppImage, oldContent, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newAppImage := []byte("AppImage-v1.5.0-signed-update")
	appImageHash := sha256Hex(newAppImage)

	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := updater.DefaultMinisignPublicKey

	var srv *httptest.Server
	manifest := updater.ChannelManifest{
		SchemaVersion: 1,
		Version:       "1.5.0",
		Channel:       "stable",
		PublishedAt:   time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		ReleaseNotes:  "SendBeam Desktop 1.5.0 notes",
		Assets: map[string]updater.ReleaseAsset{
			"SendBeam-linux-amd64.AppImage": {
				Name:        "SendBeam-linux-amd64.AppImage",
				DownloadURL: "",
				SHA256:      appImageHash,
				Size:        int64(len(newAppImage)),
			},
		},
	}

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifest.Assets["SendBeam-linux-amd64.AppImage"] = updater.ReleaseAsset{
			Name:        "SendBeam-linux-amd64.AppImage",
			DownloadURL: srv.URL + "/download/SendBeam-linux-amd64.AppImage",
			SHA256:      appImageHash,
			Size:        int64(len(newAppImage)),
		}
		data, _ := json.Marshal(manifest)
		sig, _ := updater.SignMinisign(data, testSeed, testPub, "stable.json")

		switch r.URL.Path {
		case "/stable.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		case "/stable.json.minisig":
			_, _ = w.Write([]byte(sig))
		case "/download/SendBeam-linux-amd64.AppImage":
			_, _ = w.Write(newAppImage)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfgStore, _ := config.NewStore(filepath.Join(tempDir, "config"), nil)

	var emittedEvents []UpdateStatus
	var mu sync.Mutex
	emitter := func(name string, data any) {
		if name == UpdateEventName {
			if st, ok := data.(UpdateStatus); ok {
				mu.Lock()
				emittedEvents = append(emittedEvents, st)
				mu.Unlock()
			}
		}
	}

	svc := NewUpdateService(
		emitter,
		cfgStore,
		updater.WithBaseURL(srv.URL),
		updater.WithExecutablePath(targetAppImage),
		updater.WithTargetPlatform("linux", "amd64"),
		updater.WithDesktopFormat("appimage"),
		updater.WithMinisignPublicKey(testPub),
		updater.WithHTTPClient(srv.Client()),
	)

	// In test, set ProductVersion to 1.4.0
	origVer := ProductVersion
	ProductVersion = "1.4.0"
	defer func() { ProductVersion = origVer }()

	// 1. Check
	st, err := svc.CheckUpdate("stable")
	if err != nil {
		t.Fatalf("CheckUpdate failed: %v", err)
	}
	if st.State != "available" {
		t.Fatalf("expected state available, got %q (message: %s)", st.State, st.Message)
	}
	if st.LatestVersion != "1.5.0" {
		t.Fatalf("expected latest version 1.5.0, got %s", st.LatestVersion)
	}

	// 2. Apply
	appliedSt, err := svc.ApplyUpdate()
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}
	if appliedSt.State != "ready_to_restart" || !appliedSt.NeedsRestart {
		t.Fatalf("expected ready_to_restart, got %+v", appliedSt)
	}

	// Verify file was updated on disk
	got, err := os.ReadFile(targetAppImage)
	if err != nil {
		t.Fatalf("ReadFile after update: %v", err)
	}
	if string(got) != "AppImage-v1.5.0-signed-update" {
		t.Fatalf("file content mismatch: got %q", string(got))
	}
}

func TestUpdateService_ManagedByDeb(t *testing.T) {
	t.Setenv("SENDBEAM_PACKAGE_MANAGER", "deb")

	tempDir := t.TempDir()
	cfgStore, _ := config.NewStore(filepath.Join(tempDir, "config"), nil)

	svc := NewUpdateService(
		nil,
		cfgStore,
		updater.WithExecutablePath("/usr/bin/sendbeam"),
	)

	st, err := svc.CheckUpdate("stable")
	if err != nil {
		t.Fatalf("CheckUpdate unexpected error: %v", err)
	}
	if st.State != "managed_by_pkg_manager" {
		t.Fatalf("expected managed_by_pkg_manager, got %q", st.State)
	}
	if st.ManagedByPkgManager != "deb" {
		t.Fatalf("expected deb, got %q", st.ManagedByPkgManager)
	}
}

func TestUpdateService_ChannelSwitching(t *testing.T) {
	tempDir := t.TempDir()
	cfgStore, _ := config.NewStore(filepath.Join(tempDir, "config"), nil)

	svc := NewUpdateService(nil, cfgStore)

	if err := svc.SetChannel("beta"); err != nil {
		t.Fatalf("SetChannel(beta) failed: %v", err)
	}
	if svc.GetStatus().Channel != "beta" {
		t.Fatalf("expected beta channel, got %s", svc.GetStatus().Channel)
	}

	cfg, err := cfgStore.Load()
	if err != nil || cfg.UpdateChannel != "beta" {
		t.Fatalf("config not persisted: cfg=%+v, err=%v", cfg, err)
	}

	if err := svc.SetChannel("stable"); err != nil {
		t.Fatalf("SetChannel(stable) failed: %v", err)
	}
	if svc.GetStatus().Channel != "stable" {
		t.Fatalf("expected stable channel, got %s", svc.GetStatus().Channel)
	}
}
