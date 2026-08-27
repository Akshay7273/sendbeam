package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdater_CheckAndApply(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam")

	oldBinary := []byte("sendbeam-v1.3.0")
	if err := os.WriteFile(targetBinary, oldBinary, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newBinary := []byte("sendbeam-v1.4.0-updated")
	tarData := createTestTarGz(t, "sendbeam", newBinary)
	tarHash := sha256Hex(tarData)

	archiveName := "sendbeam-cli-linux-amd64.tar.gz"

	// Mock server
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/Akshay7273/sendbeam/releases":
			releases := []map[string]any{
				{
					"tag_name":     "v1.4.0",
					"prerelease":   false,
					"published_at": time.Now().Format(time.RFC3339),
					"body":         "v1.4.0 release notes",
					"assets": []map[string]any{
						{
							"name":                 archiveName,
							"size":                 len(tarData),
							"browser_download_url": srv.URL + "/download/" + archiveName,
						},
						{
							"name":                 "SHA256SUMS.txt",
							"size":                 100,
							"browser_download_url": srv.URL + "/download/SHA256SUMS.txt",
						},
					},
				},
				{
					"tag_name":     "v1.5.0-beta.1",
					"prerelease":   true,
					"published_at": time.Now().Format(time.RFC3339),
					"body":         "v1.5.0 beta notes",
					"assets": []map[string]any{
						{
							"name":                 archiveName,
							"size":                 len(tarData),
							"browser_download_url": srv.URL + "/download/" + archiveName,
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(releases)
		case "/download/SHA256SUMS.txt":
			manifest := fmt.Sprintf("%s  %s\n", tarHash, archiveName)
			_, _ = w.Write([]byte(manifest))
		case "/download/" + archiveName:
			_, _ = w.Write(tarData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Test 1: Stable channel from v1.3.0 -> finds v1.4.0 (and ignores v1.5.0-beta.1)
	u, err := New(
		"1.3.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithGitHubAPI(true),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetBinary),
		WithHTTPClient(srv.Client()),
	)
	if err != nil {
		t.Fatalf("New updater: %v", err)
	}

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !check.UpdateAvailable {
		t.Fatalf("expected update to be available, message: %s", check.Message)
	}
	if check.LatestVersion.String() != "1.4.0" {
		t.Fatalf("expected latest version 1.4.0 on stable channel, got %s", check.LatestVersion)
	}
	if check.TargetAsset == nil || check.TargetAsset.SHA256 != tarHash {
		t.Fatalf("target asset sha256 mismatch: got %v, expected %s", check.TargetAsset, tarHash)
	}

	// Apply update
	if err := u.Apply(context.Background(), check); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify file on disk was updated
	updated, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile after apply: %v", err)
	}
	if !bytes.Equal(updated, newBinary) {
		t.Fatalf("binary on disk not updated: got %q", string(updated))
	}

	// Test 2: Checking when already on 1.4.0 on stable channel -> no update
	uCurrent, _ := New(
		"1.4.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithGitHubAPI(true),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetBinary),
		WithHTTPClient(srv.Client()),
	)
	checkCurrent, err := uCurrent.Check(context.Background())
	if err != nil {
		t.Fatalf("Check on current version failed: %v", err)
	}
	if checkCurrent.UpdateAvailable {
		t.Fatalf("expected no update on current version, got updateAvailable=true")
	}

	// Test 3: Checking on Beta channel from 1.4.0 -> finds 1.5.0-beta.1
	uBeta, _ := New(
		"1.4.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithGitHubAPI(true),
		WithChannel(ChannelBeta),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetBinary),
		WithHTTPClient(srv.Client()),
	)
	checkBeta, err := uBeta.Check(context.Background())
	if err != nil {
		t.Fatalf("Check on beta failed: %v", err)
	}
	if !checkBeta.UpdateAvailable {
		t.Fatalf("expected beta update available, got false (%s)", checkBeta.Message)
	}
	if checkBeta.LatestVersion.String() != "1.5.0-beta.1" {
		t.Fatalf("expected beta version 1.5.0-beta.1, got %s", checkBeta.LatestVersion)
	}
}

func TestUpdater_DevVersion(t *testing.T) {
	u, err := New("dev", "Akshay7273/sendbeam")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check on dev version failed: %v", err)
	}
	if check.UpdateAvailable {
		t.Fatal("dev version should not report automatic update available")
	}
}

func TestUpdater_SignedChannelManifest_HappyPath(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam")

	oldBinary := []byte("sendbeam-v1.5.0")
	if err := os.WriteFile(targetBinary, oldBinary, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newBinary := []byte("sendbeam-v1.6.0-signed-update")
	tarData := createTestTarGz(t, "sendbeam", newBinary)
	tarHash := sha256Hex(tarData)

	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := DefaultMinisignPublicKey

	archiveName := "sendbeam-cli-linux-amd64.tar.gz"

	var srv *httptest.Server
	manifest := ChannelManifest{
		SchemaVersion: 1,
		Version:       "1.6.0",
		Channel:       "stable",
		PublishedAt:   time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		ReleaseNotes:  "SendBeam v1.6.0 release",
		Assets: map[string]ReleaseAsset{
			"linux-amd64": {
				Name:        archiveName,
				DownloadURL: "", // populated below
				SHA256:      tarHash,
				Size:        int64(len(tarData)),
			},
		},
	}

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifest.Assets["linux-amd64"] = ReleaseAsset{
			Name:        archiveName,
			DownloadURL: srv.URL + "/download/" + archiveName,
			SHA256:      tarHash,
			Size:        int64(len(tarData)),
		}
		data, _ := json.Marshal(manifest)
		sig, _ := SignMinisign(data, testSeed, testPub, "stable.json")

		switch r.URL.Path {
		case "/stable.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		case "/stable.json.minisig":
			_, _ = w.Write([]byte(sig))
		case "/download/" + archiveName:
			_, _ = w.Write(tarData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, err := New(
		"1.5.0",
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

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !check.UpdateAvailable {
		t.Fatalf("expected update to be available, got: %s", check.Message)
	}
	if check.LatestVersion.String() != "1.6.0" {
		t.Fatalf("expected version 1.6.0, got: %s", check.LatestVersion)
	}

	if err := u.Apply(context.Background(), check); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	updated, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile after apply: %v", err)
	}
	if !bytes.Equal(updated, newBinary) {
		t.Fatalf("target binary content mismatch: %s", string(updated))
	}
}

func TestUpdater_SignedChannelManifest_TamperedPayload(t *testing.T) {
	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := DefaultMinisignPublicKey

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stable.json":
			_, _ = w.Write([]byte(`{"version":"1.6.0","channel":"stable","tampered":true}`))
		case "/stable.json.minisig":
			orig := []byte(`{"version":"1.6.0","channel":"stable"}`)
			sig, _ := SignMinisign(orig, testSeed, testPub, "stable.json")
			_, _ = w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, _ := New(
		"1.5.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithChannel(ChannelStable),
		WithMinisignPublicKey(testPub),
		WithHTTPClient(srv.Client()),
	)

	_, err := u.Check(context.Background())
	if err == nil {
		t.Fatal("expected signature verification error on tampered payload, got nil")
	}
}

func TestUpdater_SignedChannelManifest_DowngradeRejection(t *testing.T) {
	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := DefaultMinisignPublicKey

	manifest := ChannelManifest{
		SchemaVersion: 1,
		Version:       "1.5.0", // older than current 1.6.0
		Channel:       "stable",
		PublishedAt:   time.Now().UTC(),
		Assets: map[string]ReleaseAsset{
			"linux-amd64": {
				Name:        "sendbeam-cli-linux-amd64.tar.gz",
				DownloadURL: "https://example.com/sendbeam.tar.gz",
				SHA256:      "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	data, _ := json.Marshal(manifest)
	sig, _ := SignMinisign(data, testSeed, testPub, "stable.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stable.json":
			_, _ = w.Write(data)
		case "/stable.json.minisig":
			_, _ = w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, _ := New(
		"1.6.0", // running newer version
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithMinisignPublicKey(testPub),
		WithHTTPClient(srv.Client()),
	)

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if check.UpdateAvailable {
		t.Fatal("expected UpdateAvailable to be false for older candidate (downgrade rejection)")
	}
}

func TestUpdater_Desktop_SignedChannelManifest_AppImage(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")

	oldContent := []byte("desktop-v1.5.0-appimage")
	if err := os.WriteFile(targetAppImage, oldContent, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newAppImage := []byte("desktop-v1.6.0-appimage-updated")
	appImageHash := sha256Hex(newAppImage)

	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := DefaultMinisignPublicKey

	var srv *httptest.Server
	manifest := ChannelManifest{
		SchemaVersion: 1,
		Version:       "1.6.0",
		Channel:       "stable",
		PublishedAt:   time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		ReleaseNotes:  "SendBeam Desktop v1.6.0",
		Assets: map[string]ReleaseAsset{
			"SendBeam-linux-amd64.AppImage": {
				Name:        "SendBeam-linux-amd64.AppImage",
				DownloadURL: "",
				SHA256:      appImageHash,
				Size:        int64(len(newAppImage)),
			},
		},
	}

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifest.Assets["SendBeam-linux-amd64.AppImage"] = ReleaseAsset{
			Name:        "SendBeam-linux-amd64.AppImage",
			DownloadURL: srv.URL + "/download/SendBeam-linux-amd64.AppImage",
			SHA256:      appImageHash,
			Size:        int64(len(newAppImage)),
		}
		data, _ := json.Marshal(manifest)
		sig, _ := SignMinisign(data, testSeed, testPub, "stable.json")

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

	u, err := New(
		"1.5.0",
		"Akshay7273/sendbeam",
		WithProductKind(ProductKindDesktop),
		WithBaseURL(srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithDesktopFormat("appimage"),
		WithExecutablePath(targetAppImage),
		WithMinisignPublicKey(testPub),
		WithHTTPClient(srv.Client()),
	)
	if err != nil {
		t.Fatalf("New desktop updater: %v", err)
	}

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Desktop Check failed: %v", err)
	}

	if !check.UpdateAvailable {
		t.Fatalf("expected update to be available, message: %s", check.Message)
	}

	if err := u.Apply(context.Background(), check); err != nil {
		t.Fatalf("Desktop Apply failed: %v", err)
	}

	updated, err := os.ReadFile(targetAppImage)
	if err != nil {
		t.Fatalf("ReadFile after update: %v", err)
	}
	if !bytes.Equal(updated, newAppImage) {
		t.Fatalf("desktop AppImage content not updated: got %q", string(updated))
	}
}

func TestUpdater_Desktop_PackageManager_Detection(t *testing.T) {
	t.Setenv("SENDBEAM_PACKAGE_MANAGER", "deb")

	u, _ := New(
		"1.5.0",
		"Akshay7273/sendbeam",
		WithProductKind(ProductKindDesktop),
		WithExecutablePath("/usr/bin/sendbeam"),
	)

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if check.ManagedByPkgManager != "deb" {
		t.Fatalf("expected ManagedByPkgManager=deb, got %q", check.ManagedByPkgManager)
	}
	if check.UpdateAvailable {
		t.Fatal("expected UpdateAvailable=false when managed by package manager")
	}
}
