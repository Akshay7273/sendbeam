// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// archProbeServer serves a SIGNED manifest with an arbitrary asset map and
// counts artifact downloads, so wrong-architecture acceptance and
// signature-failure egress are observable.
type archProbeServer struct {
	srv          *httptest.Server
	signedAssets map[string]ReleaseAsset
	downloads    atomic.Int64
	manifest     ChannelManifest
}

func newArchProbeServer(t *testing.T, version string, assets map[string]ReleaseAsset) *archProbeServer {
	t.Helper()
	p := &archProbeServer{signedAssets: assets}
	testSeed := sec01TestSeed
	testPub := sec01TestPub

	p.manifest = ChannelManifest{
		SchemaVersion: 1,
		Version:       version,
		Channel:       "stable",
		PublishedAt:   time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
		ReleaseNotes:  "SB-R11 arch probe",
		Assets:        assets,
	}

	var srv *httptest.Server
	signWith := testSeed
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, a := range p.manifest.Assets {
			a.DownloadURL = srv.URL + "/download/" + a.Name
			p.manifest.Assets[a.Name] = a
		}
		data, _ := json.Marshal(p.manifest)
		sig, _ := SignMinisign(data, signWith, testPub, "stable.json")
		switch r.URL.Path {
		case "/stable.json":
			_, _ = w.Write(data)
		case "/stable.json.minisig":
			_, _ = w.Write([]byte(sig))
		case "/download/SendBeam-linux-arm64.AppImage":
			p.downloads.Add(1)
			_, _ = w.Write([]byte("arm64-binary-impostor"))
		case "/download/SendBeam-windows-arm64-installer.exe":
			p.downloads.Add(1)
			_, _ = w.Write([]byte("arm64-installer-impostor"))
		default:
			http.NotFound(w, r)
		}
	}))
	p.srv = srv
	t.Cleanup(srv.Close)
	return p
}

func archSha(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// TestUpdater_WrongArchAppImageRejected: a signed manifest that only offers
// an arm64 AppImage must NOT be applied to an amd64 client — asset selection
// must fail closed before any download.
func TestUpdater_WrongArchAppImageRejected(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")
	if err := os.WriteFile(targetAppImage, []byte("AppImage-v1.4.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	impostor := []byte("arm64-binary-impostor")
	probe := newArchProbeServer(t, "99.0.0", map[string]ReleaseAsset{
		"SendBeam-linux-arm64.AppImage": {
			Name:   "SendBeam-linux-arm64.AppImage",
			SHA256: archSha(impostor),
			Size:   int64(len(impostor)),
		},
	})

	u, err := New("1.4.0", "Akshay7273/sendbeam",
		WithBaseURL(probe.srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetAppImage),
		WithDesktopFormat("appimage"),
		WithProductKind(ProductKindDesktop),
		WithMinisignPublicKey(sec01TestPub),
		WithHTTPClient(probe.srv.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}

	check, err := u.Check(context.Background())
	if err == nil {
		t.Fatalf("wrong-arch asset accepted for amd64 client: %+v", check.TargetAsset)
	}
	// Discriminator: the failure must be asset selection, not a signature
	// or version error — the manifest IS authentic and NEWER.
	if !strings.Contains(err.Error(), "no desktop distribution artifact found") {
		t.Fatalf("wrong-arch rejection for the wrong reason: %v", err)
	}
	if check != nil && check.UpdateAvailable {
		t.Fatalf("wrong-arch update reported available: %+v", check)
	}
	if got := probe.downloads.Load(); got != 0 {
		t.Fatalf("wrong-arch artifact downloaded %d time(s)", got)
	}
	// The local binary must be untouched.
	data, err := os.ReadFile(targetAppImage)
	if err != nil || string(data) != "AppImage-v1.4.0" {
		t.Fatal("local target was modified during a refused check")
	}
}

// TestUpdater_WrongArchInstallerRejected: same rule for the Windows
// installer fallback path.
func TestUpdater_WrongArchInstallerRejected(t *testing.T) {
	tempDir := t.TempDir()
	targetExe := filepath.Join(tempDir, "sendbeam-desktop.exe")
	if err := os.WriteFile(targetExe, []byte("desktop-v1.4.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	impostor := []byte("arm64-installer-impostor")
	probe := newArchProbeServer(t, "99.0.0", map[string]ReleaseAsset{
		"SendBeam-windows-arm64-installer.exe": {
			Name:   "SendBeam-windows-arm64-installer.exe",
			SHA256: archSha(impostor),
			Size:   int64(len(impostor)),
		},
	})

	u, err := New("1.4.0", "Akshay7273/sendbeam",
		WithBaseURL(probe.srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("windows", "amd64"),
		WithExecutablePath(targetExe),
		WithDesktopFormat("installer"),
		WithProductKind(ProductKindDesktop),
		WithMinisignPublicKey(sec01TestPub),
		WithHTTPClient(probe.srv.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}

	check, err := u.Check(context.Background())
	if err == nil {
		t.Fatalf("wrong-arch installer accepted for amd64 client: %+v", check.TargetAsset)
	}
	if !strings.Contains(err.Error(), "no desktop distribution artifact found") {
		t.Fatalf("wrong-arch rejection for the wrong reason: %v", err)
	}
	if got := probe.downloads.Load(); got != 0 {
		t.Fatalf("wrong-arch installer downloaded %d time(s)", got)
	}
}

// TestUpdater_ManifestFromWrongKeyRejected: a manifest signed by any key
// other than the pinned verification key must fail closed BEFORE the
// artifact is contacted — the download endpoint must never be hit. (SEC01:
// tests pin an independent disposable key; the production anchor is never
// referenced from test code.)
func TestUpdater_ManifestFromWrongKeyRejected(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")
	if err := os.WriteFile(targetAppImage, []byte("AppImage-v1.4.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("AppImage-v99.0.0-attacker-build")
	probe := newArchProbeServer(t, "99.0.0", map[string]ReleaseAsset{
		"SendBeam-linux-amd64.AppImage": {
			Name:   "SendBeam-linux-amd64.AppImage",
			SHA256: archSha(payload),
			Size:   int64(len(payload)),
		},
	})
	// Re-sign the server's manifest with an attacker-controlled key.
	attackerSeed := "5b02346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ac"

	mux := http.NewServeMux()
	data, _ := json.Marshal(probe.manifest)
	sig, err := SignMinisign(data, attackerSeed, "", "stable.json")
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/stable.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) })
	mux.HandleFunc("/stable.json.minisig", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sig)) })
	probe.srv.Config.Handler = mux

	u, err := New("1.4.0", "Akshay7273/sendbeam",
		WithBaseURL(probe.srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetAppImage),
		WithDesktopFormat("appimage"),
		WithMinisignPublicKey(sec01TestPub),
		WithHTTPClient(probe.srv.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, checkErr := u.Check(context.Background())
	if checkErr == nil {
		t.Fatal("attacker-signed manifest accepted")
	}
	if got := probe.downloads.Load(); got != 0 {
		t.Fatalf("artifact endpoint hit %d time(s) despite invalid manifest signature", got)
	}
}
