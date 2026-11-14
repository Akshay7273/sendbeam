// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/updater"
)

// updateProbeServer serves a signed manifest and a payload and records every
// request path it received, so tests can count the updater's real network
// calls (no dial-blocking tricks: the server itself is the evidence).
type updateProbeServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []string
}

func newUpdateProbeServer(t *testing.T, payload []byte) *updateProbeServer {
	t.Helper()
	p := &updateProbeServer{}
	payloadHash := sha256Hex(payload)
	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := updater.DefaultMinisignPublicKey

	var manifest updater.ChannelManifest
	var downloadURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.requests = append(p.requests, r.URL.Path)
		p.mu.Unlock()
		manifest = updater.ChannelManifest{
			SchemaVersion: 1,
			Version:       "99.0.0",
			Channel:       "stable",
			PublishedAt:   time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
			ReleaseNotes:  "SB-R11 probe",
			Assets: map[string]updater.ReleaseAsset{
				"SendBeam-linux-amd64.AppImage": {
					Name:        "SendBeam-linux-amd64.AppImage",
					DownloadURL: downloadURL,
					SHA256:      payloadHash,
					Size:        int64(len(payload)),
				},
			},
		}
		data, _ := json.Marshal(manifest)
		sig, _ := updater.SignMinisign(data, testSeed, testPub, "stable.json")
		switch r.URL.Path {
		case "/stable.json":
			_, _ = w.Write(data)
		case "/stable.json.minisig":
			_, _ = w.Write([]byte(sig))
		case "/download/SendBeam-linux-amd64.AppImage":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	p.srv = srv
	downloadURL = srv.URL + "/download/SendBeam-linux-amd64.AppImage"
	t.Cleanup(srv.Close)
	return p
}

func (p *updateProbeServer) downloadCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, path := range p.requests {
		if path == "/download/SendBeam-linux-amd64.AppImage" {
			n++
		}
	}
	return n
}

func (p *updateProbeServer) checkCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, path := range p.requests {
		if path == "/stable.json" {
			n++
		}
	}
	return n
}

// TestApplyUpdateAfterLocalOnlySwitchIsBlocked is the SB-R11 Part E
// discriminator: Online at CheckUpdate, policy switches to LocalOnly, then
// ApplyUpdate must perform ZERO prohibited egress (no manifest re-fetch, no
// artifact download).
func TestApplyUpdateAfterLocalOnlySwitchIsBlocked(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")
	if err := os.WriteFile(targetAppImage, []byte("AppImage-v1.4.0"), 0755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("AppImage-v99.0.0-should-never-be-downloaded")
	probe := newUpdateProbeServer(t, payload)

	cfgStore, _ := config.NewStore(filepath.Join(tempDir, "config"), nil)

	emitter := func(_ string, _ any) {}

	svc := NewUpdateService(
		emitter,
		cfgStore,
		updater.WithBaseURL(probe.srv.URL),
		updater.WithExecutablePath(targetAppImage),
		updater.WithTargetPlatform("linux", "amd64"),
		updater.WithDesktopFormat("appimage"),
		updater.WithHTTPClient(probe.srv.Client()),
	)

	policy := netpolicy.Online
	svc.SetNetworkPolicyProvider(func() netpolicy.Policy { return policy })

	origVer := ProductVersion
	ProductVersion = "1.4.0"
	defer func() { ProductVersion = origVer }()

	// Step 1: check while Online — egress allowed, update becomes available.
	if _, err := svc.CheckUpdate("stable"); err != nil {
		t.Fatalf("CheckUpdate: %v", err)
	}
	if got := probe.checkCount(); got != 1 {
		t.Fatalf("manifest checks = %d, want 1", got)
	}

	// Step 2: the user switches to LocalOnly before the update is applied.
	policy = netpolicy.LocalOnly

	// Step 3: ApplyUpdate — the effective policy is now LocalOnly, so this
	// must refuse WITHOUT any network egress.
	st, err := svc.ApplyUpdate()
	if err == nil {
		t.Fatalf("ApplyUpdate succeeded under LocalOnly policy: %+v", st)
	}
	if st.State != "skipped_local_only" {
		t.Fatalf("state = %q, want skipped_local_only (error: %v)", st.State, err)
	}
	if got := probe.downloadCount(); got != 0 {
		t.Fatalf("PROHIBITED EGRESS: artifact downloaded %d time(s) under LocalOnly", got)
	}
	if got := probe.checkCount(); got != 1 {
		t.Fatalf("PROHIBITED EGRESS: extra manifest fetch under LocalOnly (%d total)", got)
	}
}
// TestApplyUpdateWithCorruptConfigConfigFailsClosed composes the REAL
// fail-closed policy closure (main.go) with the SB-R11 apply-time gate: a
// corrupt desktop config must degrade to LocalOnly and block the download
// with zero egress — never inherit Online from the earlier check.
func TestApplyUpdateWithCorruptConfigFailsClosed(t *testing.T) {
	tempDir := t.TempDir()
	targetAppImage := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")
	if err := os.WriteFile(targetAppImage, []byte("AppImage-v1.4.0"), 0755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("AppImage-v99.0.0-should-never-be-downloaded")
	probe := newUpdateProbeServer(t, payload)

	cfgDir := filepath.Join(tempDir, "config")
	cfgStore, _ := config.NewStore(cfgDir, nil)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Write a config through the real Save path first, then corrupt the
	// policy value on disk by hand (raw file edit, no Patch — mirrors a
	// user hand-edit or disk damage; Validate() would rightly reject this
	// value through the API).
	if err := cfgStore.Save(config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, config.ConfigFileName)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.Replace(string(raw), "online", "NOT-A-POLICY", 1)
	if corrupt == string(raw) {
		t.Fatal("could not corrupt the config: policy value not found")
	}
	if err := os.WriteFile(cfgPath, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}

	// The provider mirrors main.go's production closure: unreadable or
	// unusable config fails closed to LocalOnly.
	getPolicy := func() netpolicy.Policy {
		cfg, err := cfgStore.Load()
		if err != nil {
			return netpolicy.LocalOnly
		}
		p, err := netpolicy.Parse(cfg.NetworkPolicy)
		if err != nil {
			return netpolicy.LocalOnly
		}
		return p
	}

	svc := NewUpdateService(
		func(_ string, _ any) {},
		cfgStore,
		updater.WithBaseURL(probe.srv.URL),
		updater.WithExecutablePath(targetAppImage),
		updater.WithTargetPlatform("linux", "amd64"),
		updater.WithDesktopFormat("appimage"),
		updater.WithHTTPClient(probe.srv.Client()),
	)
	svc.SetNetworkPolicyProvider(getPolicy)

	origVer := ProductVersion
	ProductVersion = "1.4.0"
	defer func() { ProductVersion = origVer }()

	// CheckUpdate with the corrupt config: skipped (fail-closed), so no
	// update becomes available and ApplyUpdate must refuse without egress.
	st, err := svc.CheckUpdate("stable")
	if err != nil {
		t.Fatalf("CheckUpdate with corrupt config: %v", err)
	}
	if st.State != "skipped_local_only" {
		t.Fatalf("state = %q, want skipped_local_only under corrupt config", st.State)
	}
	if got := probe.checkCount(); got != 0 {
		t.Fatalf("PROHIBITED EGRESS: manifest fetched %d time(s) with corrupt config", got)
	}

	st, err = svc.ApplyUpdate()
	if err == nil {
		t.Fatalf("ApplyUpdate succeeded with corrupt config: %+v", st)
	}
	if got := probe.downloadCount(); got != 0 {
		t.Fatalf("PROHIBITED EGRESS: artifact downloaded under corrupt config")
	}
}
