// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// schemaProbeServer serves a signed manifest with caller-controlled schema
// version and channel, and counts downloads.
type schemaProbeServer struct {
	srv       *httptest.Server
	version   string
	schema    int
	channel   string
	downloads int
}

func newSchemaProbeServer(t *testing.T, version string, schema int, channel string) *schemaProbeServer {
	t.Helper()
	p := &schemaProbeServer{version: version, schema: schema, channel: channel}
	testSeed := "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533ad"
	testPub := DefaultMinisignPublicKey

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download/SendBeam-linux-amd64.AppImage" {
			p.downloads++
			_, _ = w.Write([]byte("payload-should-never-download"))
			return
		}
		manifest := ChannelManifest{
			SchemaVersion: p.schema,
			Version:       p.version,
			Channel:       p.channel,
			PublishedAt:   time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
			ReleaseNotes:  "SB-R11 schema probe",
			Assets: map[string]ReleaseAsset{
				"SendBeam-linux-amd64.AppImage": {
					Name:        "SendBeam-linux-amd64.AppImage",
					DownloadURL: srv.URL + "/download/SendBeam-linux-amd64.AppImage",
					SHA256:      archSha([]byte("payload-should-never-download")),
					Size:        29,
				},
			},
		}
		data, _ := json.Marshal(manifest)
		sig, _ := SignMinisign(data, testSeed, testPub, channel+".json")
		switch r.URL.Path {
		case "/stable.json":
			_, _ = w.Write(data)
		case "/stable.json.minisig":
			_, _ = w.Write([]byte(sig))
		case "/beta.json":
			_, _ = w.Write(data)
		case "/beta.json.minisig":
			_, _ = w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	p.srv = srv
	t.Cleanup(srv.Close)
	return p
}

func newSchemaUpdater(t *testing.T, probe *schemaProbeServer, target string, ch Channel) *Updater {
	t.Helper()
	u, err := New("1.4.0", "Akshay7273/sendbeam",
		WithBaseURL(probe.srv.URL),
		WithChannel(ch),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(target),
		WithDesktopFormat("appimage"),
		WithProductKind(ProductKindDesktop),
		WithHTTPClient(probe.srv.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestUpdater_FutureSchemaVersionRejected: a validly-SIGNED manifest with an
// unknown future schema_version must fail closed (unknown dialects are not
// silently misread), with zero artifact downloads.
func TestUpdater_FutureSchemaVersionRejected(t *testing.T) {
	tempDir := t.TempDir()
	target := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")
	if err := os.WriteFile(target, []byte("AppImage-v1.4.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	probe := newSchemaProbeServer(t, "99.0.0", ManifestSchemaVersion+1, "stable")

	u := newSchemaUpdater(t, probe, target, ChannelStable)
	_, err := u.Check(context.Background())
	if err == nil {
		t.Fatal("future-schema manifest accepted")
	}
	if !strings.Contains(err.Error(), "unsupported manifest schema_version") {
		t.Fatalf("rejection for the wrong reason: %v", err)
	}
	if probe.downloads != 0 {
		t.Fatalf("artifact downloaded %d time(s) under future schema", probe.downloads)
	}
}

// TestUpdater_WrongChannelManifestRejected: a manifest signed for the beta
// channel served as stable.json must not drive stable updates.
func TestUpdater_WrongChannelManifestRejected(t *testing.T) {
	tempDir := t.TempDir()
	target := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")
	if err := os.WriteFile(target, []byte("AppImage-v1.4.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	probe := newSchemaProbeServer(t, "99.0.0", ManifestSchemaVersion, "beta")

	u := newSchemaUpdater(t, probe, target, ChannelStable)
	_, err := u.Check(context.Background())
	if err == nil {
		t.Fatal("wrong-channel manifest accepted")
	}
	if !strings.Contains(err.Error(), "does not match requested channel") {
		t.Fatalf("rejection for the wrong reason: %v", err)
	}
	if probe.downloads != 0 {
		t.Fatalf("artifact downloaded %d time(s) under wrong channel", probe.downloads)
	}
}

// TestUpdater_Schema1StillAccepted guards the fix against over-tightening:
// the current production dialect (schema_version 1, matching channel) still
// flows through end-to-end.
func TestUpdater_Schema1StillAccepted(t *testing.T) {
	tempDir := t.TempDir()
	target := filepath.Join(tempDir, "SendBeam-linux-amd64.AppImage")
	if err := os.WriteFile(target, []byte("AppImage-v1.4.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	probe := newSchemaProbeServer(t, "99.0.0", ManifestSchemaVersion, "stable")

	u := newSchemaUpdater(t, probe, target, ChannelStable)
	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("schema-1 manifest rejected: %v", err)
	}
	if !check.UpdateAvailable {
		t.Fatalf("expected update availability: %s", check.Message)
	}
}
