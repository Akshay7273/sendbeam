package updater

// SEC01 Phase E negative tests: the updater client must fail closed when the
// signature is missing or malformed, and the failure must carry the precise
// reason (discriminable by message) so a removed fetch-stage check cannot
// hide behind the downstream parser failure. The artifact endpoint must
// never be contacted in any of these states.
//
// Signing credentials are the independent disposable SEC01 test key
// (sec01_testkeys_test.go); the production anchor is never referenced.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type sigProbe struct {
	srv       *httptest.Server
	manifest  []byte
	sigBody   string // served verbatim at /.minisig (may be empty)
	sigStatus int    // HTTP status for the .minisig endpoint
	downloads atomic.Int64
}

func newSigProbe(t *testing.T, sigStatus int, sigBody string) *sigProbe {
	t.Helper()
	data := []byte(`{"schema_version":1,"version":"9.0.0","channel":"stable","assets":{}}`)
	p := &sigProbe{manifest: data, sigBody: sigBody, sigStatus: sigStatus}
	mux := http.NewServeMux()
	mux.HandleFunc("/stable.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(p.manifest)
	})
	mux.HandleFunc("/stable.json.minisig", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(p.sigStatus)
		_, _ = w.Write([]byte(p.sigBody))
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, _ *http.Request) {
		p.downloads.Add(1)
		_, _ = w.Write([]byte("impostor-artifact"))
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func newSigProbeUpdater(t *testing.T, p *sigProbe) *Updater {
	t.Helper()
	target := filepath.Join(t.TempDir(), "SendBeam-linux-amd64.AppImage")
	u, err := New("1.4.0", "Akshay7273/sendbeam",
		WithBaseURL(p.srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(target),
		WithDesktopFormat("appimage"),
		WithProductKind(ProductKindDesktop),
		WithMinisignPublicKey(sec01TestPub),
		WithHTTPClient(p.srv.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// assertSigFailure: check must fail with ErrInvalidSignature carrying the
// expected reason substring, and the artifact endpoint must never have been
// contacted.
func assertSigFailure(t *testing.T, p *sigProbe, wantSubstr string) {
	t.Helper()
	u := newSigProbeUpdater(t, p)
	check, err := u.Check(context.Background())
	if err == nil {
		t.Fatalf("unsigned/malformed manifest accepted: %+v", check)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("failure for the wrong reason: %v (want substring %q)", err, wantSubstr)
	}
	if got := p.downloads.Load(); got != 0 {
		t.Fatalf("artifact endpoint contacted %d time(s) despite missing/invalid signature", got)
	}
}

// TestUpdater_MissingSignatureFailsClosed: a 404 on <channel>.json.minisig
// must fail with the explicit missing-signature reason. Mutation-discriminated:
// removing the signature HTTP-status check in fetchSignedManifest routes this
// case into the signature-parse error instead, failing this test.
func TestUpdater_MissingSignatureFailsClosed(t *testing.T) {
	assertSigFailure(t, newSigProbe(t, http.StatusNotFound, ""), "missing signature file")
}

// TestUpdater_EmptySignatureFailsClosed: an empty signature payload must be
// rejected as invalid, not treated as a missing fetch or swallowed.
func TestUpdater_EmptySignatureFailsClosed(t *testing.T) {
	assertSigFailure(t, newSigProbe(t, http.StatusOK, ""), "invalid signature format")
}

// TestUpdater_GarbageSignatureFailsClosed: a non-minisign signature payload
// must be rejected as invalid signature format (parse stage), with zero
// artifact contact.
func TestUpdater_GarbageSignatureFailsClosed(t *testing.T) {
	assertSigFailure(t, newSigProbe(t, http.StatusOK, "not a minisign signature"), "invalid signature format")
}

// TestUpdater_ServerErrorSignatureFailsClosed: a 5xx on the signature
// endpoint must fail closed with the missing-signature reason (the client
// must not retry-with-acceptance or proceed unsigned).
func TestUpdater_ServerErrorSignatureFailsClosed(t *testing.T) {
	assertSigFailure(t, newSigProbe(t, http.StatusInternalServerError, ""), "missing signature file")
}
