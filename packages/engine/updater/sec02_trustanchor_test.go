package updater

// SB-SEC02 trust-anchor rotation tests.
//
// These define the contract the shipped client must satisfy once the
// production pin is replaced, and MUST already hold today so that the
// re-pin commit is a one-line trust-root change CI validates rather than a
// behaviour change nobody tested.
//
// The two keys below are independent disposable test keys generated with
// crypto/rand inside the SEC02 workstream:
//
//   sec02ReplacementSeed/Pub — stands in for the FUTURE replacement key
//   sec02RetiredSeed/Pub     — stands in for the RETIRED compromised key
//
// Neither derives the production anchor; the SEC01 guard re-derives every
// 64-hex literal against the pinned key on every CI run.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	sec02ReplacementSeed = "eca906775603ae696a1a6894e5521ef64cfb83adf6bca20d52347a2c9b034692"
	sec02ReplacementPub  = "RWR9DlQGL0MKUH0OVAYvQwpQfLy32cciskskoMcZe7RbGIsbqTkolluW"
	sec02RetiredSeed     = "1f358376e75c10aedb7871fa8b49aaaa3514d34c56f33a7c9b955cd9d707a565"
	sec02RetiredPub      = "RWS6c3+vrXWoUbpzf6+tdahRwyFPkKRqJky8CCi8qXK55dDkrVKrQpia"
	sec02UnrelatedSeed   = "acf273de0cf0ba62c8da9731fbdd06936a5333decac44625672c6cee6c42a69b"
	sec02UnrelatedPub    = "RWSS1a+NIcD2rpLVr40hwPau8l8hgypPfs5IsmepFAS1CUDE9xLRVE2B"
)

// sec02Server serves signed channel manifests for one signing key and counts
// artifact requests, so "zero downloads on failure" is provable rather than
// asserted.
type sec02Server struct {
	srv       *httptest.Server
	downloads atomic.Int64
	// sigOverride replaces the served signature payload verbatim when
	// hasOverride is set. The boolean matters: an empty signature is itself
	// a malformed-signature case, so "" cannot double as "no override".
	sigOverride string
	hasOverride bool
}

// sec02Manifest renders the manifest body for a channel. Download URLs are
// absolute against the server, so a host-mismatch bug cannot hide.
func (s *sec02Server) manifest(channel string) []byte {
	return []byte(fmt.Sprintf(
		`{"schema_version":1,"version":"9.9.9","channel":%q,`+
			`"assets":{"linux-amd64":{"name":"SendBeam-linux-amd64.AppImage",`+
			`"size":16,"download_url":%q,`+
			`"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}}`,
		channel, s.srv.URL+"/download/SendBeam-linux-amd64.AppImage"))
}

func newSec02Server(t *testing.T, signSeed, signPub string) *sec02Server {
	t.Helper()
	s := &sec02Server{}
	mux := http.NewServeMux()
	for _, ch := range []string{"stable", "beta"} {
		channel := ch
		mux.HandleFunc("/"+channel+".json", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(s.manifest(channel))
		})
		mux.HandleFunc("/"+channel+".json.minisig", func(w http.ResponseWriter, _ *http.Request) {
			if s.hasOverride {
				_, _ = w.Write([]byte(s.sigOverride))
				return
			}
			sig, err := SignMinisign(s.manifest(channel), signSeed, signPub, channel+".json")
			if err != nil {
				t.Errorf("signing fixture for %s: %v", channel, err)
				http.Error(w, "signing failed", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(sig))
		})
	}
	mux.HandleFunc("/download/", func(w http.ResponseWriter, _ *http.Request) {
		s.downloads.Add(1)
		_, _ = w.Write([]byte("artifact-bytes"))
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func newSec02Updater(t *testing.T, s *sec02Server, pinnedPub string) *Updater {
	t.Helper()
	u, err := New("1.0.0", "Akshay7273/sendbeam",
		WithBaseURL(s.srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(filepath.Join(t.TempDir(), "SendBeam-linux-amd64.AppImage")),
		WithDesktopFormat("appimage"),
		WithProductKind(ProductKindDesktop),
		WithMinisignPublicKey(pinnedPub),
		WithHTTPClient(s.srv.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestSec02_ReplacementKeyAccepted: a client pinned to the replacement key
// accepts a replacement-key signature. Baseline the rotation must preserve.
func TestSec02_ReplacementKeyAccepted(t *testing.T) {
	s := newSec02Server(t, sec02ReplacementSeed, sec02ReplacementPub)
	u := newSec02Updater(t, s, sec02ReplacementPub)

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("replacement-key manifest rejected: %v", err)
	}
	if !check.UpdateAvailable {
		t.Fatalf("expected an available update, got %+v", check)
	}
}

// TestSec02_RetiredKeyRejected: a replacement-pinned client must reject a
// RETIRED-key signature. This is what makes rotation meaningful — without it,
// re-pinning changes a label without removing the attacker's capability.
func TestSec02_RetiredKeyRejected(t *testing.T) {
	s := newSec02Server(t, sec02RetiredSeed, sec02RetiredPub)
	u := newSec02Updater(t, s, sec02ReplacementPub)

	check, err := u.Check(context.Background())
	if err == nil {
		t.Fatalf("retired-key signature ACCEPTED by replacement-pinned client: %+v", check)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
	if got := s.downloads.Load(); got != 0 {
		t.Fatalf("artifact downloaded %d time(s) despite retired-key signature", got)
	}
}

// TestSec02_NoFallbackToRetiredAnchor is the explicit no-dual-trust gate: the
// retired-key signature must be rejected on every channel, with no fallback
// path rescuing it.
func TestSec02_NoFallbackToRetiredAnchor(t *testing.T) {
	for _, ch := range []Channel{ChannelStable, ChannelBeta} {
		t.Run(string(ch), func(t *testing.T) {
			s := newSec02Server(t, sec02RetiredSeed, sec02RetiredPub)
			u, err := New("1.0.0", "Akshay7273/sendbeam",
				WithBaseURL(s.srv.URL),
				WithChannel(ch),
				WithTargetPlatform("linux", "amd64"),
				WithExecutablePath(filepath.Join(t.TempDir(), "a.AppImage")),
				WithDesktopFormat("appimage"),
				WithProductKind(ProductKindDesktop),
				WithMinisignPublicKey(sec02ReplacementPub),
				WithHTTPClient(s.srv.Client()),
			)
			if err != nil {
				t.Fatal(err)
			}
			if check, err := u.Check(context.Background()); err == nil {
				t.Fatalf("retired-key signature accepted (no-fallback violated): %+v", check)
			}
			if got := s.downloads.Load(); got != 0 {
				t.Fatalf("artifact downloaded %d time(s) on rejection", got)
			}
		})
	}
}

// TestSec02_RejectsMismatchedKeyEitherDirection: a pin only ever authorizes
// its own key. Checks both directions so the test cannot pass by accident
// when only one side is wired correctly.
func TestSec02_RejectsMismatchedKeyEitherDirection(t *testing.T) {
	t.Run("replacement signature under retired pin", func(t *testing.T) {
		s := newSec02Server(t, sec02ReplacementSeed, sec02ReplacementPub)
		u := newSec02Updater(t, s, sec02RetiredPub)
		if _, err := u.Check(context.Background()); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got: %v", err)
		}
	})
	t.Run("retired signature under replacement pin", func(t *testing.T) {
		s := newSec02Server(t, sec02RetiredSeed, sec02RetiredPub)
		u := newSec02Updater(t, s, sec02ReplacementPub)
		if _, err := u.Check(context.Background()); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got: %v", err)
		}
	})
}

// TestSec02_UnrelatedKeyRejected: a third key, unrelated to both sides, must
// also fail — proving the check is a real cryptographic comparison rather
// than an "is it one of our known keys" lookup.
func TestSec02_UnrelatedKeyRejected(t *testing.T) {
	s := newSec02Server(t, sec02UnrelatedSeed, sec02UnrelatedPub)
	u := newSec02Updater(t, s, sec02ReplacementPub)
	if _, err := u.Check(context.Background()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
	if got := s.downloads.Load(); got != 0 {
		t.Fatalf("artifact downloaded %d time(s) on invalid signature", got)
	}
}

// TestSec02_MalformedSignatureFailsClosed: torn and truncated signature
// payloads must fail closed with zero artifact requests.
func TestSec02_MalformedSignatureFailsClosed(t *testing.T) {
	cases := map[string]string{
		"two lines":      "untrusted comment: torn\nAAAA\n",
		"empty":          "",
		"not base64":     "untrusted comment: x\n!!!!\nuntrusted comment: y\n!!!!\n",
		"truncated part": "untrusted comment: x\nQUJD\nuntrusted comment: y\nQUJD\n",
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSec02Server(t, sec02ReplacementSeed, sec02ReplacementPub)
			s.sigOverride = payload
			s.hasOverride = true
			u := newSec02Updater(t, s, sec02ReplacementPub)
			if _, err := u.Check(context.Background()); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("expected ErrInvalidSignature, got: %v", err)
			}
			if got := s.downloads.Load(); got != 0 {
				t.Fatalf("artifact downloaded %d time(s) on malformed signature", got)
			}
		})
	}
}

// TestSec02_MalformedPinnedKeyFailsClosed: a client whose pin is corrupt
// must fail closed for every signature, not silently fail open. This is the
// configuration-error case: a partially-applied re-pin, a truncated
// minisign.pub, or a wrong constant must not degrade into "accept anything".
func TestSec02_MalformedPinnedKeyFailsClosed(t *testing.T) {
	badPins := map[string]string{
		"empty":            "",
		"not base64":       "!!!!not-a-key!!!!",
		"short raw key":    "AAAA",
		"wrong alg prefix": "TW9ub2RpZ2l0IGtleSB2YWx1ZSBoZXJlIGZvciB0ZXN0aW5n",
	}
	for name, pin := range badPins {
		t.Run(name, func(t *testing.T) {
			s := newSec02Server(t, sec02ReplacementSeed, sec02ReplacementPub)
			u := newSec02Updater(t, s, pin)
			_, err := u.Check(context.Background())
			if err == nil {
				t.Fatal("CHECK SUCCEEDED WITH A MALFORMED PINNED KEY (fail-open)")
			}
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("expected ErrInvalidSignature, got: %v", err)
			}
			if got := s.downloads.Load(); got != 0 {
				t.Fatalf("artifact downloaded %d time(s) with a malformed pin", got)
			}
		})
	}
}

// TestSec02_TamperedPayloadFailsClosed: modifying the manifest after signing
// must fail (the rotation must not weaken payload integrity).
func TestSec02_TamperedPayloadFailsClosed(t *testing.T) {
	s := newSec02Server(t, sec02ReplacementSeed, sec02ReplacementPub)
	u := newSec02Updater(t, s, sec02ReplacementPub)
	base := u.BaseURL
	_ = base
	// Serve a valid signature over a manifest whose version was changed.
	mux := http.NewServeMux()
	mux.HandleFunc("/stable.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Replace(string(s.manifest("stable")), "9.9.9", "9.9.8", 1)))
	})
	mux.HandleFunc("/stable.json.minisig", func(w http.ResponseWriter, _ *http.Request) {
		sig, err := SignMinisign(s.manifest("stable"), sec02ReplacementSeed, sec02ReplacementPub, "stable.json")
		if err != nil {
			t.Errorf("signing fixture: %v", err)
			return
		}
		_, _ = w.Write([]byte(sig))
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, _ *http.Request) {
		s.downloads.Add(1)
	})
	tampered := httptest.NewServer(mux)
	defer tampered.Close()
	u.BaseURL = tampered.URL
	u.HTTPClient = tampered.Client()

	if _, err := u.Check(context.Background()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered payload, got: %v", err)
	}
	if got := s.downloads.Load(); got != 0 {
		t.Fatalf("artifact downloaded %d time(s) on tampered payload", got)
	}
}
