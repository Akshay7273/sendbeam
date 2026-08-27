package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/server/internal/signal"
	"github.com/sendbeam/wire"
)

func testRouterWithHub(t *testing.T, cfg Config) (http.Handler, *signal.Hub) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := signal.NewHub(ctx, cfg.Signal, logger)
	h, err := router(ctx, cfg, hub, logger)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	return h, hub
}

func testRouter(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	h, _ := testRouterWithHub(t, cfg)
	return h
}

func TestHealthz(t *testing.T) {
	h := testRouter(t, Config{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %q, want ok", body["status"])
	}
}

func TestReadyz(t *testing.T) {
	h, hub := testRouterWithHub(t, Config{})

	// Normal readiness
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var ready readyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ready); err != nil {
		t.Fatalf("json: %v", err)
	}
	if ready.Status != "ready" || ready.Draining {
		t.Fatalf("expected ready response: %+v", ready)
	}

	// Drain in background
	go func() { _ = hub.Drain(context.Background()) }()
	time.Sleep(10 * time.Millisecond)

	// Draining readiness (503 Service Unavailable)
	recDraining := httptest.NewRecorder()
	h.ServeHTTP(recDraining, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recDraining.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recDraining.Code)
	}
	var draining readyResponse
	if err := json.Unmarshal(recDraining.Body.Bytes(), &draining); err != nil {
		t.Fatalf("json: %v", err)
	}
	if draining.Status != "draining" || !draining.Draining {
		t.Fatalf("expected draining response: %+v", draining)
	}
}

func TestBuildLogger(t *testing.T) {
	l1 := BuildLogger("json", "debug")
	if l1 == nil {
		t.Fatal("expected json logger")
	}
	l2 := BuildLogger("text", "error")
	if l2 == nil {
		t.Fatal("expected text logger")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := testRouter(t, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Error("missing Content-Security-Policy")
	} else if !strings.Contains(got, "wasm-unsafe-eval") {
		t.Errorf("CSP missing wasm-unsafe-eval for hash-wasm: %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestSPAFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := testRouter(t, Config{WebDir: dir})

	// A client-side route with no matching file falls back to index.html.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/send/abc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "<!doctype html>hi" {
		t.Fatalf("body = %q, want index.html contents", body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	h := testRouter(t, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain metrics", got)
	}
	body := rec.Body.String()
	for _, want := range []string{"sendbeam_rooms", "sendbeam_relay_bytes_total", "sendbeam_errors_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestConfigEndpoint(t *testing.T) {
	h := testRouter(t, Config{PublicURL: "https://send.example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got := string(body["publicUrl"]); got != `"https://send.example.com"` {
		t.Errorf("publicUrl = %s, want https://send.example.com", got)
	}
}

func TestConfigEndpointEmpty(t *testing.T) {
	h := testRouter(t, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config.json", nil))
	var body map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if got := string(body["publicUrl"]); got != `""` {
		t.Errorf("publicUrl = %s, want empty when not configured", got)
	}
}

func TestConfigEndpointICEServers(t *testing.T) {
	h := testRouter(t, Config{
		ICEServerURLs: []string{"stun:stun1.example.com:3478", "stun:stun2.example.com:3478"},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		ICEServers []wire.ICEEntry `json:"iceServers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(body.ICEServers) != 1 {
		t.Fatalf("iceServers len = %d, want 1 folded entry", len(body.ICEServers))
	}
	if got := strings.Join(body.ICEServers[0].URLs, ","); got != "stun:stun1.example.com:3478,stun:stun2.example.com:3478" {
		t.Errorf("urls = %q", got)
	}
}

func TestConfigEndpointNoICEServersOmitsEmpty(t *testing.T) {
	h := testRouter(t, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config.json", nil))
	var body struct {
		ICEServers []wire.ICEEntry `json:"iceServers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(body.ICEServers) != 0 {
		t.Fatalf("iceServers len = %d, want 0 when unset", len(body.ICEServers))
	}
}

func TestConfigEndpointInvalidICEServersFailsStartup(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{ICEServerURLs: []string{"://not-a-url"}}
	hub := signal.NewHub(ctx, cfg.Signal, logger)
	if h, err := router(ctx, cfg, hub, logger); err == nil {
		t.Errorf("expected router error for malformed ICE URL, got handler %v", h)
	}
}

func TestModeReporting(t *testing.T) {
	cases := map[string]Config{
		"dev-proxy": {DevProxy: "http://localhost:5173"},
		"static":    {WebDir: "/tmp/x"},
		"api-only":  {},
	}
	for want, cfg := range cases {
		if got := cfg.Mode(); got != want {
			t.Errorf("Mode() = %q, want %q", got, want)
		}
	}
}
