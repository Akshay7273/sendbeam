// Package httpserver wires the HTTP surface for sendbeamd: health, readiness, security headers,
// metrics, and serving the web app — either from a built directory (prod) or by proxying the
// Vite dev server (dev). The signaling handler mounts on the same router.
package httpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/sendbeam/server/internal/signal"
	"github.com/sendbeam/wire"
)

// Config controls how sendbeamd serves the web app and terminates TLS.
type Config struct {
	Addr            string        // listen address, e.g. ":8443"
	TLSCert         string        // path to TLS cert (PEM); empty => plain HTTP (dev/testing only)
	TLSKey          string        // path to TLS key (PEM)
	WebDir          string        // directory of the built web bundle to serve (prod)
	DevProxy        string        // URL of the Vite dev server to proxy to (dev); overrides WebDir
	PublicURL       string        // public base URL for invite links (e.g. https://send.example.com/); empty = auto-detect from page
	LogFormat       string        // "text" or "json"
	LogLevel        string        // "debug", "info", "warn", "error"
	ShutdownTimeout time.Duration // timeout for graceful shutdown draining

	// ICEServerURLs are STUN (and future TURN) URLs published to clients via /config.json so
	// the web app gathers direct-path candidates against the operator's chosen servers instead
	// of the bundled defaults. Parsed with SENDBEAM_ICE_SERVERS (comma-separated).
	ICEServerURLs []string

	Signal signal.Config // signaling limits + WSS origin allowlist
}

// ConfigFromEnv reads configuration from SENDBEAM_* environment variables with defaults.
func ConfigFromEnv() Config {
	shutdownTimeout := 15 * time.Second
	if d, ok := envDuration("SENDBEAM_SHUTDOWN_TIMEOUT"); ok {
		shutdownTimeout = d
	}

	return Config{
		Addr:            env("SENDBEAM_ADDR", ":8443"),
		TLSCert:         os.Getenv("SENDBEAM_TLS_CERT"),
		TLSKey:          os.Getenv("SENDBEAM_TLS_KEY"),
		WebDir:          os.Getenv("SENDBEAM_WEB_DIR"),
		DevProxy:        os.Getenv("SENDBEAM_WEB_DEV_PROXY"),
		PublicURL:       os.Getenv("SENDBEAM_PUBLIC_URL"),
		LogFormat:       env("SENDBEAM_LOG_FORMAT", "text"),
		LogLevel:        env("SENDBEAM_LOG_LEVEL", "info"),
		ShutdownTimeout: shutdownTimeout,
		ICEServerURLs:   splitList(os.Getenv("SENDBEAM_ICE_SERVERS")),
		Signal:          signal.ConfigFromEnv(),
	}
}

// BuildLogger creates an *slog.Logger based on the configured log format and log level.
func BuildLogger(format, level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if strings.ToLower(format) == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// Mode reports how the web app is being served, for logging.
func (c Config) Mode() string {
	switch {
	case c.DevProxy != "":
		return "dev-proxy"
	case c.WebDir != "":
		return "static"
	default:
		return "api-only"
	}
}

// Server wraps *http.Server with SendBeam's config so it can choose TLS vs plain HTTP.
type Server struct {
	http   *http.Server
	cfg    Config
	hub    *signal.Hub
	cancel context.CancelFunc
}

// New builds a Server with the SendBeam router and sensible timeouts.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	hub := signal.NewHub(ctx, cfg.Signal, logger)
	handler, err := router(ctx, cfg, hub, logger)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Server{
		cfg:    cfg,
		hub:    hub,
		cancel: cancel,
		http: &http.Server{
			Addr:              cfg.Addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
			// No WriteTimeout: signaling/relay use long-lived streaming connections.
		},
	}, nil
}

// Hub returns the server's signaling hub.
func (s *Server) Hub() *signal.Hub {
	return s.hub
}

// ListenAndServe serves over TLS when a cert/key are configured, else plain HTTP.
func (s *Server) ListenAndServe() error {
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return s.http.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server and drains active connections before exit.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.hub != nil {
		_ = s.hub.Drain(ctx)
	}
	s.cancel()
	return s.http.Shutdown(ctx)
}

// configResponse is the shape of /config.json published to the web app.
type configResponse struct {
	PublicURL  string          `json:"publicUrl"`
	LanIP      string          `json:"lanIp"`
	ICEServers []wire.ICEEntry `json:"iceServers"`
}

type readyResponse struct {
	Status      string `json:"status"`
	Rooms       int    `json:"rooms"`
	Connections int    `json:"connections"`
	Draining    bool   `json:"draining"`
}

func router(ctx context.Context, cfg Config, hub *signal.Hub, logger *slog.Logger) (http.Handler, error) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	// Parse and validate ICE config once at startup so a malformed server list fails fast
	// instead of surfacing an empty/misleading config to clients.
	iceEntries, err := wire.ParseICEServers(cfg.ICEServerURLs)
	if err != nil {
		return nil, fmt.Errorf("config: invalid SENDBEAM_ICE_SERVERS: %w", err)
	}

	// Liveness check: returns 200 OK as long as the process is alive.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Readiness check: returns 200 OK during normal operation, and 503 Service Unavailable when draining.
	r.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		m := hub.Metrics()
		draining := hub.IsDraining()
		status := "ready"
		code := http.StatusOK
		if draining {
			status = "draining"
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(readyResponse{
			Status:      status,
			Rooms:       m.Rooms,
			Connections: m.ActiveConnections,
			Draining:    draining,
		})
	})

	r.Get("/config.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// no-cache: clients must never reuse stale ICE config; credential-bearing entries are
		// short-lived and must be re-fetched (see wire.ICEConfigTTL).
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(configResponse{
			PublicURL:  cfg.PublicURL,
			LanIP:      firstLanIP(),
			ICEServers: iceEntries,
		})
	})

	// Signaling endpoint: origin-checked, rate-limited WebSocket rendezvous.
	r.Handle("/ws", hub.Handler(ctx))
	r.Handle("/metrics", hub.MetricsHandler())

	// Web app: dev proxy takes precedence, then a static build dir.
	switch {
	case cfg.DevProxy != "":
		proxy, err := devProxy(cfg.DevProxy)
		if err != nil {
			return nil, err
		}
		r.Handle("/*", proxy)
	case cfg.WebDir != "":
		r.Handle("/*", spaFileServer(cfg.WebDir))
	default:
		logger.Warn("no web source configured; serving /healthz and /readyz only")
	}

	return r, nil
}

// devProxy reverse-proxies everything (including Vite HMR websockets) to the dev server.
func devProxy(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid SENDBEAM_WEB_DEV_PROXY %q: %w", target, err)
	}
	return httputil.NewSingleHostReverseProxy(u), nil
}

// spaFileServer serves static files and falls back to index.html for client routes.
func spaFileServer(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	index := strings.TrimRight(dir, "/") + "/index.html"
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/")
		if path == "" {
			http.ServeFile(w, req, index)
			return
		}
		if _, err := os.Stat(dir + "/" + path); os.IsNotExist(err) {
			http.ServeFile(w, req, index) // SPA deep-link fallback
			return
		}
		fs.ServeHTTP(w, req)
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string) (time.Duration, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

// splitList splits a comma-separated env list, trimming whitespace and dropping empty items.
func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstLanIP returns the first non-loopback IPv4 address, or "" if none is found.
func firstLanIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}
