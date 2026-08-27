// Command sendbeamd serves the SendBeam web bundle over TLS (or reverse-proxies the Vite
// development server), exposes /healthz and /readyz, and hosts the blind signaling endpoint.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sendbeam/server/internal/httpserver"
)

func main() {
	cfg := httpserver.ConfigFromEnv()
	logger := httpserver.BuildLogger(cfg.LogFormat, cfg.LogLevel)

	srv, err := httpserver.New(cfg, logger)
	if err != nil {
		logger.Error("failed to build server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("sendbeamd listening",
			"addr", cfg.Addr,
			"tls", cfg.TLSCert != "",
			"mode", cfg.Mode(),
			"log_format", cfg.LogFormat,
		)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "err", err)
			os.Exit(1)
		}
	}
}
