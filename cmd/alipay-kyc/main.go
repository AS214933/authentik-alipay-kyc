package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/authentik-alipay-kyc/internal/alipay"
	"github.com/example/authentik-alipay-kyc/internal/authentik"
	"github.com/example/authentik-alipay-kyc/internal/config"
	"github.com/example/authentik-alipay-kyc/internal/oidc"
	"github.com/example/authentik-alipay-kyc/internal/server"
	"github.com/example/authentik-alipay-kyc/internal/stats"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: config.LogLevelFromEnv("LOG_LEVEL", slog.LevelInfo),
	}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	oidcClient, err := oidc.New(ctx, cfg.OIDC)
	if err != nil {
		logger.Error("configure oidc", "error", err)
		os.Exit(1)
	}

	statsStore, err := stats.NewStore(cfg.StatsFile)
	if err != nil {
		logger.Error("configure stats store", "error", err)
		os.Exit(1)
	}

	app := server.New(server.Dependencies{
		Config:     cfg,
		Logger:     logger,
		OIDC:       oidcClient,
		Authentik:  authentik.NewClient(cfg.Authentik),
		Alipay:     alipay.NewClient(cfg.Alipay),
		Stats:      statsStore,
		StaticFS:   server.StaticFiles(),
		HTTPClient: http.DefaultClient,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go app.StartKYCWorker(ctx)

	go func() {
		logger.Info("listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown failed", "error", err)
		os.Exit(1)
	}
}
