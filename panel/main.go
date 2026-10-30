// Caddy Sentinel panel: live Caddyfile editor, metrics, IDS/IPS and WAF
// management for Caddy servers running the sentinel module.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/core"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var cfg core.Config
	var debug, showVersion bool
	flag.StringVar(&cfg.Listen, "listen", env("SENTINEL_LISTEN", "127.0.0.1:7600"), "HTTP listen address of the panel")
	flag.StringVar(&cfg.DataDir, "data", env("SENTINEL_DATA", "/var/lib/caddy-sentinel"), "data directory (database, agent token)")
	flag.StringVar(&cfg.CaddyAdmin, "caddy-admin", env("SENTINEL_CADDY_ADMIN", "http://127.0.0.1:2019"), "Caddy admin API (http://host:port or unix//path/to.sock)")
	flag.StringVar(&cfg.Caddyfile, "caddyfile", env("SENTINEL_CADDYFILE", "/etc/caddy/Caddyfile"), "path of the main Caddyfile")
	flag.StringVar(&cfg.CaddyBin, "caddy-bin", env("SENTINEL_CADDY_BIN", "caddy"), "caddy binary for full validation (empty = disabled)")
	flag.StringVar(&cfg.TokenFile, "token-file", env("SENTINEL_TOKEN_FILE", ""), "agent token file (default <data>/agent.token)")
	flag.BoolVar(&debug, "debug", os.Getenv("SENTINEL_DEBUG") != "", "debug logging")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	if showVersion {
		fmt.Println("caddy-sentinel panel", core.Version)
		return
	}

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	e, err := core.NewEngine(cfg, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e.Run(ctx)

	static := web.FS()
	if dir := os.Getenv("SENTINEL_WEB_DIR"); dir != "" {
		// serve the UI from disk (development / customisation)
		static = os.DirFS(dir)
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           core.NewServer(e, static),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// long polls (agent commands) and live streams end on SIGTERM instead
		// of holding up the shutdown; database writes use their own context
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		// let running requests (e.g. an ingest batch being written) finish
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("caddy sentinel panel listening", "addr", cfg.Listen, "caddyfile", cfg.Caddyfile, "caddy_admin", cfg.CaddyAdmin, "data", cfg.DataDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server", "err", err)
		os.Exit(1)
	}
	<-shutdownDone
	if !e.Wait(15 * time.Second) {
		log.Warn("background tasks still running at shutdown")
	}
	_ = e.Store.Close()
	log.Info("caddy sentinel panel stopped")
}
