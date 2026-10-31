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
	"os/user"
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
	flag.StringVar(&cfg.DataDir, "data", env("SENTINEL_DATA", "/var/lib/caddy-sentinel"), "data directory (database, mirrors; only the panel's user should be able to read it)")
	flag.StringVar(&cfg.CaddyAdmin, "caddy-admin", env("SENTINEL_CADDY_ADMIN", "http://127.0.0.1:2019"), "Caddy admin API (http://host:port or unix//path/to.sock)")
	flag.StringVar(&cfg.Caddyfile, "caddyfile", env("SENTINEL_CADDYFILE", "/etc/caddy/Caddyfile"), "path of the main Caddyfile")
	caddyBin, set := os.LookupEnv("SENTINEL_CADDY_BIN") // set but empty = full validation off
	if !set {
		caddyBin = "caddy"
	}
	flag.StringVar(&cfg.CaddyBin, "caddy-bin", caddyBin, "caddy binary for full validation (empty = disabled)")
	flag.StringVar(&cfg.StagingDir, "staging", env("SENTINEL_STAGING", ""), "directory for staged configurations, readable by Caddy (default <data>/staging)")
	flag.StringVar(&cfg.TokenFile, "token-file", env("SENTINEL_TOKEN_FILE", ""), "agent token file of the local Caddy, readable by Caddy (default <data>/agent.token)")
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

	checkSeparation(log, cfg)

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

// checkSeparation warns when Caddy could read the panel's database: the
// panel runs as the user caddy (installations before the own user
// caddy-sentinel was introduced) or the data directory is accessible for
// group or others. The Docker image runs both containers with the same
// uid, separated by volumes, so the user name is not checked there.
func checkSeparation(log *slog.Logger, cfg core.Config) {
	_, docker := os.LookupEnv("SENTINEL_CADDY_DATA")
	if u, err := user.Current(); err == nil && u.Username == "caddy" && !docker {
		log.Warn("the panel runs as the same user as Caddy: Caddy – and every editor through the Caddyfile (e.g. file_server) – can read the panel database with all secrets. Run 'sudo caddy-sentinel-update' once: it moves the panel to its own user caddy-sentinel.")
	}
	if st, err := os.Stat(cfg.DataDir); err == nil && st.Mode().Perm()&0o077 != 0 && !docker {
		log.Warn("data directory is accessible for group or others – it should be 0700 (sudo chmod 0700 "+cfg.DataDir+")", "mode", fmt.Sprintf("%#o", st.Mode().Perm()))
	}
}
