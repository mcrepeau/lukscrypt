package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"lukscrypt/internal/api"
	"lukscrypt/internal/db"
	"lukscrypt/internal/vault"
)

//go:embed web/index.html
var webFiles embed.FS

// version is overridden at build time via:
//
//	go build -ldflags="-X main.version=v1.2.3"
var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/data/lukscrypt.db"
	}

	storageDirs := parseList(os.Getenv("VAULT_STORAGE_DIRS"), "/vaults")
	mountDirs := parseList(os.Getenv("VAULT_MOUNT_DIRS"), "/mnt")
	maxSizeGB := parseMaxSize(os.Getenv("VAULT_MAX_SIZE_GB"), 100)

	authUser := os.Getenv("AUTH_USER")
	if authUser == "" {
		authUser = "admin"
	}
	authPass := os.Getenv("AUTH_PASSWORD")
	if authPass == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			slog.Error("failed to generate auth password", "err", err)
			os.Exit(1)
		}
		authPass = hex.EncodeToString(b)
		slog.Warn("AUTH_PASSWORD not set — generated password", "user", authUser, "password", authPass)
	}

	// TRUST_PROXY must be enabled explicitly: honoring X-Forwarded-For by
	// default would let clients spoof their IP to the unlock rate limiter.
	trustProxy := parseBool(os.Getenv("TRUST_PROXY"), false)

	// AUTO_LOCK_HOURS: maximum time a vault may stay unlocked; 0 (default)
	// disables auto-lock. A float allows sub-hour policies (e.g. 0.5 = 30 min).
	autoLockHours := parseAutoLockHours(os.Getenv("AUTO_LOCK_HOURS"))

	database, err := db.Open(dbPath)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	slog.Info("starting",
		"version", version,
		"storage_dirs", storageDirs,
		"mount_dirs", mountDirs,
		"max_vault_size_gb", maxSizeGB,
		"trust_proxy", trustProxy,
		"auto_lock_hours", autoLockHours,
	)

	// serverCtx is cancelled on shutdown to stop background goroutines and
	// interrupt any in-progress vault creation (dd, cryptsetup, etc.) so that
	// SSE connections close naturally before Shutdown drains HTTP connections.
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	srv := newHTTPServer(api.NewMux(serverCtx, database, webFiles, storageDirs, mountDirs, authUser, authPass, maxSizeGB, trustProxy, autoLockHours, version))

	go func() {
		slog.Info("lukscrypt listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	sig := <-quit
	slog.Info("received signal, shutting down", "signal", sig.String())

	// Cancel first: in-flight vault operations are interrupted, cleanup
	// goroutines exit, and open SSE streams receive any final events and close.
	// Shutdown then waits for remaining HTTP connections to drain.
	serverCancel()

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer drainCancel()
	drainErr := srv.Shutdown(drainCtx)
	if drainErr != nil {
		// Don't exit yet: locking the vaults below is more important than a
		// clean HTTP drain. Exit with a non-zero status afterwards.
		slog.Error("HTTP shutdown timed out; continuing to vault locking", "err", drainErr)
	}

	// Graceful shutdown locking: close every unlocked vault so no stale
	// device-mapper or loop devices remain on the host kernel (they outlive
	// the container). This runs after the HTTP drain so no unlock/lock
	// handler is in flight; the operation mutex's protection is therefore
	// not needed. Requires the container's stop grace period to exceed the
	// drain timeout — otherwise the SIGKILL lands here (see stop_grace_period
	// in docker-compose.yml).
	slog.Info("locking unlocked vaults for shutdown")
	lockCtx, lockCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer lockCancel()
	failures := vault.LockAllUnlocked(lockCtx, database)
	for _, f := range failures {
		slog.Error("shutdown lock failed — vault may remain open on the host", "vault", f.Vault, "err", f.Err)
	}
	switch {
	case len(failures) > 0:
		slog.Warn("shutdown complete with vaults still unlocked", "count", len(failures))
	case drainErr != nil:
		// drained uncleanly but all vaults locked
	default:
		slog.Info("shutdown complete — all vaults locked")
	}
	if drainErr != nil {
		os.Exit(1)
	}
}

// newHTTPServer builds the HTTP server with defensive timeouts. Without them,
// slowloris-style connections — even unauthenticated ones — are held open
// indefinitely and also stall srv.Shutdown() during the graceful drain.
//
// WriteTimeout is deliberately left at zero: it is an absolute per-response
// deadline, and the SSE progress stream (/api/vaults/events/{jobID}) is a
// long-lived response — a vault creation on a filesystem without fallocate
// (dd fallback) can stream progress for tens of minutes on large images.
// ReadHeaderTimeout/ReadTimeout only bound reading the request and
// IdleTimeout only applies between keep-alive requests, so none of them
// affect an in-flight SSE stream.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,  // slowloris: bound header reading
		ReadTimeout:       30 * time.Second,  // whole request incl. body (keyfile uploads)
		IdleTimeout:       120 * time.Second, // keep-alive connections between requests
	}
}

// parseMaxSize parses a positive integer env var, falling back to defaultVal.
// Exits the process if the value is present but not a positive integer.
func parseMaxSize(env string, defaultVal int) int {
	if env == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(env)
	if err != nil || n <= 0 {
		slog.Error("VAULT_MAX_SIZE_GB must be a positive integer", "value", env)
		os.Exit(1)
	}
	return n
}

// parseBool parses an optional boolean env var, falling back to defaultVal.
// Exits the process if the value is present but not a valid boolean.
func parseBool(env string, defaultVal bool) bool {
	if env == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(env)
	if err != nil {
		slog.Error("environment variable must be a boolean (true/false/1/0)", "value", env)
		os.Exit(1)
	}
	return b
}

// parseAutoLockHours parses AUTO_LOCK_HOURS: empty or 0 disables auto-lock;
// negative values are rejected. A float allows sub-hour policies (0.5 = 30 min).
func parseAutoLockHours(env string) float64 {
	if env == "" {
		return 0
	}
	v, err := strconv.ParseFloat(env, 64)
	if err != nil || v < 0 {
		slog.Error("AUTO_LOCK_HOURS must be a non-negative number of hours (e.g. 6 or 0.5; 0 disables)", "value", env)
		os.Exit(1)
	}
	return v
}

// parseList splits a comma-separated env var and falls back to defaultVal if empty.
func parseList(env, defaultVal string) []string {
	var out []string
	for _, s := range strings.Split(env, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = []string{defaultVal}
	}
	return out
}
