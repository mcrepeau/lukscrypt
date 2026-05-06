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
	)

	// serverCtx is cancelled on shutdown to stop background goroutines and
	// interrupt any in-progress vault creation (dd, cryptsetup, etc.) so that
	// SSE connections close naturally before Shutdown drains HTTP connections.
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	srv := &http.Server{
		Addr:    ":8080",
		Handler: api.NewMux(serverCtx, database, webFiles, storageDirs, mountDirs, authUser, authPass, maxSizeGB, version),
	}

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

	if err := srv.Shutdown(drainCtx); err != nil {
		slog.Error("shutdown timed out", "err", err)
		os.Exit(1)
	}
	slog.Info("shutdown complete")
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
