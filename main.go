package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"log"
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

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/data/vaultmgr.db"
	}

	storageDirs := parseList(os.Getenv("VAULT_STORAGE_DIRS"), "/vaults")
	mountDirs   := parseList(os.Getenv("VAULT_MOUNT_DIRS"), "/mnt")
	maxSizeGB   := parseMaxSize(os.Getenv("VAULT_MAX_SIZE_GB"), 100)

	authUser := os.Getenv("AUTH_USER")
	if authUser == "" {
		authUser = "admin"
	}
	authPass := os.Getenv("AUTH_PASSWORD")
	if authPass == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("failed to generate auth password: %v", err)
		}
		authPass = hex.EncodeToString(b)
		log.Printf("AUTH_PASSWORD not set — generated password for user %q: %s", authUser, authPass)
	}

	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	log.Printf("storage dirs: %v", storageDirs)
	log.Printf("mount dirs: %v", mountDirs)
	log.Printf("max vault size: %d GB", maxSizeGB)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: api.NewMux(database, webFiles, storageDirs, mountDirs, authUser, authPass, maxSizeGB),
	}

	go func() {
		log.Printf("vaultmgr listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	sig := <-quit
	log.Printf("received %s, shutting down", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown timed out: %v", err)
	}
	log.Printf("shutdown complete")
}

// parseMaxSize parses a positive integer env var, falling back to defaultVal.
// Exits the process if the value is present but not a positive integer.
func parseMaxSize(env string, defaultVal int) int {
	if env == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(env)
	if err != nil || n <= 0 {
		log.Fatalf("VAULT_MAX_SIZE_GB must be a positive integer, got %q", env)
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
