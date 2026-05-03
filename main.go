package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	addr := ":8080"
	log.Printf("vaultmgr listening on %s", addr)
	log.Printf("max vault size: %d GB", maxSizeGB)
	log.Fatal(http.ListenAndServe(addr, api.NewMux(database, webFiles, storageDirs, mountDirs, authUser, authPass, maxSizeGB)))
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
