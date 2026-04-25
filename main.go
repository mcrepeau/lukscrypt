package main

import (
	"embed"
	"log"
	"net/http"
	"os"
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

	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	log.Printf("storage dirs: %v", storageDirs)
	log.Printf("mount dirs: %v", mountDirs)
	addr := ":8080"
	log.Printf("vaultmgr listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, api.NewMux(database, webFiles, storageDirs, mountDirs)))
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
