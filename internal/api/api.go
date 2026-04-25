// Package api wires up the HTTP router and handlers for the vaultmgr web UI
// and JSON API. All state-mutating vault operations are serialized through a
// single mutex to prevent device-mapper races under concurrent requests.
package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"lukscrypt/internal/db"
	"lukscrypt/internal/vault"
)

type handler struct {
	db          *db.DB
	webFS       embed.FS
	storageDirs []string
	mountDirs   []string
	jobs        map[string]<-chan vault.ProgressEvent
	jobsMu      sync.Mutex
	// opMu serializes vault state-changing operations (lock/unlock/create) to
	// prevent races on the device-mapper subsystem when multiple requests arrive
	// in rapid succession.
	opMu sync.Mutex
}

// vaultResponse is the JSON shape sent to the frontend.
type vaultResponse struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	SizeGB     int    `json:"size_gb"`
	MountPoint string `json:"mount_point"`
	MapperName string `json:"mapper_name"`
	CreatedAt  string `json:"created_at"`
	Unlocked   bool   `json:"unlocked"`
	Mounted    bool   `json:"mounted"`
}

func NewMux(database *db.DB, webFiles embed.FS, storageDirs, mountDirs []string) http.Handler {
	h := &handler{
		db:          database,
		webFS:       webFiles,
		storageDirs: storageDirs,
		mountDirs:   mountDirs,
		jobs:        make(map[string]<-chan vault.ProgressEvent),
	}

	mux := http.NewServeMux()
	// Static
	mux.HandleFunc("GET /{$}", h.index)
	// Config
	mux.HandleFunc("GET /api/config", h.getConfig)
	// Vault CRUD
	mux.HandleFunc("GET /api/vaults", h.listVaults)
	mux.HandleFunc("POST /api/vaults", h.createVault)
	mux.HandleFunc("DELETE /api/vaults/{id}", h.deleteVault)
	// Actions
	mux.HandleFunc("POST /api/vaults/{id}/unlock", h.unlockVault)
	mux.HandleFunc("POST /api/vaults/{id}/lock", h.lockVault)
	// SSE progress stream — must be registered before /{id} patterns to win specificity
	mux.HandleFunc("GET /api/vaults/events/{jobID}", h.vaultEvents)

	return mux
}

func (h *handler) getConfig(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"storage_dirs": h.storageDirs,
		"mount_dirs":   h.mountDirs,
	})
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	data, err := h.webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (h *handler) listVaults(w http.ResponseWriter, r *http.Request) {
	vaults, err := h.db.ListVaults()
	if err != nil {
		jsonErr(w, "failed to list vaults", http.StatusInternalServerError)
		return
	}
	resp := make([]vaultResponse, len(vaults))
	for i, v := range vaults {
		resp[i] = toResponse(v)
	}
	jsonOK(w, resp)
}

func (h *handler) createVault(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		SizeGB   int    `json:"size_gb"`
		Password string `json:"password"`
		MountDir string `json:"mount_dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Path == "" || req.SizeGB <= 0 || req.Password == "" || req.MountDir == "" {
		jsonErr(w, "all fields are required and size_gb must be positive", http.StatusBadRequest)
		return
	}
	if !h.allowedStorageDir(req.Path) {
		jsonErr(w, "storage directory not allowed", http.StatusBadRequest)
		return
	}
	if !h.allowedMountDir(req.MountDir) {
		jsonErr(w, "mount directory not allowed", http.StatusBadRequest)
		return
	}

	// Full mount point is always <mount_dir>/<vault_name>.
	mountPoint := req.MountDir + "/" + req.Name

	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	ch := make(chan vault.ProgressEvent, 64)

	h.jobsMu.Lock()
	h.jobs[jobID] = ch
	h.jobsMu.Unlock()

	go vault.Create(h.db, req.Name, req.Path, req.SizeGB, req.Password, mountPoint, ch)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

func (h *handler) vaultEvents(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobID")

	h.jobsMu.Lock()
	ch, ok := h.jobs[jobID]
	h.jobsMu.Unlock()

	if !ok {
		jsonErr(w, "job not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// Client disconnected. Remove the job entry so the map doesn't
			// grow unbounded; the creation goroutine uses non-blocking sends
			// so it will finish regardless of whether anyone is reading.
			h.jobsMu.Lock()
			delete(h.jobs, jobID)
			h.jobsMu.Unlock()
			return
		case event, open := <-ch:
			if !open {
				// Channel closed — creation finished, clean up job entry.
				h.jobsMu.Lock()
				delete(h.jobs, jobID)
				h.jobsMu.Unlock()
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				log.Printf("marshal event: %v", err)
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *handler) unlockVault(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Password == "" {
		jsonErr(w, "password is required", http.StatusBadRequest)
		return
	}
	v, err := h.db.GetVault(id)
	if err != nil {
		jsonErr(w, "vault not found", http.StatusNotFound)
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if err := vault.Unlock(v, req.Password); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	jsonOK(w, toResponse(*v))
}

func (h *handler) lockVault(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	v, err := h.db.GetVault(id)
	if err != nil {
		jsonErr(w, "vault not found", http.StatusNotFound)
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if err := vault.Lock(v); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	jsonOK(w, toResponse(*v))
}

func (h *handler) deleteVault(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	v, err := h.db.GetVault(id)
	if err != nil {
		jsonErr(w, "vault not found", http.StatusNotFound)
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if err := vault.Delete(v); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := h.db.DeleteVault(id); err != nil {
		jsonErr(w, "failed to remove vault record", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// helpers

func toResponse(v db.Vault) vaultResponse {
	return vaultResponse{
		ID:         v.ID,
		Name:       v.Name,
		Path:       v.Path,
		SizeGB:     v.SizeGB,
		MountPoint: v.MountPoint,
		MapperName: v.MapperName,
		CreatedAt:  v.CreatedAt,
		Unlocked:   vault.IsUnlocked(&v),
		Mounted:    vault.IsMounted(&v),
	}
}

func parseID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *handler) allowedStorageDir(path string) bool {
	for _, d := range h.storageDirs {
		if d == path {
			return true
		}
	}
	return false
}

func (h *handler) allowedMountDir(path string) bool {
	for _, d := range h.mountDirs {
		if d == path {
			return true
		}
	}
	return false
}
