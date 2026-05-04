// Package api wires up the HTTP router and handlers for the vaultmgr web UI
// and JSON API. All state-mutating vault operations are serialized through a
// single mutex to prevent device-mapper races under concurrent requests.
package api

import (
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"lukscrypt/internal/db"
	"lukscrypt/internal/vault"
)

// unlockEntry pairs a rate limiter with a last-seen timestamp for cleanup.
type unlockEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// jobEntry tracks an in-progress vault creation for the SSE progress stream.
type jobEntry struct {
	ch      <-chan vault.ProgressEvent
	created time.Time
}

type handler struct {
	db          *db.DB
	webFS       embed.FS
	storageDirs []string
	mountDirs   []string
	authUser    string
	authPass    string
	maxSizeGB   int
	jobs        map[string]*jobEntry
	jobsMu      sync.Mutex
	// opMu serializes vault state-changing operations (lock/unlock/create) to
	// prevent races on the device-mapper subsystem when multiple requests arrive
	// in rapid succession.
	opMu           sync.Mutex
	pendingNames   map[string]struct{} // names of vaults currently being created
	unlockLimiters map[string]*unlockEntry
	unlockMu       sync.Mutex
}

// responseWriter wraps http.ResponseWriter to capture the status code for
// request logging. It forwards Flush so SSE streams continue to work.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// vaultResponse is the JSON shape sent to the frontend.
type vaultResponse struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	SizeGB         int    `json:"size_gb"`
	MountPoint     string `json:"mount_point"`
	MapperName     string `json:"mapper_name"`
	CreatedAt      string `json:"created_at"`
	Unlocked       bool   `json:"unlocked"`
	Mounted        bool   `json:"mounted"`
	DiskUsedBytes  int64  `json:"disk_used_bytes,omitempty"`
	DiskTotalBytes int64  `json:"disk_total_bytes,omitempty"`
}

func NewMux(database *db.DB, webFiles embed.FS, storageDirs, mountDirs []string, authUser, authPass string, maxSizeGB int) http.Handler {
	h := &handler{
		db:             database,
		webFS:          webFiles,
		storageDirs:    storageDirs,
		mountDirs:      mountDirs,
		authUser:       authUser,
		authPass:       authPass,
		maxSizeGB:      maxSizeGB,
		jobs:           make(map[string]*jobEntry),
		pendingNames:   make(map[string]struct{}),
		unlockLimiters: make(map[string]*unlockEntry),
	}
	go h.cleanupLimiters()
	go h.cleanupJobs()

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
	mux.HandleFunc("POST /api/vaults/{id}/mount", h.mountVault)
	// SSE progress stream — must be registered before /{id} patterns to win specificity
	mux.HandleFunc("GET /api/vaults/events/{jobID}", h.vaultEvents)

	authenticated := h.requestLogger(h.securityHeaders(h.basicAuth(mux)))

	// /healthz is unauthenticated so container orchestrators can probe it without credentials.
	top := http.NewServeMux()
	top.HandleFunc("GET /healthz", h.healthz)
	top.Handle("/", authenticated)
	return top
}

func (h *handler) healthz(w http.ResponseWriter, r *http.Request) {
	if err := h.db.Ping(); err != nil {
		jsonErr(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
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
	mounts := vault.ReadMounts()
	resp := make([]vaultResponse, len(vaults))
	for i, v := range vaults {
		resp[i] = toResponse(v, mounts)
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
	if len(req.Password) < 8 {
		jsonErr(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if req.SizeGB > h.maxSizeGB {
		jsonErr(w, fmt.Sprintf("size_gb exceeds maximum allowed size of %d GB", h.maxSizeGB), http.StatusBadRequest)
		return
	}
	if !isValidVaultName(req.Name) {
		jsonErr(w, "vault name may only contain lowercase letters, numbers, and hyphens (max 64 chars)", http.StatusBadRequest)
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

	// Reserve the name under opMu so a second concurrent create request for
	// the same name can't race past the "file already exists" check in vault.Create.
	h.opMu.Lock()
	if _, inFlight := h.pendingNames[req.Name]; inFlight {
		h.opMu.Unlock()
		jsonErr(w, "vault creation already in progress for this name", http.StatusConflict)
		return
	}
	h.pendingNames[req.Name] = struct{}{}
	h.opMu.Unlock()

	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	ch := make(chan vault.ProgressEvent, 64)

	h.jobsMu.Lock()
	h.jobs[jobID] = &jobEntry{ch: ch, created: time.Now()}
	h.jobsMu.Unlock()

	go func() {
		defer func() {
			h.opMu.Lock()
			delete(h.pendingNames, req.Name)
			h.opMu.Unlock()
		}()
		vault.Create(h.db, req.Name, req.Path, req.SizeGB, req.Password, mountPoint, ch)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

func (h *handler) vaultEvents(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobID")

	h.jobsMu.Lock()
	entry, ok := h.jobs[jobID]
	h.jobsMu.Unlock()

	if !ok {
		jsonErr(w, "job not found", http.StatusNotFound)
		return
	}
	ch := entry.ch

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
				slog.Error("marshal SSE event", "err", err)
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *handler) unlockVault(w http.ResponseWriter, r *http.Request) {
	if !h.unlockAllowed(r) {
		jsonErr(w, "too many unlock attempts — wait before trying again", http.StatusTooManyRequests)
		return
	}
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
	if len(req.Password) < 8 {
		jsonErr(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if err := vault.Unlock(v, req.Password); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	jsonOK(w, toResponse(*v, vault.ReadMounts()))
}

func (h *handler) lockVault(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if err := vault.Lock(v); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	jsonOK(w, toResponse(*v, vault.ReadMounts()))
}

func (h *handler) mountVault(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if err := vault.Mount(v); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	jsonOK(w, toResponse(*v, vault.ReadMounts()))
}

func (h *handler) deleteVault(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	// Delete the DB record first. If the filesystem cleanup subsequently fails,
	// we log the orphaned files for manual removal — but there is no ghost entry
	// in the DB. Reversing this order would leave a ghost entry pointing at a
	// nonexistent file, which is harder to recover from.
	if err := h.db.DeleteVault(id); err != nil {
		jsonErr(w, "failed to remove vault record", http.StatusInternalServerError)
		return
	}
	if err := vault.Delete(v); err != nil {
		slog.Warn("filesystem cleanup failed after DB delete", "vault", v.Name, "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// helpers

func toResponse(v db.Vault, mounts []byte) vaultResponse {
	unlocked, mounted := vault.StatusIn(&v, mounts)
	resp := vaultResponse{
		ID:         v.ID,
		Name:       v.Name,
		Path:       v.Path,
		SizeGB:     v.SizeGB,
		MountPoint: v.MountPoint,
		MapperName: v.MapperName,
		CreatedAt:  v.CreatedAt,
		Unlocked:   unlocked,
		Mounted:    mounted,
	}
	if resp.Mounted {
		resp.DiskUsedBytes, resp.DiskTotalBytes = vault.DiskUsage(v.MountPoint)
	}
	return resp
}

// lookupVault fetches a vault by ID and writes the appropriate error response
// if it cannot be found. Returns (vault, true) on success, (nil, false) on failure.
func (h *handler) lookupVault(w http.ResponseWriter, id int64) (*db.Vault, bool) {
	v, err := h.db.GetVault(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonErr(w, "vault not found", http.StatusNotFound)
		} else {
			jsonErr(w, "database error", http.StatusInternalServerError)
		}
		return nil, false
	}
	return v, true
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

// unlockAllowed returns true if the request's IP is within its rate limit.
// Each IP gets a burst of 5 attempts; after exhausting the burst, one attempt
// is allowed every 30 seconds. This limits brute-force password guessing while
// still allowing a user to quickly retry after a typo.
func (h *handler) unlockAllowed(r *http.Request) bool {
	ip := clientIP(r)
	h.unlockMu.Lock()
	e, ok := h.unlockLimiters[ip]
	if !ok {
		e = &unlockEntry{limiter: rate.NewLimiter(rate.Every(30*time.Second), 5)}
		h.unlockLimiters[ip] = e
	}
	e.lastSeen = time.Now()
	allowed := e.limiter.Allow()
	h.unlockMu.Unlock()
	return allowed
}

// cleanupJobs removes job entries that have been around for more than 30 minutes.
// This covers the case where a client POSTs to /api/vaults but never connects
// to the SSE endpoint to consume the channel — the goroutine finishes and closes
// the channel, but the map entry would otherwise linger forever.
func (h *handler) cleanupJobs() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.jobsMu.Lock()
		for id, e := range h.jobs {
			if time.Since(e.created) > 30*time.Minute {
				delete(h.jobs, id)
			}
		}
		h.jobsMu.Unlock()
	}
}

// cleanupLimiters removes rate-limiter entries that have been idle for more
// than 10 minutes to prevent unbounded memory growth.
func (h *handler) cleanupLimiters() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.unlockMu.Lock()
		for ip, e := range h.unlockLimiters {
			if time.Since(e.lastSeen) > 10*time.Minute {
				delete(h.unlockLimiters, ip)
			}
		}
		h.unlockMu.Unlock()
	}
}

// clientIP extracts the real client IP, respecting X-Forwarded-For when
// running behind a reverse proxy. Note: X-Forwarded-For can be spoofed if the
// app is directly internet-facing without a trusted proxy stripping the header.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// requestLogger logs method, path, status, and duration for every request.
func (h *handler) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", clientIP(r),
		)
	})
}

// securityHeaders sets defensive HTTP headers on every response.
// CSP permits only same-origin resources; 'unsafe-inline' is required because
// the single-file UI embeds all styles and scripts inline.
func (h *handler) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		hdr.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		hdr.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; "+
				"img-src 'self' data:; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'",
		)
		next.ServeHTTP(w, r)
	})
}

func (h *handler) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(h.authUser))
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(h.authPass))
		if !ok || userMatch != 1 || passMatch != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="vaultmgr"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isValidVaultName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
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
