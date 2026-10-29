// Package api wires up the HTTP router and handlers for the lukscrypt web UI
// and JSON API. All state-mutating vault operations are serialized through a
// single mutex to prevent device-mapper races under concurrent requests.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"lukscrypt/internal/db"
	"lukscrypt/internal/vault"

	"golang.org/x/time/rate"
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
	ctx         context.Context
	version     string
	db          *db.DB
	webFS       embed.FS
	storageDirs []string
	mountDirs   []string
	authUser    string
	authPass    string
	maxSizeGB   int
	trustProxy  bool
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

func NewMux(ctx context.Context, database *db.DB, webFiles embed.FS, storageDirs, mountDirs []string, authUser, authPass string, maxSizeGB int, trustProxy bool, version string) http.Handler {
	h := &handler{
		ctx:            ctx,
		version:        version,
		db:             database,
		webFS:          webFiles,
		storageDirs:    storageDirs,
		mountDirs:      mountDirs,
		authUser:       authUser,
		authPass:       authPass,
		maxSizeGB:      maxSizeGB,
		trustProxy:     trustProxy,
		jobs:           make(map[string]*jobEntry),
		pendingNames:   make(map[string]struct{}),
		unlockLimiters: make(map[string]*unlockEntry),
	}
	go h.cleanupLimiters(ctx)
	go h.cleanupJobs(ctx)

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
	// By-name unlock: for scripts (see README "Unlocking without the
	// browser") so they don't depend on database ids, which can change when
	// the database is rebuilt.
	mux.HandleFunc("POST /api/vaults/by-name/{name}/unlock", h.unlockVaultByName)
	mux.HandleFunc("POST /api/vaults/{id}/lock", h.lockVault)
	mux.HandleFunc("POST /api/vaults/{id}/mount", h.mountVault)
	// Keyslot management — mutates the LUKS header, so handlers take opMu.
	// The existing passphrase required by both is the same brute-force
	// surface as unlock, hence the same rate limiting.
	mux.HandleFunc("POST /api/vaults/{id}/keyslot/add", h.keyslotAdd)
	mux.HandleFunc("POST /api/vaults/{id}/keyslot/remove", h.keyslotRemove)
	// LUKS header details — read-only, no opMu needed (never touches device-mapper).
	// The literal "details" segment comes before {id} because any pattern of the
	// form {id}/<literal> would ambiguously overlap the events/{jobID} route
	// (Go's stdlib mux has no inline regex to constrain wildcards).
	mux.HandleFunc("GET /api/vaults/details/{id}", h.vaultDetails)
	// SSE progress stream — must be registered before /{id} patterns to win specificity
	mux.HandleFunc("GET /api/vaults/events/{jobID}", h.vaultEvents)

	authenticated := h.requestLogger(h.securityHeaders(h.csrfGuard(h.basicAuth(mux))))

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
	jsonOK(w, map[string]string{"status": "ok", "version": h.version})
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

	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		jsonErr(w, "failed to generate job id", http.StatusInternalServerError)
		h.opMu.Lock()
		delete(h.pendingNames, req.Name)
		h.opMu.Unlock()
		return
	}
	jobID := hex.EncodeToString(idBytes[:])
	ch := make(chan vault.ProgressEvent, 64)

	h.jobsMu.Lock()
	h.jobs[jobID] = &jobEntry{ch: ch, created: time.Now()}
	h.jobsMu.Unlock()

	go func() {
		defer func() {
			// vault.Create's own defer closes ch, so we must not close or send
			// on it here — only log. Without this recover, a panic would crash
			// the entire server process.
			if r := recover(); r != nil {
				slog.Error("panic in vault.Create goroutine", "vault", req.Name, "panic", r)
			}
			h.opMu.Lock()
			delete(h.pendingNames, req.Name)
			h.opMu.Unlock()
		}()
		vault.Create(h.ctx, h.db, req.Name, req.Path, req.SizeGB, req.Password, mountPoint, ch)
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
	password, key, ok := h.parseUnlockCredentials(w, r)
	if !ok {
		return
	}
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.unlockResolved(w, password, key, v)
}

// unlockVaultByName is unlockVault addressed by vault name instead of id, for
// documented scripts (see README "Unlocking without the browser").
func (h *handler) unlockVaultByName(w http.ResponseWriter, r *http.Request) {
	if !h.unlockAllowed(r) {
		jsonErr(w, "too many unlock attempts — wait before trying again", http.StatusTooManyRequests)
		return
	}
	password, key, ok := h.parseUnlockCredentials(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !isValidVaultName(name) {
		jsonErr(w, "invalid vault name", http.StatusBadRequest)
		return
	}
	v, err := h.db.GetVaultByName(name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonErr(w, "vault not found", http.StatusNotFound)
		} else {
			jsonErr(w, "database error", http.StatusInternalServerError)
		}
		return
	}
	h.unlockResolved(w, password, key, v)
}

// parseUnlockCredentials decodes the request body and validates the
// password-or-keyfile pair, writing the error response itself. Runs before
// any vault lookup so malformed requests are rejected without leaking
// which vault ids exist.
func (h *handler) parseUnlockCredentials(w http.ResponseWriter, r *http.Request) (password string, key []byte, ok bool) {
	var req struct {
		Password string `json:"password"`
		KeyFile  string `json:"key_file"` // base64-encoded keyfile bytes
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return "", nil, false
	}
	// Exactly one of password / key_file must be provided.
	if (req.Password == "") == (req.KeyFile == "") {
		jsonErr(w, "provide either password or key_file (not both)", http.StatusBadRequest)
		return "", nil, false
	}
	if req.KeyFile != "" {
		key, err := decodeKeyFile(req.KeyFile)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return "", nil, false
		}
		return "", key, true
	}
	if len(req.Password) < 8 {
		jsonErr(w, "password must be at least 8 characters", http.StatusBadRequest)
		return "", nil, false
	}
	return req.Password, nil, true
}

// unlockResolved performs the serialized unlock once the vault record and
// validated credential are in hand.
func (h *handler) unlockResolved(w http.ResponseWriter, password string, key []byte, v *db.Vault) {
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if key != nil {
		if err := vaultUnlockKeyFile(v, key); err != nil {
			jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	} else if err := vaultUnlock(v, password); err != nil {
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

// keyslotAdd adds a passphrase keyslot. The existing passphrase must match a
// valid slot; the vault's data area is untouched. On success the re-read
// header details are returned so the UI can update its keyslot table in one
// round trip.
func (h *handler) keyslotAdd(w http.ResponseWriter, r *http.Request) {
	if !h.unlockAllowed(r) {
		jsonErr(w, "too many attempts — wait before trying again", http.StatusTooManyRequests)
		return
	}
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	var req struct {
		ExistingPassword string `json:"existing_password"`
		ExistingKeyFile  string `json:"existing_key_file"` // base64-encoded
		NewPassword      string `json:"new_password"`
		NewKeyFile       string `json:"new_key_file"` // base64-encoded
		// KeySlot is optional: nil (or absent) lets cryptsetup pick the first
		// free slot. A pointer distinguishes an explicit slot 0 from absent.
		KeySlot *int `json:"key_slot"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Exactly one credential of each kind: existing (password or keyfile)
	// proves authority; new (password or keyfile) becomes the slot's content.
	if (req.ExistingPassword == "") == (req.ExistingKeyFile == "") {
		jsonErr(w, "provide either existing_password or existing_key_file (not both)", http.StatusBadRequest)
		return
	}
	if (req.NewPassword == "") == (req.NewKeyFile == "") {
		jsonErr(w, "provide either new_password or new_key_file (not both)", http.StatusBadRequest)
		return
	}
	if req.NewPassword != "" && len(req.NewPassword) < 8 {
		jsonErr(w, "new_password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	// Decode keyfile uploads up front so malformed input is rejected before
	// any vault lookup or lock acquisition.
	var existingCred, newCred []byte
	if req.NewKeyFile != "" {
		if newCred, err = decodeKeyFile(req.NewKeyFile); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.ExistingKeyFile != "" {
		if existingCred, err = decodeKeyFile(req.ExistingKeyFile); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	slot := -1
	if req.KeySlot != nil {
		if *req.KeySlot < 0 || *req.KeySlot > vault.MaxKeySlot {
			jsonErr(w, fmt.Sprintf("key_slot must be between 0 and %d", vault.MaxKeySlot), http.StatusBadRequest)
			return
		}
		slot = *req.KeySlot
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()

	// Pure-password keeps the validated single-stdin luksAddKey path; any
	// keyfile credential goes through the temp-file variant.
	if req.NewKeyFile == "" && req.ExistingKeyFile == "" {
		if err := vaultAddKey(v, req.ExistingPassword, req.NewPassword, slot); err != nil {
			jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	} else {
		if existingCred == nil {
			existingCred = []byte(req.ExistingPassword)
		}
		if newCred == nil {
			newCred = []byte(req.NewPassword)
		}
		if err := vaultAddKeyFile(v, existingCred, newCred, slot); err != nil {
			jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	d, err := vaultDumpDetails(v)
	if err != nil {
		// The slot was added but the header could not be re-read. Tell the
		// caller the mutation succeeded rather than reporting a plain error.
		slog.Warn("keyslot added but header re-read failed", "vault", v.Name, "err", err)
		jsonErr(w, "keyslot added but failed to re-read header: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, d)
}

// keyslotRemove removes the keyslot at index key_slot. The password must match
// a different, still-valid slot; removing the last valid slot is refused both
// here (409) and by cryptsetup. Returns the re-read header details on success.
func (h *handler) keyslotRemove(w http.ResponseWriter, r *http.Request) {
	if !h.unlockAllowed(r) {
		jsonErr(w, "too many attempts — wait before trying again", http.StatusTooManyRequests)
		return
	}
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	var req struct {
		Password string `json:"password"`
		KeySlot  int    `json:"key_slot"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Password == "" || req.KeySlot < 0 || req.KeySlot > vault.MaxKeySlot {
		jsonErr(w, "password is required and key_slot must be between 0 and 31", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	d, err := vaultDumpDetails(v)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := vault.ValidateKillSlot(d, req.KeySlot); err != nil {
		jsonErr(w, err.Error(), http.StatusConflict)
		return
	}
	if err := vaultKillSlot(v, req.Password, req.KeySlot); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	d, err = vaultDumpDetails(v)
	if err != nil {
		slog.Warn("keyslot removed but header re-read failed", "vault", v.Name, "err", err)
		jsonErr(w, "keyslot removed but failed to re-read header: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, d)
}

// vaultDetails returns the vault's LUKS header information (cipher, hash,
// key size, keyslots, UUID). Only the header is read — no passphrase is
// required and the vault may be locked or unlocked.
func (h *handler) vaultDetails(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid vault id", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	d, err := vaultDumpDetails(v)
	if err != nil {
		// The image file is unreadable or not a LUKS container (e.g. deleted
		// on disk while the DB record remains).
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	jsonOK(w, d)
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
	// Refuse before touching the DB: if the record were removed first, an
	// unlocked vault would vanish from the UI while its image and mounted
	// filesystem stay live on disk.
	if vaultIsUnlocked(v) {
		jsonErr(w, "vault must be locked before deletion", http.StatusUnprocessableEntity)
		return
	}
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
	ip := clientIP(r, h.trustProxy)
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
func (h *handler) cleanupJobs(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.jobsMu.Lock()
			for id, e := range h.jobs {
				if time.Since(e.created) > 30*time.Minute {
					delete(h.jobs, id)
				}
			}
			h.jobsMu.Unlock()
		}
	}
}

// cleanupLimiters removes rate-limiter entries that have been idle for more
// than 10 minutes to prevent unbounded memory growth.
func (h *handler) cleanupLimiters(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.unlockMu.Lock()
			for ip, e := range h.unlockLimiters {
				if time.Since(e.lastSeen) > 10*time.Minute {
					delete(h.unlockLimiters, ip)
				}
			}
			h.unlockMu.Unlock()
		}
	}
}

// clientIP extracts the client IP for rate limiting. X-Forwarded-For is only
// honored when trustProxy is enabled, and then only the last entry is used:
// a trusted proxy appends the real client IP after any client-supplied value,
// so the last entry is the one the proxy added. Honoring the first entry — or
// any XFF value when not behind a proxy — would let an attacker mint a fresh
// rate-limit bucket per request with a spoofed header.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
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
			"ip", clientIP(r, h.trustProxy),
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

// csrfGuard rejects cross-origin state-changing requests. Browsers attach
// cached Basic Auth credentials to every request targeting the origin, so a
// malicious page could otherwise trigger lock/mount/delete side effects via a
// cross-site form POST even though it cannot read the response. Browsers
// always send an Origin header on cross-origin requests; non-browser clients
// (curl, scripts, orchestrators) send none and pass through unaffected.
func (h *handler) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" {
				if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
					jsonErr(w, "cross-origin requests are not allowed", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// vaultIsUnlocked is a package-level indirection over vault.IsUnlocked so
// tests can simulate an unlocked vault without a real /dev/mapper entry.
var vaultIsUnlocked = vault.IsUnlocked

// vaultDumpDetails is a package-level indirection over vault.DumpDetails so
// tests can stub the cryptsetup subprocess.
var vaultDumpDetails = vault.DumpDetails

// vaultAddKey and vaultKillSlot are indirections over vault.AddKey/KillSlot
// for the same reason.
var (
	vaultAddKey   = vault.AddKey
	vaultKillSlot = vault.KillSlot
)

// vaultUnlock, vaultUnlockKeyFile and vaultAddKeyFile follow the same pattern.
var (
	vaultUnlock        = vault.Unlock
	vaultUnlockKeyFile = vault.UnlockKeyFile
	vaultAddKeyFile    = vault.AddKeyFile
)

// decodeKeyFile decodes and validates a base64 keyfile upload: 8 bytes to
// 1 MiB, mirroring the password policy (the content IS the credential).
func decodeKeyFile(b64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("key_file is not valid base64")
	}
	if len(data) < vault.MinKeyFileSize {
		return nil, fmt.Errorf("key_file must be at least %d bytes", vault.MinKeyFileSize)
	}
	if len(data) > vault.MaxKeyFileSize {
		return nil, fmt.Errorf("key_file exceeds maximum size of %d bytes", vault.MaxKeyFileSize)
	}
	return data, nil
}

func (h *handler) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(h.authUser))
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(h.authPass))
		if !ok || userMatch != 1 || passMatch != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="lukscrypt"`)
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
