// Package api wires up the HTTP router and handlers for the lukscrypt web UI
// and JSON API. State-mutating vault operations serialize on a single mutex
// (opMu): lock/unlock/grow/keyslot/delete hold it for the whole operation,
// while the long-running create pipeline runs in a background goroutine and
// instead reserves its vault name and image path under opMu — so concurrent
// creates and imports cannot claim the same identity (which would leave a
// ghost DB record pointing at an image the create's cleanup deleted).
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"lukscrypt/internal/db"
	"lukscrypt/internal/vault"

	"golang.org/x/time/rate"
)

// unlockEntry pairs a rate limiter with a last-seen timestamp for cleanup.
// Shared by the unlock and auth-failure limiters.
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
	// opMu serializes vault state-changing operations to prevent races on the
	// device-mapper subsystem when multiple requests arrive in rapid
	// succession. lock/unlock/grow/keyslot/delete hold it for the whole
	// operation; create holds it only to reserve its identity, because its
	// pipeline (fallocate/dd + cryptsetup + mkfs) can run for a long time.
	opMu sync.Mutex
	// pendingNames/pendingPaths hold the identities of vaults whose creation
	// goroutine is still running, reserved under opMu. Create and import both
	// consult them under opMu, so no record can be inserted for a name or
	// image path that an in-flight create will later clean up.
	pendingNames   map[string]struct{}
	pendingPaths   map[string]struct{}
	unlockLimiters map[string]*unlockEntry
	unlockMu       sync.Mutex
	// authLimiters rate-limits failed Basic Auth attempts per client IP, so
	// the master AUTH_PASSWORD cannot be brute-forced at unlimited speed
	// through any endpoint's 401 responses.
	authLimiters map[string]*unlockEntry
	authMu       sync.Mutex
	// sessions is the in-memory UI login store (single process; a restart
	// just means everyone logs in again). Basic Auth remains valid for API
	// clients — a valid Authorization header passes without a session.
	sessions      map[string]*session
	sessionsMu    sync.Mutex
	sessionIdle   time.Duration // sliding expiry, touched on each request
	sessionMaxAge time.Duration // absolute cap from login
	// autoLockHours is the maximum time a vault may stay unlocked; 0 disables
	// auto-lock. unlockedAt records when each vault was unlocked, so the
	// auto-lock sweep can enforce the policy. In-memory by design: runtime
	// state is derived from the OS, not persisted.
	autoLockHours float64
	unlockedAt    map[int64]time.Time
	unlockedMu    sync.Mutex
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

func NewMux(ctx context.Context, database *db.DB, webFiles embed.FS, storageDirs, mountDirs []string, authUser, authPass string, maxSizeGB int, trustProxy bool, autoLockHours float64, sessionIdle, sessionMaxAge time.Duration, version string) http.Handler {
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
		autoLockHours:  autoLockHours,
		sessionIdle:    sessionIdle,
		sessionMaxAge:  sessionMaxAge,
		sessions:       make(map[string]*session),
		jobs:           make(map[string]*jobEntry),
		pendingNames:   make(map[string]struct{}),
		pendingPaths:   make(map[string]struct{}),
		unlockLimiters: make(map[string]*unlockEntry),
		authLimiters:   make(map[string]*unlockEntry),
		unlockedAt:     make(map[int64]time.Time),
	}
	go h.cleanupLimiters(ctx)
	go h.cleanupJobs(ctx)
	go h.autoLockLoop(ctx)
	go h.cleanupSessions(ctx)

	mux := http.NewServeMux()
	// Static
	mux.HandleFunc("GET /{$}", h.index)
	// Config
	mux.HandleFunc("GET /api/config", h.getConfig)
	// Vault CRUD
	mux.HandleFunc("GET /api/vaults", h.listVaults)
	mux.HandleFunc("POST /api/vaults", h.createVault)
	mux.HandleFunc("POST /api/vaults/import", h.importVault)
	mux.HandleFunc("DELETE /api/vaults/{id}", h.deleteVault)
	// Actions
	mux.HandleFunc("POST /api/vaults/{id}/unlock", h.unlockVault)
	mux.HandleFunc("POST /api/vaults/{id}/lock", h.lockVault)
	mux.HandleFunc("POST /api/vaults/{id}/mount", h.mountVault)
	// Grow is online-safe while mounted; it holds the operation mutex for
	// the whole run so lock/unlock cannot race the resize.
	mux.HandleFunc("POST /api/vaults/{id}/grow", h.growVault)
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
	// Logout (authed: a valid session or Basic Auth is required to reach it)
	mux.HandleFunc("POST /logout", h.logout)
	// API tokens — revocable credentials for scripts/curl (hashed at rest)
	mux.HandleFunc("GET /api/tokens", h.listTokens)
	mux.HandleFunc("POST /api/tokens", h.createToken)
	mux.HandleFunc("DELETE /api/tokens/{id}", h.deleteToken)

	authenticated := h.requestLogger(h.securityHeaders(h.csrfGuard(h.limitBody(h.auth(mux)))))

	// /healthz is unauthenticated so container orchestrators can probe it without
	// credentials. /login is the public UI login page (its POST is rate-limited like
	// any other credential check).
	top := http.NewServeMux()
	top.HandleFunc("GET /healthz", h.healthz)
	top.Handle("GET /login", h.requestLogger(h.securityHeaders(http.HandlerFunc(h.loginPage))))
	top.Handle("POST /login", h.requestLogger(h.securityHeaders(http.HandlerFunc(h.login))))
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

	// Reserve the name and image path under opMu so a concurrent create or
	// import cannot claim the same identity while this creation is in flight:
	// the goroutine below deletes the image on failure, and a DB record
	// pointing at it (e.g. from a racing import) would become a ghost.
	imgPath := filepath.ToSlash(filepath.Join(req.Path, req.Name+".img"))
	h.opMu.Lock()
	if _, inFlight := h.pendingNames[req.Name]; inFlight {
		h.opMu.Unlock()
		jsonErr(w, "vault creation already in progress for this name", http.StatusConflict)
		return
	}
	if _, inFlight := h.pendingPaths[imgPath]; inFlight {
		h.opMu.Unlock()
		jsonErr(w, "vault creation already in progress for this image path", http.StatusConflict)
		return
	}
	h.pendingNames[req.Name] = struct{}{}
	h.pendingPaths[imgPath] = struct{}{}
	h.opMu.Unlock()

	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		jsonErr(w, "failed to generate job id", http.StatusInternalServerError)
		h.releasePending(req.Name, imgPath)
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
			h.releasePending(req.Name, imgPath)
		}()
		vaultCreate(h.ctx, h.db, req.Name, req.Path, req.SizeGB, req.Password, mountPoint, ch)
		// A successfully created vault ends up unlocked and mounted — start its
		// auto-lock window now. (The unlock endpoint marks its own vaults, and
		// the startup scan covers crash-restarts; creation was the missing
		// path, so created vaults were never auto-locked.)
		if v, err := h.db.GetVaultByName(req.Name); err == nil && vaultIsUnlocked(v) {
			h.markUnlocked(v.ID)
			slog.Info("auto-lock: vault unlocked by creation — window starts now", "vault", req.Name)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// releasePending drops the name and image-path reservations of a vault
// creation that finished (or never started). The caller must not hold opMu.
func (h *handler) releasePending(name, imgPath string) {
	h.opMu.Lock()
	delete(h.pendingNames, name)
	delete(h.pendingPaths, imgPath)
	h.opMu.Unlock()
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
			// grow unbounded, but keep draining ch until the creation
			// goroutine closes it: the goroutine's terminal send blocks, and
			// without a drainer it would stall on a full buffer.
			h.jobsMu.Lock()
			delete(h.jobs, jobID)
			h.jobsMu.Unlock()
			for range ch {
			}
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
		KeyFile  string `json:"key_file"` // base64-encoded keyfile bytes
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Exactly one of password / key_file must be provided.
	if (req.Password == "") == (req.KeyFile == "") {
		jsonErr(w, "provide either password or key_file (not both)", http.StatusBadRequest)
		return
	}
	var key []byte
	if req.KeyFile != "" {
		if key, err = decodeKeyFile(req.KeyFile); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if len(req.Password) < 8 {
		jsonErr(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if req.KeyFile != "" {
		if err := vaultUnlockKeyFile(h.ctx, v, key); err != nil {
			jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	} else if err := vaultUnlock(h.ctx, v, req.Password); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// Start (or restart) the auto-lock window for this vault.
	h.markUnlocked(v.ID)
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
	if err := vaultLock(v); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// Manual lock ends the auto-lock window.
	h.clearUnlocked(v.ID)
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
		slog.Info("keyslot added", "vault", v.Name, "slot", slot, "credential", "password")
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
		credKind := "password+keyfile"
		if req.NewKeyFile == "" {
			credKind = "keyfile"
		} else if req.ExistingKeyFile == "" {
			credKind = "password"
		}
		slog.Info("keyslot added", "vault", v.Name, "slot", slot, "credential", credKind)
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
		KeyFile  string `json:"key_file"` // base64-encoded keyfile bytes
		KeySlot  int    `json:"key_slot"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.KeySlot < 0 || req.KeySlot > vault.MaxKeySlot {
		jsonErr(w, "key_slot must be between 0 and 31", http.StatusBadRequest)
		return
	}
	// Exactly one remaining credential — a passphrase or a keyfile, whichever
	// matches a different, still-valid keyslot. Keyfile support matters when
	// the only other valid slot is keyfile-based.
	if (req.Password == "") == (req.KeyFile == "") {
		jsonErr(w, "provide either password or key_file (not both)", http.StatusBadRequest)
		return
	}
	var key []byte
	if req.KeyFile != "" {
		if key, err = decodeKeyFile(req.KeyFile); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
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
	if req.KeyFile != "" {
		err = vaultKillSlotKeyFile(v, key, req.KeySlot)
	} else {
		err = vaultKillSlot(v, req.Password, req.KeySlot)
	}
	if err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	slog.Info("keyslot removed", "vault", v.Name, "slot", req.KeySlot)
	d, err = vaultDumpDetails(v)
	if err != nil {
		slog.Warn("keyslot removed but header re-read failed", "vault", v.Name, "err", err)
		jsonErr(w, "keyslot removed but failed to re-read header: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, d)
}

// importVault registers an existing image file as a vault. Nothing is
// created or copied: the operator has already placed the image inside an
// allowlisted storage directory (moved it, restored it from a backup, or is
// recovering records after a lost database). The image is validated as a
// readable LUKS container before the record is created, and its size is
// derived from the file — the image is the truth.
func (h *handler) importVault(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		MountDir string `json:"mount_dir"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Path == "" || req.MountDir == "" {
		jsonErr(w, "name, path and mount_dir are required", http.StatusBadRequest)
		return
	}
	if !isValidVaultName(req.Name) {
		jsonErr(w, "vault name may only contain lowercase letters, numbers, and hyphens (max 64 chars)", http.StatusBadRequest)
		return
	}
	cleanedPath, ok := h.pathInStorageDir(req.Path)
	if !ok {
		jsonErr(w, "path is not inside an allowed storage directory", http.StatusBadRequest)
		return
	}
	// Store the canonical path so vault records never contain ".." segments.
	req.Path = cleanedPath
	if !h.allowedMountDir(req.MountDir) {
		jsonErr(w, "mount directory not allowed", http.StatusBadRequest)
		return
	}

	// opMu holds through check-and-insert so the uniqueness checks cannot
	// race a concurrent import or create.
	h.opMu.Lock()
	defer h.opMu.Unlock()
	// A creation goroutine may be mid-flight for this name or image path with
	// no DB record yet. Its failure cleanup deletes the image — registering
	// it here would leave a ghost record pointing at a missing file. Refuse
	// while the creation runs.
	if _, inFlight := h.pendingNames[req.Name]; inFlight {
		jsonErr(w, "vault creation already in progress for this name", http.StatusConflict)
		return
	}
	if _, inFlight := h.pendingPaths[req.Path]; inFlight {
		jsonErr(w, "vault creation already in progress for this image path", http.StatusConflict)
		return
	}
	existing, err := h.db.ListVaults()
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	for _, v := range existing {
		if v.Name == req.Name {
			jsonErr(w, "a vault with this name already exists", http.StatusConflict)
			return
		}
		if v.Path == req.Path {
			jsonErr(w, fmt.Sprintf("this image is already registered to vault %q", v.Name), http.StatusConflict)
			return
		}
	}
	// Refuse a stale mapper device with the same name (e.g. left over from
	// a crash) — luksOpen would otherwise fail confusingly at unlock time.
	if _, err := os.Stat("/dev/mapper/" + req.Name); err == nil {
		jsonErr(w, "/dev/mapper/"+req.Name+" already exists — close it first or choose a different vault name", http.StatusConflict)
		return
	}
	// The image must be a readable LUKS container before the record exists.
	probe := db.Vault{Name: req.Name, Path: req.Path, MapperName: req.Name}
	if _, err := vaultDumpDetails(&probe); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	info, err := os.Stat(req.Path)
	if err != nil {
		jsonErr(w, "image file is not readable: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// Ceil to GB so the displayed size never understates the file; grow's
	// delta math then stays conservative.
	sizeGB := int((info.Size() + (1 << 30) - 1) / (1 << 30))
	mountPoint := req.MountDir + "/" + req.Name
	v, err := h.db.CreateVault(req.Name, req.Path, sizeGB, mountPoint, req.Name)
	if err != nil {
		jsonErr(w, "failed to register vault", http.StatusInternalServerError)
		return
	}
	slog.Info("vault imported", "name", req.Name, "path", req.Path, "size_gb", sizeGB)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toResponse(*v, vault.ReadMounts()))
}

// growVault extends a vault's image, LUKS device and ext4 filesystem.
// Requires the unlock credential (password or keyfile) because cryptsetup
// resize must re-derive the volume key — kernel-keyring reuse is unreliable
// inside containers. The vault must be unlocked AND mounted (online resize2fs
// is the safe path); grow-only by design. Runs synchronously under opMu.
func (h *handler) growVault(w http.ResponseWriter, r *http.Request) {
	// The credential is verified against a keyslot (cryptsetup resize must
	// re-derive the volume key), so this is the same brute-force surface as
	// unlock and shares its rate limiter.
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
		SizeGB   int    `json:"size_gb"`
		Password string `json:"password"`
		KeyFile  string `json:"key_file"` // base64-encoded keyfile bytes
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.SizeGB <= 0 {
		jsonErr(w, "size_gb must be positive", http.StatusBadRequest)
		return
	}
	if req.SizeGB > h.maxSizeGB {
		jsonErr(w, fmt.Sprintf("size_gb exceeds maximum allowed size of %d GB", h.maxSizeGB), http.StatusBadRequest)
		return
	}
	// Exactly one credential, same rule as unlock.
	if (req.Password == "") == (req.KeyFile == "") {
		jsonErr(w, "provide either password or key_file (not both)", http.StatusBadRequest)
		return
	}
	var key []byte
	if req.KeyFile != "" {
		if key, err = decodeKeyFile(req.KeyFile); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if len(req.Password) < 8 {
		jsonErr(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	} else {
		key = []byte(req.Password)
	}
	v, ok := h.lookupVault(w, id)
	if !ok {
		return
	}
	h.opMu.Lock()
	defer h.opMu.Unlock()
	// Re-fetch under the lock so a just-completed concurrent grow is
	// accounted for before validating the grow-only rule.
	fresh, err := h.db.GetVault(id)
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	v = fresh
	// Unlocked, and mounted for preference: resize2fs is online-safe while
	// mounted, and an unlocked-but-unmounted grow would need an offline fsck.
	if !vaultIsUnlocked(v) {
		jsonErr(w, "vault must be unlocked before growing — unlock and mount it first", http.StatusConflict)
		return
	}
	if !vaultIsMounted(v) {
		jsonErr(w, "vault must be mounted before growing", http.StatusConflict)
		return
	}
	if req.SizeGB <= v.SizeGB {
		jsonErr(w, fmt.Sprintf("grow only — vault is already %d GB; shrinking is not supported", v.SizeGB), http.StatusUnprocessableEntity)
		return
	}
	if err := vaultGrow(h.ctx, v, req.SizeGB, key); err != nil {
		jsonErr(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	slog.Info("vault grown", "vault", v.Name, "from_gb", v.SizeGB, "to_gb", req.SizeGB)
	if err := h.db.UpdateVaultSize(id, req.SizeGB); err != nil {
		jsonErr(w, "vault grew but updating the record failed", http.StatusInternalServerError)
		return
	}
	updated, err := h.db.GetVault(id)
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, toResponse(*updated, vault.ReadMounts()))
}

// pathInStorageDir canonicalizes p and reports whether the file it refers to
// is located inside one of the allowlisted storage directories. It returns the
// cleaned path, which the caller should persist so records stay canonical.
//
// Two checks, in order:
//   - syntactic: filepath.Clean collapses ".", ".." and duplicate slashes, so
//     "/vaults/../secret.img" cleans to "/secret.img" and fails the prefix
//     check. The trailing-slash guard keeps "/vaults2/x.img" from matching
//     allowlist "/vaults".
//   - semantic: when both sides can be resolved, symlinks are resolved on the
//     file AND the storage dir, and the resolved file must stay inside the
//     resolved dir — a symlink planted inside a storage dir cannot point
//     outside the allowlist.
//
// If resolution fails (e.g. the storage dir or file does not exist yet), the
// syntactic result stands; a missing image is rejected later by the LUKS
// probe / stat with a more precise error.
func (h *handler) pathInStorageDir(p string) (string, bool) {
	// Clean collapses ".", ".." and duplicate separators; ToSlash normalizes
	// to forward slashes so the prefix checks behave identically on every OS
	// (on the Linux target both are no-ops).
	cleaned := filepath.ToSlash(filepath.Clean(p))
	native := filepath.Clean(p)
	for _, dir := range h.storageDirs {
		dir = strings.TrimSuffix(dir, "/")
		if dir == "" || !strings.HasPrefix(cleaned, dir+"/") {
			continue
		}
		resolvedDir, dirErr := filepath.EvalSymlinks(filepath.FromSlash(dir))
		resolved, fileErr := filepath.EvalSymlinks(native)
		if dirErr == nil && fileErr == nil {
			return cleaned, strings.HasPrefix(
				filepath.ToSlash(resolved), filepath.ToSlash(resolvedDir)+"/")
		}
		return cleaned, true
	}
	return cleaned, false
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
	// Stop tracking any leftover auto-lock window (possible when the vault
	// was locked externally while the policy was disabled).
	h.clearUnlocked(id)
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

// ── Auto-lock ─────────────────────────────────────────────────────────────────
// A background sweep enforces AUTO_LOCK_HOURS: the maximum time a vault may
// stay unlocked. The policy is duration-based, not activity-based — the
// container cannot observe host-side SMB access; a busy mount simply makes
// the lock attempt fail with "target is busy", which defers the lock to the
// next sweep. Lazy unmount is deliberately NOT used: auto-lock must mean
// actually locked.

func (h *handler) markUnlocked(id int64) {
	h.unlockedMu.Lock()
	h.unlockedAt[id] = time.Now()
	h.unlockedMu.Unlock()
}

func (h *handler) clearUnlocked(id int64) {
	h.unlockedMu.Lock()
	delete(h.unlockedAt, id)
	h.unlockedMu.Unlock()
}

// autoLockLoop sweeps once per minute. At startup, vaults that are still
// unlocked (e.g. after a SIGKILL restart) get the process start time as the
// beginning of their window — the graceful-shutdown locking normally ensures
// there are none.
func (h *handler) autoLockLoop(ctx context.Context) {
	vaults, err := h.db.ListVaults()
	if err != nil {
		slog.Warn("auto-lock: could not list vaults at startup", "err", err)
	} else {
		for i := range vaults {
			if vault.IsUnlocked(&vaults[i]) {
				h.markUnlocked(vaults[i].ID)
				slog.Info("auto-lock: vault unlocked at startup — window starts now", "vault", vaults[i].Name)
			}
		}
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.autoLockSweep(time.Now())
		}
	}
}

// autoLockSweep locks every vault whose unlocked window has exceeded the
// policy. Lock attempts are serialized per vault under opMu, so a sweep can
// never race a user-initiated lock/unlock/grow.
func (h *handler) autoLockSweep(now time.Time) {
	if h.autoLockHours <= 0 {
		return
	}
	window := time.Duration(h.autoLockHours * float64(time.Hour))
	h.unlockedMu.Lock()
	expired := make([]int64, 0, len(h.unlockedAt))
	for id, since := range h.unlockedAt {
		if now.Sub(since) >= window {
			expired = append(expired, id)
		}
	}
	h.unlockedMu.Unlock()
	for _, id := range expired {
		h.autoLockVault(id, now)
	}
}

func (h *handler) autoLockVault(id int64, now time.Time) {
	since := h.unlockedSince(id)
	v, err := h.db.GetVault(id)
	if err != nil {
		// Record vanished (deleted vault) — stop tracking it.
		h.clearUnlocked(id)
		return
	}
	lockCtx, cancel := context.WithTimeout(h.ctx, 15*time.Second)
	defer cancel()
	h.opMu.Lock()
	// Re-read the window under opMu: a manual lock→unlock between the read at
	// the top of this function and this lock restarts the window, and the
	// sweep must not lock a freshly unlocked vault. opMu→unlockedMu is the
	// established lock order (unlockVault marks under opMu), so calling
	// unlockedSince here cannot deadlock.
	if h.windowRestarted(id, since) {
		h.opMu.Unlock()
		return
	}
	err = vaultAutoLock(lockCtx, v)
	h.opMu.Unlock()
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "already locked"):
			// Locked out from under us (operator CLI, etc.) — stop tracking.
			h.clearUnlocked(id)
		case strings.Contains(err.Error(), "busy"):
			// In use via SMB — defer to the next sweep.
			slog.Debug("auto-lock deferred: mount is busy", "vault", v.Name)
		default:
			slog.Warn("auto-lock failed", "vault", v.Name, "err", err)
		}
		return
	}
	h.clearUnlocked(id)
	slog.Info("vault auto-locked",
		"vault", v.Name,
		"policy_hours", h.autoLockHours,
		"unlocked_for", now.Sub(since).Round(time.Second).String(),
	)
}

func (h *handler) unlockedSince(id int64) time.Time {
	h.unlockedMu.Lock()
	defer h.unlockedMu.Unlock()
	return h.unlockedAt[id]
}

// windowRestarted reports whether the vault's unlock timestamp no longer
// matches since — i.e. the auto-lock window was restarted (or cleared) after
// since was read. The caller must hold opMu.
func (h *handler) windowRestarted(id int64, since time.Time) bool {
	return !h.unlockedSince(id).Equal(since)
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

// cleanupLimiters removes rate-limiter entries (unlock and auth-failure) that
// have been idle for more than 10 minutes to prevent unbounded memory growth.
func (h *handler) cleanupLimiters(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	sweep := func(mu *sync.Mutex, m map[string]*unlockEntry) {
		mu.Lock()
		for ip, e := range m {
			if time.Since(e.lastSeen) > 10*time.Minute {
				delete(m, ip)
			}
		}
		mu.Unlock()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep(&h.unlockMu, h.unlockLimiters)
			sweep(&h.authMu, h.authLimiters)
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

// maxBodyBytes caps request bodies. Keyfile uploads are base64 of at most
// 1 MiB (≈1.4 MB on the wire), so 8 MiB leaves generous headroom while
// bounding how much memory a single request can make the server allocate.
const maxBodyBytes = 8 << 20

// limitBody wraps r.Body in a MaxBytesReader: an oversized body then fails the
// JSON decode with 400 instead of being read into memory without bound. It
// sits outside basicAuth so the cap applies even to unauthenticated requests.
func (h *handler) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
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

// vaultIsMounted follows the same pattern for the mounted state check.
var vaultIsMounted = vault.IsMounted

// vaultDumpDetails is a package-level indirection over vault.DumpDetails so
// tests can stub the cryptsetup subprocess.
var vaultDumpDetails = vault.DumpDetails

// vaultAddKey and vaultKillSlot are indirections over vault.AddKey/KillSlot
// for the same reason.
var (
	vaultAddKey          = vault.AddKey
	vaultKillSlot        = vault.KillSlot
	vaultKillSlotKeyFile = vault.KillSlotKeyFile
)

// vaultUnlock, vaultUnlockKeyFile and vaultAddKeyFile follow the same pattern.
// The unlock variants take a context so an in-flight unlock is interrupted on
// shutdown instead of stalling the HTTP drain.
var (
	vaultUnlock        = vault.UnlockContext
	vaultUnlockKeyFile = vault.UnlockKeyFileContext
	vaultAddKeyFile    = vault.AddKeyFile
)

// vaultGrow indirection over vault.Grow for the same reason.
var vaultGrow = vault.Grow

// vaultCreate indirection over vault.Create so tests can simulate a
// successful creation pipeline (which inserts the DB record).
var vaultCreate = vault.Create

// vaultAutoLock is vault.LockContext, used by the auto-lock sweep.
var vaultAutoLock = vault.LockContext

// vaultLock is vault.Lock (the manual lock path), stubbable in tests.
var vaultLock = vault.Lock

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

// session is one UI login. In-memory by design: the app is single-process, and
// a restart simply means everyone logs in again.
type session struct {
	createdAt time.Time
	lastSeen  time.Time
}

const sessionCookieName = "lukscrypt_session"

// validCredentials checks the master credentials in constant time.
func (h *handler) validCredentials(user, pass string) bool {
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(h.authUser))
	passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(h.authPass))
	return userMatch == 1 && passMatch == 1
}

// hashToken is the at-rest form of an API token (SHA-256 hex). The raw token
// is shown exactly once, at creation.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newAPIToken generates a fresh raw token (lukscrypt_ + 64 hex chars).
func newAPIToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "lukscrypt_" + hex.EncodeToString(b[:]), nil
}

// validAPICredentials accepts the master Basic Auth pair OR an API token —
// as `Authorization: Bearer <token>` (no username) or as the Basic Auth
// password with the configured username. Returns (tokenID, isToken, ok).
func (h *handler) validAPICredentials(r *http.Request) (int64, bool, bool) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tok := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if t, err := h.db.GetAPITokenByHash(hashToken(tok)); err == nil {
			return t.ID, true, true
		}
		return 0, false, false
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return 0, false, false
	}
	if h.validCredentials(user, pass) {
		return 0, false, true
	}
	// Token used as the Basic Auth password (curl -u admin:lukscrypt_...).
	if subtle.ConstantTimeCompare([]byte(user), []byte(h.authUser)) == 1 {
		if t, err := h.db.GetAPITokenByHash(hashToken(pass)); err == nil {
			return t.ID, true, true
		}
	}
	return 0, false, false
}

// apiTokenResponse is the JSON shape for token endpoints. Token (the raw
// secret) is set only on creation; TokenHash is never serialized.
type apiTokenResponse struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	Token      string `json:"token,omitempty"`
}

func (h *handler) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := h.db.ListAPITokens()
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	resp := make([]apiTokenResponse, len(toks))
	for i, t := range toks {
		resp[i] = apiTokenResponse{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt}
	}
	jsonOK(w, resp)
}

// createToken issues a new API token. The raw token is returned exactly once;
// only its hash is stored.
func (h *handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		jsonErr(w, "name is required (max 64 chars)", http.StatusBadRequest)
		return
	}
	raw, err := newAPIToken()
	if err != nil {
		jsonErr(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	t, err := h.db.CreateAPIToken(req.Name, hashToken(raw))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonErr(w, "a token with this name already exists", http.StatusConflict)
			return
		}
		jsonErr(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	slog.Info("api token created", "name", req.Name, "token_id", t.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(apiTokenResponse{
		ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt, Token: raw,
	})
}

// deleteToken revokes a token by id.
func (h *handler) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		jsonErr(w, "invalid token id", http.StatusBadRequest)
		return
	}
	deleted, err := h.db.DeleteAPIToken(id)
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	if !deleted {
		jsonErr(w, "token not found", http.StatusNotFound)
		return
	}
	slog.Info("api token revoked", "token_id", id)
	w.WriteHeader(http.StatusNoContent)
}

// auth accepts either a valid session cookie (the UI path, with expiry and
// logout) or a valid Basic Auth header (the API/script path — no session is
// created, so curl keeps working unchanged). Failures are throttled per IP:
// without that, the master AUTH_PASSWORD could be brute-forced at unlimited
// speed via the 401s of any endpoint.
func (h *handler) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.validSession(r) {
			h.clearAuthFailures(r)
			next.ServeHTTP(w, r)
			return
		}
		if tokenID, isToken, ok := h.validAPICredentials(r); ok {
			// A successful login resets this IP's failure counter, so a user who
			// typo'd a few times is not locked out later.
			h.clearAuthFailures(r)
			if isToken {
				// Best-effort audit touch; never fail the request over it.
				h.db.TouchAPIToken(tokenID)
			}
			next.ServeHTTP(w, r)
			return
		}
		// 429 deliberately omits WWW-Authenticate — the client is throttled, not
		// unauthorized, so browsers should not re-prompt.
		if !h.authAllowed(r) {
			jsonErr(w, "too many failed login attempts — wait before trying again", http.StatusTooManyRequests)
			return
		}
		// A browser navigating without credentials gets the login page instead
		// of a native 401 prompt; API clients (fetch/curl) get the standard 401
		// challenge and the UI redirects on 401.
		if r.Method == http.MethodGet && r.Header.Get("Authorization") == "" &&
			strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="lukscrypt"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// validSession reports whether the request carries a live session cookie and
// refreshes its idle timestamp (sliding expiry). Expired sessions are deleted.
func (h *handler) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	s, ok := h.sessions[c.Value]
	if !ok {
		return false
	}
	now := time.Now()
	if now.Sub(s.lastSeen) > h.sessionIdle || now.Sub(s.createdAt) > h.sessionMaxAge {
		delete(h.sessions, c.Value)
		return false
	}
	s.lastSeen = now
	return true
}

// loginPage serves the UI login form (public route).
func (h *handler) loginPage(w http.ResponseWriter, r *http.Request) {
	data, err := h.webFS.ReadFile("web/login.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// login verifies the master credentials (rate-limited like every other
// credential check) and issues a session cookie.
func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if !h.authAllowed(r) {
		jsonErr(w, "too many failed login attempts — wait before trying again", http.StatusTooManyRequests)
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.User == "" || req.Password == "" {
		jsonErr(w, "user and password are required", http.StatusBadRequest)
		return
	}
	if !h.validCredentials(req.User, req.Password) {
		// No WWW-Authenticate here: this is a form login, and the header would
		// make browsers pop the native Basic Auth dialog over the form.
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	h.clearAuthFailures(r)
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		jsonErr(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(b[:])
	now := time.Now()
	h.sessionsMu.Lock()
	h.sessions[token] = &session{createdAt: now, lastSeen: now}
	h.sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure only over TLS — plain-HTTP local testing must still work.
		Secure: r.TLS != nil,
		MaxAge: int(h.sessionMaxAge.Seconds()),
	})
	slog.Info("session created", "user", req.User, "ip", clientIP(r, h.trustProxy))
	jsonOK(w, map[string]any{"ok": true})
}

// logout deletes the caller's session and clears the cookie. Registered on the
// authed mux, so a valid session or Basic Auth is required to reach it.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		h.sessionsMu.Lock()
		delete(h.sessions, c.Value)
		h.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: -1,
	})
	slog.Info("session ended (logout)", "ip", clientIP(r, h.trustProxy))
	jsonOK(w, map[string]any{"ok": true})
}

// cleanupSessions drops expired sessions every 5 minutes so the map cannot
// grow unbounded.
func (h *handler) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			h.sessionsMu.Lock()
			for tok, s := range h.sessions {
				if now.Sub(s.lastSeen) > h.sessionIdle || now.Sub(s.createdAt) > h.sessionMaxAge {
					delete(h.sessions, tok)
				}
			}
			h.sessionsMu.Unlock()
		}
	}
}

// authAllowed consumes a failure token for the request's IP: burst of 5, then
// one attempt per minute. Only failures are counted — successful logins never
// touch the limiter (they reset it instead).
func (h *handler) authAllowed(r *http.Request) bool {
	ip := clientIP(r, h.trustProxy)
	h.authMu.Lock()
	defer h.authMu.Unlock()
	e, ok := h.authLimiters[ip]
	if !ok {
		e = &unlockEntry{limiter: rate.NewLimiter(rate.Every(time.Minute), 5)}
		h.authLimiters[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// clearAuthFailures drops the failure entry for the request's IP after a
// successful login.
func (h *handler) clearAuthFailures(r *http.Request) {
	ip := clientIP(r, h.trustProxy)
	h.authMu.Lock()
	delete(h.authLimiters, ip)
	h.authMu.Unlock()
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
