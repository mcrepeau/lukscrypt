package api

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lukscrypt/internal/db"
	"lukscrypt/internal/vault"
)

// newTestMux builds a NewMux wired to an in-memory SQLite database.
// storageDirs=["/vaults"], mountDirs=["/mnt"], maxSizeGB=100.
// embed.FS{} (zero value) is used in place of the real web assets; the index
// handler returns 404, which is fine because we don't test that route here.
func newTestMux(t *testing.T) (http.Handler, *db.DB) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	h := NewMux(context.Background(), database, embed.FS{}, []string{"/vaults"}, []string{"/mnt"}, "admin", "testpass", 100, false, "test")
	return h, database
}

// auth performs an authenticated request and returns the recorded response.
func auth(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	return request(h, method, path, "admin", "testpass", "127.0.0.1:9999", body)
}

// request is the low-level helper used directly when credentials or
// RemoteAddr need to be controlled.
func request(h http.Handler, method, path, user, pass, remoteAddr string, body any) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.RemoteAddr = remoteAddr
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// --- /healthz -----------------------------------------------------------------

func TestHealthz(t *testing.T) {
	h, _ := newTestMux(t)
	w := request(h, http.MethodGet, "/healthz", "", "", "127.0.0.1:9999", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf(`status = %q, want "ok"`, resp["status"])
	}
}

// Healthz must work without credentials.
func TestHealthzNoAuth(t *testing.T) {
	h, _ := newTestMux(t)
	w := request(h, http.MethodGet, "/healthz", "", "", "127.0.0.1:9999", nil)
	if w.Code == http.StatusUnauthorized {
		t.Error("/healthz should be unauthenticated but got 401")
	}
}

// --- Basic auth ---------------------------------------------------------------

func TestBasicAuth(t *testing.T) {
	h, _ := newTestMux(t)
	tests := []struct {
		name     string
		user     string
		pass     string
		wantCode int
	}{
		{"no credentials", "", "", http.StatusUnauthorized},
		{"wrong user", "root", "testpass", http.StatusUnauthorized},
		{"wrong password", "admin", "wrongpass", http.StatusUnauthorized},
		{"correct credentials", "admin", "testpass", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(h, http.MethodGet, "/api/config", tt.user, tt.pass, "127.0.0.1:9999", nil)
			if w.Code != tt.wantCode {
				t.Errorf("got %d, want %d", w.Code, tt.wantCode)
			}
		})
	}
}

// --- Security headers ---------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodGet, "/api/config", nil)

	exact := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}
	for _, c := range exact {
		t.Run(c.header, func(t *testing.T) {
			if got := w.Header().Get(c.header); got != c.want {
				t.Errorf("%s = %q, want %q", c.header, got, c.want)
			}
		})
	}
	// CSP is long; spot-check the most security-critical directive.
	t.Run("Content-Security-Policy contains frame-ancestors none", func(t *testing.T) {
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP missing frame-ancestors: %q", csp)
		}
	})
}

// --- GET /api/config ----------------------------------------------------------

func TestGetConfig(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodGet, "/api/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var resp map[string][]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dirs := resp["storage_dirs"]; len(dirs) != 1 || dirs[0] != "/vaults" {
		t.Errorf("storage_dirs = %v, want [/vaults]", dirs)
	}
	if dirs := resp["mount_dirs"]; len(dirs) != 1 || dirs[0] != "/mnt" {
		t.Errorf("mount_dirs = %v, want [/mnt]", dirs)
	}
}

// --- GET /api/vaults ----------------------------------------------------------

func TestListVaultsEmpty(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodGet, "/api/vaults", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var resp []any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 0 {
		t.Errorf("got %d vault(s), want 0", len(resp))
	}
}

func TestListVaultsWithEntry(t *testing.T) {
	h, database := newTestMux(t)
	if _, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault"); err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	w := auth(h, http.MethodGet, "/api/vaults", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var resp []vaultResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("got %d vault(s), want 1", len(resp))
	}
	if resp[0].Name != "testvault" {
		t.Errorf("name = %q, want testvault", resp[0].Name)
	}
	// In a test environment the vault is never actually open, so both flags
	// must be false.
	if resp[0].Unlocked || resp[0].Mounted {
		t.Errorf("expected locked/unmounted, got unlocked=%v mounted=%v", resp[0].Unlocked, resp[0].Mounted)
	}
}

// --- POST /api/vaults (validation) -------------------------------------------

// validCreateBody returns a body that passes all validation checks.
func validCreateBody() map[string]any {
	return map[string]any{
		"name":      "myvault",
		"path":      "/vaults",
		"size_gb":   5,
		"password":  "strongpassword",
		"mount_dir": "/mnt",
	}
}

// with returns a copy of base with the given key overridden.
func with(base map[string]any, key string, val any) map[string]any {
	m := map[string]any{}
	for k, v := range base {
		m[k] = v
	}
	m[key] = val
	return m
}

func TestCreateVaultValidation(t *testing.T) {
	h, _ := newTestMux(t)
	tests := []struct {
		name string
		body map[string]any
	}{
		{"missing name", with(validCreateBody(), "name", "")},
		{"missing path", with(validCreateBody(), "path", "")},
		{"missing password", with(validCreateBody(), "password", "")},
		{"missing mount_dir", with(validCreateBody(), "mount_dir", "")},
		{"zero size", with(validCreateBody(), "size_gb", 0)},
		{"negative size", with(validCreateBody(), "size_gb", -1)},
		{"size exceeds max", with(validCreateBody(), "size_gb", 101)},
		{"password too short", with(validCreateBody(), "password", "short")},
		{"invalid name — uppercase", with(validCreateBody(), "name", "MyVault")},
		{"invalid name — underscore", with(validCreateBody(), "name", "my_vault")},
		{"invalid name — too long", with(validCreateBody(), "name", strings.Repeat("a", 65))},
		{"invalid name — path traversal", with(validCreateBody(), "name", "../etc")},
		{"invalid name — slash", with(validCreateBody(), "name", "my/vault")},
		{"disallowed storage dir", with(validCreateBody(), "path", "/etc")},
		{"disallowed storage dir — subdir", with(validCreateBody(), "path", "/vaults/sub")},
		{"disallowed mount dir", with(validCreateBody(), "mount_dir", "/tmp")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := auth(h, http.MethodPost, "/api/vaults", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400", w.Code)
			}
		})
	}
}

func TestCreateVaultInvalidJSON(t *testing.T) {
	h, _ := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/api/vaults", strings.NewReader("not json"))
	req.RemoteAddr = "127.0.0.1:9999"
	req.SetBasicAuth("admin", "testpass")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

// TestCreateVaultAccepted checks that a request passing all validation gets 202
// with a non-empty job_id. The background goroutine will fail (no cryptsetup),
// but the HTTP response is already delivered before that happens.
func TestCreateVaultAccepted(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults", validCreateBody())
	if w.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["job_id"] == "" {
		t.Error("expected non-empty job_id in response")
	}
}

// TestCreateVaultJobIDIsRandom checks that two accepted create requests receive
// different job IDs (the old implementation used UnixNano which was predictable).
func TestCreateVaultJobIDIsRandom(t *testing.T) {
	h, _ := newTestMux(t)
	body1 := validCreateBody()
	body2 := with(validCreateBody(), "name", "myvault2")

	w1 := auth(h, http.MethodPost, "/api/vaults", body1)
	w2 := auth(h, http.MethodPost, "/api/vaults", body2)
	if w1.Code != http.StatusAccepted || w2.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for both requests, got %d and %d", w1.Code, w2.Code)
	}

	var r1, r2 map[string]string
	json.NewDecoder(w1.Body).Decode(&r1)
	json.NewDecoder(w2.Body).Decode(&r2)
	if r1["job_id"] == r2["job_id"] {
		t.Errorf("both requests returned the same job_id %q", r1["job_id"])
	}
}

// TestCreateVaultDuplicateInFlight checks that a second create request for the
// same vault name returns 409 while the first is still in flight. We simulate
// an in-flight creation by registering the name in pendingNames directly —
// this is possible because the tests are in the same package.
func TestCreateVaultDuplicateInFlight(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	h := &handler{
		db:             database,
		storageDirs:    []string{"/vaults"},
		mountDirs:      []string{"/mnt"},
		authUser:       "admin",
		authPass:       "testpass",
		maxSizeGB:      100,
		jobs:           make(map[string]*jobEntry),
		pendingNames:   map[string]struct{}{"myvault": {}}, // simulate in-flight creation
		unlockLimiters: make(map[string]*unlockEntry),
	}

	b, _ := json.Marshal(validCreateBody())
	req := httptest.NewRequest(http.MethodPost, "/api/vaults", bytes.NewReader(b))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	h.createVault(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("got %d, want 409 when vault creation already in progress", w.Code)
	}
}

// --- DELETE /api/vaults/{id} -------------------------------------------------

func TestDeleteVaultNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodDelete, "/api/vaults/99999", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestDeleteVaultInvalidID(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodDelete, "/api/vaults/notanid", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestDeleteVaultSuccess(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	w := auth(h, http.MethodDelete, fmt.Sprintf("/api/vaults/%d", v.ID), nil)
	// The filesystem cleanup will fail (image file doesn't exist), but the
	// handler logs the error and still returns 204.
	if w.Code != http.StatusNoContent {
		t.Errorf("got %d, want 204; body: %s", w.Code, w.Body.String())
	}

	// Verify the DB record is gone.
	_, err = database.GetVault(v.ID)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("vault record still present after delete; GetVault err = %v", err)
	}
}

// TestDeleteVaultUnlocked verifies that deleting an unlocked vault is refused
// BEFORE the DB record is removed. The old behavior deleted the record first,
// making the vault vanish from the UI while its image and mounted filesystem
// stayed live on disk.
func TestDeleteVaultUnlocked(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	orig := vaultIsUnlocked
	vaultIsUnlocked = func(*db.Vault) bool { return true } // simulate an unlocked vault
	t.Cleanup(func() { vaultIsUnlocked = orig })

	w := auth(h, http.MethodDelete, fmt.Sprintf("/api/vaults/%d", v.ID), nil)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422", w.Code)
	}
	if _, err := database.GetVault(v.ID); err != nil {
		t.Errorf("DB record was removed despite refused delete: %v", err)
	}
}

// --- CSRF protection ----------------------------------------------------------

// TestCSRFCrossOriginBlocked checks that state-changing requests carrying a
// mismatched Origin header are rejected. A malicious page can attach the
// browser's cached Basic Auth credentials to a cross-site form POST, so
// lock/mount/delete must not be reachable cross-origin.
func TestCSRFCrossOriginBlocked(t *testing.T) {
	h, _ := newTestMux(t)
	tests := []struct {
		name   string
		method string
		path   string
		origin string
	}{
		{"cross-origin POST", http.MethodPost, "/api/vaults/1/lock", "https://evil.example"},
		{"cross-origin DELETE", http.MethodDelete, "/api/vaults/1", "https://evil.example"},
		{"origin null", http.MethodPost, "/api/vaults/1/lock", "null"},
		{"malformed origin", http.MethodPost, "/api/vaults/1/lock", "://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = "127.0.0.1:9999"
			req.SetBasicAuth("admin", "testpass")
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("got %d, want 403", w.Code)
			}
		})
	}
}

// TestCSRFSameOriginAllowed checks that a matching Origin passes through to
// the handler (404 because the vault does not exist, not 403).
func TestCSRFSameOriginAllowed(t *testing.T) {
	h, _ := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "http://nas.local:8080/api/vaults/99999/lock", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.SetBasicAuth("admin", "testpass")
	req.Header.Set("Origin", "http://nas.local:8080")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404 (same-origin request must pass through)", w.Code)
	}
}

// TestCSRFNoOriginAllowed checks that requests without an Origin header
// (curl, scripts, orchestrators) are unaffected by the CSRF guard.
func TestCSRFNoOriginAllowed(t *testing.T) {
	h, _ := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/api/vaults/99999/lock", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.SetBasicAuth("admin", "testpass")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404 (no-Origin request must pass through)", w.Code)
	}
}

// Cross-origin GETs are read-only and must pass the CSRF guard.
func TestCSRFCrossOriginGetAllowed(t *testing.T) {
	h, _ := newTestMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/vaults", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.SetBasicAuth("admin", "testpass")
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("got %d, want 200", w.Code)
	}
}

// --- POST /api/vaults/{id}/unlock --------------------------------------------

func TestUnlockVaultValidation(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	path := fmt.Sprintf("/api/vaults/%d/unlock", v.ID)

	tests := []struct {
		name     string
		body     any
		wantCode int
	}{
		{"empty body", map[string]any{}, http.StatusBadRequest},
		{"empty password", map[string]any{"password": ""}, http.StatusBadRequest},
		{"short password", map[string]any{"password": "short"}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := auth(h, http.MethodPost, path, tt.body)
			if w.Code != tt.wantCode {
				t.Errorf("got %d, want %d", w.Code, tt.wantCode)
			}
		})
	}
}

func TestUnlockVaultNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults/99999/unlock", map[string]string{"password": "strongpassword"})
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

// TestUnlockVaultRateLimit verifies that the 5-burst limit is enforced per IP.
// Requests 1–5 from the same IP should not be rate-limited (they'll get 404
// because vault 99999 doesn't exist); the 6th must return 429.
func TestUnlockVaultRateLimit(t *testing.T) {
	h, _ := newTestMux(t)
	body := map[string]string{"password": "strongpassword"}
	const ip = "10.99.99.1:4321"

	for i := range 5 {
		w := request(h, http.MethodPost, "/api/vaults/99999/unlock", "admin", "testpass", ip, body)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d unexpectedly rate-limited", i+1)
		}
	}
	w := request(h, http.MethodPost, "/api/vaults/99999/unlock", "admin", "testpass", ip, body)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("6th request: got %d, want 429", w.Code)
	}
}

// TestUnlockVaultRateLimitPerIP checks that rate limits are scoped per IP:
// exhausting one IP's budget must not affect another IP.
func TestUnlockVaultRateLimitPerIP(t *testing.T) {
	h, _ := newTestMux(t)
	body := map[string]string{"password": "strongpassword"}

	// Exhaust IP A's budget.
	for range 6 {
		request(h, http.MethodPost, "/api/vaults/99999/unlock", "admin", "testpass", "10.0.0.1:1111", body)
	}

	// IP B should still have its own fresh budget.
	w := request(h, http.MethodPost, "/api/vaults/99999/unlock", "admin", "testpass", "10.0.0.2:2222", body)
	if w.Code == http.StatusTooManyRequests {
		t.Error("IP B was rate-limited despite never sending a request")
	}
}

// --- POST /api/vaults/{id}/lock ----------------------------------------------

func TestLockVaultNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults/99999/lock", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestLockVaultAlreadyLocked(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/lock", v.ID), nil)
	// Vault is not open in the test environment, so Lock returns an error.
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422", w.Code)
	}
}

// --- POST /api/vaults/{id}/mount ---------------------------------------------

func TestMountVaultNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults/99999/mount", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestMountVaultNotUnlocked(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/mount", v.ID), nil)
	// Vault is locked in the test environment, so Mount returns an error.
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422", w.Code)
	}
}

// --- GET /api/vaults/{id}/details ----------------------------------------------

func stubDumpDetails(t *testing.T, fn func(*db.Vault) (*vault.LUKSDetails, error)) {
	t.Helper()
	orig := vaultDumpDetails
	vaultDumpDetails = fn
	t.Cleanup(func() { vaultDumpDetails = orig })
}

func TestVaultDetails(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	// The dump function is stubbed because no real cryptsetup/LUKS image
	// exists in the test environment.
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return &vault.LUKSDetails{
			Version:     "2",
			Cipher:      "aes-xts-plain64",
			Hash:        "sha256",
			KeySizeBits: 512,
			UUID:        "6a2f5e10-94c3-4d7a-8f21-0b3c9e8d7a1f",
			KeySlots:    []vault.KeySlot{{Index: 0, Type: "argon2id", Status: "valid"}},
		}, nil
	})

	w := auth(h, http.MethodGet, fmt.Sprintf("/api/vaults/details/%d", v.ID), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp vault.LUKSDetails
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Version != "2" || resp.Cipher != "aes-xts-plain64" || resp.KeySizeBits != 512 {
		t.Errorf("unexpected details: %+v", resp)
	}
	if len(resp.KeySlots) != 1 || resp.KeySlots[0].Type != "argon2id" {
		t.Errorf("keyslots = %+v", resp.KeySlots)
	}
}

func TestVaultDetailsNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodGet, "/api/vaults/details/99999", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestVaultDetailsInvalidID(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodGet, "/api/vaults/details/notanid", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

// A record whose image file is missing (or not a LUKS container) must produce
// a 422 with the cryptsetup error, not a 500.
func TestVaultDetailsDumpFailure(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return nil, fmt.Errorf("luksDump: Device /vaults/testvault.img is not a valid LUKS device")
	})
	w := auth(h, http.MethodGet, fmt.Sprintf("/api/vaults/details/%d", v.ID), nil)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422; body: %s", w.Code, w.Body.String())
	}
}

// --- POST /api/vaults/import ----------------------------------------------------

// newTestMuxWithDirs builds a mux with custom allowlists, for import tests
// that need the storage dir to point at a real temporary directory.
func newTestMuxWithDirs(t *testing.T, storageDirs, mountDirs []string) (http.Handler, *db.DB) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	h := NewMux(context.Background(), database, embed.FS{}, storageDirs, mountDirs, "admin", "testpass", 100, false, "test")
	return h, database
}

func TestImportVaultValidation(t *testing.T) {
	h, _ := newTestMux(t)
	tests := []struct {
		name string
		body map[string]any
	}{
		{"missing name", map[string]any{"path": "/vaults/x.img", "mount_dir": "/mnt"}},
		{"missing path", map[string]any{"name": "x", "mount_dir": "/mnt"}},
		{"missing mount_dir", map[string]any{"name": "x", "path": "/vaults/x.img"}},
		{"invalid name", map[string]any{"name": "BadName", "path": "/vaults/x.img", "mount_dir": "/mnt"}},
		{"path outside storage dirs", map[string]any{"name": "x", "path": "/etc/x.img", "mount_dir": "/mnt"}},
		{"path in sibling dir with shared prefix", map[string]any{"name": "x", "path": "/vaults2/x.img", "mount_dir": "/mnt"}},
		{"mount dir not allowed", map[string]any{"name": "x", "path": "/vaults/x.img", "mount_dir": "/tmp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(h, http.MethodPost, "/api/vaults/import", "admin", "testpass", "10.6.6.6:6", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestImportVaultNameTaken(t *testing.T) {
	h, database := newTestMux(t)
	if _, err := database.CreateVault("taken", "/vaults/taken.img", 5, "/mnt/taken", "taken"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return &vault.LUKSDetails{Version: "2"}, nil
	})
	w := auth(h, http.MethodPost, "/api/vaults/import",
		map[string]any{"name": "taken", "path": "/vaults/other.img", "mount_dir": "/mnt"})
	if w.Code != http.StatusConflict {
		t.Errorf("got %d, want 409; body: %s", w.Code, w.Body.String())
	}
}

// The same image file must never be registered twice: two mapper names over
// one underlying file is a data-corruption scenario.
func TestImportVaultPathTaken(t *testing.T) {
	h, database := newTestMux(t)
	if _, err := database.CreateVault("first", "/vaults/first.img", 5, "/mnt/first", "first"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return &vault.LUKSDetails{Version: "2"}, nil
	})
	w := auth(h, http.MethodPost, "/api/vaults/import",
		map[string]any{"name": "second", "path": "/vaults/first.img", "mount_dir": "/mnt"})
	if w.Code != http.StatusConflict {
		t.Errorf("got %d, want 409; body: %s", w.Code, w.Body.String())
	}
	// The second record must not have been created.
	if v, err := database.GetVaultByName("second"); err == nil {
		t.Errorf("vault record was created despite the conflict: %+v", v)
	}
}

func TestImportVaultNotLuks(t *testing.T) {
	h, _ := newTestMux(t)
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return nil, fmt.Errorf("luksDump: Device /vaults/x.img is not a valid LUKS device")
	})
	w := auth(h, http.MethodPost, "/api/vaults/import",
		map[string]any{"name": "x", "path": "/vaults/x.img", "mount_dir": "/mnt"})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422; body: %s", w.Code, w.Body.String())
	}
}

func TestImportVaultSuccess(t *testing.T) {
	// ToSlash: pathInStorageDir compares forward-slash prefixes, and the
	// storage dirs on Linux are always forward-slash paths.
	dir := filepath.ToSlash(t.TempDir())
	img := dir + "/restored.img"
	// A sparse 3 GiB file stands in for a real vault image; the size is
	// derived from the file, so the record must report 3 GB.
	if err := os.WriteFile(img, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Truncate(img, 3<<30); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	h, database := newTestMuxWithDirs(t, []string{dir}, []string{"/mnt"})
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return &vault.LUKSDetails{Version: "2", UUID: "some-uuid"}, nil
	})

	w := auth(h, http.MethodPost, "/api/vaults/import",
		map[string]any{"name": "restored", "path": img, "mount_dir": "/mnt"})
	if w.Code != http.StatusCreated {
		t.Fatalf("got %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var resp vaultResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "restored" || resp.SizeGB != 3 || resp.MountPoint != "/mnt/restored" {
		t.Errorf("response = %+v", resp)
	}
	got, err := database.GetVaultByName("restored")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Path != img || got.SizeGB != 3 {
		t.Errorf("db record = %+v", got)
	}
}

// --- POST /api/vaults/{id}/grow -------------------------------------------------

func stubVaultState(t *testing.T, unlocked bool, mounted bool, grow func(context.Context, *db.Vault, int) error) {
	t.Helper()
	origUnlock, origMounted, origGrow := vaultIsUnlocked, vaultIsMounted, vaultGrow
	vaultIsUnlocked = func(*db.Vault) bool { return unlocked }
	vaultIsMounted = func(*db.Vault) bool { return mounted }
	if grow != nil {
		vaultGrow = grow
	}
	t.Cleanup(func() { vaultIsUnlocked, vaultIsMounted, vaultGrow = origUnlock, origMounted, origGrow })
}

func TestGrowVaultValidation(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	path := fmt.Sprintf("/api/vaults/%d/grow", v.ID)
	tests := []struct {
		name string
		body map[string]any
	}{
		{"zero size", map[string]any{"size_gb": 0}},
		{"negative size", map[string]any{"size_gb": -5}},
		{"exceeds max", map[string]any{"size_gb": 101}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(h, http.MethodPost, path, "admin", "testpass", "10.9.9.9:9", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestGrowVaultNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults/99999/grow", map[string]any{"size_gb": 20})
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestGrowVaultMustBeMounted(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	tests := []struct {
		name     string
		unlocked bool
		mounted  bool
	}{
		{"locked vault", false, false},
		{"unlocked but not mounted", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubVaultState(t, tt.unlocked, tt.mounted, nil)
			w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), map[string]any{"size_gb": 20})
			if w.Code != http.StatusConflict {
				t.Errorf("got %d, want 409; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestGrowVaultGrowOnly(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	growCalled := false
	stubVaultState(t, true, true, func(context.Context, *db.Vault, int) error {
		growCalled = true
		return nil
	})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), map[string]any{"size_gb": 10})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422; body: %s", w.Code, w.Body.String())
	}
	if growCalled {
		t.Error("vault.Grow was invoked despite same-size request")
	}
}

func TestGrowVaultSuccess(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var gotSize int
	stubVaultState(t, true, true, func(_ context.Context, _ *db.Vault, sizeGB int) error {
		gotSize = sizeGB
		return nil
	})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), map[string]any{"size_gb": 25})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if gotSize != 25 {
		t.Errorf("vault.Grow called with %d, want 25", gotSize)
	}
	var resp vaultResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SizeGB != 25 {
		t.Errorf("response size_gb = %d, want 25", resp.SizeGB)
	}
	got, err := database.GetVault(v.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.SizeGB != 25 {
		t.Errorf("db record size_gb = %d, want 25", got.SizeGB)
	}
}

func TestGrowVaultFailure(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	stubVaultState(t, true, true, func(context.Context, *db.Vault, int) error {
		return fmt.Errorf("cryptsetup resize: Operation aborted")
	})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), map[string]any{"size_gb": 25})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422", w.Code)
	}
	// The size display must not have been updated.
	got, err := database.GetVault(v.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.SizeGB != 10 {
		t.Errorf("db record size_gb = %d, want 10 (unchanged)", got.SizeGB)
	}
}

// --- POST /api/vaults/{id}/keyslot/add ----------------------------------------

func stubKeyOps(t *testing.T, add func(*db.Vault, string, string, int) error, kill func(*db.Vault, string, int) error, dump func(*db.Vault) (*vault.LUKSDetails, error)) {
	t.Helper()
	origAdd, origKill, origDump := vaultAddKey, vaultKillSlot, vaultDumpDetails
	vaultAddKey, vaultKillSlot, vaultDumpDetails = add, kill, dump
	t.Cleanup(func() { vaultAddKey, vaultKillSlot, vaultDumpDetails = origAdd, origKill, origDump })
}

func keyslotAddBody() map[string]any {
	return map[string]any{
		"existing_password": "correct horse",
		"new_password":      "battery staple",
	}
}

func TestKeyslotAddValidation(t *testing.T) {
	h, _ := newTestMux(t)
	base := keyslotAddBody()
	tests := []struct {
		name string
		body map[string]any
	}{
		{"missing existing password", with(base, "existing_password", "")},
		{"missing new password", with(base, "new_password", "")},
		{"short new password", with(base, "new_password", "short")},
		{"negative slot", with(base, "key_slot", -1)},
		{"slot too high", with(base, "key_slot", 32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fresh IP per case: the endpoint rate-limits before validating,
			// so validation tests would otherwise burn the shared burst.
			w := request(h, http.MethodPost, "/api/vaults/99999/keyslot/add", "admin", "testpass", "10.1.1.1:1", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestKeyslotAddNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults/99999/keyslot/add", keyslotAddBody())
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestKeyslotAddSuccess(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var gotSlot int
	stubKeyOps(t,
		func(_ *db.Vault, _, _ string, slot int) error {
			gotSlot = slot
			return nil
		},
		nil,
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2", KeySlots: []vault.KeySlot{
				{Index: 0, Type: "argon2id", Status: "valid"},
				{Index: 1, Type: "argon2id", Status: "valid"},
			}}, nil
		})

	// Explicit slot 0 — a pointer, so 0 must not be treated as "auto".
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/add", v.ID), with(keyslotAddBody(), "key_slot", 0))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if gotSlot != 0 {
		t.Errorf("slot passed to vault.AddKey = %d, want 0", gotSlot)
	}
	var resp vault.LUKSDetails
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.KeySlots) != 2 {
		t.Errorf("keyslots = %+v, want 2 slots in response", resp.KeySlots)
	}
}

func TestKeyslotAddAutoSlot(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var gotSlot = 42
	stubKeyOps(t,
		func(_ *db.Vault, _, _ string, slot int) error {
			gotSlot = slot
			return nil
		},
		nil,
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2"}, nil
		})
	// No key_slot in the body — cryptsetup should pick (slot < 0).
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/add", v.ID), keyslotAddBody())
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if gotSlot != -1 {
		t.Errorf("slot passed to vault.AddKey = %d, want -1 (auto)", gotSlot)
	}
}

func TestKeyslotAddWrongExistingPassword(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	stubKeyOps(t,
		func(*db.Vault, string, string, int) error {
			return fmt.Errorf("luksAddKey: No key available with this passphrase")
		},
		nil, nil)
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/add", v.ID), keyslotAddBody())
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422", w.Code)
	}
}

func TestKeyslotAddRateLimit(t *testing.T) {
	h, _ := newTestMux(t)
	stubKeyOps(t, func(*db.Vault, string, string, int) error { return nil }, nil, nil)
	const ip = "10.7.7.7:7777"
	for i := range 5 {
		w := request(h, http.MethodPost, "/api/vaults/99999/keyslot/add", "admin", "testpass", ip, keyslotAddBody())
		// 404 (vault missing) is fine — what matters is that it isn't 429.
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d unexpectedly rate-limited", i+1)
		}
	}
	w := request(h, http.MethodPost, "/api/vaults/99999/keyslot/add", "admin", "testpass", ip, keyslotAddBody())
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("6th request: got %d, want 429", w.Code)
	}
}

// --- POST /api/vaults/{id}/unlock and /keyslot/add with keyfiles ----------------

// b64 returns the base64 of s, for keyfile bodies.
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func stubKeyfileOps(t *testing.T, unlockKey func(*db.Vault, []byte) error, addKeyFile func(*db.Vault, []byte, []byte, int) error) {
	t.Helper()
	origUnlock, origAdd := vaultUnlockKeyFile, vaultAddKeyFile
	vaultUnlockKeyFile, vaultAddKeyFile = unlockKey, addKeyFile
	t.Cleanup(func() { vaultUnlockKeyFile, vaultAddKeyFile = origUnlock, origAdd })
}

func TestUnlockWithKeyFile(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var gotKey []byte
	stubKeyfileOps(t,
		func(_ *db.Vault, key []byte) error {
			gotKey = key
			return nil
		},
		nil)
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/unlock", v.ID),
		map[string]string{"key_file": b64("a-file-keyfile-0123456789")})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if string(gotKey) != "a-file-keyfile-0123456789" {
		t.Errorf("key passed to vault.UnlockKeyFile = %q", gotKey)
	}
}

func TestUnlockKeyFileValidation(t *testing.T) {
	h, _ := newTestMux(t)
	tests := []struct {
		name string
		body map[string]any
	}{
		{"neither password nor key_file", map[string]any{}},
		{"both password and key_file", map[string]any{"password": "strongpassword", "key_file": b64("12345678")}},
		{"invalid base64", map[string]any{"key_file": "!!!not-base64!!!"}},
		{"keyfile too short", map[string]any{"key_file": b64("1234")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(h, http.MethodPost, "/api/vaults/99999/unlock", "admin", "testpass", "10.3.3.3:3", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestKeyslotAddWithNewKeyFile(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var gotExisting, gotNew []byte
	stubKeyOps(t, nil, nil,
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2"}, nil
		})
	stubKeyfileOps(t, nil,
		func(_ *db.Vault, existing, newKey []byte, _ int) error {
			gotExisting, gotNew = existing, newKey
			return nil
		})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/add", v.ID), map[string]any{
		"existing_password": "correct horse",
		"new_key_file":      b64("random-keyfile-bytes-0123456789"),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if string(gotExisting) != "correct horse" {
		t.Errorf("existing credential = %q, want the typed password", gotExisting)
	}
	if string(gotNew) != "random-keyfile-bytes-0123456789" {
		t.Errorf("new credential = %q, want the decoded keyfile", gotNew)
	}
}

func TestKeyslotAddWithExistingKeyFile(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var gotExisting []byte
	stubKeyOps(t, nil, nil,
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2"}, nil
		})
	stubKeyfileOps(t, nil,
		func(_ *db.Vault, existing, _ []byte, _ int) error {
			gotExisting = existing
			return nil
		})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/add", v.ID), map[string]any{
		"existing_key_file": b64("existing-slot-keyfile-01234567"),
		"new_password":      "battery staple",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if string(gotExisting) != "existing-slot-keyfile-01234567" {
		t.Errorf("existing credential = %q, want the decoded keyfile", gotExisting)
	}
}

func TestKeyslotAddKeyFileValidation(t *testing.T) {
	h, _ := newTestMux(t)
	base := map[string]any{
		"existing_password": "correct horse",
		"new_password":      "battery staple",
	}
	tests := []struct {
		name string
		body map[string]any
	}{
		{"both new credentials", with(base, "new_key_file", b64("12345678"))},
		{"both existing credentials", with(base, "existing_key_file", b64("12345678"))},
		{"invalid base64 new keyfile", with(with(base, "new_password", ""), "new_key_file", "!!!not-base64!!!")},
		{"new keyfile too short", with(with(base, "new_password", ""), "new_key_file", b64("1234"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(h, http.MethodPost, "/api/vaults/99999/keyslot/add", "admin", "testpass", "10.4.4.4:4", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

// --- POST /api/vaults/{id}/keyslot/remove -------------------------------------

func TestKeyslotRemoveValidation(t *testing.T) {
	h, _ := newTestMux(t)
	tests := []struct {
		name string
		body map[string]any
	}{
		{"missing password", map[string]any{"key_slot": 1}},
		{"negative slot", map[string]any{"password": "correct horse", "key_slot": -1}},
		{"slot too high", map[string]any{"password": "correct horse", "key_slot": 32}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(h, http.MethodPost, "/api/vaults/99999/keyslot/remove", "admin", "testpass", "10.2.2.2:2", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestKeyslotRemoveNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults/99999/keyslot/remove", map[string]any{"password": "correct horse", "key_slot": 1})
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

// Killing the last valid keyslot must be refused with 409 BEFORE
// vault.KillSlot runs — otherwise the master key becomes unreachable.
func TestKeyslotRemoveLastSlot(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	killCalled := false
	stubKeyOps(t, nil,
		func(*db.Vault, string, int) error {
			killCalled = true
			return nil
		},
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2", KeySlots: []vault.KeySlot{
				{Index: 0, Type: "argon2id", Status: "valid"},
			}}, nil
		})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/remove", v.ID), map[string]any{"password": "correct horse", "key_slot": 0})
	if w.Code != http.StatusConflict {
		t.Errorf("got %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if killCalled {
		t.Error("vault.KillSlot was invoked despite the last-slot guard")
	}
}

func TestKeyslotRemoveSuccess(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var killedSlot = -1
	stubKeyOps(t, nil,
		func(_ *db.Vault, _ string, slot int) error {
			killedSlot = slot
			return nil
		},
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2", KeySlots: []vault.KeySlot{
				{Index: 0, Type: "argon2id", Status: "valid"},
				{Index: 1, Type: "argon2id", Status: "valid"},
			}}, nil
		})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/remove", v.ID), map[string]any{"password": "correct horse", "key_slot": 1})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if killedSlot != 1 {
		t.Errorf("slot passed to vault.KillSlot = %d, want 1", killedSlot)
	}
	var resp vault.LUKSDetails
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.KeySlots) != 2 {
		t.Errorf("keyslots = %+v, want re-read details in response", resp.KeySlots)
	}
}

func TestKeyslotRemoveWrongPassword(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	stubKeyOps(t, nil,
		func(*db.Vault, string, int) error {
			return fmt.Errorf("luksKillSlot: No key available with this passphrase")
		},
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2", KeySlots: []vault.KeySlot{
				{Index: 0, Type: "argon2id", Status: "valid"},
				{Index: 1, Type: "argon2id", Status: "valid"},
			}}, nil
		})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/remove", v.ID), map[string]any{"password": "wrong", "key_slot": 1})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422", w.Code)
	}
}
