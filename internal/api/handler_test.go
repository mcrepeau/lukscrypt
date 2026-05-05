package api

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lukscrypt/internal/db"
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
	h := NewMux(context.Background(), database, embed.FS{}, []string{"/vaults"}, []string{"/mnt"}, "admin", "testpass", 100)
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
