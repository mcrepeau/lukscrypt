package api

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"runtime"
	"strings"
	"testing"
	"time"

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
	h := NewMux(context.Background(), database, embed.FS{}, []string{"/vaults"}, []string{"/mnt"}, "admin", "testpass", 100, false, 0, time.Hour, 24*time.Hour, "test")
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

// --- Basic Auth rate limiting ---------------------------------------------------

// Failed logins are throttled per IP (burst of 5, then 1/min) so the master
// AUTH_PASSWORD cannot be brute-forced at unlimited speed via any 401.
func TestBasicAuthRateLimit(t *testing.T) {
	h, _ := newTestMux(t)
	// The burst of 5 failures is allowed through as plain 401s.
	for i := 0; i < 5; i++ {
		w := request(h, http.MethodGet, "/api/config", "admin", "wrongpass", "10.9.9.9:1234", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: got %d, want 401", i, w.Code)
		}
	}
	// The 6th failure within the window is throttled.
	w := request(h, http.MethodGet, "/api/config", "admin", "wrongpass", "10.9.9.9:1234", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", w.Code)
	}
	if wa := w.Header().Get("WWW-Authenticate"); wa != "" {
		t.Errorf("429 carries WWW-Authenticate %q — browsers would re-prompt", wa)
	}
	// Correct credentials still succeed (auth is checked before the limiter)...
	w = request(h, http.MethodGet, "/api/config", "admin", "testpass", "10.9.9.9:1234", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("correct creds: got %d, want 200", w.Code)
	}
	// ...and reset the counter, so the next failure is a plain 401 again.
	w = request(h, http.MethodGet, "/api/config", "admin", "wrongpass", "10.9.9.9:1234", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("after successful login: got %d, want 401", w.Code)
	}
}

// Each client IP gets its own failure bucket.
func TestBasicAuthRateLimitPerIP(t *testing.T) {
	h, _ := newTestMux(t)
	for i := 0; i < 6; i++ {
		request(h, http.MethodGet, "/api/config", "admin", "wrongpass", "10.9.9.9:1234", nil)
	}
	w := request(h, http.MethodGet, "/api/config", "admin", "wrongpass", "10.8.8.8:1234", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("other IP: got %d, want 401 (own bucket, not 429)", w.Code)
	}
}

// --- Sessions (UI login) --------------------------------------------------------

func loginRequest(h http.Handler, user, pass, remoteAddr string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"user": user, "password": pass})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatal("no session cookie in login response")
	return nil
}

func requestWithCookie(h http.Handler, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:9999"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// The full UI flow: login issues a cookie, the cookie authenticates API calls,
// logout invalidates it. Basic Auth keeps working alongside (TestBasicAuth).
func TestLoginLogoutFlow(t *testing.T) {
	h, _ := newTestMux(t)

	// Wrong credentials → 401, no cookie.
	w := loginRequest(h, "admin", "wrongpass", "10.7.7.1:1")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong login: got %d, want 401", w.Code)
	}
	if c := sessionCookieOrNil(w); c != nil {
		t.Fatal("session cookie issued on failed login")
	}

	// Correct credentials → 200 + cookie.
	w = loginRequest(h, "admin", "testpass", "10.7.7.1:1")
	if w.Code != http.StatusOK {
		t.Fatalf("login: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	cookie := sessionCookie(t, w)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags: HttpOnly=%v SameSite=%v — want HttpOnly + SameSite=Strict", cookie.HttpOnly, cookie.SameSite)
	}

	// The cookie alone authenticates (no Basic Auth header).
	if w := requestWithCookie(h, http.MethodGet, "/api/config", cookie); w.Code != http.StatusOK {
		t.Errorf("api with session cookie: got %d, want 200", w.Code)
	}

	// Logout invalidates the session server-side.
	if w := requestWithCookie(h, http.MethodPost, "/logout", cookie); w.Code != http.StatusOK {
		t.Fatalf("logout: got %d, want 200", w.Code)
	}
	if w := requestWithCookie(h, http.MethodGet, "/api/config", cookie); w.Code != http.StatusUnauthorized {
		t.Errorf("api after logout: got %d, want 401", w.Code)
	}
}

func sessionCookieOrNil(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

// Login attempts share the per-IP failure limiter: burst 5, then 429.
func TestLoginRateLimited(t *testing.T) {
	h, _ := newTestMux(t)
	for i := 0; i < 5; i++ {
		if w := loginRequest(h, "admin", "wrongpass", "10.7.7.2:1"); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: got %d, want 401", i, w.Code)
		}
	}
	if w := loginRequest(h, "admin", "wrongpass", "10.7.7.2:1"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("6th failure: got %d, want 429", w.Code)
	}
}

// A browser navigating to / without credentials is redirected to the login
// page instead of getting a native 401 prompt.
func TestBrowserNavigationRedirectsToLogin(t *testing.T) {
	h, _ := newTestMux(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("got %d Location=%q, want 303 /login", w.Code, w.Header().Get("Location"))
	}
	// API-style request (no HTML accept) still gets the 401 challenge.
	req2 := httptest.NewRequest(http.MethodGet, "/api/vaults", nil)
	req2.RemoteAddr = "127.0.0.1:9999"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized || w2.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("api request: got %d, want 401 with WWW-Authenticate", w2.Code)
	}
}

// Sessions expire: idle timeout and absolute max age both invalidate them.
func TestSessionExpiry(t *testing.T) {
	h := &handler{
		authUser:       "admin",
		authPass:       "testpass",
		authLimiters:   make(map[string]*unlockEntry),
		sessions:       make(map[string]*session),
		sessionIdle:    time.Minute,
		sessionMaxAge:  time.Hour,
	}
	body, _ := json.Marshal(map[string]string{"user": "admin", "password": "testpass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	h.login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login: got %d, want 200", w.Code)
	}
	cookie := sessionCookie(t, w)

	authed := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	authed.AddCookie(cookie)
	if !h.validSession(authed) {
		t.Fatal("fresh session should be valid")
	}

	// Age the session past the idle timeout.
	h.sessionsMu.Lock()
	for _, s := range h.sessions {
		s.lastSeen = time.Now().Add(-2 * time.Hour)
	}
	h.sessionsMu.Unlock()
	if h.validSession(authed) {
		t.Error("idle-expired session still valid")
	}

	// Fresh session, but older than the absolute max age.
	h2 := &handler{
		authUser: "admin", authPass: "testpass",
		authLimiters: make(map[string]*unlockEntry), sessions: make(map[string]*session),
		sessionIdle: time.Hour, sessionMaxAge: time.Minute,
	}
	req2 := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body)) // fresh body
	req2.RemoteAddr = "127.0.0.1:9999"
	w2 := httptest.NewRecorder()
	h2.login(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second login: got %d, want 200; body: %s", w2.Code, w2.Body.String())
	}
	cookie2 := sessionCookie(t, w2)
	h2.sessionsMu.Lock()
	for _, s := range h2.sessions {
		s.createdAt = time.Now().Add(-2 * time.Hour)
	}
	h2.sessionsMu.Unlock()
	authed2 := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	authed2.AddCookie(cookie2)
	if h2.validSession(authed2) {
		t.Error("session past its absolute max age still valid")
	}
}

// The public /login route gets the same pre-auth hardening as the authed
// chain: body cap and CSRF origin guard.
func TestLoginPreAuthHardening(t *testing.T) {
	h, _ := newTestMux(t)

	// Oversized login body → 400, not read into memory.
	big := map[string]string{"user": "admin", "password": strings.Repeat("x", maxBodyBytes)}
	b, _ := json.Marshal(big)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
	req.RemoteAddr = "10.7.7.3:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized /login body: got %d, want 400; body: %s", w.Code, w.Body.String())
	}

	// Cross-origin POST /login → 403 before any credential check.
	body, _ := json.Marshal(map[string]string{"user": "admin", "password": "testpass"})
	req2 := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req2.RemoteAddr = "10.7.7.4:1"
	req2.Header.Set("Origin", "https://evil.example")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("cross-origin /login: got %d, want 403", w2.Code)
	}

	// Same-origin POST /login passes the guard.
	req3 := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req3.RemoteAddr = "10.7.7.5:1"
	req3.Header.Set("Origin", "http://"+req3.Host)
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("same-origin /login: got %d, want 200; body: %s", w3.Code, w3.Body.String())
	}
}

// The session cookie must be Secure whenever the outer hop is TLS — directly
// (r.TLS) or behind a trusted TLS proxy (TRUST_PROXY=true, where r.TLS is nil).
// Plain-HTTP local testing keeps it off.
func TestSessionCookieSecureFlag(t *testing.T) {
	loginWith := func(trustProxy bool, useTLS bool) *http.Cookie {
		h := &handler{
			authUser: "admin", authPass: "testpass", trustProxy: trustProxy,
			authLimiters: make(map[string]*unlockEntry), sessions: make(map[string]*session),
			sessionIdle: time.Hour, sessionMaxAge: 24 * time.Hour,
		}
		body, _ := json.Marshal(map[string]string{"user": "admin", "password": "testpass"})
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9999"
		if useTLS {
			req.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		h.login(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("login: got %d", w.Code)
		}
		return sessionCookie(t, w)
	}
	if c := loginWith(false, false); c.Secure {
		t.Error("plain HTTP local testing: cookie must NOT be Secure")
	}
	if c := loginWith(false, true); !c.Secure {
		t.Error("direct TLS: cookie must be Secure")
	}
	if c := loginWith(true, false); !c.Secure {
		t.Error("behind TLS proxy (TRUST_PROXY): cookie must be Secure even though r.TLS is nil")
	}
}

// --- API tokens ---------------------------------------------------------------

func bearerRequest(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// Full token lifecycle: create (raw token shown once) → Bearer works →
// Basic-with-token works → master password still works → revoke → 401.
func TestAPITokensFlow(t *testing.T) {
	h, _ := newTestMux(t)

	w := auth(h, http.MethodPost, "/api/tokens", map[string]any{"name": "nas-backup"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID == 0 || created.Name != "nas-backup" || !strings.HasPrefix(created.Token, "lukscrypt_") {
		t.Errorf("created = %+v", created)
	}

	// Duplicate name → 409.
	if w := auth(h, http.MethodPost, "/api/tokens", map[string]any{"name": "nas-backup"}); w.Code != http.StatusConflict {
		t.Errorf("duplicate name: got %d, want 409", w.Code)
	}

	// List shows metadata only — never the raw token or the hash.
	w = auth(h, http.MethodGet, "/api/tokens", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, created.Token) || strings.Contains(body, "token_hash") {
		t.Errorf("list response leaks token material: %s", body)
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(body), &list); err != nil || len(list) != 1 || list[0]["name"] != "nas-backup" {
		t.Errorf("list = %v, err=%v", list, err)
	}

	// Bearer token authenticates.
	if w := bearerRequest(h, http.MethodGet, "/api/config", created.Token); w.Code != http.StatusOK {
		t.Errorf("bearer: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// Token as the Basic Auth password works too (curl -u admin:lukscrypt_...).
	if w := request(h, http.MethodGet, "/api/config", "admin", created.Token, "127.0.0.1:9999", nil); w.Code != http.StatusOK {
		t.Errorf("basic-with-token: got %d, want 200", w.Code)
	}
	// Master password still works.
	if w := auth(h, http.MethodGet, "/api/config", nil); w.Code != http.StatusOK {
		t.Errorf("master basic auth: got %d, want 200", w.Code)
	}
	// Wrong token → 401.
	if w := bearerRequest(h, http.MethodGet, "/api/config", "lukscrypt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); w.Code != http.StatusUnauthorized {
		t.Errorf("bad bearer: got %d, want 401", w.Code)
	}

	// Revoke → 204; the token stops working immediately.
	if w := auth(h, http.MethodDelete, fmt.Sprintf("/api/tokens/%d", created.ID), nil); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: got %d, want 204", w.Code)
	}
	if w := bearerRequest(h, http.MethodGet, "/api/config", created.Token); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: got %d, want 401", w.Code)
	}
	if w := auth(h, http.MethodDelete, fmt.Sprintf("/api/tokens/%d", created.ID), nil); w.Code != http.StatusNotFound {
		t.Errorf("re-revoke: got %d, want 404", w.Code)
	}
}

func TestCreateTokenValidation(t *testing.T) {
	h, _ := newTestMux(t)
	tests := map[string]map[string]any{
		"empty name":   {"name": ""},
		"missing name": {},
		"too long":     {"name": strings.Repeat("a", 65)},
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			w := auth(h, http.MethodPost, "/api/tokens", body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
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
		pendingPaths:   make(map[string]struct{}),
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

// newCreateTestHandler builds a handler wired for calling createVault
// directly, with the maps createVault needs initialized.
func newCreateTestHandler(t *testing.T, database *db.DB) *handler {
	t.Helper()
	return &handler{
		ctx:            context.Background(),
		db:             database,
		storageDirs:    []string{"/vaults"},
		mountDirs:      []string{"/mnt"},
		authUser:       "admin",
		authPass:       "testpass",
		maxSizeGB:      100,
		autoLockHours:  0.02,
		jobs:           make(map[string]*jobEntry),
		pendingNames:   make(map[string]struct{}),
		pendingPaths:   make(map[string]struct{}),
		unlockLimiters: make(map[string]*unlockEntry),
		authLimiters:   make(map[string]*unlockEntry),
		unlockedAt:     make(map[int64]time.Time),
	}
}

func callCreateVault(h *handler, body map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/vaults", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.createVault(w, req)
	return w
}

// waitPendingReleased polls until the create goroutine has released the
// pending-name reservation (its defer runs after the auto-lock marking).
func waitPendingReleased(t *testing.T, h *handler, name string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.opMu.Lock()
		_, pending := h.pendingNames[name]
		h.opMu.Unlock()
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("create goroutine did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func isMarkedUnlocked(h *handler, id int64) bool {
	h.unlockedMu.Lock()
	defer h.unlockedMu.Unlock()
	_, ok := h.unlockedAt[id]
	return ok
}

// A vault created via POST /api/vaults ends up unlocked and mounted — its
// auto-lock window must start at creation, not only on an explicit unlock
// (regression: created vaults were never auto-locked).
func TestCreateVaultStartsAutoLockWindow(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	h := newCreateTestHandler(t, database)

	// Simulate a successful create pipeline: insert the DB record.
	origCreate := vaultCreate
	vaultCreate = func(_ context.Context, d *db.DB, name, path string, sizeGB int, _ string, mountPoint string, ch chan<- vault.ProgressEvent) {
		defer close(ch)
		d.CreateVault(name, path+"/"+name+".img", sizeGB, mountPoint, name)
	}
	t.Cleanup(func() { vaultCreate = origCreate })
	origIsUnlocked := vaultIsUnlocked
	vaultIsUnlocked = func(*db.Vault) bool { return true }
	t.Cleanup(func() { vaultIsUnlocked = origIsUnlocked })

	if w := callCreateVault(h, validCreateBody()); w.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202; body: %s", w.Code, w.Body.String())
	}
	waitPendingReleased(t, h, "myvault")
	if !isMarkedUnlocked(h, 1) {
		t.Error("created vault was not marked unlocked — auto-lock would never lock it")
	}
}

// A failed creation must NOT start an auto-lock window (no record, device
// closed by cleanup).
func TestCreateVaultFailureDoesNotStartAutoLockWindow(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	h := newCreateTestHandler(t, database)

	origCreate := vaultCreate
	vaultCreate = func(_ context.Context, _ *db.DB, _ string, _ string, _ int, _ string, _ string, ch chan<- vault.ProgressEvent) {
		defer close(ch) // fails: no record inserted
	}
	t.Cleanup(func() { vaultCreate = origCreate })
	origIsUnlocked := vaultIsUnlocked
	vaultIsUnlocked = func(*db.Vault) bool { return true }
	t.Cleanup(func() { vaultIsUnlocked = origIsUnlocked })

	if w := callCreateVault(h, validCreateBody()); w.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202; body: %s", w.Code, w.Body.String())
	}
	waitPendingReleased(t, h, "myvault")
	if isMarkedUnlocked(h, 1) {
		t.Error("failed creation must not start an auto-lock window")
	}
}

// Oversized request bodies are rejected with 400 instead of being read into
// memory without bound (MaxBytesReader). The 8 MiB cap leaves keyfile
// uploads (≤ ~1.4 MB on the wire) plenty of headroom.
func TestBodySizeLimit(t *testing.T) {
	h, _ := newTestMux(t)
	big := with(validCreateBody(), "password", strings.Repeat("x", maxBodyBytes))
	w := auth(h, http.MethodPost, "/api/vaults", big)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid request body") {
		t.Errorf("oversized body: got %d, body %q — want 400 invalid request body", w.Code, w.Body.String())
	}
	// A normal-sized body still reaches validation (400 here is the password
	// rule, proving the decode succeeded).
	w = auth(h, http.MethodPost, "/api/vaults", with(validCreateBody(), "password", "short"))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "password must be at least 8") {
		t.Errorf("small body: got %d, body %q — want 400 password rule (decode succeeded)", w.Code, w.Body.String())
	}
}

// When the SSE client disconnects mid-creation, the handler keeps draining the
// job channel until the creation goroutine closes it — so the goroutine's
// blocking terminal send never stalls on a full buffer.
func TestVaultEventsDrainsAfterDisconnect(t *testing.T) {
	ch := make(chan vault.ProgressEvent, 4)
	h := &handler{
		jobs: map[string]*jobEntry{"job1": {ch: ch, created: time.Now()}},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/vaults/events/job1", nil)
	req.SetPathValue("jobID", "job1") // direct call bypasses the mux's pattern matching
	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { h.vaultEvents(w, req); close(done) }()

	ch <- vault.ProgressEvent{Step: "creating", Percent: 10}
	cancel() // client disconnects
	// Feed the terminal event and close: the handler must drain and return.
	ch <- vault.ProgressEvent{Step: "done", Done: true, Percent: 100}
	close(ch)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("vaultEvents did not return after the job channel closed")
	}
	h.jobsMu.Lock()
	_, stillThere := h.jobs["job1"]
	h.jobsMu.Unlock()
	if stillThere {
		t.Error("job entry was not removed after client disconnect")
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
	h := NewMux(context.Background(), database, embed.FS{}, storageDirs, mountDirs, "admin", "testpass", 100, false, 0, time.Hour, 24*time.Hour, "test")
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
		{"path traversal with dot-dot", map[string]any{"name": "x", "path": "/vaults/../etc/x.img", "mount_dir": "/mnt"}},
		{"path traversal with double slash", map[string]any{"name": "x", "path": "/vaults//../etc/x.img", "mount_dir": "/mnt"}},
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

// An import racing an in-flight create of the same name or image path must be
// refused with 409: the create goroutine deletes the image on failure, and a
// record inserted here would become a ghost pointing at a missing file.
func TestImportVaultConflictsWithInFlightCreate(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return nil, fmt.Errorf("luksDump: not a valid LUKS device")
	})
	h := &handler{
		db:           database,
		storageDirs:  []string{"/vaults"},
		mountDirs:    []string{"/mnt"},
		pendingNames: map[string]struct{}{"myvault": {}},          // simulate in-flight creation
		pendingPaths: map[string]struct{}{"/vaults/creating.img": {}}, // simulate in-flight creation
	}
	call := func(body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/vaults/import", bytes.NewReader(b))
		w := httptest.NewRecorder()
		h.importVault(w, req)
		return w
	}
	if w := call(map[string]any{"name": "myvault", "path": "/vaults/other.img", "mount_dir": "/mnt"}); w.Code != http.StatusConflict {
		t.Errorf("name conflict: got %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if w := call(map[string]any{"name": "other", "path": "/vaults/creating.img", "mount_dir": "/mnt"}); w.Code != http.StatusConflict {
		t.Errorf("path conflict: got %d, want 409; body: %s", w.Code, w.Body.String())
	}
	// An unrelated import passes the pending checks and fails later at the
	// LUKS probe (422) — proving it was not blocked by the reservations.
	if w := call(map[string]any{"name": "other", "path": "/vaults/other.img", "mount_dir": "/mnt"}); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unrelated import: got %d, want 422 (past the pending checks); body: %s", w.Code, w.Body.String())
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

// pathInStorageDir canonicalizes before the prefix check: a ".." segment must
// not let an image outside the allowlist be registered (and later unlocked,
// mounted or deleted) through the import endpoint.
func TestImportVaultRejectsTraversal(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	storage := root + "/vaults"
	outside := root + "/secret"
	if err := os.MkdirAll(storage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside+"/secret.img", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, database := newTestMuxWithDirs(t, []string{storage}, []string{"/mnt"})
	// If validation were bypassed the import would succeed — the stub turns a
	// bypass into a visible 201 instead of the expected 400.
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return &vault.LUKSDetails{Version: "2"}, nil
	})
	paths := []string{
		storage + "/../secret/secret.img",
		storage + "/./../secret/secret.img",
		storage + "//../secret/secret.img",
		storage + "/sub/../../secret/secret.img",
		outside + "/secret.img", // absolute path outside the allowlist
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			w := auth(h, http.MethodPost, "/api/vaults/import",
				map[string]any{"name": "evil", "path": p, "mount_dir": "/mnt"})
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
	if v, err := database.GetVaultByName("evil"); err == nil {
		t.Errorf("vault record was created from a traversal path: %+v", v)
	}
}

// A symlink inside a storage dir must not let an import point outside the
// allowlist: both the file and the storage dir are resolved (EvalSymlinks)
// before the containment check.
func TestImportVaultRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Symlink requires privileges on Windows")
	}
	root := filepath.ToSlash(t.TempDir())
	storage := root + "/vaults"
	outside := root + "/secret"
	if err := os.MkdirAll(storage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside+"/secret.img", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside+"/secret.img", storage+"/link.img"); err != nil {
		t.Fatal(err)
	}
	h, database := newTestMuxWithDirs(t, []string{storage}, []string{"/mnt"})
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return &vault.LUKSDetails{Version: "2"}, nil
	})
	w := auth(h, http.MethodPost, "/api/vaults/import",
		map[string]any{"name": "link", "path": storage + "/link.img", "mount_dir": "/mnt"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if v, err := database.GetVaultByName("link"); err == nil {
		t.Errorf("vault record was created through a symlink escape: %+v", v)
	}
}

// A ".." segment that stays inside the allowlist is fine, but the stored
// record must hold the canonical path, never the raw input.
func TestImportVaultStoresCleanedPath(t *testing.T) {
	storage := filepath.ToSlash(t.TempDir())
	img := storage + "/real.img"
	if err := os.WriteFile(img, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 1<<30); err != nil {
		t.Fatal(err)
	}
	h, database := newTestMuxWithDirs(t, []string{storage}, []string{"/mnt"})
	stubDumpDetails(t, func(*db.Vault) (*vault.LUKSDetails, error) {
		return &vault.LUKSDetails{Version: "2"}, nil
	})
	w := auth(h, http.MethodPost, "/api/vaults/import",
		map[string]any{"name": "real", "path": storage + "/sub/../real.img", "mount_dir": "/mnt"})
	if w.Code != http.StatusCreated {
		t.Fatalf("got %d, want 201; body: %s", w.Code, w.Body.String())
	}
	got, err := database.GetVaultByName("real")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Path != img {
		t.Errorf("stored path = %q, want canonical %q", got.Path, img)
	}
}

// --- POST /api/vaults/{id}/grow -------------------------------------------------

func stubVaultState(t *testing.T, unlocked bool, mounted bool, grow func(context.Context, *db.Vault, int, []byte) error) {
	t.Helper()
	origUnlock, origMounted, origGrow := vaultIsUnlocked, vaultIsMounted, vaultGrow
	vaultIsUnlocked = func(*db.Vault) bool { return unlocked }
	vaultIsMounted = func(*db.Vault) bool { return mounted }
	if grow != nil {
		vaultGrow = grow
	}
	t.Cleanup(func() { vaultIsUnlocked, vaultIsMounted, vaultGrow = origUnlock, origMounted, origGrow })
}

func growBody(sizeGB int) map[string]any {
	return map[string]any{"size_gb": sizeGB, "password": "correct horse"}
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
		{"zero size", growBody(0)},
		{"negative size", growBody(-5)},
		{"exceeds max", growBody(101)},
		{"no credential", map[string]any{"size_gb": 20}},
		{"both credentials", map[string]any{"size_gb": 20, "password": "correct horse", "key_file": b64("12345678")}},
		{"short password", map[string]any{"size_gb": 20, "password": "short"}},
		{"keyfile too short", map[string]any{"size_gb": 20, "key_file": b64("1234")}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fresh IP per case — the endpoint rate-limits before validating,
			// and the burst is only 5 per IP.
			ip := fmt.Sprintf("10.9.9.%d:9", 200+i)
			w := request(h, http.MethodPost, path, "admin", "testpass", ip, tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestGrowVaultNotFound(t *testing.T) {
	h, _ := newTestMux(t)
	w := auth(h, http.MethodPost, "/api/vaults/99999/grow", growBody(20))
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
			w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), growBody(20))
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
	stubVaultState(t, true, true, func(context.Context, *db.Vault, int, []byte) error {
		growCalled = true
		return nil
	})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), growBody(10))
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
	var gotKey []byte
	stubVaultState(t, true, true, func(_ context.Context, _ *db.Vault, sizeGB int, key []byte) error {
		gotSize = sizeGB
		gotKey = key
		return nil
	})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), growBody(25))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if gotSize != 25 {
		t.Errorf("vault.Grow called with %d, want 25", gotSize)
	}
	if string(gotKey) != "correct horse" {
		t.Errorf("credential passed to vault.Grow = %q, want the typed password", gotKey)
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

// A keyfile credential must reach vault.Grow as the decoded bytes.
func TestGrowVaultWithKeyFile(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	var gotKey []byte
	stubVaultState(t, true, true, func(_ context.Context, _ *db.Vault, _ int, key []byte) error {
		gotKey = key
		return nil
	})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID),
		map[string]any{"size_gb": 25, "key_file": b64("a-file-keyfile-0123456789")})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if string(gotKey) != "a-file-keyfile-0123456789" {
		t.Errorf("credential = %q, want decoded keyfile bytes", gotKey)
	}
}

func TestGrowVaultFailure(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	stubVaultState(t, true, true, func(context.Context, *db.Vault, int, []byte) error {
		return fmt.Errorf("cryptsetup resize: Nothing to read on input")
	})
	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/grow", v.ID), growBody(25))
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

// The grow endpoint shares unlock's per-IP rate limiter.
func TestGrowVaultRateLimit(t *testing.T) {
	h, _ := newTestMux(t)
	const ip = "10.10.10.10:10"
	for i := range 5 {
		w := request(h, http.MethodPost, "/api/vaults/99999/grow", "admin", "testpass", ip, growBody(20))
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d unexpectedly rate-limited", i+1)
		}
	}
	w := request(h, http.MethodPost, "/api/vaults/99999/grow", "admin", "testpass", ip, growBody(20))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("6th request: got %d, want 429", w.Code)
	}
}

// --- Auto-lock -------------------------------------------------------------------

func stubAutoLock(t *testing.T, fn func(context.Context, *db.Vault) error) {
	t.Helper()
	orig := vaultAutoLock
	vaultAutoLock = fn
	t.Cleanup(func() { vaultAutoLock = orig })
}

// newAutoLockHandler builds a handler struct directly (autoLockSweep tests
// don't need the full router), with auto-lock enabled and one seeded vault.
func newAutoLockHandler(t *testing.T, hours float64, seedAge time.Duration) (*handler, *db.Vault) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	v, err := database.CreateVault("avault", "/vaults/avault.img", 1, "/mnt/avault", "avault")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := &handler{
		ctx:           context.Background(),
		db:            database,
		autoLockHours: hours,
		jobs:          make(map[string]*jobEntry),
		pendingNames:  make(map[string]struct{}),
		unlockLimiters: make(map[string]*unlockEntry),
		unlockedAt:    make(map[int64]time.Time),
	}
	h.unlockedAt[v.ID] = time.Now().Add(-seedAge)
	return h, v
}

func TestAutoLockSweepLocksExpiredVault(t *testing.T) {
	h, v := newAutoLockHandler(t, 1, 2*time.Hour) // policy 1h, unlocked 2h ago
	locked := false
	stubAutoLock(t, func(context.Context, *db.Vault) error {
		locked = true
		return nil
	})
	h.autoLockSweep(time.Now())
	if !locked {
		t.Fatal("expired vault was not locked")
	}
	if _, ok := h.unlockedAt[v.ID]; ok {
		t.Error("unlock timestamp not cleared after successful auto-lock")
	}
}

func TestAutoLockSweepRespectsWindow(t *testing.T) {
	h, _ := newAutoLockHandler(t, 1, 30*time.Minute) // policy 1h, unlocked 30 min ago
	called := false
	stubAutoLock(t, func(context.Context, *db.Vault) error {
		called = true
		return nil
	})
	h.autoLockSweep(time.Now())
	if called {
		t.Error("vault locked before the auto-lock window elapsed")
	}
}

func TestAutoLockDisabled(t *testing.T) {
	h, _ := newAutoLockHandler(t, 0, 24*time.Hour) // disabled, unlocked a day ago
	called := false
	stubAutoLock(t, func(context.Context, *db.Vault) error {
		called = true
		return nil
	})
	h.autoLockSweep(time.Now())
	if called {
		t.Error("vault locked although auto-lock is disabled")
	}
}

// A busy mount (SMB clients hold files open) defers the lock: the timestamp
// must be kept so the next sweep retries.
func TestAutoLockDefersBusyMounts(t *testing.T) {
	h, v := newAutoLockHandler(t, 1, 2*time.Hour)
	stubAutoLock(t, func(context.Context, *db.Vault) error {
		return fmt.Errorf("umount: /mnt/avault: target is busy")
	})
	h.autoLockSweep(time.Now())
	if _, ok := h.unlockedAt[v.ID]; !ok {
		t.Error("unlock timestamp cleared although the mount was busy — the vault would never be auto-locked")
	}
}

// A vault locked out from under us (operator CLI) stops being tracked.
func TestAutoLockClearsAlreadyLocked(t *testing.T) {
	h, v := newAutoLockHandler(t, 1, 2*time.Hour)
	stubAutoLock(t, func(context.Context, *db.Vault) error {
		return fmt.Errorf("vault is already locked")
	})
	h.autoLockSweep(time.Now())
	if _, ok := h.unlockedAt[v.ID]; ok {
		t.Error("unlock timestamp kept for an already-locked vault")
	}
}

// Unlock through the API starts the window; manual lock ends it.
// The sweep re-reads the unlock timestamp under opMu and must not lock a
// vault whose window was restarted (manual lock→unlock) after the timestamp
// was first read.
func TestWindowRestartedGuard(t *testing.T) {
	h := &handler{unlockedAt: make(map[int64]time.Time)}
	t1 := time.Now().Add(-time.Hour)
	h.unlockedMu.Lock()
	h.unlockedAt[7] = t1
	h.unlockedMu.Unlock()

	if h.windowRestarted(7, t1) {
		t.Error("unchanged window reported as restarted")
	}
	// A manual unlock restarts the window → detected.
	h.markUnlocked(7)
	if !h.windowRestarted(7, t1) {
		t.Error("restarted window (new timestamp) not detected")
	}
	// A manual lock clears the entry (zero time) → also "changed".
	h.clearUnlocked(7)
	if !h.windowRestarted(7, t1) {
		t.Error("cleared window not detected")
	}
}

// autoLockVault with an unchanged timestamp proceeds to the lock even when
// called directly (the sweep's expiry filter is bypassed here; the guard
// must pass because the window did not restart).
func TestAutoLockVaultProceedsWhenWindowUnchanged(t *testing.T) {
	h, v := newAutoLockHandler(t, 1, 30*time.Minute) // fresh window
	called := false
	stubAutoLock(t, func(context.Context, *db.Vault) error {
		called = true
		return nil
	})
	h.autoLockVault(v.ID, time.Now())
	if !called {
		t.Error("autoLockVault skipped the lock although the window did not restart")
	}
}

func TestUnlockLockBookkeeping(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	v, err := database.CreateVault("avault", "/vaults/avault.img", 1, "/mnt/avault", "avault")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := &handler{
		ctx:            context.Background(),
		db:             database,
		jobs:           make(map[string]*jobEntry),
		pendingNames:   make(map[string]struct{}),
		unlockLimiters: make(map[string]*unlockEntry),
		unlockedAt:    make(map[int64]time.Time),
	}
	origUnlock, origLock := vaultUnlock, vaultLock
	vaultUnlock = func(context.Context, *db.Vault, string) error { return nil }
	vaultLock = func(*db.Vault) error { return nil }
	t.Cleanup(func() { vaultUnlock, vaultLock = origUnlock, origLock })

	// Unlock → timestamp recorded. PathValue must be set manually: the
	// request bypasses the mux's pattern matching.
	body := `{"password":"strongpassword"}`
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vaults/%d/unlock", v.ID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", v.ID))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	h.unlockVault(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if _, ok := h.unlockedAt[v.ID]; !ok {
		t.Fatal("unlock did not record a timestamp")
	}

	// Lock → timestamp cleared.
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vaults/%d/lock", v.ID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", v.ID))
	req.RemoteAddr = "127.0.0.1:9999"
	w = httptest.NewRecorder()
	h.lockVault(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("lock: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if _, ok := h.unlockedAt[v.ID]; ok {
		t.Error("lock did not clear the unlock timestamp")
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

func stubKeyfileOps(t *testing.T, unlockKey func(context.Context, *db.Vault, []byte) error, addKeyFile func(*db.Vault, []byte, []byte, int) error) {
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
		func(_ context.Context, _ *db.Vault, key []byte) error {
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
		{"no credential", map[string]any{"key_slot": 1}},
		{"both password and key_file", map[string]any{"password": "correct horse", "key_file": b64("a-file-keyfile-0123456789"), "key_slot": 1}},
		{"invalid key_file base64", map[string]any{"key_file": "!!!not-base64!!!", "key_slot": 1}},
		{"key_file too short", map[string]any{"key_file": b64("short"), "key_slot": 1}},
		{"negative slot", map[string]any{"password": "correct horse", "key_slot": -1}},
		{"slot too high", map[string]any{"password": "correct horse", "key_slot": 32}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// One IP per subtest: the endpoint shares unlock's rate limiter
			// (burst 5), so a shared IP would 429 before reaching validation.
			w := request(h, http.MethodPost, "/api/vaults/99999/keyslot/remove", "admin", "testpass", fmt.Sprintf("10.2.2.%d:2", i+1), tt.body)
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

// keyslot/remove also accepts a keyfile as the remaining credential — needed
// when the only other valid keyslot is keyfile-based.
func TestKeyslotRemoveWithKeyFile(t *testing.T) {
	h, database := newTestMux(t)
	v, err := database.CreateVault("testvault", "/vaults/testvault.img", 10, "/mnt/testvault", "testvault")
	if err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	stubKeyOps(t, nil, nil,
		func(*db.Vault) (*vault.LUKSDetails, error) {
			return &vault.LUKSDetails{Version: "2", KeySlots: []vault.KeySlot{
				{Index: 0, Type: "argon2id", Status: "valid"},
				{Index: 1, Type: "argon2id", Status: "valid"},
			}}, nil
		})
	var gotKey []byte
	var gotSlot = -1
	origKillKF := vaultKillSlotKeyFile
	vaultKillSlotKeyFile = func(_ *db.Vault, key []byte, slot int) error {
		gotKey, gotSlot = key, slot
		return nil
	}
	t.Cleanup(func() { vaultKillSlotKeyFile = origKillKF })

	w := auth(h, http.MethodPost, fmt.Sprintf("/api/vaults/%d/keyslot/remove", v.ID),
		map[string]any{"key_file": b64("a-file-keyfile-0123456789"), "key_slot": 1})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if string(gotKey) != "a-file-keyfile-0123456789" || gotSlot != 1 {
		t.Errorf("KillSlotKeyFile got key=%q slot=%d, want keyfile and slot 1", gotKey, gotSlot)
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
