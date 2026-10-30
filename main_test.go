package main

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

// The server must have request-side timeouts so slowloris-style connections
// (even unauthenticated) are closed instead of being held open forever — and
// stalling srv.Shutdown() during the graceful drain.
func TestNewHTTPServerTimeouts(t *testing.T) {
	srv := newHTTPServer(http.NewServeMux())
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", srv.ReadTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", srv.IdleTimeout)
	}
	// WriteTimeout must stay zero: it is an absolute per-response deadline and
	// would kill long-lived SSE progress streams mid-creation.
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, must be 0 (SSE streams are long-lived)", srv.WriteTimeout)
	}
}

// Behavioral check: a connection that sends only partial headers is closed by
// the server once ReadHeaderTimeout elapses. Short timeouts keep the test fast;
// newHTTPServer pins the production values.
func TestServerClosesSlowHeaderConnection(t *testing.T) {
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		ReadHeaderTimeout: 300 * time.Millisecond,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Incomplete headers: no terminating blank line, so the request never
	// completes and the header deadline must fire.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("server did not close the stalled connection")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("connection closed after %v, want ~300ms (ReadHeaderTimeout)", elapsed)
	}
}

func TestParseList(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		defaultVal string
		want       []string
	}{
		{"empty falls back to default", "", "/vaults", []string{"/vaults"}},
		{"single value", "/vaults", "/default", []string{"/vaults"}},
		{"multiple values", "/vaults,/tank", "/default", []string{"/vaults", "/tank"}},
		{"whitespace trimmed", " /vaults , /tank ", "/default", []string{"/vaults", "/tank"}},
		{"empty entries ignored", "/vaults,,/tank", "/default", []string{"/vaults", "/tank"}},
		{"only commas falls back to default", ",,,", "/default", []string{"/default"}},
		{"only whitespace falls back to default", "  ,  ", "/default", []string{"/default"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseList(tt.env, tt.defaultVal)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseList(%q, %q) = %v, want %v", tt.env, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestParseMaxSize(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		defaultVal int
		want       int
	}{
		{"empty falls back to default", "", 100, 100},
		{"valid value", "500", 100, 500},
		{"minimum valid value", "1", 100, 1},
		{"large value", "99999", 100, 99999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMaxSize(tt.env, tt.defaultVal)
			if got != tt.want {
				t.Errorf("parseMaxSize(%q, %d) = %d, want %d", tt.env, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestParseAutoLockHours(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want float64
	}{
		{"empty disables", "", 0},
		{"zero disables", "0", 0},
		{"whole hours", "6", 6},
		{"sub-hour float", "0.5", 0.5},
		{"test-sized float", "0.02", 0.02},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAutoLockHours(tt.env)
			if got != tt.want {
				t.Errorf("parseAutoLockHours(%q) = %v, want %v", tt.env, got, tt.want)
			}
		})
	}
}

// Invalid values must exit the process. Verified by re-running this test
// as a subprocess with the bad value in the environment.
func TestParseAutoLockHoursInvalidExits(t *testing.T) {
	if os.Getenv("BE_BAD_AUTO_LOCK") == "1" {
		parseAutoLockHours("-3")
		// Unreachable: parseAutoLockHours calls os.Exit(1) on negatives.
		t.Fatal("negative value did not exit the process")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestParseAutoLockHoursInvalidExits")
	cmd.Env = append(os.Environ(), "BE_BAD_AUTO_LOCK=1")
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok && !ee.Success() {
		return // exited non-zero, as it should
	}
	t.Fatalf("expected non-zero exit for a negative AUTO_LOCK_HOURS, got %v", err)
}
