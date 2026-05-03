package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestIsValidVaultName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// valid
		{"lowercase letters", "myvault", true},
		{"hyphens", "my-vault", true},
		{"numbers", "vault2", true},
		{"mixed", "my-vault-2", true},
		{"single char", "a", true},
		{"max length (64)", strings.Repeat("a", 64), true},

		// invalid: length
		{"empty", "", false},
		{"too long (65)", strings.Repeat("a", 65), false},

		// invalid: disallowed characters
		{"uppercase", "MyVault", false},
		{"underscore", "my_vault", false},
		{"space", "my vault", false},
		{"dot", "my.vault", false},
		{"leading hyphen", "-vault", true}, // hyphens anywhere are allowed
		{"trailing hyphen", "vault-", true},

		// invalid: path traversal attempts
		{"dot-dot", "..", false},
		{"dot-dot-slash", "../etc", false},
		{"slash", "my/vault", false},
		{"absolute path", "/etc/passwd", false},
		{"null byte", "vault\x00name", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidVaultName(tt.input); got != tt.want {
				t.Errorf("isValidVaultName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"direct connection", "1.2.3.4:5678", "", "1.2.3.4"},
		{"single XFF entry", "proxy:9999", "10.0.0.1", "10.0.0.1"},
		{"XFF with surrounding spaces", "proxy:9999", "  10.0.0.1  ", "10.0.0.1"},
		{"XFF chain takes first entry", "proxy:9999", "10.0.0.1, 10.0.0.2, 10.0.0.3", "10.0.0.1"},
		{"XFF chain with spaces", "proxy:9999", " 10.0.0.1 , 10.0.0.2", "10.0.0.1"},
		{"IPv6 remote addr", "[::1]:8080", "", "::1"},
		{"unparseable remote addr falls back", "badaddr", "", "badaddr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIP(r); got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAllowedStorageDir(t *testing.T) {
	h := &handler{
		storageDirs: []string{"/vaults", "/tank/encrypted"},
	}
	tests := []struct {
		path string
		want bool
	}{
		{"/vaults", true},
		{"/tank/encrypted", true},
		{"/etc", false},
		{"/vaults/subdir", false},  // subdirectory of allowed dir is not allowed
		{"/tank", false},           // parent of allowed dir is not allowed
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := h.allowedStorageDir(tt.path); got != tt.want {
				t.Errorf("allowedStorageDir(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestAllowedMountDir(t *testing.T) {
	h := &handler{
		mountDirs: []string{"/mnt"},
	}
	tests := []struct {
		path string
		want bool
	}{
		{"/mnt", true},
		{"/mnt/subdir", false},
		{"/srv", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := h.allowedMountDir(tt.path); got != tt.want {
				t.Errorf("allowedMountDir(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
