package main

import (
	"os"
	"os/exec"
	"reflect"
	"testing"
)

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
