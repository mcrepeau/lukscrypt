package main

import (
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
