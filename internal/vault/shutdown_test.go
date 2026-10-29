package vault

import (
	"context"
	"testing"

	"lukscrypt/internal/db"
)

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// All vaults locked (no /dev/mapper entries, no mounts) — LockAllUnlocked
// must do nothing and report no failures.
func TestLockAllUnlockedAllLocked(t *testing.T) {
	database := openTestDB(t)
	if _, err := database.CreateVault("a", "/vaults/a.img", 1, "/mnt/a", "a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := database.CreateVault("b", "/vaults/b.img", 1, "/mnt/b", "b"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	failures := LockAllUnlocked(context.Background(), database)
	if len(failures) != 0 {
		t.Errorf("failures = %v, want none", failures)
	}
}

// A vault that reports as unlocked but cannot be locked (no real device in
// the test environment) must be reported by name, and must not stop the
// remaining vaults from being processed.
func TestLockAllUnlockedCollectsFailures(t *testing.T) {
	database := openTestDB(t)
	if _, err := database.CreateVault("good", "/vaults/good.img", 1, "/mnt/good", "good"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := database.CreateVault("busy", "/vaults/busy.img", 1, "/mnt/busy", "busy"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Simulate both vaults as unlocked; the lock attempts then fail because
	// the test environment has no device-mapper entries.
	orig := isUnlocked
	isUnlocked = func(*db.Vault) bool { return true }
	t.Cleanup(func() { isUnlocked = orig })

	failures := LockAllUnlocked(context.Background(), database)
	if len(failures) != 2 {
		t.Fatalf("failures = %v, want 2 (one per unlocked vault)", failures)
	}
	// Both vaults must be named — the shutdown log relies on it.
	names := map[string]bool{}
	for _, f := range failures {
		names[f.Vault] = true
	}
	if !names["good"] || !names["busy"] {
		t.Errorf("failure vault names = %v, want good and busy", names)
	}
}

// A cancelled context must surface as failures, not block shutdown forever.
func TestLockAllUnlockedRespectsContext(t *testing.T) {
	database := openTestDB(t)
	if _, err := database.CreateVault("x", "/vaults/x.img", 1, "/mnt/x", "x"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	orig := isUnlocked
	isUnlocked = func(*db.Vault) bool { return true }
	t.Cleanup(func() { isUnlocked = orig })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already expired

	failures := LockAllUnlocked(ctx, database)
	if len(failures) != 1 {
		t.Fatalf("failures = %v, want 1", failures)
	}
}
