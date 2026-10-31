//go:build integration

package vault

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"lukscrypt/internal/db"
)

// TestIntegrationVaultLifecycle runs the REAL pipeline — cryptsetup, loop
// devices, device-mapper, /proc/mounts — end to end: create, header details,
// lock, unlock (wrong + right password), grow, keyslot add/remove, lock,
// delete. It needs root and cryptsetup, so it is gated behind the
// "integration" build tag:
//
//	sudo go test -tags integration -race -v ./internal/vault/
//
// CI runs it under sudo on ubuntu-latest (see .github/workflows/ci.yml).
// Normal `go test ./...` never compiles this file.
func TestIntegrationVaultLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration test needs root (loop devices, device-mapper, mount)")
	}
	for _, tool := range []string{"cryptsetup", "mkfs.ext4", "resize2fs", "mount", "umount"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}

	root := t.TempDir()
	storageDir := filepath.Join(root, "vaults")
	name := "itest"
	mountPoint := filepath.Join(root, "mnt", name)
	password := "integration-test-password"
	secondPassword := "second-passphrase-123"

	database, err := db.Open(filepath.Join(root, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Best-effort cleanup even on failure: close the mapper, remove files.
	t.Cleanup(func() {
		if v, err := database.GetVaultByName(name); err == nil {
			LockContext(context.Background(), v)
			Delete(v)
			database.DeleteVault(v.ID)
		}
	})

	// ── Create (fallocate → luksFormat → luksOpen → mkfs → mount → DB) ──
	ch := make(chan ProgressEvent, 256)
	lastCh := make(chan ProgressEvent, 1)
	go func() {
		var last ProgressEvent
		for ev := range ch {
			if ev.Error != "" {
				t.Errorf("progress error event: %s", ev.Error)
			}
			last = ev
		}
		lastCh <- last
	}()
	Create(ctx, database, name, storageDir, 1, password, mountPoint, ch)
	final := <-lastCh
	if !final.Done {
		t.Fatalf("create did not complete: %+v", final)
	}

	v, err := database.GetVaultByName(name)
	if err != nil {
		t.Fatalf("no DB record after create: %v", err)
	}
	if final.VaultID != v.ID {
		t.Errorf("done event vault_id = %d, DB id = %d", final.VaultID, v.ID)
	}
	if !IsUnlocked(v) {
		t.Error("/dev/mapper/" + name + " missing after create")
	}
	if !IsMounted(v) {
		t.Error("mount point not in /proc/mounts after create")
	}
	info, err := os.Stat(v.Path)
	if err != nil || info.Size() < 1<<30 {
		t.Errorf("image file size = %v, %v — want ≥ 1 GiB", info, err)
	}

	// ── LUKS header details (real luksDump) ──
	d, err := DumpDetails(v)
	if err != nil {
		t.Fatalf("DumpDetails: %v", err)
	}
	if d.Version != "2" {
		t.Errorf("LUKS version = %q, want 2", d.Version)
	}
	if d.Cipher == "" || d.UUID == "" || d.KeySizeBits == 0 {
		t.Errorf("incomplete header details: %+v", d)
	}
	if len(d.KeySlots) != 1 {
		t.Errorf("keyslots after create = %d, want 1", len(d.KeySlots))
	}

	// ── Lock, then unlock with wrong and right password ──
	if err := Lock(v); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if IsUnlocked(v) || IsMounted(v) {
		t.Error("vault still unlocked/mounted after Lock")
	}
	if err := Unlock(v, "definitely-wrong-password"); err == nil {
		t.Error("unlock with wrong password succeeded")
	}
	if IsUnlocked(v) {
		t.Error("mapper present after failed unlock")
	}
	if err := Unlock(v, password); err != nil {
		t.Fatalf("unlock with correct password: %v", err)
	}
	if !IsMounted(v) {
		t.Error("not mounted after unlock")
	}

	// ── Grow 1 GiB → 2 GiB online ──
	if err := Grow(ctx, v, 2, []byte(password)); err != nil {
		t.Fatalf("grow: %v", err)
	}
	info, _ = os.Stat(v.Path)
	if info.Size() < 2<<30 {
		t.Errorf("image not extended by grow: size = %d", info.Size())
	}

	// ── Keyslots: add a second passphrase, use it to unlock, remove slot 0 ──
	if err := AddKey(v, password, secondPassword, -1); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	d, err = DumpDetails(v)
	if err != nil || len(d.KeySlots) != 2 {
		t.Fatalf("keyslots after AddKey = %d, %v — want 2", len(d.KeySlots), err)
	}
	if err := Lock(v); err != nil {
		t.Fatalf("lock before keyslot unlock test: %v", err)
	}
	if err := Unlock(v, secondPassword); err != nil {
		t.Errorf("unlock with the NEW keyslot failed: %v", err)
	}
	if !IsMounted(v) {
		t.Error("not mounted after unlock with new keyslot")
	}
	// Remove slot 0 (original passphrase), authorized by the new one.
	d, _ = DumpDetails(v)
	if err := ValidateKillSlot(d, 0); err != nil {
		t.Fatalf("ValidateKillSlot(slot 0): %v", err)
	}
	if err := KillSlot(v, secondPassword, 0); err != nil {
		t.Fatalf("KillSlot(0): %v", err)
	}
	d, _ = DumpDetails(v)
	if len(d.KeySlots) != 1 {
		t.Errorf("keyslots after KillSlot = %d, want 1", len(d.KeySlots))
	}
	// The last valid slot must be protected.
	if err := ValidateKillSlot(d, d.KeySlots[0].Index); err == nil {
		t.Error("ValidateKillSlot allowed removing the last valid keyslot")
	}

	// ── Final lock + delete ──
	if err := Lock(v); err != nil {
		t.Fatalf("final lock: %v", err)
	}
	if IsUnlocked(v) {
		t.Error("mapper still present after final lock")
	}
	if err := database.DeleteVault(v.ID); err != nil {
		t.Fatalf("delete record: %v", err)
	}
	if err := Delete(v); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(v.Path); !os.IsNotExist(err) {
		t.Error("image file still present after Delete")
	}
}
