package db

import (
	"database/sql"
	"testing"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestCreateAndGetVault(t *testing.T) {
	d := newTestDB(t)
	created, err := d.CreateVault("test", "/vaults/test.img", 5, "/mnt/test", "test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v, err := d.GetVault(created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v.Name != "test" || v.Path != "/vaults/test.img" || v.MountPoint != "/mnt/test" {
		t.Errorf("vault = %+v", v)
	}
}

func TestGetVaultMissing(t *testing.T) {
	d := newTestDB(t)
	if _, err := d.GetVault(42); err != sql.ErrNoRows {
		t.Errorf("err = %v, want sql.ErrNoRows", err)
	}
}

func TestCreateVaultDuplicateName(t *testing.T) {
	d := newTestDB(t)
	if _, err := d.CreateVault("test", "/vaults/test.img", 5, "/mnt/test", "test"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := d.CreateVault("test", "/vaults/other.img", 5, "/mnt/other", "test"); err == nil {
		t.Error("duplicate name should fail (UNIQUE constraint)")
	}
}

func TestDeleteVault(t *testing.T) {
	d := newTestDB(t)
	v, err := d.CreateVault("test", "/vaults/test.img", 5, "/mnt/test", "test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.DeleteVault(v.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := d.GetVault(v.ID); err != sql.ErrNoRows {
		t.Errorf("err = %v, want sql.ErrNoRows", err)
	}
}

func TestAPITokenCRUD(t *testing.T) {
	d := newTestDB(t)
	tok, err := d.CreateAPIToken("nas-backup", "hash-aaa")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tok.ID == 0 || tok.Name != "nas-backup" {
		t.Errorf("token = %+v", tok)
	}
	// Duplicate name is rejected.
	if _, err := d.CreateAPIToken("nas-backup", "hash-bbb"); err == nil {
		t.Error("duplicate token name accepted")
	}
	// Lookup by hash.
	got, err := d.GetAPITokenByHash("hash-aaa")
	if err != nil || got.ID != tok.ID {
		t.Errorf("GetAPITokenByHash = %+v, %v", got, err)
	}
	if _, err := d.GetAPITokenByHash("nope"); err != sql.ErrNoRows {
		t.Errorf("missing hash: err = %v, want sql.ErrNoRows", err)
	}
	// List.
	toks, err := d.ListAPITokens()
	if err != nil || len(toks) != 1 || toks[0].TokenHash != "hash-aaa" {
		t.Errorf("list = %+v, %v", toks, err)
	}
	// Touch + delete.
	if err := d.TouchAPIToken(tok.ID); err != nil {
		t.Fatalf("touch: %v", err)
	}
	got, _ = d.GetAPITokenByHash("hash-aaa")
	if got.LastUsedAt == "" {
		t.Error("last_used_at not set after touch")
	}
	deleted, err := d.DeleteAPIToken(tok.ID)
	if err != nil || !deleted {
		t.Errorf("delete = %v, %v", deleted, err)
	}
	deleted, _ = d.DeleteAPIToken(tok.ID)
	if deleted {
		t.Error("second delete reported a row deleted")
	}
}
