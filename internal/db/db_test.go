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
