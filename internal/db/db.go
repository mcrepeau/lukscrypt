// Package db provides a thin SQLite-backed store for vault metadata.
// It intentionally stores only static configuration (path, size, mount point,
// mapper name); runtime state (mounted/unlocked) is derived live from the OS.
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

type Vault struct {
	ID         int64
	Name       string
	Path       string
	SizeGB     int
	MountPoint string
	MapperName string
	CreatedAt  string
}

func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	if err := migrate(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{conn: conn}, nil
}

func migrate(conn *sql.DB) error {
	// WAL mode allows concurrent reads during writes and is safe for single-process use.
	// synchronous=NORMAL gives a good durability/performance balance under WAL.
	for _, pragma := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=NORMAL`,
	} {
		if _, err := conn.Exec(pragma); err != nil {
			return fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}
	_, err := conn.Exec(`CREATE TABLE IF NOT EXISTS vaults (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT UNIQUE NOT NULL,
		path        TEXT NOT NULL,
		size_gb     INTEGER NOT NULL,
		mount_point TEXT NOT NULL,
		mapper_name TEXT NOT NULL,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	return err
}

func (d *DB) Close() error { return d.conn.Close() }

func (d *DB) CreateVault(name, path string, sizeGB int, mountPoint, mapperName string) (*Vault, error) {
	res, err := d.conn.Exec(
		`INSERT INTO vaults (name, path, size_gb, mount_point, mapper_name) VALUES (?, ?, ?, ?, ?)`,
		name, path, sizeGB, mountPoint, mapperName,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Vault{
		ID:         id,
		Name:       name,
		Path:       path,
		SizeGB:     sizeGB,
		MountPoint: mountPoint,
		MapperName: mapperName,
	}, nil
}

func (d *DB) ListVaults() ([]Vault, error) {
	rows, err := d.conn.Query(
		`SELECT id, name, path, size_gb, mount_point, mapper_name, created_at FROM vaults ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vaults []Vault
	for rows.Next() {
		var v Vault
		if err := rows.Scan(&v.ID, &v.Name, &v.Path, &v.SizeGB, &v.MountPoint, &v.MapperName, &v.CreatedAt); err != nil {
			return nil, err
		}
		vaults = append(vaults, v)
	}
	return vaults, rows.Err()
}

func (d *DB) GetVault(id int64) (*Vault, error) {
	var v Vault
	err := d.conn.QueryRow(
		`SELECT id, name, path, size_gb, mount_point, mapper_name, created_at FROM vaults WHERE id = ?`, id,
	).Scan(&v.ID, &v.Name, &v.Path, &v.SizeGB, &v.MountPoint, &v.MapperName, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (d *DB) DeleteVault(id int64) error {
	_, err := d.conn.Exec(`DELETE FROM vaults WHERE id = ?`, id)
	return err
}
