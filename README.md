# LUKSCrypt

A self-hosted web UI for managing LUKS-encrypted vault files on Linux, designed to run
as a privileged Docker container on a NAS (tested on Debian 12 / OpenMediaVault).

## Features

- Create LUKS vault image files and unlock/lock them from the browser
- LUKS header details per vault (cipher, keyslots, UUID) — works on locked vaults
- Passphrase keyslot management (add/remove; the last valid keyslot is protected)
- Unlock with a password **or** a keyfile; keyfile-based keyslots supported
- Scriptable API — no auto-unlock by design; credentials never rest on the NAS
- Real-time creation progress over SSE; fast `fallocate` allocation (`dd` fallback)
- Optional auto-lock after a configurable unlocked duration (busy mounts defer, never lazy-unmounted)
- Online grow of mounted vaults (grow-only)
- Import existing vault images (moved files, restored backups, lost-database recovery)
- HTTP Basic Auth (random password generated if unset) with per-IP rate limiting on failed logins and unlock attempts
- Graceful shutdown locks all unlocked vaults on SIGTERM/SIGINT
- Mounts propagate to the host via shared bind-mounts so SMB sees vault contents
- Vault metadata in SQLite (WAL); runtime state derived live from the OS
- Configurable storage/mount dirs via env vars; concurrent ops serialized against device-mapper races

## Architecture

```
lukscrypt/
├── main.go                  # Entry point — env config, DB, HTTP server
├── internal/
│   ├── api/api.go           # HTTP router + handlers (Go 1.22 stdlib mux)
│   ├── db/db.go             # SQLite vault metadata (modernc.org/sqlite)
│   └── vault/               # LUKS ops: create/unlock/lock/delete, luksDump, keyslots, grow
└── web/index.html           # Single-page UI, embedded in the binary (//go:embed)
```

Single static executable, no external file dependencies — the frontend is compiled in.

## Requirements

**Host (NAS):** Linux with dm-crypt/device-mapper and Docker privileged-container support
(`cryptsetup`, `e2fsprogs`, `util-linux` ship in the image).
**Build machine:** Go 1.22+, Docker buildx (cross-builds ARM64 for most NAS hardware).

## Deployment

Pre-built `linux/amd64` / `linux/arm64` images are published to GHCR on every tagged release.

```yaml
services:
  lukscrypt:
    image: ghcr.io/mcrepeau/lukscrypt:latest
    container_name: lukscrypt
    ports:
      - "8080:8080"
    volumes:
      - lukscrypt-data:/data
      # Vault images MUST live on a persistent bind mount or named volume —
      # otherwise recreating the container destroys the .img files while the
      # database survives, leaving ghost vault entries.
      - type: bind
        source: /srv/lukscrypt/vaults   # persistent host path
        target: /vaults
      # Shared propagation: mounts made in the container appear on the host (SMB).
      - type: bind
        source: /mnt
        target: /mnt
        bind:
          propagation: shared
    environment:
      DB_PATH: /data/lukscrypt.db
      VAULT_STORAGE_DIRS: /vaults
      VAULT_MOUNT_DIRS: /mnt
      # TRUST_PROXY: "true"     # behind a reverse proxy → rate limits use X-Forwarded-For
      # AUTO_LOCK_HOURS: "6"    # auto-lock after 6h unlocked (0.5 = 30 min; 0 = off)
      # SESSION_IDLE_HOURS: "12" # UI session idle timeout (default 12h)
      # AUTH_USER: admin         # default: admin
      # AUTH_PASSWORD: changeme  # default: random, printed once in container logs
    privileged: true          # needed for dm-crypt / loop devices / mount
    restart: unless-stopped
    stop_grace_period: 60s    # graceful shutdown locks all vaults; the default 10s would cut it short

volumes:
  lukscrypt-data:
```

```bash
docker compose pull && docker compose up -d
```

On SIGTERM/SIGINT the server drains HTTP, then unmounts + `luksClose`s every unlocked
vault, so restarts never leave stale device-mapper/loop devices on the host.

**Never expose port 8080 directly in production — put it behind a TLS-terminating
reverse proxy** (below). For local testing only, the UI is at `http://<nas-ip>:8080`.

### Reverse proxy and HTTPS

HTTP Basic Auth sends credentials as base64 plaintext — without TLS anyone on the
network can read them from a single request. Behind a proxy, set `TRUST_PROXY: "true"`
so rate limiting sees real client IPs (only the last `X-Forwarded-For` entry is trusted).

Caddy (recommended, automatic TLS — use `tls internal` for a local domain):

```caddyfile
lukscrypt.example.com {
    reverse_proxy localhost:8080
}
```

Nginx equivalent: `proxy_pass http://localhost:8080` with `X-Forwarded-For $remote_addr`,
`proxy_buffering off` and `proxy_read_timeout 3600s` (required for the SSE progress stream).

To keep 8080 off the host entirely, run both containers on an internal Docker network
with only the proxy publishing ports (proxy → `http://lukscrypt:8080`; no `ports:` on lukscrypt).

### Mount propagation

`propagation: shared` on the bind-mounted dirs makes container mounts visible on the
host. If you see `mount: /mnt: mount point is not a shared mount`, run once on the NAS:
`mount --make-shared /mnt`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DB_PATH` | `/data/lukscrypt.db` | SQLite database file |
| `VAULT_STORAGE_DIRS` | `/vaults` | Comma-separated dirs where `.img` files may be created |
| `VAULT_MOUNT_DIRS` | `/mnt` | Comma-separated base dirs; vaults mount at `<dir>/<name>` |
| `AUTH_USER` | `admin` | Basic Auth username |
| `AUTH_PASSWORD` | *(random)* | Generated at startup and printed to logs if unset — set it explicitly in production |
| `VAULT_MAX_SIZE_GB` | `100` | Max vault size in GB (positive integer) |
| `TRUST_PROXY` | `false` | `true` only behind a trusted proxy; enables per-client rate limiting via the last `X-Forwarded-For` entry |
| `AUTO_LOCK_HOURS` | `0` (off) | Max time unlocked before auto-lock (e.g. `6`, `0.5`); busy mounts defer to the next sweep — never lazy-unmounted |
| `SESSION_IDLE_HOURS` | `12` | UI session idle timeout (sliding — refreshed on each request) |
| `SESSION_MAX_AGE_HOURS` | `168` | Absolute max UI session lifetime (7 days), regardless of activity |

Multiple storage/mount dirs (e.g. `VAULT_STORAGE_DIRS: /vaults,/tank/encrypted`) show a
dropdown in the UI; a single value is used automatically.

### API tokens

Scripts and cron jobs should not carry the master password. Create a named, revocable
token in the UI (**API tokens** button) or via `POST /api/tokens` with `{"name": "nas-backup"}` —
the raw token is shown **exactly once** and only its SHA-256 hash is stored. Revoke with
`DELETE /api/tokens/{id}` (e.g. when a script is retired). Use it as
`Authorization: Bearer <token>`, or as the Basic Auth password: `curl -u admin:<token> …`.
The master `AUTH_USER`/`AUTH_PASSWORD` keeps working unchanged.

### Unlocking without the browser

```bash
# find the vault's numeric id via GET /api/vaults, then:
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"password": "..."}' https://lukscrypt.example.com/api/vaults/1/unlock
# or with a keyfile that stays on your machine:
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"key_file\": \"$(base64 -w0 vault.key)\"}" https://lukscrypt.example.com/api/vaults/1/unlock
```

There is **no auto-unlock by design**: a key stored anywhere the NAS can reach would be
taken with the machine, defeating encryption-at-rest against physical theft. After a
reboot, vaults stay locked until you unlock them. Run these over TLS — the credential
travels in the request body.

### Auto-lock

`AUTO_LOCK_HOURS` sets the max unlocked duration (default `0` = off). A sweep every minute
unmounts + `luksClose`s expired vaults (logged as `vault auto-locked`). Deliberate
behaviors: duration-based, not activity-based (the container can't observe host-side SMB
traffic; a busy mount just fails `umount` with *target is busy* and the lock retries next
sweep — never lazy-unmounted); a vault created via the API starts its window at creation;
a crash-restart restarts the window at process start.

### Logs

Structured JSON to stdout (`docker logs lukscrypt`). Note `docker compose down` deletes
container logs — use a logging driver (`journald`, `syslog`, ...) or bound json-file
(`max-size: "10m"`, `max-file: "3"`) for a persistent audit trail. The DB in `/data` is a
single small SQLite file — copy it off the NAS as your config backup.

## Vault lifecycle

**Import / move.** Images are self-contained, so back them up or move them with any
server-side tool (ideally while locked). To move: copy the image, delete the old vault in
the UI, then import the copy — `POST /api/vaults/import` with `{"name", "path", "mount_dir"}`.
The path must be inside an allowlisted storage dir (canonicalized first — `..` segments
and symlinks are resolved before the check), the image must be a readable LUKS container,
and a name/path already registered or being created is refused with `409`. Import is also
the lost-database recovery path.

**Grow.** A mounted vault grows online — `fallocate` the image (`dd` fallback),
`cryptsetup resize`, `resize2fs` — and requires the unlock credential (password or
keyfile; `cryptsetup resize` must re-derive the volume key, and kernel keyrings are
unreliable inside containers). Grow-only (`422` for same-or-smaller), capped by
`VAULT_MAX_SIZE_GB`; failures are recoverable by re-running after a lock/unlock cycle.

**Create** runs `fallocate` → `cryptsetup luksFormat` → `luksOpen` → `mkfs.ext4` →
`mount <mount_dir>/<name>` → `chmod 0777` (so SMB users can write) → save metadata to
SQLite. Vault names must match `[a-z0-9-]{1,64}`.

**Unlock / lock / delete:** `luksOpen` + `mount`; `umount` + `luksClose`; delete requires
the vault locked and removes the DB record, image file and mount-point dir.

## API reference

All endpoints except `/healthz` require HTTP Basic Auth.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/healthz` | No | Health check — `{"status":"ok","version":"..."}` |
| `GET` | `/api/config` | Yes | Allowed storage and mount directories |
| `GET` | `/api/vaults` | Yes | Lists vaults with live mounted/unlocked status |
| `POST` | `/api/vaults` | Yes | Creates a vault (`202` + `job_id`) |
| `GET` | `/api/vaults/events/{job_id}` | Yes | SSE stream for creation progress |
| `POST` | `/api/vaults/{id}/unlock` | Yes | Unlock + mount with `password` or base64 `key_file` |
| `POST` | `/api/vaults/{id}/lock` | Yes | Unmount + lock |
| `POST` | `/api/vaults/{id}/mount` | Yes | Re-mount an already-unlocked vault |
| `POST` | `/api/vaults/import` | Yes | Register an existing image (no copy); `409` if name/path taken or being created, `422` if not LUKS |
| `POST` | `/api/vaults/{id}/grow` | Yes | Online grow to `size_gb` with `password`/`key_file`; grow-only, `409` if not mounted |
| `POST` | `/api/vaults/{id}/keyslot/add` | Yes | Add a keyslot (returns re-read LUKS details) |
| `POST` | `/api/vaults/{id}/keyslot/remove` | Yes | Remove keyslot by index with `password`/`key_file`; `409` if last valid keyslot |
| `GET` | `/api/vaults/details/{id}` | Yes | LUKS header details — read-only, no passphrase needed |
| `DELETE` | `/api/vaults/{id}` | Yes | Delete a locked vault (image + mount dir); `422` if still unlocked |
| `GET` | `/api/tokens` | Yes | List API tokens (metadata only — hashes and raw tokens never returned) |
| `POST` | `/api/tokens` | Yes | Create a token (`{"name": "..."}`); returns the raw token once (`201`), `409` on duplicate name |
| `DELETE` | `/api/tokens/{id}` | Yes | Revoke a token (`204`, `404` if unknown) |

### Examples

Create:

```json
POST /api/vaults
{ "name": "private", "path": "/vaults", "size_gb": 100, "password": "...", "mount_dir": "/mnt" }
```

LUKS details (`GET /api/vaults/details/{id}`) — header fields only, no key material:

```json
{ "version": "2", "cipher": "aes-xts-plain64", "hash": "sha256", "key_size_bits": 512,
  "uuid": "...", "keyslots": [{"index": 0, "type": "argon2id", "status": "valid"}] }
```

Keyslots — add requires exactly one existing and one new credential (password or base64
keyfile, 8 B–1 MiB); remove requires a credential matching a *different* valid slot and
is refused with `409` on the last valid slot:

```json
POST /api/vaults/{id}/keyslot/add     { "existing_password": "...", "new_password": "..." }  // key_slot optional
POST /api/vaults/{id}/keyslot/remove  { "password": "...", "key_slot": 1 }  // or "key_file": "<base64>"
```

Credentials go to `cryptsetup` over stdin, never the command line. Passphrases are
single-line (cryptsetup truncates at the first newline). Both endpoints share unlock's
rate limiter.

SSE progress (`GET /api/vaults/events/{job_id}`), steps
`creating` → `encrypting` → `opening` → `formatting` → `mounting` → `done`:

```
data: {"step":"creating","message":"...","percent":60}
data: {"step":"done","message":"...","percent":100,"done":true,"vault_id":1}
data: {"error":"luksFormat: ..."}
```

## Security considerations

- **TLS is required in production** — Basic Auth is base64 plaintext; always use a
  TLS-terminating reverse proxy and never expose 8080 on untrusted networks.
- **Every endpoint requires auth**: the UI uses a session login (`/login` → HttpOnly,
  SameSite=Strict cookie; idle expiry `SESSION_IDLE_HOURS`, absolute cap
  `SESSION_MAX_AGE_HOURS`; Logout button ends it server-side), while API clients use
  HTTP Basic Auth unchanged. An unset `AUTH_PASSWORD` generates a random one printed
  once to the logs. Failed logins are rate-limited per IP (burst 5, then 1/min,
  HTTP `429`); unlock/grow/keyslot attempts too (burst 5, then 1 per 30s).
  `X-Forwarded-For` is honored only with `TRUST_PROXY=true`, last entry only.
- **API tokens are stored hashed** (SHA-256), shown once at creation, and individually
  revocable — a leaked script token never requires rotating the master password.
- **Credentials never appear in argv** — passphrases/keyfiles go to the subprocess's
  stdin (`--key-file=-` with an exact `--keyfile-size`), invisible in `/proc/<pid>/cmdline`.
  Keyfiles are never written to persistent storage (the one `0600` temp file for
  keyslot/add is wiped and removed immediately after).
- **The container runs `privileged`** (full kernel access for dm-crypt/loop/mount) —
  restrict network exposure accordingly.
- **Server-side validation everywhere**: vault names `[a-z0-9-]{1,64}` (no path
  traversal); storage/mount dirs allowlisted (import paths canonicalized and
  symlink-checked); request bodies capped at 8 MiB; HTTP timeouts set; cross-origin
  POST/DELETE rejected via the `Origin` header (CSRF); CSP, `X-Frame-Options: DENY`, etc.
- **LUKS header details expose no key material** — only cipher parameters, keyslot
  metadata and identifiers, behind the same auth.
- **Keyslot changes require an existing valid credential** and can never remove the last
  valid slot (`409` before `luksKillSlot` runs; cryptsetup enforces it too).

## Development

```bash
go run .                                                            # Linux only — needs root + cryptsetup
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=v1.6.0" -o lukscrypt .
go test ./... && go vet ./...
```

Pure-Go SQLite (modernc.org/sqlite) → fully static binary, cross-compiles cleanly to ARM64.

## License

[MIT License](LICENSE) — Copyright (c) 2026 mcrepeau.
