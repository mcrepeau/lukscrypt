# LUKSCrypt

A self-hosted web UI for managing LUKS-encrypted vault files on Linux.
Designed to run as a privileged Docker container on a NAS (tested on Debian 12 / OpenMediaVault).

## Features

- Create encrypted vault image files backed by LUKS (via `cryptsetup`)
- Unlock (open + mount) and lock (unmount + close) vaults from the browser
- Real-time creation progress over Server-Sent Events
- Fast allocation via `fallocate` (near-instantaneous); falls back to `dd` on unsupported filesystems
- HTTP Basic Auth — a random password is generated on first start if none is configured
- Vault metadata persisted in SQLite (WAL mode); runtime state derived live from the OS
- Configurable storage and mount base directories via environment variables
- Mounts propagate to the host via shared bind-mount so SMB shares see the vault contents
- Concurrent lock/unlock/create operations serialized to prevent device-mapper races
- Rate-limited unlock endpoint to slow brute-force password attempts

## Architecture

```
lukscrypt/
├── main.go                  # Entry point — reads env, opens DB, starts HTTP server
├── internal/
│   ├── api/api.go           # HTTP router and handlers (Go 1.22 stdlib mux)
│   ├── db/db.go             # SQLite store for vault metadata (modernc.org/sqlite)
│   └── vault/vault.go       # LUKS operations: create, unlock, lock, delete
└── web/index.html           # Single-page UI — dark theme, SSE progress, embedded in binary
```

The frontend is embedded directly into the binary at compile time (`//go:embed`), so the
container ships as a single static executable with no external file dependencies.

## Requirements

**Host (NAS):**
- Linux kernel with `dm-crypt` / device-mapper support (standard on any modern distribution)
- `cryptsetup`, `e2fsprogs`, `util-linux` — installed automatically inside the container image
- Docker with privileged container support

**Build machine:**
- Go 1.22+
- Docker with `buildx` for cross-platform builds (e.g. ARM64 for most NAS hardware)

## Deployment

### 1. Build and push the image

```bash
# For ARM64 NAS (e.g. Raspberry Pi, most Synology/QNAP models)
docker buildx build \
  --platform linux/arm64 \
  -t registry.example.com/lukscrypt:latest \
  --push .

# For AMD64
docker buildx build \
  --platform linux/amd64 \
  -t registry.example.com/lukscrypt:latest \
  --push .
```

### 2. Configure `docker-compose.yml`

```yaml
services:
  lukscrypt:
    image: registry.example.com/lukscrypt:latest
    container_name: lukscrypt
    ports:
      - "8080:8080"
    volumes:
      - lukscrypt-data:/data
      - type: bind
        source: /mnt         # adjust to match your NAS layout
        target: /mnt
        bind:
          propagation: shared
    environment:
      DB_PATH: /data/lukscrypt.db
      VAULT_STORAGE_DIRS: /vaults
      VAULT_MOUNT_DIRS: /mnt
      # AUTH_USER: admin          # default: admin
      # AUTH_PASSWORD: changeme   # default: random, printed once in container logs
    privileged: true
    restart: unless-stopped

volumes:
  lukscrypt-data:
```

### 3. Deploy on the NAS

```bash
docker compose pull && docker compose up -d
```

For local testing only, the UI is reachable at `http://<nas-ip>:8080`.
**In production, do not expose port 8080 directly — put it behind a TLS-terminating reverse proxy** (see [Reverse proxy and HTTPS](#reverse-proxy-and-https) below).

### Reverse proxy and HTTPS

**HTTP Basic Auth sends credentials as base64-encoded plaintext.** Without TLS anyone on
the same network can read the username and password from a single HTTP request. A
TLS-terminating reverse proxy is required for any non-localhost deployment.

#### Caddy (recommended — automatic TLS)

```caddyfile
lukscrypt.example.com {
    reverse_proxy localhost:8080
}
```

Run `caddy run` and Caddy handles certificate issuance and renewal automatically via
Let's Encrypt. For a local domain (no public DNS) use a private CA or a self-signed cert:

```caddyfile
lukscrypt.nas.local {
    tls internal
    reverse_proxy localhost:8080
}
```

#### Nginx

```nginx
server {
    listen 443 ssl;
    server_name lukscrypt.example.com;

    ssl_certificate     /etc/ssl/certs/lukscrypt.crt;
    ssl_certificate_key /etc/ssl/private/lukscrypt.key;

    location / {
        proxy_pass         http://localhost:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $remote_addr;
        # Required for SSE (vault creation progress stream)
        proxy_buffering    off;
        proxy_read_timeout 3600s;
    }
}
server {
    listen 80;
    server_name luk.example.com;
    return 301 https://$host$request_uri;
}
```

#### Docker network isolation

When the reverse proxy runs in Docker too, bind lukscrypt to the internal network
instead of exposing a host port:

```yaml
services:
  lukscrypt:
    image: registry.example.com/lukscrypt:latest
    # No 'ports' mapping — not reachable from outside the Docker network
    networks:
      - proxy
    environment:
      # ... (same as above)
    privileged: true
    restart: unless-stopped

  caddy:
    image: caddy:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy-data:/data
    networks:
      - proxy

networks:
  proxy:

volumes:
  lukscrypt-data:
  caddy-data:
```

With this layout `caddy` proxies to `http://lukscrypt:8080` and port 8080 is never
exposed on the host.

### Mount propagation

Mounts created inside the container must be visible on the host (so SMB and other services
can serve vault contents). This is achieved via `propagation: shared` on the bind-mounted
directories. On Debian 12 with systemd the root filesystem is shared by default.

If you see `mount: /mnt: mount point is not a shared mount`, run once on the NAS:

```bash
mount --make-shared /mnt
```

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `DB_PATH` | `/data/lukscrypt.db` | Path to the SQLite database file |
| `VAULT_STORAGE_DIRS` | `/vaults` | Comma-separated list of directories where vault `.img` files may be created |
| `VAULT_MOUNT_DIRS` | `/mnt` | Comma-separated list of base directories under which vaults are mounted |
| `AUTH_USER` | `admin` | HTTP Basic Auth username |
| `AUTH_PASSWORD` | *(generated)* | HTTP Basic Auth password. If unset, a random 32-character hex password is generated at startup and printed to the container logs. Set this to a stable value in production. |
| `VAULT_MAX_SIZE_GB` | `100` | Maximum size in GB that a vault may be created with. Must be a positive integer. |

### Multiple storage / mount locations

```yaml
environment:
  VAULT_STORAGE_DIRS: /vaults,/tank/encrypted
  VAULT_MOUNT_DIRS: /mnt,/srv/shares
```

When more than one option is configured a dropdown appears in the UI.
When only one is configured the field is hidden and the value is used automatically.

### Mount point convention

Vaults are always mounted at `<VAULT_MOUNT_DIRS entry>/<vault-name>`.
For example, a vault named `private` with mount dir `/mnt` mounts at `/mnt/private`.

## Vault lifecycle

### Create

1. Enter a vault name (lowercase letters, numbers, hyphens — max 64 chars), storage directory, size (GB) and password
2. The server runs (in order):
   - `fallocate -l <size>` — allocates the image file instantly (falls back to `dd if=/dev/zero` with live progress if the filesystem does not support fallocate)
   - `cryptsetup luksFormat` — encrypts the container
   - `cryptsetup luksOpen` — opens the LUKS device
   - `mkfs.ext4` — formats the filesystem
   - `mount` — mounts at `<mount_dir>/<name>`
   - `chmod 0777` — sets world-writable permissions on the root directory so SMB users can write (stored inside the filesystem, persists across lock/unlock)
3. Vault metadata is saved to SQLite

### Unlock

```
cryptsetup luksOpen <image> <mapper-name>
mount /dev/mapper/<mapper-name> <mount-point>
```

### Lock

```
umount <mount-point>
cryptsetup luksClose <mapper-name>
```

### Delete

The vault must be locked first. The database record is removed first, then the `.img` file
and mount point directory are deleted from disk.

## API reference

All endpoints require HTTP Basic Auth.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/config` | Returns allowed storage and mount directories |
| `GET` | `/api/vaults` | Lists all vaults with live mounted/unlocked status |
| `POST` | `/api/vaults` | Creates a new vault (returns `202` with `job_id`) |
| `GET` | `/api/vaults/events/{job_id}` | SSE stream for vault creation progress |
| `POST` | `/api/vaults/{id}/unlock` | Unlocks and mounts a vault |
| `POST` | `/api/vaults/{id}/lock` | Unmounts and locks a vault |
| `DELETE` | `/api/vaults/{id}` | Deletes a locked vault (image file + mount directory) |

### Create vault request body

```json
{
  "name":      "private",
  "path":      "/vaults",
  "size_gb":   100,
  "password":  "...",
  "mount_dir": "/mnt"
}
```

Vault names must match `[a-z0-9-]{1,64}`.

### SSE event format

```
data: {"step":"creating","message":"Container file allocated.","percent":60}
data: {"step":"encrypting","message":"Encrypting vault with LUKS...","percent":62}
data: {"step":"done","message":"Vault created and mounted successfully!","percent":100,"done":true,"vault_id":1}
data: {"error":"luksFormat: ..."}
```

Steps in order: `creating` → `encrypting` → `opening` → `formatting` → `mounting` → `done`

When `fallocate` is unavailable the `creating` step emits incremental progress events
(`percent` 0–60) as `dd` writes the file block by block.

## Security considerations

- **TLS is required in production.** HTTP Basic Auth transmits credentials as
  base64-encoded plaintext. Without HTTPS any observer on the network can read your
  username and password. Always serve this application through a TLS-terminating
  reverse proxy (Caddy, Nginx, Traefik, etc.) and never expose port 8080 directly
  on an untrusted network. See [Reverse proxy and HTTPS](#reverse-proxy-and-https).
- **HTTP Basic Auth** is enforced on every endpoint, including the UI. If `AUTH_PASSWORD`
  is not set, a random 32-character password is generated at startup and printed once to the
  container logs. Set it explicitly in production so the password survives container restarts.
- **Passwords are never passed as command-line arguments.** They are written to each
  `cryptsetup` subprocess's stdin and are not visible in `/proc/<pid>/cmdline`.
- **The container runs as `privileged`** which grants full kernel access. Restrict
  network exposure — do not expose port 8080 directly on untrusted interfaces.
- **Vault names are strictly validated** server-side: only lowercase letters, numbers and
  hyphens are accepted. This prevents path traversal via crafted vault names.
- **Storage and mount directories are allowlisted** server-side. The client cannot specify
  arbitrary paths — any path not in `VAULT_STORAGE_DIRS` / `VAULT_MOUNT_DIRS` is rejected
  with `400 Bad Request`.
- **Unlock attempts are rate-limited** per client IP: burst of 5 attempts, then one attempt
  per 30 seconds. This limits brute-force password guessing.

## Development

```bash
# Run locally (Linux only — LUKS operations require root and cryptsetup)
go run .

# Build binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o lukscrypt .

# Vet
go vet ./...
```

The SQLite driver (`modernc.org/sqlite`) is pure Go — no CGO required. The binary is
fully static and cross-compiles cleanly with `GOARCH=arm64`.
