# LUKSCrypt

A self-hosted web UI for managing LUKS-encrypted vault files on Linux.
Designed to run as a privileged Docker container on a NAS (tested on Debian 12 / OpenMediaVault).

## Features

- Create encrypted vault image files backed by LUKS (via `cryptsetup`)
- Unlock (open + mount) and lock (unmount + close) vaults from the browser
- View LUKS header details per vault (version, cipher, hash, key size, keyslots, UUID) — lazily loaded, works on locked vaults
- Manage passphrase keyslots (add/remove) — multiple passphrases per vault without re-encrypting data; the last valid keyslot is protected
- Unlock with a password or a keyfile, and add keyfile-based keyslots (e.g. a random blob kept in a password manager as a break-glass credential)
- Scriptable unlocking over the API — no auto-unlock by design; credentials never rest on the NAS
- Real-time creation progress over Server-Sent Events
- Fast allocation via `fallocate` (near-instantaneous); falls back to `dd` on unsupported filesystems
- HTTP Basic Auth — a random password is generated on first start if none is configured
- Vault metadata persisted in SQLite (WAL mode); runtime state derived live from the OS
- Configurable storage and mount base directories via environment variables
- Import an existing vault image — register an image placed in a storage directory (moved file, restored backup, or lost-database recovery); records never mutate their identity
- Grow a mounted vault online (image + LUKS device + filesystem) — grow-only by design; vaults cannot be shrunk
- Mounts propagate to the host via shared bind-mount so SMB shares see the vault contents
- Concurrent lock/unlock/create operations serialized to prevent device-mapper races
- Graceful shutdown: unlocked vaults are locked (unmounted + closed) on SIGTERM/SIGINT so restarts never leave stale device-mapper or loop devices on the host
- Optional auto-lock: lock vaults automatically after a configurable unlocked duration; busy mounts defer, they are never lazy-unmounted
- Rate-limited unlock endpoint to slow brute-force password attempts

## Architecture

```
lukscrypt/
├── main.go                  # Entry point — reads env, opens DB, starts HTTP server
├── internal/
│   ├── api/api.go           # HTTP router and handlers (Go 1.22 stdlib mux)
│   ├── db/db.go             # SQLite store for vault metadata (modernc.org/sqlite)
│   ├── vault/vault.go       # LUKS operations: create, unlock, lock, delete
│   ├── vault/luksdump.go    # LUKS header details (luksDump / --dump-json-metadata)
│   └── vault/keys.go        # Keyslot management (luksAddKey / luksKillSlot)
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

### 1. Configure `docker-compose.yml`

Pre-built images for `linux/amd64` and `linux/arm64` are published to the GitHub Container Registry on every tagged release.

```yaml
services:
  lukscrypt:
    image: ghcr.io/mcrepeau/lukscrypt:latest
    container_name: lukscrypt
    ports:
      - "8080:8080"
    volumes:
      - lukscrypt-data:/data
      # Vault image files MUST live on a persistent bind mount (as here) or a
      # named volume. If /vaults is left in the container's writable layer,
      # the .img files are destroyed whenever the container is recreated
      # (compose down, image upgrade, ...) while the database survives —
      # leaving ghost vault entries that can no longer be unlocked.
      - type: bind
        source: /srv/lukscrypt/vaults   # adjust to a persistent host path
        target: /vaults
      - type: bind
        source: /mnt         # adjust to match your NAS layout
        target: /mnt
        bind:
          propagation: shared
    environment:
      DB_PATH: /data/lukscrypt.db
      VAULT_STORAGE_DIRS: /vaults
      VAULT_MOUNT_DIRS: /mnt
      # TRUST_PROXY: "true"      # set when behind a reverse proxy (rate limiting
      #                           # then uses X-Forwarded-For)
      # AUTO_LOCK_HOURS: "6"     # lock vaults after 6 hours unlocked; a float
      #                           # works (0.5 = 30 min); default 0 = disabled
      # AUTH_USER: admin          # default: admin
      # AUTH_PASSWORD: changeme   # default: random, printed once in container logs
    privileged: true
    restart: unless-stopped
    # Graceful shutdown drains HTTP and locks every unlocked vault; the default
    # 10s SIGKILL grace period would cut that short.
    stop_grace_period: 60s

volumes:
  lukscrypt-data:
```

On `SIGTERM`/`SIGINT` the server drains HTTP connections, then locks every vault that
is currently unlocked (unmount + `cryptsetup luksClose`), so a container stop or
restart never leaves stale device-mapper or loop devices on the host kernel. Failures
are logged per vault and don't prevent the exit — if a vault's mount is busy (e.g.
an SMB client holds open files), the log will name it.

### 2. Deploy on the NAS

```bash
docker compose pull && docker compose up -d
```

For local testing only, the UI is reachable at `http://<nas-ip>:8080`.
**In production, do not expose port 8080 directly — put it behind a TLS-terminating reverse proxy** (see [Reverse proxy and HTTPS](#reverse-proxy-and-https) below).

### Reverse proxy and HTTPS

**HTTP Basic Auth sends credentials as base64-encoded plaintext.** Without TLS anyone on
the same network can read the username and password from a single HTTP request. A
TLS-terminating reverse proxy is required for any non-localhost deployment.

When running behind a reverse proxy, set `TRUST_PROXY: "true"` so the unlock rate limiter
sees real client IPs (via `X-Forwarded-For`) instead of lumping all clients into the
proxy's single rate-limit bucket.

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
    image: ghcr.io/mcrepeau/lukscrypt:latest
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
| `TRUST_PROXY` | `false` | Set to `true` only when running behind a trusted reverse proxy. Enables `X-Forwarded-For` for per-client rate limiting (only the last, proxy-appended entry is used). Leave `false` when the app is reachable directly — otherwise clients could spoof the header to bypass rate limiting. |
| `AUTO_LOCK_HOURS` | `0` *(disabled)* | Maximum time a vault may stay unlocked before lukscrypt locks it automatically (e.g. `6`, or `0.5` for 30 minutes). A mount that is busy (open SMB files) defers the lock to the next sweep — auto-lock never lazy-unmounts, and it means *actually locked*. |

### Multiple storage / mount locations

```yaml
environment:
  VAULT_STORAGE_DIRS: /vaults,/tank/encrypted
  VAULT_MOUNT_DIRS: /mnt,/srv/shares
```

When more than one option is configured a dropdown appears in the UI.
When only one is configured the field is hidden and the value is used automatically.

### Unlocking without the browser

Vaults can be unlocked from a script or another machine with the documented API.
Find the vault's numeric id in the list endpoint (`GET /api/vaults`), then:

```bash
curl -su "$USER:$PASS" -H 'Content-Type: application/json' \
  -d '{"password": "..."}' \
  http://nas.local:8080/api/vaults/1/unlock
```

Or with a keyfile that stays on your machine:

```bash
curl -su "$USER:$PASS" -H 'Content-Type: application/json' \
  -d "{\"key_file\": \"$(base64 -w0 vault.key)\"}" \
  http://nas.local:8080/api/vaults/1/unlock
```

**There is no auto-unlock feature, by design.** Unlocking a vault should require a
human decision: if the key were stored anywhere the NAS can reach autonomously —
most obviously on the NAS itself — a thief who takes the machine would take the key
with it, and encryption-at-rest would protect nothing against physical theft. After
a reboot, vaults stay locked until you unlock them from your browser or with the
commands above; the credential never rests on the NAS.

Run these over TLS (see [Reverse proxy and HTTPS](#reverse-proxy-and-https)) — the
password or keyfile travels in the request body.

### Auto-lock

Set `AUTO_LOCK_HOURS` to the maximum time a vault may stay unlocked (default `0` =
disabled). A background sweep runs once a minute and locks every vault whose window
has elapsed: unmount, `cryptsetup luksClose`, and a `vault auto-locked` log line
with the vault name, policy and how long it was unlocked.

Two behaviors are deliberate:

- **Duration-based, not activity-based.** The window starts when the vault is
  unlocked — a vault created through the API counts as unlocked from the moment
  creation completes, since creation ends with the vault open and mounted. The
  container cannot observe host-side SMB access, so there is no
  activity signal to reset it. The honest in-use detection happens at lock time:
  a mount with open SMB files makes the `umount` fail with *target is busy*, and
  the lock is simply retried on the next sweep. Lazy unmount is never used —
  auto-lock must mean actually locked.
- **Crash-restarts restart the window.** Graceful shutdown locks everything, so
  an unlocked vault at process start means the container was killed; its window
  starts at process start (logged as `vault unlocked at startup`).

### Logs and retention

All events — every request plus domain events like `vault auto-locked`,
`keyslot added`, `vault grown` — are logged as structured JSON to stdout
(`docker logs lukscrypt`). Two operational notes:

- **`docker compose down` deletes the container's logs** (a plain `stop` keeps
  them). For an audit trail that survives recreations, ship logs off the host:
  configure a logging driver (e.g. `journald`, `syslog`, or your collector), or
  at minimum bound on-disk growth:

  ```yaml
  services:
    lukscrypt:
      logging:
        driver: json-file
        options:
          max-size: "10m"
          max-file: "3"
  ```

- The database itself (`/data`, a single SQLite file) holds only vault metadata —
  copy it off the NAS as your configuration backup.

### Mount point convention

Vaults are always mounted at `<VAULT_MOUNT_DIRS entry>/<vault-name>`.
For example, a vault named `private` with mount dir `/mnt` mounts at `/mnt/private`.

## Vault lifecycle

### Moving and importing vault images

Vault image files are self-contained (LUKS header + encrypted data), so they can be
moved or backed up with any server-side tool (`cp`, `rsync`, restic, btrfs snapshots —
ideally while the vault is locked). There is no path-editing API: records are immutable
in their identity fields. To move a vault, copy the image, delete the old vault in the
UI (which removes the old image and record), then import the copy:

```json
POST /api/vaults/import
{ "name": "private", "path": "/vaults/private.img", "mount_dir": "/mnt" }
```

Import registers an existing image file — nothing is created or copied. The image must
live inside an allowlisted storage directory and be a readable LUKS container (validated
before the record is created); its size is derived from the file. The submitted path is
canonicalized first — `..` segments and symlinks are resolved before the allowlist check —
so an image outside the allowlisted directories cannot be registered via traversal or a
link, and the stored record always holds the canonical path. A path already
registered to another vault is refused with `409` — two mapper names over one image
would corrupt data. Import is also the recovery path after a lost database: register
each surviving image and the vaults are back.

**Back up your database volume anyway** (`/data` is a single small SQLite file) —
import makes its loss recoverable, but back when you still remember which image is which.

### Growing a vault

A mounted vault can be grown online — the filesystem stays available and is
extended in place:

```
fallocate -l <new size>  ← extend the image file (dd append fallback)
cryptsetup resize        ← the LUKS device picks up the new size
resize2fs                ← the ext4 filesystem grows while mounted
```

The vault's credential (`password` or `key_file`) is required: `cryptsetup resize`
must re-derive the volume key to reload the device-mapper table. On a normal host
LUKS2 can reuse the kernel session keyring, but keyrings are unreliable inside
containers, so lukscrypt always provides the credential explicitly — the same
one that unlocks the vault. The grow endpoint shares unlock's rate limiter for
the same reason.

Growing is **online and grow-only**: ext4 cannot shrink without an offline
fsck/resize sequence that is too data-destructive to automate, so the API refuses
same-or-smaller sizes with `422`. Each step can fail independently and every
failure state is recoverable by re-running the grow after a lock/unlock cycle —
a failed `cryptsetup resize` merely leaves an extended image with a stale device
size. The `VAULT_MAX_SIZE_GB` cap from creation applies to grows too.

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

All endpoints except `/healthz` require HTTP Basic Auth.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/healthz` | No | Health check — returns `{"status":"ok","version":"..."}` |
| `GET` | `/api/config` | Yes | Returns allowed storage and mount directories |
| `GET` | `/api/vaults` | Yes | Lists all vaults with live mounted/unlocked status |
| `POST` | `/api/vaults` | Yes | Creates a new vault (returns `202` with `job_id`) |
| `GET` | `/api/vaults/events/{job_id}` | Yes | SSE stream for vault creation progress |
| `POST` | `/api/vaults/{id}/unlock` | Yes | Unlocks and mounts a vault with `password` or base64 `key_file` |
| `POST` | `/api/vaults/{id}/lock` | Yes | Unmounts and locks a vault |
| `POST` | `/api/vaults/{id}/mount` | Yes | Re-mounts an already-unlocked vault |
| `POST` | `/api/vaults/import` | Yes | Registers an existing image file as a vault (no copy); `409` if the name or path is already registered or currently being created, `422` if not a LUKS container |
| `POST` | `/api/vaults/{id}/grow` | Yes | Grows a mounted vault to `size_gb` (online) with `password` or base64 `key_file`; grow-only, `409` if not mounted |
| `POST` | `/api/vaults/{id}/keyslot/add` | Yes | Adds a passphrase keyslot (returns re-read LUKS details) |
| `POST` | `/api/vaults/{id}/keyslot/remove` | Yes | Removes a keyslot by index with `password` or base64 `key_file` (returns re-read LUKS details); returns `409` if it is the last valid keyslot |
| `GET` | `/api/vaults/details/{id}` | Yes | LUKS header details (cipher, hash, key size, keyslots, UUID) — read-only, no passphrase required, works on locked vaults |
| `DELETE` | `/api/vaults/{id}` | Yes | Deletes a locked vault (image file + mount directory); returns `422` if the vault is still unlocked |

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

### LUKS details response

`GET /api/vaults/details/{id}` returns a summary of the vault's LUKS header:

```json
{
  "version": "2",
  "cipher": "aes-xts-plain64",
  "hash": "sha256",
  "key_size_bits": 512,
  "uuid": "6a2f5e10-94c3-4d7a-8f21-0b3c9e8d7a1f",
  "keyslots": [
    {"index": 0, "type": "argon2id", "status": "valid"}
  ]
}
```

The literal `details` segment comes before `{id}` to avoid a routing-pattern conflict
with `/api/vaults/events/{jobID}` (Go's stdlib mux cannot constrain wildcards with
regexes). If the image file is missing or not a LUKS container, the endpoint returns
`422` with the `cryptsetup` error message.

### Keyslot management

```json
POST /api/vaults/{id}/keyslot/add
{ "existing_password": "...", "new_password": "...", "key_slot": 1 }
```

`key_slot` is optional (omitted = let cryptsetup pick the first free slot). Exactly one
existing credential (`existing_password` or base64 `existing_key_file`) and exactly one
new credential (`new_password` or base64 `new_key_file`) must be provided. Keyfile
uploads must decode to 8 bytes – 1 MiB; a keyfile is the credential itself, so the
minimum mirrors the 8-character password policy. When only passwords are involved the
credentials go to `cryptsetup luksAddKey` over stdin; when a keyfile is involved, the
existing credential is piped via stdin (`--key-file=-` with an exact `--keyfile-size`)
and the new credential goes through a `0600` temp file that is removed immediately
after — cryptsetup has no two-input stdin mode. Works on locked and unlocked vaults:
only the LUKS header is modified, never the data area.

```json
POST /api/vaults/{id}/keyslot/remove
{ "password": "...", "key_slot": 1 }
```

or, when the other valid keyslot is keyfile-based:

```json
{ "key_file": "<base64>", "key_slot": 1 }
```

Exactly one of `password` / `key_file` must be provided, and it must match a
*different*, still-valid keyslot (that is the proof of authority for removing one).
Removing the last valid keyslot would make the master key — and therefore the vault
data — permanently unrecoverable, so it is refused with `409` before `cryptsetup
luksKillSlot` runs (cryptsetup enforces the same rule as a second line of defense).
Both endpoints are rate-limited like unlock, since a wrong existing credential is the
same brute-force surface.

Passphrases are single-line: cryptsetup reads one line from stdin, so a passphrase
containing a newline is truncated at the first newline — never use newlines in a
passphrase.

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
  per 30 seconds. This limits brute-force password guessing. `X-Forwarded-For` is only
  honored when `TRUST_PROXY=true` is set (and only the last, proxy-appended entry is
  trusted), so the limit cannot be bypassed with a spoofed header.
- **Failed logins are rate-limited** per client IP: burst of 5, then one attempt per minute
  (HTTP `429`). Without this, the master Basic Auth password could be brute-forced at
  unlimited speed through any endpoint's `401` responses. A successful login resets the
  counter, and the same `X-Forwarded-For` rules as the unlock limiter apply.
- **Cross-origin requests are rejected.** State-changing endpoints (POST/DELETE) check the
  browser-sent `Origin` header and refuse cross-site requests, so a malicious web page
  cannot trigger lock/mount/delete actions with the browser's cached Basic Auth
  credentials. Non-browser clients (curl, scripts) send no `Origin` and are unaffected.
- **LUKS header details expose no key material.** `cryptsetup luksDump` (and its LUKS2
  `--dump-json-metadata` variant) read only non-secret header fields — cipher parameters,
  keyslot metadata and identifiers — and the endpoint sits behind the same Basic Auth
  as every other API route.
- **Keyslot management requires an existing passphrase.** Adding a keyslot requires the
  existing passphrase; removing one requires the passphrase of a different, still-valid
  keyslot. These credentials are the same proof unlock requires, so the endpoints share
  unlock's per-IP rate limiter. Passphrases are written to the subprocess's stdin, never
  to its command line.
- **Keyfiles are never written to persistent storage.** Keyfile bytes uploaded as base64
  are piped to `cryptsetup` via stdin (`--key-file=-` with an exact `--keyfile-size`, so
  binary content is used verbatim and truncated reads fail instead of becoming a weaker
  credential). The one exception is `keyslot/add` with a new keyfile, where cryptsetup's
  two-input limitation requires a `0600` temp file that is deleted immediately after
  the command exits. Like passphrases, keyfiles are only as safe as the transport —
  use TLS.

## Development

```bash
# Run locally (Linux only — LUKS operations require root and cryptsetup)
go run .

# Build binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o lukscrypt .

# Build with version string
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=v1.0.0" -o lukscrypt .

# Run tests
go test ./...

# Vet
go vet ./...
```

The SQLite driver (`modernc.org/sqlite`) is pure Go — no CGO required. The binary is
fully static and cross-compiles cleanly with `GOARCH=arm64`.

## License

[MIT License](LICENSE) — Copyright (c) 2026 mcrepeau.
