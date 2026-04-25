# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 gives a fully static binary (modernc.org/sqlite is pure Go).
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /lukscrypt .

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# cryptsetup  — LUKS format/open/close
# e2fsprogs   — mkfs.ext4
# util-linux  — mount / umount
# dmsetup     — required by cryptsetup at runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cryptsetup \
        e2fsprogs \
        util-linux \
        dmsetup \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /lukscrypt /usr/local/bin/lukscrypt

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

CMD ["lukscrypt"]
