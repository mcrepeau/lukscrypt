# ── Stage 1: build ────────────────────────────────────────────────────────────
# --platform=$BUILDPLATFORM runs the builder on the host's native architecture
# so Go toolchain binaries execute without QEMU. GOARCH=$TARGETARCH tells the
# Go compiler to cross-compile for the target platform (e.g. arm64).
# CGO_ENABLED=0 makes this work without a cross-C-compiler.
FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS builder

ARG TARGETARCH

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /lukscrypt .

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

# VOLUME creates /data automatically — no RUN mkdir needed (which would fail
# when cross-building for a different architecture without QEMU).
VOLUME ["/data"]

EXPOSE 8080

CMD ["lukscrypt"]
