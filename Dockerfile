# syntax=docker/dockerfile:1.4
# Pre-built net-snmp 5.9.5.2 (fixes segfaults in Alpine's 5.9.4)
# Built from Dockerfile.netsnmp via .github/workflows/netsnmp-base.yml
FROM ghcr.io/towerops-app/netsnmp-alpine:5.9.5.2 AS netsnmp

# Build stage
FROM rust:1.93-alpine AS builder

# Build arguments provided by Docker buildx
ARG TARGETPLATFORM
ARG TARGETARCH
ARG VERSION=0.1.0-unknown

WORKDIR /app

# Install build dependencies (net-snmp headers/libs from pre-built image)
RUN apk add --no-cache musl-dev protobuf-dev openssl-dev openssl-libs-static cmake perl g++
COPY --from=netsnmp /usr/include/net-snmp /usr/include/net-snmp
COPY --from=netsnmp /usr/lib/libnetsnmp* /usr/lib/
COPY --from=netsnmp /usr/lib/libsnmp* /usr/lib/

# Determine Rust target based on platform and add it
RUN case "$TARGETPLATFORM" in \
    "linux/amd64") RUST_TARGET="x86_64-unknown-linux-musl" ;; \
    "linux/arm64") RUST_TARGET="aarch64-unknown-linux-musl" ;; \
    *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    echo "$RUST_TARGET" > /tmp/rust-target && \
    rustup target add "$RUST_TARGET"

# Copy manifests and build files
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY native ./native

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer) with BuildKit cache mounts
# Cache is separated by target architecture for multi-platform builds
RUN --mount=type=cache,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git-${TARGETARCH},target=/usr/local/cargo/git \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/app/target \
    RUST_TARGET=$(cat /tmp/rust-target) && \
    BUILD_VERSION="$VERSION" cargo build --release --target "$RUST_TARGET"

# Remove dummy src
RUN rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual application with BuildKit cache mounts
RUN --mount=type=cache,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git-${TARGETARCH},target=/usr/local/cargo/git \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/app/target \
    RUST_TARGET=$(cat /tmp/rust-target) && \
    touch src/main.rs && \
    BUILD_VERSION="$VERSION" cargo build --release --target "$RUST_TARGET" && \
    cp "target/$RUST_TARGET/release/towerops-agent" /tmp/towerops-agent

# Runtime stage - must match builder's Alpine version for ABI compatibility
# (rust:1.93-alpine uses Alpine 3.23)
FROM alpine:3.23

# Install runtime dependencies
# iputils provides ping with setuid root (doesn't require CAP_NET_RAW)
RUN apk add --no-cache ca-certificates iputils openssl

# Copy net-snmp 5.9.5.2 shared libraries from pre-built image
COPY --from=netsnmp /usr/lib/libnetsnmp.so* /usr/lib/

# Copy binary from builder
COPY --from=builder /tmp/towerops-agent /usr/local/bin/towerops-agent

# Create non-root user
RUN addgroup -g 1000 towerops && \
    adduser -D -u 1000 -G towerops towerops

# Allow non-root user to overwrite binary during self-update
RUN chown towerops /usr/local/bin/towerops-agent

USER towerops

CMD ["towerops-agent"]
