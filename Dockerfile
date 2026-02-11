# syntax=docker/dockerfile:1.4
# Build stage - Debian bookworm with glibc (fixes musl fork-safety SIGSEGV)
FROM rust:1.93-bookworm AS builder

# Build arguments provided by Docker buildx
ARG TARGETPLATFORM
ARG TARGETARCH
ARG VERSION=0.1.0-unknown

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    libsnmp-dev \
    cmake \
    g++ \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Determine Rust target based on platform
RUN case "$TARGETPLATFORM" in \
    "linux/amd64") RUST_TARGET="x86_64-unknown-linux-gnu" ;; \
    "linux/arm64") RUST_TARGET="aarch64-unknown-linux-gnu" ;; \
    *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    echo "$RUST_TARGET" > /tmp/rust-target

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

# Runtime stage - Debian slim with glibc
FROM debian:12-slim

# Install runtime dependencies
# iputils-ping provides ping with setuid root (doesn't require CAP_NET_RAW)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iputils-ping \
    libsnmp40 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /tmp/towerops-agent /usr/local/bin/towerops-agent

# Create non-root user
RUN groupadd -g 1000 towerops && \
    useradd -u 1000 -g towerops -s /bin/false towerops

# Allow non-root user to overwrite binary during self-update
RUN chown towerops /usr/local/bin/towerops-agent

USER towerops

CMD ["towerops-agent"]
