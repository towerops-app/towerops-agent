# Build stage
FROM rust:1.83-alpine AS builder

# Build arguments provided by Docker buildx
ARG TARGETPLATFORM
ARG VERSION=0.1.0-unknown

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache musl-dev protobuf-dev

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

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer)
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    BUILD_VERSION="$VERSION" cargo build --release --target "$RUST_TARGET"

# Remove dummy src
RUN rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual application
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    touch src/main.rs && \
    BUILD_VERSION="$VERSION" cargo build --release --target "$RUST_TARGET" && \
    cp "target/$RUST_TARGET/release/towerops-agent" /tmp/towerops-agent

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
# docker-cli is needed for self-update functionality
RUN apk add --no-cache ca-certificates su-exec docker-cli

# Create data directory
RUN mkdir -p /data

# Copy binary from builder
COPY --from=builder /tmp/towerops-agent /usr/local/bin/towerops-agent

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Volume for database
VOLUME ["/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD test -f /data/towerops-agent.db || exit 1

# Create non-root user (entrypoint will drop to this user)
RUN addgroup -g 1000 towerops && \
    adduser -D -u 1000 -G towerops towerops

# Start as root, entrypoint will fix permissions and drop to towerops user
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
