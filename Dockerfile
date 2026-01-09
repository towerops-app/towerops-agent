# Build stage
FROM rust:1.83-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache musl-dev

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release --target x86_64-unknown-linux-musl

# Remove dummy src
RUN rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual application
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create data directory
RUN mkdir -p /data

# Copy binary from builder
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/towerops-agent /usr/local/bin/

# Volume for database
VOLUME ["/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD test -f /data/towerops-agent.db || exit 1

# Run as non-root user
RUN addgroup -g 1000 towerops && \
    adduser -D -u 1000 -G towerops towerops && \
    chown -R towerops:towerops /data

USER towerops

ENTRYPOINT ["towerops-agent"]
