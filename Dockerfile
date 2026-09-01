FROM golang:1.27-alpine3.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o towerops-agent .

# Chainguard's Wolfi. Alpine left us shipping CVEs we could not clear: seven
# High findings in libcrypto3/libssl3 needed an `apk upgrade` on every build
# because the base tag lagged its own branch, and busybox 1.37 carried
# CVE-2025-60876 with no fix in any Alpine branch, edge included. Wolfi
# rebuilds continuously and ships busybox 1.38, so the image scans clean.
#
# Deliberately unpinned. Only `:latest` is available on Chainguard's free
# tier, and tracking it is the point — pinning a digest would freeze us on a
# snapshot that goes stale, which is the problem this base was chosen to
# solve. The Grype gate in CI is what catches a bad upstream push.
FROM cgr.dev/chainguard/wolfi-base:latest
# ca-certificates-bundle is already in wolfi-base; only ping and setcap are
# missing. libcap-utils is removed again in the same layer so the setcap
# binary never ships in the released image.
RUN apk upgrade --no-cache && apk add --no-cache iputils libcap-utils
COPY --from=builder /app/towerops-agent /usr/local/bin/towerops-agent
# wolfi's iputils ships no separate ping6 binary, and its `ping` resolves IPv6
# targets itself — which is what the agent's exec fallback uses when ping6 is
# absent. /data holds the trust-on-first-use store, so the unprivileged runtime
# user must own it.
RUN adduser -D -u 1000 towerops && \
    mkdir -p /data && \
    chown towerops /usr/local/bin/towerops-agent /data && \
    setcap cap_net_raw,cap_net_bind_service+ep /usr/local/bin/towerops-agent && \
    setcap cap_net_raw+p /usr/local/bin/ping && \
    apk del libcap-utils
ENV TOWEROPS_HOST_KEYS_FILE=/data/known_hosts.json
# Without a persistent volume, container recreation resets the TOFU store and
# defeats host-key and TLS-certificate pinning.
VOLUME /data
WORKDIR /data
USER towerops
CMD ["/usr/local/bin/towerops-agent"]
