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

FROM alpine:3.24
# `apk upgrade` before installing: the alpine base tag is rebuilt on its own
# schedule, so the libcrypto3/libssl3 baked into it lag the release branch.
# Left alone, the published image shipped seven High CVEs (CVE-2026-18798,
# CVE-2026-63076, CVE-2026-14457, CVE-2026-14456, CVE-2026-63072,
# CVE-2026-54874, CVE-2026-63075), all already fixed in 3.5.8-r0. This holds
# regardless of which base tag Dependabot bumps us to.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates iputils libcap
COPY --from=builder /app/towerops-agent /usr/local/bin/towerops-agent
RUN adduser -D -u 1000 towerops && \
    chown towerops /usr/local/bin/towerops-agent && \
    setcap cap_net_raw+ep /usr/local/bin/towerops-agent && \
    setcap cap_net_raw+p /bin/ping
USER towerops
CMD ["towerops-agent"]
