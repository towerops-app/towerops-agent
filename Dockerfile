FROM golang:1.25-alpine3.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o towerops-agent .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates iputils libcap && \
    setcap cap_net_raw+p /bin/ping
COPY --from=builder /app/towerops-agent /usr/local/bin/towerops-agent
RUN adduser -D -u 1000 towerops && chown towerops /usr/local/bin/towerops-agent
USER towerops
CMD ["towerops-agent"]
