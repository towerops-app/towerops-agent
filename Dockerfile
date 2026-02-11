FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o towerops-agent .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates iputils
COPY --from=builder /app/towerops-agent /usr/local/bin/towerops-agent
RUN adduser -D -u 1000 towerops && chown towerops /usr/local/bin/towerops-agent
USER towerops
CMD ["towerops-agent"]
