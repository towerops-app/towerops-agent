.PHONY: all proto test test-fast test-short build vet lint

all: vet lint test build

proto:
	protoc --go_out=. --go_opt=module=github.com/towerops-app/towerops-agent proto/agent.proto

test:
	go test -race -v -count=1 -timeout 60s ./...

test-fast:
	go test -count=1 -timeout 60s ./...

test-short:
	go test -count=1 -timeout 30s -short ./...

build:
	go build -o towerops-agent .

vet:
	go vet ./...

lint:
	golangci-lint run

