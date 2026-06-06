.PHONY: proto test test-fast test-race build vet lint

proto:
	protoc --go_out=. --go_opt=paths=source_relative proto/agent.proto
	@# protoc outputs to proto/ due to go_package; move to pb/
	mv proto/agent.pb.go pb/agent.pb.go

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

all: proto vet test build
