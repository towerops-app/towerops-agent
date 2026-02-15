.PHONY: proto test build vet lint

proto:
	protoc --go_out=. --go_opt=paths=source_relative proto/agent.proto
	@# protoc outputs to proto/ due to go_package; move to pb/
	mv proto/agent.pb.go pb/agent.pb.go

test:
	go test -race -v ./...

build:
	go build -o towerops-agent .

vet:
	go vet ./...

lint:
	golangci-lint run

all: proto vet test build
