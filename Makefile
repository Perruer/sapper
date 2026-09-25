.DEFAULT_GOAL := all
VERSION ?= dev

all: build test

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/Perruer/sapper/cmd/root.Version=$(VERSION)" -o bin/sapper .

test:
	go test ./...

# Runs the Redis tests against a real server instead of the in-process one
test-redis:
	docker compose up -d redis
	TEST_REDIS_URL=localhost:6379 go test ./pkg/storages/ ./e2e/

vet:
	go vet -structtag=false ./...

# Regenerates gen/ from api/v1/service.proto (buf, protoc-gen-go and protoc-gen-connect-go on PATH)
generate:
	buf generate

wire:
	cd cmd/server && wire

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t ghcr.io/perruer/sapper:$(VERSION) .

clean:
	rm -rf bin

.PHONY: all build test test-redis vet generate wire docker-build clean
