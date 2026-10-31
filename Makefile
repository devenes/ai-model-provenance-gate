BINARY_NAME := ai-model-provenance
MODULE := github.com/devenes/ai-model-provenance-gate
VERSION ?= 0.1.0
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.ToolVersion=$(VERSION) \
	-X $(MODULE)/internal/version.GitCommit=$(GIT_COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE) \
	-X $(MODULE)/internal/version.BuildType=local

GOVULNCHECK ?= $(shell which govulncheck 2>/dev/null || echo "$(HOME)/go/bin/govulncheck")

.PHONY: all build test test-race vet fmt fmt-check lint vulncheck e2e release-artifacts check clean

all: check build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/ai-model-provenance

fmt:
	gofmt -s -w .

fmt-check:
	@test -z "$$(gofmt -s -l .)" || (echo "gofmt check failed on:" && gofmt -s -l . && exit 1)

vet:
	go vet ./...

test:
	go test -v -count=1 ./...

test-race:
	go test -v -count=1 -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run ./...

vulncheck:
	$(GOVULNCHECK) ./...

e2e: build
	./scripts/run-e2e-demo.sh

release-artifacts:
	./scripts/package-release.sh

check: fmt-check vet test-race lint vulncheck e2e

clean:
	rm -rf bin/ dist/ coverage.out
