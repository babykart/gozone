APP_NAME := gozone
BIN_DIR := ./bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/babykart/gozone/cmd.version=$(VERSION) \
           -X github.com/babykart/gozone/cmd.commit=$(COMMIT) \
           -X github.com/babykart/gozone/cmd.buildDate=$(DATE)

.PHONY: default build run test test-verbose test-race clean fmt vet gosec update docker-build docker-up docker-down auto-gen-rel gen-rel gen-tag help

default: help

# build the binary
build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME) .

# build and run locally
run: build
	$(BIN_DIR)/$(APP_NAME) server --config config.yaml

# run tests (bypass the result cache: a branch switch or an edited test must
# actually re-run, cached PASS results can mask both)
test:
	go test -count=1 ./...

# run tests with verbose output
test-verbose:
	go test -count=1 -v ./...

# run tests with the race detector — same flags as CI (pr.yml), so local
# parity is verifiable instead of memorised
test-race:
	go test -race -count=1 ./...

# remove build artifacts and database
clean:
	rm -rf $(BIN_DIR)/$(APP_NAME) ./data/gozone.db*

# format all source files
fmt:
	go fmt ./...

# run vet on all packages
vet:
	go vet ./...

# run gosec security analysis (optional tool)
gosec:
	@if command -v gosec > /dev/null 2>&1; then \
		gosec -exclude-dir='.cache|vendor|bin' -no-fail ./...; \
	else \
		echo "gosec not installed. Run: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

# run update
update:
	go get -u ./...
	go mod tidy
	go mod vendor

# build Docker image
docker-build:
	docker build -t gozone .

# start services with docker-compose
docker-up:
	docker-compose up -d

# stop services
docker-down:
	docker-compose down

# auto generate the next release (requires git-cliff)
auto-gen-rel:
	@_TAG=v$$(git cliff --bumped-version) && \
	git cliff --unreleased --tag $$_TAG -o && \
	git commit -a -s -S -m "chore(release): prepare for $$_TAG" && \
	git tag -s $$_TAG -m "$$_TAG"

# generate release with specific tag
gen-rel:
	@[ -n "$(TAG)" ] || (echo "Usage: make gen-rel TAG=v0.8.0" && exit 1)
	git cliff --unreleased --tag $(TAG) -o
	git commit -a -s -S -m "chore(release): prepare for $(TAG)"
	git tag -s $(TAG) -m "$(TAG)"

# generate next tag
gen-tag:
	@git cliff --bumped-version

# show available commands
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build           Build the binary"
	@echo "  run             Build and run locally"
	@echo "  test            Run tests (bypassing the result cache)"
	@echo "  test-verbose    Run tests with verbose output"
	@echo "  test-race       Run tests with the race detector (matches CI)"
	@echo "  clean           Remove build artifacts and database"
	@echo "  fmt             Format all source files"
	@echo "  vet             Run vet on all packages"
	@echo "  gosec           Run gosec security analysis"
	@echo "  update          Update all dependencies"
	@echo "  docker-build    Build Docker image"
	@echo "  docker-up       Start services with docker-compose"
	@echo "  docker-down     Stop services"
	@echo "  auto-gen-rel    Auto generate the next release"
	@echo "  gen-rel         Generate release (use TAG=<version>)"
	@echo "  gen-tag         Show next version tag"
	@echo "  help            Show this message"
