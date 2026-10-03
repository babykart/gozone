# gozone — PowerDNS Admin Interface
# https://github.com/casey/just

app_name := "gozone"
bin_dir := "./bin"
# git and git-cliff are needed only by the release recipes; their require()
# calls live inside those recipes so a missing tool cannot break unrelated
# commands like build, test or fmt (the version/commit backticks below
# already degrade to "dev" when git is absent).

version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
commit  := `git rev-parse --short HEAD 2>/dev/null`
date    := `date -u +%Y-%m-%dT%H:%M:%SZ`
ldflags := "-X github.com/babykart/gozone/cmd.version=" + version + " -X github.com/babykart/gozone/cmd.commit=" + commit + " -X github.com/babykart/gozone/cmd.buildDate=" + date

# show available commands
default:
    @just --list

# build the binary
build:
    go build -ldflags "{{ ldflags }}" -o {{ bin_dir }}/{{ app_name }} .

# build and run locally
run: build
    {{ bin_dir }}/{{ app_name }} server --config config.yaml

# run tests (bypass the result cache: a branch switch or an edited test must
# actually re-run, cached PASS results can mask both)
test:
    go test -count=1 ./...

# run tests with verbose output
test-verbose:
    go test -count=1 -v ./...

# run frontend (app.js) unit tests; pure Node, no browser or npm deps
test-js:
    node --test web/jstest/

# run tests with the race detector — same flags as CI (pr.yml), so local
# parity is verifiable instead of memorised
test-race:
    go test -race -count=1 ./...

# remove build artifacts and database
clean:
    rm -rf {{ bin_dir }}/{{ app_name }} ./data/gozone.db*

# format all source files
fmt:
    go fmt ./...

# run vet on all packages
vet:
    go vet ./...

# run staticcheck static analysis (fails on findings, mirroring CI)
staticcheck:
    staticcheck ./...

# run gosec security analysis (fails on findings, mirroring CI)
gosec:
    gosec -exclude-dir='\.cache|vendor|bin' ./...

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

# Auto generate the next release
auto-gen-rel:
    #!/usr/bin/env sh
    _TAG=v$({{ require("git-cliff") }} --bumped-version)
    {{ require("git-cliff") }} --unreleased --tag ${_TAG} -o
    {{ require("git") }} commit -a -s -S -m "chore(release): prepare for ${_TAG}"
    {{ require("git") }} tag -s ${_TAG} -m "${_TAG}"

# Generate release
gen-rel tag:
    {{ require("git-cliff") }} --unreleased --tag {{ tag }} -o
    {{ require("git") }} commit -a -s -S -m "chore(release): prepare for {{ tag }}"
    {{ require("git") }} tag -s {{ tag }} -m "{{ tag }}"

# Generate tag
gen-tag:
    @{{ require("git-cliff") }} --bumped-version
