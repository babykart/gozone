# gozone — PowerDNS Admin Interface
# https://github.com/casey/just

app_name := "gozone"
bin_dir := "./bin"
git_bin := require("git")
git_cliff_bin := require("git-cliff")

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

# run tests
test:
    go test ./...

# run tests with verbose output
test-verbose:
    go test -v ./...

# remove build artifacts and database
clean:
    rm -rf {{ bin_dir }}/{{ app_name }} ./data/gozone.db*

# format all source files
fmt:
    go fmt ./...

# run vet on all packages
vet:
    go vet ./...

# run gosec security analysis
gosec:
    gosec -exclude-dir='\.cache|vendor|bin' -no-fail ./...

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
    _TAG=v$({{ git_cliff_bin }} --bumped-version)
    {{ git_cliff_bin }} --unreleased --tag ${_TAG} -o
    {{ git_bin }} commit -a -s -S -m "chore(release): prepare for ${_TAG}"
    {{ git_bin }} tag -s ${_TAG} -m "${_TAG}"

# Generate release
gen-rel tag:
    {{ git_cliff_bin }} --unreleased --tag {{ tag }} -o
    {{ git_bin }} commit -a -s -S -m "chore(release): prepare for {{ tag }}"
    {{ git_bin }} tag -s {{ tag }} -m "{{ tag }}"

# Generate tag
gen-tag:
    @{{ git_cliff_bin }} --bumped-version
