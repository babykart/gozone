# gozone — PowerDNS Admin Interface
# https://github.com/casey/just

app_name := "gozone"
bin_dir := "./bin"
git_bin := require("git")
git_cliff_bin := require("git-cliff")

# show available commands
default:
    @just --list

# build the binary
build:
    go build -o {{ bin_dir }}/{{ app_name }} ./cmd/gozone

# build and run locally
run: build
    {{ bin_dir }}/{{ app_name }} -config config.yaml

# run tests
test:
    go test ./...

# run tests with verbose output
test-verbose:
    go test -v ./...

# remove build artifacts and database
clean:
    rm -rf {{ bin_dir }}/{{ app_name }} data/gozone.db

# format all source files
fmt:
    go fmt ./...

# run vet on all packages
vet:
    go vet ./...

# download and tidy dependencies
deps:
    go mod download
    go mod tidy

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
gen-release tag:
    {{ git_cliff_bin }} --unreleased --tag {{ tag }} -o
    {{ git_bin }} commit -a -s -S -m "chore(release): prepare for {{ tag }}"
    {{ git_bin }} tag -s {{ tag }} -m "{{ tag }}"

# Generate tag
gen-tag:
    @{{ git_cliff_bin }} --bumped-version
