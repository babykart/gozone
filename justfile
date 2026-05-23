# gozone — PowerDNS Admin Interface
# https://github.com/casey/just

app_name := "gozone"
bin_dir := "./bin"

# show available commands
default:
    @just --list

# build the binary
build:
    go build -o {{ bin_dir }}/{{ app_name }} ./cmd/gozone

# build and run locally
run: build
    ./{{ bin_dir }}/{{ app_name }} -config config.yaml

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
