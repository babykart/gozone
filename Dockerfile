# Build stage
FROM golang:1.26-alpine AS builder

# Version metadata injected via ldflags. .dockerignore excludes .git, so these
# default to "dev"/"none"/"unknown"; pass --build-arg VERSION=... (e.g. from
# `git describe --tags`) in CI to stamp a real release.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
# Copy vendored dependencies first for Docker layer caching: this layer only
# changes when go.mod/go.sum or vendor/ change. The build runs in vendor mode
# (deps are committed under vendor/), so no `go mod download` is needed.
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags "-X github.com/babykart/gozone/cmd.version=${VERSION} -X github.com/babykart/gozone/cmd.commit=${COMMIT} -X github.com/babykart/gozone/cmd.buildDate=${DATE}" \
    -o /gozone .

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /gozone /gozone
# Symlink /usr/bin/gozone → /gozone so the binary is reachable via PATH lookup
# (docker/kubectl exec `gozone ...`); see README "Emergency recovery".
RUN ln -s /gozone /usr/bin/gozone
COPY config.yaml .

RUN mkdir -p /app/data && \
    addgroup -g 65532 nonroot && \
    adduser -D -u 65532 -G nonroot nonroot && \
    chown -R nonroot:nonroot /app/data

USER nonroot

EXPOSE 8080

# Image-level healthcheck so orchestrators that read only the image (plain
# `docker run`, Kubernetes, Nomad) benefit, not just docker-compose. It probes
# the LIVENESS endpoint: the process is up and serving HTTP. Dependency health
# (database, PowerDNS) is deliberately excluded — an unreachable PowerDNS or a
# database hiccup must not mark the container unhealthy and trigger restart
# cascades across a fleet. Orchestrators that want dependency-aware gating
# (load-balancer removal, rollout checks) should probe /health/ready, which
# returns 503 when DB or PowerDNS is unreachable. busybox wget ships with
# alpine.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health/live || exit 1

CMD ["/gozone", "server", "--config", "config.yaml"]
