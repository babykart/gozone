# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
# Copy vendored dependencies first for Docker layer caching: this layer only
# changes when go.mod/go.sum or vendor/ change. The build runs in vendor mode
# (deps are committed under vendor/), so no `go mod download` is needed.
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /gozone .

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

CMD ["/gozone", "server", "--config", "config.yaml"]
