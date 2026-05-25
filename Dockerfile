# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /gozone ./cmd/gozone

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /gozone /gozone
COPY web/ web/
COPY config.yaml .

RUN mkdir -p /app/data

RUN addgroup -g 65532 nonroot && \
    adduser -D -u 65532 -G nonroot nonroot && \
    chown -R nonroot:nonroot /app

USER nonroot

EXPOSE 8080

ENV GOZONE_ADMIN_PASSWORD=""
ENV GOZONE_SECRET_KEY=""
ENV GOZONE_PDNS_API_URL=""
ENV GOZONE_PDNS_API_KEY=""

CMD ["/gozone", "-config", "config.yaml"]
