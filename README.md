# GoZone - PowerDNS Admin Interface in Go

[![License](https://img.shields.io/badge/License-MIT-blue)](https://opensource.org/licenses/MIT)

A clean web interface for managing PowerDNS authoritative DNS servers.

## Features

- **Zone Management**: List, create, edit, and delete DNS zones
- **Record Management**: Full CRUD for all DNS record types (A, AAAA, CNAME, MX, TXT, etc.)
- **User Management**: Admin and user roles with access control
- **Activity Logging**: Track all zone and user operations
- **REST API**: JSON API for zone and record automation
- **DynDNS 2 Support**: Dynamic DNS updates via `/nic/update` endpoint
- **PowerDNS Integration**: Communicates through the PowerDNS REST API
- **DNSSEC Support**: Zone rectification and slave notification
- **Single Binary**: Compiled Go binary with embedded SQLite database
- **Docker Support**: Ready-to-use Docker and docker-compose setup

## Quick Start

### Local Development

```bash
# Download dependencies
just deps

# Build and run
just run
```

Open http://localhost:8080 — default admin credentials: `admin` / `admin`

### Docker

```bash
# Start with docker-compose (includes PowerDNS)
just docker-up

# Or build and run standalone
just docker-build
docker run -d -p 8080:8080 gozone
```

## Configuration

Configuration is via `config.yaml` or environment variables:

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `server.host` | `GOZONE_SERVER_HOST` | `0.0.0.0` |
| `server.port` | `GOZONE_SERVER_PORT` | `8080` |
| `server.secret_key` | `GOZONE_SECRET_KEY` | `change-me...` |
| `database.driver` | `GOZONE_DB_DRIVER` | `sqlite3` |
| `database.dsn` | `GOZONE_DB_DSN` | `./data/gozone.db` |
| `powerdns.api_url` | `GOZONE_PDNS_API_URL` | `http://localhost:8081` |
| `powerdns.api_key` | `GOZONE_PDNS_API_KEY` | `changeme` |
| `powerdns.server_id` | `GOZONE_PDNS_SERVER_ID` | `localhost` |
| `auth.session_duration_hours` | `GOZONE_SESSION_DURATION` | `24` |
| `auth.bcrypt_cost` | — | `12` |

Initial admin password: `GOZONE_ADMIN_PASSWORD` (default: `admin`)

## API

All API endpoints require an API key passed via `X-API-Key` header.

```
GET    /api/v1/zones                  - List all zones
POST   /api/v1/zones                  - Create a zone
GET    /api/v1/zones/{zone_id}        - Get zone details
DELETE /api/v1/zones/{zone_id}        - Delete a zone
GET    /api/v1/zones/{zone_id}/records - List zone records
POST   /api/v1/zones/{zone_id}/records - Create record
PUT    /api/v1/zones/{zone_id}/records - Update record
DELETE /api/v1/zones/{zone_id}/records - Delete record
GET    /api/v1/stats                  - Server statistics
```

## DynDNS

```
GET/POST /nic/update?hostname=myhost.example.com&myip=1.2.3.4
```

Uses HTTP Basic Auth with user credentials from the local database.

## Justfile Commands

| Command | Description |
|---------|-------------|
| `just build` | Build the binary |
| `just run` | Build and run locally |
| `just test` | Run tests |
| `just test-verbose` | Run tests with verbose output |
| `just clean` | Remove build artifacts and database |
| `just fmt` | Format all source files |
| `just vet` | Run vet on all packages |
| `just deps` | Download and tidy dependencies |
| `just docker-build` | Build Docker image |
| `just docker-up` | Start services with docker-compose |
| `just docker-down` | Stop services |

## Building from Source

Requirements: Go 1.26+

```bash
just build
./bin/gozone -config config.yaml
```

## Project Structure

```
gozone/
├── cmd/gozone/main.go         # Application entry point
├── internal/
│   ├── config/config.go      # Configuration management
│   ├── database/database.go  # SQLite database layer
│   ├── dyndns/               # DynDNS protocol support
│   ├── handlers/             # HTTP handlers (web UI + API)
│   ├── middleware/auth.go     # JWT authentication
│   ├── models/               # Data models
│   └── pdns/client.go        # PowerDNS API client
├── web/
│   ├── templates/            # Go HTML templates
│   └── static/               # CSS, JS
├── config.yaml               # Default configuration
├── justfile                  # Task runner
├── Dockerfile
├── docker-compose.yml
└── go.mod
```

## License

MIT — see LICENSE file.
