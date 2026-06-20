# GoZone - PowerDNS Admin Interface in Go

[![License](https://img.shields.io/badge/License-MIT-blue)](https://opensource.org/licenses/MIT)

A clean web interface for managing PowerDNS authoritative DNS servers.

## Features

- **Zone Management**: List, create, edit, and delete DNS zones with pagination, search, and per-page controls
- **Record Management**: Full CRUD for all DNS record types (A, AAAA, CNAME, MX, TXT, SOA, etc.) with color-coded type badges and inline editing
- **Multi-database Support**: SQLite (default), MySQL, and PostgreSQL are supported. Migrations are versioned by content hash with multi-instance locks.
- **Zone Metadata**: Manage per-zone metadata (ALLOW-AXFR-FROM, ALSO-NOTIFY, SOA-EDIT, NSEC3PARAM, PRESIGNED, etc.)
- **TSIG Keys**: Create, edit, and delete TSIG keys for secured zone transfers and dynamic updates
- **Group-based Authorization**: Assign zones to groups, add users to groups — non-admin users see only their authorized zones
- **User Management**: Admin and user roles with access control
- **API Keys**: Generate and manage API keys for REST API access (SHA-256 hashed)
- **Activity Logging**: Track all zone, metadata, TSIG key, and user operations
- **REST API**: JSON API for zone, record, and statistics automation
- **PowerDNS Integration**: Communicates through the PowerDNS REST API
- **DNSSEC Support**: Zone rectification (manual + auto after key ops), slave notification
- **Dark/Light Theme**: Toggle with localStorage persistence
- **Single Binary**: Compiled Go binary with embedded templates and static files. Uses a local SQLite database by default; MySQL and PostgreSQL are also supported via configuration.
- **Docker Support**: Ready-to-use Docker and docker-compose setup

## Quick Start

### Local Development

Dependencies are vendored — no download step required.

```bash
# Build and run
make run    # or: just run
```

Open http://localhost:8080 — default admin credentials: `admin` / `admin`

### Docker

```bash
# Start with docker-compose (includes PowerDNS)
make docker-up   # or: just docker-up

# Or build and run standalone
make docker-build   # or: just docker-build
docker run -d -p 8080:8080 gozone
```

## Configuration

Configuration is via `config.yaml` or environment variables:

### Server

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `server.host` | `GOZONE_SERVER_HOST` | `0.0.0.0` |
| `server.port` | `GOZONE_SERVER_PORT` | `8080` |
| `server.app_name` | `GOZONE_APP_NAME` | `GoZone` |
| `server.secret_key` | `GOZONE_SECRET_KEY` | *auto-generated* |
| `server.secure_cookies` | `GOZONE_SECURE_COOKIES` | `false` |

### Database

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `database.driver` | `GOZONE_DB_DRIVER` | `sqlite3` |
| `database.dsn` | `GOZONE_DB_DSN` | `./data/gozone.db` |

Supported drivers: `sqlite3`, `mysql`, `postgres`. Database passwords in DSNs are automatically redacted in logs.

### PowerDNS

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `powerdns.api_url` | `GOZONE_PDNS_API_URL` | `http://localhost:8081` |
| `powerdns.api_key` | `GOZONE_PDNS_API_KEY` | `changeme` |
| `powerdns.server_id` | `GOZONE_PDNS_SERVER_ID` | `localhost` |

### Authentication

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `auth.session_duration_hours` | `GOZONE_SESSION_DURATION` | `24` |
| `auth.bcrypt_cost` | — | `12` |

### Admin User (initial seed)

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `admin.username` | `GOZONE_ADMIN_USERNAME` | `admin` |
| `admin.password` | `GOZONE_ADMIN_PASSWORD` | `admin` |
| `admin.email` | `GOZONE_ADMIN_EMAIL` | `admin@gozone.local` |
| `admin.first_name` | `GOZONE_ADMIN_FIRST_NAME` | `Admin` |
| `admin.last_name` | `GOZONE_ADMIN_LAST_NAME` | `User` |

### Logging

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `logging.level` | — | `info` |

### Secret Key

**Important**: If no `server.secret_key` is set in the config file or via `GOZONE_SECRET_KEY`, a random 32-byte key is auto-generated at startup. For security the generated key is **not** written to the logs, so it cannot be recovered after startup — the key changes on every restart, invalidating all sessions and CSRF tokens. Always set `GOZONE_SECRET_KEY` or add `server.secret_key` to `config.yaml` for a stable key.

The master secret is split into independent JWT and CSRF sub-keys via HKDF-SHA256, so compromise of one sub-key does not reveal the other.

To generate a persistent key:
```bash
openssl rand -hex 32
```

### HTTPS Configuration

Session cookies use the `Secure` flag and `SameSite=Strict` by default. The `Secure` flag is automatically enabled when the request arrives over HTTPS (direct TLS or via `X-Forwarded-Proto: https` header from a reverse proxy).

The CSRF cookie's `Secure` flag is set once at startup and cannot be decided per request, so it is controlled by `server.secure_cookies` (`GOZONE_SECURE_COOKIES`). Set it to `true` whenever GoZone is served over HTTPS. Leave it `false` for plain-HTTP development, otherwise browsers will not return the CSRF cookie and form submissions will fail validation.

**Option 1: Direct TLS**

Configure `server.port` to 443 and provide TLS certificate paths (requires a reverse proxy or Go TLS config).

**Option 2: Reverse Proxy (recommended)**

Run GoZone behind nginx, Caddy, or Traefik:

```nginx
# nginx example
server {
    listen 443 ssl;
    server_name dns-admin.example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

## Web UI

### Dashboard

Shows PowerDNS server status (connected/unreachable, version, daemon type), zone and user counts, query statistics, and recent activity logs.

### Zone View

Each zone page displays:
- **Records table** with color-coded type badges (A=blue, AAAA=violet, CNAME=orange, MX=pink, NS=cyan, etc.)
- **DNSSEC management** — view, create, activate/deactivate, and delete DNSSEC keys (KSK/ZSK) with algorithm selection and DS record display
- **Zone metadata** (admin only) — manage ALLOW-AXFR-FROM, ALSO-NOTIFY, SOA-EDIT, NSEC3PARAM, PRESIGNED, and other PowerDNS metadata kinds
- **Activity logs** — history of changes to the zone
- **Export** (BIND zone file or CSV) — download all zone records
- **Import** (BIND or CSV) — upload and batch-create records into an existing zone
- **Danger zone** (admin only) — delete zone, notify, rectify
- **Clear cache** — invalidate the local zone list cache for the current zone, available to any user with group access to the zone

### TSIG Keys

Manage TSIG keys for secured DNS operations (zone transfers, dynamic updates). Available to admin users under the TSIG Keys menu. Supports hmac-md5, hmac-sha1, hmac-sha256, and hmac-sha512 algorithms.

### DNSSEC

Admin users can manage DNSSEC for each zone directly from the zone view page. Create KSK (Key Signing Key) and ZSK (Zone Signing Key) pairs with selectable algorithms (RSA/SHA-256, RSA/SHA-512, ECDSA P-256, ECDSA P-384, Ed25519, Ed448). Activate/deactivate keys, view DS records for parent zone configuration, and delete deactivated keys. All operations are logged in the activity feed. Zone rectification is triggered automatically after every key operation (create, toggle, delete) and is also available via the Rectify button (admin-only) in the zone header.

### Export / Import

Export full zone records in RFC 1035 BIND zone file format or CSV with a single click from the zone view page. Import zone data by uploading a `.zone` or `.csv` file — records are parsed and batch-created into the existing zone. Both are restricted to users with group access to the zone.

Import uses PowerDNS `REPLACE` semantics: for each name+type pair in the file, the existing RRSet is replaced if present, or created if absent. Records not referenced in the import file are left untouched. Importing a file with fewer records than currently exist for a given name+type replaces the entire RRSet — extra existing records within that same name+type are removed.

### Zone Groups

Admin users can create groups, assign zones to groups, and add users as members. Non-admin users only see zones assigned to groups they belong to. The "Groups" link is visible in the sidebar for admin users.

### Zone Templates

Admin users can define reusable DNS record templates that pre-populate records when creating new zones or applying to existing zones. Templates support variable substitution (`IP`, `IP6`, `MX_HOST`, `TTL`, `ZONE`, etc.) and include four built-in templates (standard, mail, web, redirect). Accessible under the Templates menu in the sidebar for admin users.

### API Keys

Users can generate personal API keys for programmatic access. Keys are SHA-256 hashed before storage — the raw key is shown only once at creation time.

## API

All API endpoints require an API key passed via the `X-API-Key` header or the `Authorization: Bearer <key>` header. Both forms are supported.

### Zones

```
GET    /api/v1/zones                      - List all zones (filtered by group for non-admin)
POST   /api/v1/zones                      - Create a zone (admin only)
GET    /api/v1/zones/{zone_id}            - Get zone details
DELETE /api/v1/zones/{zone_id}            - Delete a zone (admin only)
```

### Records

```
GET    /api/v1/zones/{zone_id}/records    - List zone records
POST   /api/v1/zones/{zone_id}/records    - Create record
PUT    /api/v1/zones/{zone_id}/records    - Update record
DELETE /api/v1/zones/{zone_id}/records    - Delete record
```

### Statistics

```
GET    /api/v1/stats                      - Server statistics
```

## Commands

| Make | Just | Description |
|------|------|-------------|
| `make build` | `just build` | Build the binary |
| `make run` | `just run` | Build and run locally |
| `make test` | `just test` | Run tests |
| `make test-verbose` | `just test-verbose` | Run tests with verbose output |
| `make clean` | `just clean` | Remove build artifacts and database |
| `make fmt` | `just fmt` | Format all source files |
| `make vet` | `just vet` | Run vet on all packages |
| `make gosec` | `just gosec` | Run security static analysis |
| `make update` | `just update` | Update all dependencies |
| `make docker-build` | `just docker-build` | Build Docker image |
| `make docker-up` | `just docker-up` | Start services with docker-compose |
| `make docker-down` | `just docker-down` | Stop services |

## Building from Source

Requirements: Go 1.26+. A C compiler (gcc/clang) is required only when building with the SQLite CGO driver; MySQL and PostgreSQL builds can use `CGO_ENABLED=0`.

```bash
make build   # or: just build
./bin/gozone -config config.yaml
```

## Project Structure

```
gozone/
├── cmd/gozone/main.go            # Application entry point, routing, wiring
├── internal/
│   ├── config/config.go          # Configuration (YAML + env vars)
│   ├── database/                 # Database layer (SQLite/MySQL/Postgres)
│   │   ├── database.go           # Connection, migrations
│   │   ├── dialect.go            # Dialect interface
│   │   ├── sqlite_dialect.go     # SQLite dialect
│   │   ├── mysql_dialect.go      # MySQL dialect
│   │   ├── postgres_dialect.go   # PostgreSQL dialect
│   │   └── seed.go               # Admin user seeding
│   ├── handlers/                 # HTTP handlers (web UI + REST API)
│   │   ├── handler.go            # Handler struct, rendering
│   │   ├── zones.go              # Zone CRUD, metadata
│   │   ├── records.go            # Record CRUD
│   │   ├── users.go              # User management
│   │   ├── groups.go             # Zone group authorization
│   │   ├── tsigkeys.go           # TSIG key management
│   │   ├── templates.go          # Zone template management
│   │   ├── dnssec.go             # DNSSEC key management
│   │   ├── export.go             # Zone export (BIND + CSV)
│   │   ├── import.go             # Zone import (BIND + CSV)
│   │   ├── api.go                # REST API handlers
│   │   ├── api_keys.go           # API key management
│   │   ├── auth.go               # Login/logout
│   │   ├── dashboard.go          # Dashboard with PDNS stats
│   │   └── health.go             # Health checks
│   ├── middleware/               # HTTP middleware
│   │   ├── auth.go               # JWT authentication
│   │   ├── zoneauth.go           # Zone group authorization
│   │   ├── security.go           # Security headers
│   │   ├── ratelimit.go          # Rate limiting
│   │   └── error.go              # Error handling
│   ├── models/                   # Shared data structures
│   └── pdns/                     # PowerDNS REST API client
│       ├── client.go             # HTTP client
│       └── service.go            # ZoneService interface
├── web/
│   ├── templates/                # Embedded Go HTML templates
│   │   ├── base.html             # Sidebar, head, tail
│   │   ├── dashboard.html        # Dashboard
│   │   ├── zones.html            # Zone list
│   │   ├── zone_view.html        # Zone detail + records + metadata
│   │   ├── groups.html           # Group list
│   │   ├── group_edit.html       # Group edit (members, zones)
│   │   ├── tsigkeys.html         # TSIG key list
│   │   ├── tsigkey_create.html   # TSIG key creation
│   │   ├── tsigkey_edit.html     # TSIG key edit
│   │   ├── templates.html        # Template list
│   │   ├── template_edit.html    # Template editor with records
│   │   ├── users.html            # User list
│   │   ├── profile.html          # User profile
│   │   └── ...
│   ├── static/
│   │   ├── css/style.css         # Stylesheet (light + dark theme)
│   │   └── js/app.js             # Theme toggle, sidebar toggle
│   └── embed.go                  # Embedded filesystem
├── config.yaml                   # Default configuration
├── justfile                      # Task runner (just)
├── Makefile                      # Task runner (make)
├── Dockerfile
├── docker-compose.yml
└── go.mod
```

## License

MIT — see LICENSE file.
