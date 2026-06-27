# GoZone - PowerDNS Admin Interface in Go

[![License](https://img.shields.io/badge/License-MIT-blue)](https://opensource.org/licenses/MIT)

A clean web interface for managing PowerDNS authoritative DNS servers.

## Features

- **Zone Management**: List, create, edit, and delete DNS zones with pagination, search, and per-page controls
- **Record Management**: Full CRUD for all DNS record types (A, AAAA, CNAME, MX, TXT, SOA, etc.) with color-coded type badges and inline editing
- **RRSet Comments**: View, add, and edit PowerDNS comments per RRSet through the web UI, CSV import/export, and REST API
- **Brute-force Protection**: Per-IP and per-username login rate-limiters (compound AND), persistent per-account lockout after repeated failures, audit trail of every attempt, identical generic error response across unknown user / wrong password / locked account to block account enumeration
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

### Kubernetes (Helm)

A Helm chart is available for deploying GoZone on Kubernetes:

```bash
helm repo add babykart https://babykart.github.io/helm-charts
helm install gozone babykart/gozone
```

See the [helm-charts repository](https://github.com/babykart/helm-charts) for configuration options.

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
| `server.trusted_proxies` | `GOZONE_TRUSTED_PROXIES` | *empty* (TCP source IP only) |

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

### Login Lockout (brute-force protection)

`/login` is always protected by an in-memory per-IP rate limiter (5/min). The knobs below add defence-in-depth against credential-stuffing and distributed brute-force:

| YAML Path | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| `login_lock.max_failed_attempts` | `GOZONE_LOGIN_MAX_FAILED_ATTEMPTS` | `10` | Consecutive failed attempts per account before lock. `0` disables persistent lockout (the IP/username rate limiters still protect the endpoint). |
| `login_lock.lockout_duration_minutes` | `GOZONE_LOGIN_LOCKOUT_MINUTES` | `15` | How long the account stays locked. Every further failure extends the window so a sliding-window attack cannot recover. |
| `login_lock.username_rate_limit_per_minute` | `GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE` | `5` | In-memory per-username limiter, compounded with the per-IP limit at the route level. `0` disables. |
| `login_lock.attempts_retention_hours` | `GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS` | `24` | How long a login attempt is kept in the `login_attempts` audit table before being purged. |

The client IP is resolved through chi's `ClientIPFrom*` middleware: by default `ClientIPFromRemoteAddr` (TCP source only, fail-closed against XFF/Real-IP spoofing). When `server.trusted_proxies` is configured with a list of CIDR ranges, the middleware switches to `ClientIPFromXFF` and walks XFF right-to-left until the first non-trusted hop. Leave `trusted_proxies` empty when GoZone is directly reachable on the public Internet — an attacker in direct access cannot rotate `X-Forwarded-For` to bypass the rate-limit.

All three authentication failure paths — unknown username, wrong password, locked account — return the **same** redirect target (`/login?error=invalid_credentials`) and the same generic banner ("Invalid username or password."). The mapping is centralised in `loginErrorMessages` so the raw query code cannot leak into the rendered template, closing the account-enumeration channel that a different error message (e.g. `account_locked`) would otherwise expose. The constant-time dummy bcrypt compare on unknown users covers the timing channel; per-IP, per-username, and persistent account lockouts cover the rate channel.

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

### Activity Log Retention

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `activity.retention_days` | `GOZONE_ACTIVITY_RETENTION_DAYS` | `90` |
| `activity.batch_size` | `GOZONE_ACTIVITY_BATCH_SIZE` | `1000` |

Set `activity.retention_days` to `0` to keep activity logs indefinitely.

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
- **RRSet comments** — view, add, or edit PowerDNS comments per RRSet via the inline editor and dedicated edit page; one comment per line in the textarea
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

**Disabled records**: BIND export skips records marked `disabled` (the BIND format has no concept of disabled). CSV export keeps them with `disabled=true` so the round-trip is preserved.

**RRSet comments**: CSV export adds a `comment` column at the end of the row. Multiple comments per RRSet are joined with newlines into a single cell (using standard CSV embedded-newline quoting) and the same cell is repeated on every record row of that RRSet. On import, the cell is split on newlines (one `Comment` per line) and deduplicated across rows of the same RRSet. CSV files without the `comment` column still parse unchanged.

### RRSet Comments

GoZone exposes the PowerDNS API `comments` field for every RRSet. Comments are metadata strings attached to a whole RRSet (not to individual records) and are useful for ops notes like "managed by ops-team" or "created during migration XYZ".

- **Web UI**: a multi-line textarea (one comment per line) is available in the Add Records form, the batch create form, the dedicated Edit Record page, and the inline editor on the zone view. Existing comments are shown read-only under each record's content (styled as an italic blockquote).
- **CSV export/import**: round-trips through the optional `comment` column described above.
- **API**: pass a `comments` array in the RRSet payload when creating or updating records (see the API section below).
- **PowerDNS semantics**: the PATCH `comments` field *replaces* the entire comment list for the RRSet. GoZone preserves this behaviour — when you edit a record without touching the comment field, the existing comments are kept (the field is omitted from the PATCH body); when you add or change a comment, existing comments are echoed back and your changes are applied.
- **Clearing all comments**: the Edit Record page and the inline editor expose a "Clear all comments" checkbox. When checked, GoZone sends `"comments":[]` to PowerDNS, which deletes every existing comment for that RRSet. The checkbox only appears in the edit forms (not in the batch-create form, where no comments exist yet by default).

### Zone Groups

Admin users can create groups, assign zones to groups, and add users as members. Non-admin users only see zones assigned to groups they belong to. The "Groups" link is visible in the sidebar for admin users.

### Zone Templates

Admin users can define reusable DNS record templates that pre-populate records when creating new zones or applying to existing zones. Templates support variable substitution (`IP`, `IP6`, `MX_HOST`, `TTL`, `ZONE`, etc.) and include four built-in templates (standard, mail, web, redirect). Accessible under the Templates menu in the sidebar for admin users.

### User Management

Admin users can create, edit, and delete user accounts from the **Users** menu in the sidebar. The list shows username, email, name, role, status (Active/Disabled/Locked), and per-row actions (Edit, Lock/Unlock, Delete).

- **Self-DOS protection**: an admin cannot lock their own account from the UI; the self-lock attempt is rejected with a 400 error.
- **Account lockout**: the `Lock` button sets `locked_until = now + login_lock.lockout_duration_minutes` and resets the failed-login counter, so a manual lock and the automatic failed-login threshold share the same window. Locked accounts show a yellow badge with a tooltip showing the unlock time.
- **Unlock**: the `Unlock` button clears `locked_until` and resets the failed-login counter. The action is idempotent — unlocking a non-locked user still writes an `unlock_user` audit-log entry.
- **Audit trail**: every lock and unlock writes an `activity_logs` entry with the actor's ID and the target's username.
- **Last-admin guard**: the `UpdateUser` and `DeleteUser` handlers refuse to demote, disable, or delete the last enabled admin. The lock UI inherits this guard indirectly via the self-lock check (an admin cannot reach the lock button for the only admin).

### API Keys

Users can generate personal API keys for programmatic access. Keys are SHA-256 hashed before storage — the raw key is shown only once at creation time.

## API

All API endpoints are under `/api/v1` and require an API key. Keys are created via the Web UI at `/profile/api-keys` — the raw key is shown only once at creation time.

### Authentication

Pass the API key using one of two headers:

```bash
# Option 1: X-API-Key header (preferred)
X-API-Key: gozone_<base64-encoded-key>

# Option 2: Authorization Bearer header
Authorization: Bearer gozone_<base64-encoded-key>
```

All examples below use the `X-API-Key` header.

### Rate Limiting

API requests are rate-limited to **100 requests per minute** per API key. Exceeding the limit returns HTTP 429 with a `Retry-After` header.

### Error Responses

All errors return a JSON body:

```json
{
  "error": "human-readable label",
  "code": "ERROR_CODE",
  "message": "human-readable label"
}
```

| Error Code | HTTP Status | Meaning |
|------------|-------------|---------|
| `INVALID_JSON` | 400 | Malformed JSON body |
| `VALIDATION_ERROR` | 400 | Invalid input (domain name, record type, etc.) |
| `ZONE_NOT_FOUND` | 404 | Zone does not exist |
| `RECORD_NOT_FOUND` | 404 | Record does not exist |
| `CONFLICT` | 409 | Resource already exists |
| `UNAUTHORIZED` | 401 | Invalid or expired API key |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

### Zones

#### List zones

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones
```

Response `200`:

```json
[
  {
    "id": "example.com.",
    "name": "example.com.",
    "kind": "Native",
    "serial": 2026062001,
    "dnssec": false,
    "masters": [],
    "account": "",
    "catalog": ""
  }
]
```

Non-admin users only see zones assigned to their groups.

#### Get zone details

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones/example.com
```

Response `200`: single zone object (same format as list items).

#### Create zone (admin only)

```bash
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"newzone.com","kind":"Native","nameservers":["ns1.example.com.","ns2.example.com."]}' \
  http://localhost:8080/api/v1/zones
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `name` | string | **yes** | — | Domain name (trailing dot optional) |
| `kind` | string | no | `"Native"` | `Native`, `Master`, `Slave`, `Producer`, `Consumer` |
| `nameservers` | string[] | no | — | List of NS hostnames |
| `masters` | string[] | no | — | Required for `Slave`/`Consumer` |
| `catalog` | string | no | — | Catalog zone name |

Response `201`: the created zone object.

#### Delete zone (admin only)

```bash
curl -X DELETE \
  -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones/example.com
```

Response `200`:

```json
{"message": "zone deleted"}
```

### Records

#### List records

Without query parameters, returns every RRSet in the zone as a JSON array:

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones/example.com/records
```

Response `200`:

```json
[
  {
    "name": "www.example.com.",
    "type": "A",
    "ttl": 300,
    "records": [
      {
        "name": "www.example.com.",
        "type": "A",
        "content": "1.2.3.4",
        "ttl": 300,
        "priority": 0,
        "disabled": false
      }
    ],
    "comments": []
  }
]
```

Pass the optional `name` and `type` query parameters to fetch a single RRSet (or all RRSets matching a name) without pulling the entire zone. They map to the PowerDNS API `rrset_name` / `rrset_type` query parameters:

```bash
# Every RRSet for a given name (any type)
curl -H "X-API-Key: gozone_yourkey" \
  "http://localhost:8080/api/v1/zones/example.com/records?name=www.example.com."

# One specific RRSet (name + type)
curl -H "X-API-Key: gozone_yourkey" \
  "http://localhost:8080/api/v1/zones/example.com/records?name=www.example.com.&type=A"
```

The response is always a JSON array (possibly empty when no match). `type` requires `name`; passing `type` alone returns `400 VALIDATION_ERROR`.

#### Create record

```bash
# A record
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"www.example.com","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# MX record (priority is a separate field)
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com.","type":"MX","ttl":3600,"records":[{"content":"mail.example.com.","priority":10}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# CNAME record
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"blog.example.com","type":"CNAME","ttl":300,"records":[{"content":"example.github.io."}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# TXT record (content is auto-quoted for PowerDNS)
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com.","type":"TXT","ttl":3600,"records":[{"content":"v=spf1 include:_spf.google.com ~all"}]}' \
  http://localhost:8080/api/v1/zones/example.com/records
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | **yes** | Relative (`www`), absolute (`www.example.com.`), or `@` for apex |
| `type` | string | **yes** | Any valid DNS record type |
| `ttl` | int | **yes** | Time-to-live in seconds |
| `records` | array | **yes** | Array of record objects |
| `records[].content` | string | **yes** | Record content |
| `records[].priority` | int | no | For MX and SRV types |
| `records[].disabled` | bool | no | Default `false` |
| `comments` | array | no | Array of RRSet comments (see below) |
| `comments[].content` | string | **yes** | Comment text |
| `comments[].account` | string | no | Account name that added the comment; omitted from the request if not set (PowerDNS defaults it server-side) |
| `comments[].modified_at` | int | no | Unix timestamp; omitted from the request if not set (PowerDNS defaults it server-side) |

The `comments` array is omitted from the PATCH payload when left empty or absent, which tells PowerDNS to keep the RRSet's existing comments untouched. When provided, it *replaces* the entire comment list for the RRSet (PowerDNS `comments` semantics), so include every comment you want to keep. GoZone does not set a default `account` or `modified_at` — both fields are optional and PowerDNS fills in the server-side defaults when omitted.

> Note: the current API surface does not expose an explicit "clear comments" signal. Sending an empty `comments` array (`"comments":[]`) is normalised by GoZone's `CommentPatch` wrapper to a preserve semantic, so existing comments are kept untouched. To clear comments via automation, either issue a delete + recreate sequence or use the web UI's "Clear all comments" checkbox (which sends the purge signal directly to PowerDNS).

Response `201`:

```json
{"message": "record created"}
```

#### Update record

```bash
curl -X PUT \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"www.example.com","type":"A","ttl":600,"records":[{"content":"5.6.7.8"}]}' \
  http://localhost:8080/api/v1/zones/example.com/records
```

Response `200`:

```json
{"message": "record updated"}
```

#### Delete record

```bash
curl -X DELETE \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"www.example.com","type":"A"}' \
  http://localhost:8080/api/v1/zones/example.com/records
```

Response `200`:

```json
{"message": "record deleted"}
```

### Statistics

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/stats
```

Response `200`:

```json
{
  "statistics": [
    {"name": "zone-cache-hits", "type": "Long", "value": 12345},
    {"name": "zone-cache-misses", "type": "Long", "value": 678}
  ],
  "zone_count": 3
}
```

`zone_count` reflects the number of zones visible to the authenticated user.

### Health Endpoints (no auth required)

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/health` | `{"status":"ok"}` |
| `GET` | `/health/ready` | PowerDNS connectivity check |
| `GET` | `/health/live` | Liveness probe |

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
