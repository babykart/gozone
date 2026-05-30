# GoZone Architecture

This document describes the internal architecture of GoZone, a PowerDNS management interface written in Go. It covers system components, data flow, design decisions, and known limitations.

## Table of Contents

- [Component Diagram](#component-diagram)
- [Package Overview](#package-overview)
- [Startup Sequence](#startup-sequence)
- [Data Flow](#data-flow)
- [Authentication Flows](#authentication-flows)
- [Database Schema](#database-schema)
- [Design Decisions](#design-decisions)
- [Known Limitations](#known-limitations)

## Component Diagram

```
                         Client
                           │
         ┌─────────────────┴─────────────────┐
         │                                   │
   Web Browser                         REST Client
   (JWT cookie)                      (X-API-Key)
         │                                   │
         ▼                                   ▼
┌────────────────────────────────────────────────────┐
│                chi Router (chi v5)                 │
│                                                    │
│  ┌──────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │ Public   │  │  Web UI Group │  │ API v1 Group│ │
│  │ routes   │  │  (Auth MW)    │  │(APIKey MW)  │ │
│  └──────────┘  └───────────────┘  └─────────────┘ │
└──────────────────────┬─────────────────────────────┘
                       │
                ┌──────▼───────┐
                │   Handlers   │
                │(Handler str.)│
                └───┬──────┬───┘
                  │       │
    ┌─────────────▼─┐ ┌──▼──────────────┐
    │  SQLite DB    │ │  PowerDNS API   │
    │ (internal/db) │ │  (internal/pdns)│
    └───────────────┘ └──┬──────────────┘
                         │
                  ┌──────▼───────┐
                  │  PowerDNS    │
                  │ Authoritative│
                  └──────────────┘
```

## Package Overview

```
cmd/gozone/       Application entry point, wiring, and route registration

internal/
  config/         YAML configuration loading with GOZONE_ env var overrides
  database/       SQLite connection management and schema migrations
  handlers/       HTTP handlers for Web UI, REST API, and health checks
  middleware/     JWT authentication, API key auth, admin guard, user context
  models/         Shared data structures and JSON serialization
  pdns/           PowerDNS Authoritative Server REST API client
```

### Dependency Graph

```
cmd/gozone ──► config, database, handlers, middleware, pdns
handlers   ──► middleware, models, pdns
middleware ──► models
pdns       ──► config, models
database   ──► config
```

### Layer Responsibilities

| Layer | Role |
|-------|------|
| `cmd/gozone` | Application bootstrap: load config, open DB, create PDNS client, seed admin user, parse templates, register routes, start HTTP server |
| `handlers` | Business logic for each endpoint: parse input, call PDNS client, log activity, render templates or write JSON |
| `pdns` | HTTP client for PowerDNS REST API: zone CRUD, record management, DNSSEC rectification, statistics |
| `middleware` | Request pipeline: extract JWT/API key, load user from DB, inject into context, enforce admin role |
| `database` | Connection factory with DSN validation, schema migrations, connection pool config |
| `models` | Pure data structures — no behavior, just struct tags for JSON and SQL |
| `config` | Hierarchical config merging: defaults → YAML file → env vars |

## Startup Sequence

1. Parse `-config` flag (default: `config.yaml`)
2. **`config.Load(path)`** — start with `DefaultConfig()`, overlay YAML file, apply `GOZONE_*` env vars
3. **`database.New(cfg)`** — validate DSN, create directory, open SQLite connection (`SetMaxOpenConns(1)`), run inline migrations
4. **`pdns.NewClient(cfg)`** — create HTTP client pointing to PowerDNS API
5. **`seedAdminUser(db, cfg)`** — if `users` table is empty, insert admin/admin (or password from `GOZONE_ADMIN_PASSWORD`)
6. **`parseTemplates()`** — load `web/templates/*.html` via `template.ParseFS` from embedded filesystem (`web/embed.go`)
7. **`handlers.New(db, pdns, cfg, tmpl)`** — wire handler with all dependencies
8. **Register routes** on chi router with middleware chain
9. **`http.ListenAndServe(addr, r)`** — start HTTP server with graceful shutdown on SIGINT/SIGTERM

## Data Flow

### Web UI: User Views Zones

```
Browser ──GET /zones──► chi Router
                          │
                          ▼ Auth middleware
                     ┌────────────────┐
                     │ Extract cookie │
                     │ Parse JWT      │
                     │ Load user (DB) │
                     │ Store in ctx   │
                     └───────┬────────┘
                             ▼
                     ListZones handler
                     ┌────────────────┐
                     │ PDNS.ListZones │── HTTP ──► PowerDNS ──► [Zone...]
                     │ PDNS.ListRecs  │── HTTP ──► PowerDNS ──► [RRSet...]
                     │ getLogs (DB)  │── SQL  ──► SQLite   ──► [ActivityLog...]
                     └───────┬────────┘
                             ▼
                    render("zones.html", data)
                             │
                             ▼
                      HTML Response ──► Browser
```

### REST API: Create a Zone

```
Client ──POST /api/v1/zones──► chi Router
                                │
                                ▼ APIKeyAuth middleware
                          ┌──────────────────┐
                          │ Extract X-API-Key│
                          │ Look up key_hash │
                          │ Load user (DB)   │
                          │ Store in ctx     │
                          └───────┬──────────┘
                                  ▼
                          APICreateZone handler
                          ┌──────────────────┐
                          │ Decode JSON body │
                          │ PDNS.CreateZone  │── HTTP ──► PowerDNS ──► Zone
                          └───────┬──────────┘
                                  ▼
                          writeJSON(201, zone)
                                  │
                                  ▼
                          JSON Response ──► Client
```

## Authentication Flows

GoZone supports two authentication mechanisms, both using JWT-based sessions
stored in the request context under `UserContextKey`:

### Web UI (JWT Cookies)

```
Login POST /login
  │
  ▼
bcrypt.CompareHashAndPassword(user.PasswordHash, password)
  │
  ▼
middleware.GenerateToken(user, secret, duration)
  │
  ▼
Set-Cookie: gozone_session=<JWT>; HttpOnly; SameSite=Lax

Subsequent requests:
  │
  ▼
middleware.Auth middleware
  ├── Extract from cookie "gozone_session"
  ├── Fallback: Authorization: Bearer <JWT>
  ├── ParseToken → Claims{UserID, Username, Role}
  ├── loadUser(DB, UserID) → ensure enabled
  └── context.WithValue(UserContextKey, user)
```

### REST API (API Keys)

```
Request with X-API-Key: <key>
  │
  ▼
middleware.APIKeyAuth middleware
  ├── Extract from X-API-Key header
  ├── Fallback: Authorization: Bearer <key>
  ├── Query: SELECT user_id, expires_at FROM api_keys WHERE key_hash = ?
  ├── Check expiration
  ├── loadUser(DB, UserID) → ensure enabled
  ├── UPDATE api_keys SET last_used_at = NOW()
  └── context.WithValue(UserContextKey, user)
```

## Database Schema

GoZone uses SQLite with 4 tables:

```
users
├── id              INTEGER PK AUTOINCREMENT
├── username        TEXT UNIQUE NOT NULL
├── email           TEXT UNIQUE NOT NULL
├── password_hash   TEXT NOT NULL                ← bcrypt hash, json:"-"
├── first_name      TEXT DEFAULT ''
├── last_name       TEXT DEFAULT ''
├── role            TEXT DEFAULT 'user'          ← 'admin' or 'user'
├── enabled         INTEGER DEFAULT 1
├── created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
└── updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP

activity_logs
├── id              INTEGER PK AUTOINCREMENT
├── user_id         INTEGER FK → users(id) ON DELETE SET NULL
├── zone_id         TEXT                         ← PowerDNS zone ID
├── action          TEXT NOT NULL                ← login, create_zone, delete_record, etc.
├── details         TEXT DEFAULT ''
└── created_at      DATETIME DEFAULT CURRENT_TIMESTAMP

api_keys
├── id              INTEGER PK AUTOINCREMENT
├── user_id         INTEGER FK → users(id) ON DELETE CASCADE
├── key_hash        TEXT UNIQUE NOT NULL         ← json:"-"
├── description     TEXT DEFAULT ''
├── last_used_at    DATETIME
├── created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
└── expires_at      DATETIME

settings
├── id              INTEGER PK AUTOINCREMENT
├── key             TEXT UNIQUE NOT NULL
└── value           TEXT DEFAULT ''
```

**Indexes**: `activity_logs(user_id)`, `activity_logs(zone_id)`, `activity_logs(created_at)`, `api_keys(key_hash)`

**PowerDNS data** (zones, records, statistics) is not stored locally — it is fetched live from the PowerDNS REST API and passed through as-is. GoZone is a stateless proxy for PowerDNS data.

## Design Decisions

### SQLite Instead of PostgreSQL

GoZone targets single-node deployments and small installations. SQLite eliminates the need for a separate database server, simplifies deployment (single binary + one file), and performs well for the expected load (~100 users, <1000 zones). The `SetMaxOpenConns(1)` constraint serializes writes to prevent SQLITE_BUSY errors.

### No ORM

All SQL queries are hand-written and inlined in handler methods. This avoids ORM complexity, makes queries auditable, and keeps the dependency tree small. The trade-off is more boilerplate and no compile-time query validation.

### Single Handler Struct

All HTTP handlers are methods on a single `Handler` struct holding shared dependencies (`DB`, `PDNS`, `Cfg`, `Tmpl`). This avoids passing dependencies through middleware or global state. The struct is created once at startup and shared across all routes.

### html/template (Embedded with //go:embed)

Templates are embedded in the binary at compile time via `//go:embed` and loaded via `template.ParseFS`. This simplifies deployment to a single binary with no external template files required.

### JWT for Web Sessions

The web UI uses JWT cookies (HttpOnly, SameSite=Lax) rather than server-side sessions. This keeps the server stateless — no session store needed. The JWT contains the user ID, username, and role, verified on every request with HMAC-SHA256.

### PowerDNS as Source of Truth

GoZone never caches or stores DNS zones/records locally. All zone data is fetched live from the PowerDNS API. This means if PowerDNS is unreachable, the web UI shows errors. The health check endpoint (`/health/ready`) verifies this connectivity.

### Activity Logging in SQLite

All user actions (login, zone creation, record updates) are logged to the `activity_logs` table. This provides an audit trail without external infrastructure. Logs reference the user and zone by ID, with a human-readable `details` column.

## Known Limitations

### SQLite Constraints

- **Single writer**: `SetMaxOpenConns(1)` serializes all writes. Under heavy write load (>100 writes/second), latency increases linearly.
- **No replication**: SQLite does not support master-slave or multi-primary replication. For high-availability deployments, consider migrating to PostgreSQL.
- **No clustering**: A single SQLite file cannot be shared across multiple application instances. Horizontal scaling is not supported.
- **File-based**: The database is a single file on disk. Network file systems (NFS, CIFS) should not be used with SQLite.

### PowerDNS Dependency

- GoZone requires a running PowerDNS Authoritative Server with the REST API enabled. There is no offline or read-only mode.
- The PDNS client has a 30-second HTTP timeout. Slow or overloaded PowerDNS instances will cause request failures.
- All zone and record data is proxied — GoZone does not validate DNS record content (e.g., valid IP, correct FQDN format) before sending to PowerDNS.

### Authentication

- JWT tokens are HMAC-SHA256 with a configurable secret. There is no key rotation mechanism — changing the secret invalidates all existing sessions.
- API keys are SHA-256 hashed before comparison against the stored `key_hash`. The raw key is only shown once at creation time.
- The default admin password (`admin`/`admin`) should always be changed via `GOZONE_ADMIN_PASSWORD` at first startup.

### Web UI

- CSRF protection is implemented via gorilla/csrf middleware on all state-changing POST endpoints. Invalid CSRF tokens result in a redirect to `/login` with an error message.
- Cookies lack the `Secure` flag by default (set dynamically based on request). Enable TLS and use HTTPS in production.
- Templates are embedded at compile time via `//go:embed` and loaded with `template.ParseFS`, making deployment a single binary with no external template files required.

### Deployment

- **CGO required**: The `mattn/go-sqlite3` driver requires a C compiler. Cross-compilation from macOS to Linux requires `CGO_ENABLED=1` and a cross-compilation toolchain.
- **CI/CD**: A GitHub Actions workflow (`.github/workflows/release.yml`) builds and publishes multi-architecture Docker images to GHCR on tag pushes matching `v*`.
- **Single process**: There is no support for multiple worker processes or load-balanced deployments.

### Future Database Migration

The schema and codebase are designed for SQLite. Migrating to PostgreSQL or MySQL would require:

1. Updating the `database/database.go` driver and DSN handling
2. Replacing SQLite-specific SQL syntax (`INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL`, `CURRENT_TIMESTAMP` → `NOW()`)
3. Removing `SetMaxOpenConns(1)` and implementing a connection pool
4. Adding a migration framework for version-controlled schema changes
5. Rewriting tests that rely on `:memory:` SQLite

These are tracked in the [ROADMAP.md](../ROADMAP.md#-future-database-migration).
