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
    (JWT cookie)            (X-API-Key or Authorization: Bearer)
          │                                   │
          ▼                                   ▼
┌────────────────────────────────────────────────────┐
│                chi Router (chi v5)                 │
│                                                    │
│  ┌──────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │ Public   │  │  Web UI Group │  │ API v1 Group│  │
│  │ routes   │  │  (Auth MW)    │  │(APIKey MW)  │  │
│  └──────────┘  └───────────────┘  └─────────────┘  │
└──────────────────────-┬────────────────────────────┘
                        │
                 ┌──────▼───────┐
                 │   Handlers   │
                 │(Handler str.)│
                 └──┬-─────┬─-──┘
                    │      │
      ┌─────────────▼─┐ ┌──▼──────────────┐
      │  Configured   │ │  PowerDNS API   │
      │  SQL Database │ │  (internal/pdns)│
      │(internal/db)  │ │                 │
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
  cache/          Generic TTL cache with background eviction
  config/         YAML configuration loading with GOZONE_ env var overrides
  constants/      Application constants
  database/       Multi-dialect SQL layer (SQLite/MySQL/PostgreSQL), migrations, seeding
  errors/         HTTP-aware application errors with Unwrap support
  handlers/       HTTP handlers for Web UI, REST API, and health checks
  middleware/     JWT authentication, API key auth, admin guard, user context, rate limiting
  models/         Shared data structures and JSON serialization
  pdns/           PowerDNS Authoritative Server REST API client and ZoneService interface
  validators/     DNS and input validation helpers
```

### Dependency Graph

```
cmd/gozone ──► config, database, handlers, middleware, pdns
handlers   ──► middleware, models, pdns, cache, validators, errors
middleware ──► models, database
pdns       ──► config, models, errors
database   ──► config
```

### Layer Responsibilities

| Layer | Role |
|-------|------|
| `cmd/gozone` | Application bootstrap: load config, open DB, create PDNS client, seed admin user, parse templates, register routes, start HTTP server via `run() error` |
| `handlers` | Business logic for each endpoint: parse input, call PDNS client, log activity, render templates or write JSON |
| `pdns` | HTTP client for PowerDNS REST API: zone CRUD, record management, DNSSEC rectification, statistics; typed errors map to HTTP status codes |
| `middleware` | Request pipeline: extract JWT/API key, load user from DB, inject into context, enforce admin role, rate limiting, security headers |
| `database` | Multi-dialect connection factory with DSN validation, content-hash migrations with multi-instance locks, context-aware query methods |
| `models` | Pure data structures — no behavior, just struct tags for JSON and SQL |
| `config` | Hierarchical config merging: defaults → YAML file → env vars |
| `cache` | Generic TTL cache used by `cachedClient` to reduce PowerDNS API calls |
| `validators` | DNS name, record content, SOA numeric fields, and zone kind validation |
| `errors` | `AppError` with HTTP status code and `Unwrap()` support for `errors.Is/As` |

## Startup Sequence

1. Parse `-config` flag (default: `config.yaml`)
2. **`config.Load(path)`** — start with `DefaultConfig()`, overlay YAML file, apply `GOZONE_*` env vars
3. **`database.New(cfg)`** — validate DSN, create directory if needed, open SQL connection (SQLite uses `SetMaxOpenConns(1)`), run content-hash migrations with `Dialect.LockMigrations`
4. **`pdns.NewClient(cfg)`** — create HTTP client pointing to PowerDNS API
5. **`seedAdminUser(ctx, db, cfg)`** — if `users` table is empty, insert admin/admin (or password from `GOZONE_ADMIN_PASSWORD`)
6. **`parseTemplates()`** — load `web/templates/*.html` via `template.ParseFS` from embedded filesystem (`web/embed.go`)
7. **`handlers.New(db, pdns, cfg, tmpl)`** — wire handler with all dependencies
8. **Register routes** on chi router with middleware chain
9. **`http.ListenAndServe(addr, r)`** — start HTTP server with graceful shutdown on SIGINT/SIGTERM
10. **`run() error`** returns errors so `defer db.Close()` always executes before `logger.Fatal` in `main`

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
                      │ getLogs (DB)   │── SQL  ──► Database ──► [ActivityLog...]
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

GoZone uses a configured SQL database (SQLite by default, MySQL and PostgreSQL supported) with 4 tables:

```
users
├── id              INTEGER PK AUTOINCREMENT (SQLite) / SERIAL (Postgres) / AUTO_INCREMENT (MySQL)
├── username        TEXT/ VARCHAR UNIQUE NOT NULL
├── email           TEXT/ VARCHAR UNIQUE NOT NULL
├── password_hash   TEXT/ VARCHAR NOT NULL                ← bcrypt hash, json:"-"
├── first_name      TEXT/ VARCHAR DEFAULT ''
├── last_name       TEXT/ VARCHAR DEFAULT ''
├── role            TEXT/ VARCHAR DEFAULT 'user'          ← 'admin' or 'user'
├── enabled         INTEGER/ BOOLEAN DEFAULT 1
├── created_at      DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP
└── updated_at      DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

activity_logs
├── id              INTEGER PK AUTOINCREMENT / SERIAL / AUTO_INCREMENT
├── user_id         INTEGER FK → users(id) ON DELETE SET NULL
├── zone_id         TEXT/ VARCHAR                         ← PowerDNS zone ID
├── action          TEXT/ VARCHAR NOT NULL                ← login, create_zone, delete_record, etc.
├── details         TEXT/ VARCHAR DEFAULT ''
└── created_at      DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

api_keys
├── id              INTEGER PK AUTOINCREMENT / SERIAL / AUTO_INCREMENT
├── user_id         INTEGER FK → users(id) ON DELETE CASCADE
├── key_hash        TEXT/ VARCHAR UNIQUE NOT NULL         ← json:"-"
├── description     TEXT/ VARCHAR DEFAULT ''
├── last_used_at    DATETIME/ TIMESTAMP
├── created_at      DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP
└── expires_at      DATETIME/ TIMESTAMP

settings
├── id              INTEGER PK AUTOINCREMENT / SERIAL / AUTO_INCREMENT
├── key             TEXT/ VARCHAR UNIQUE NOT NULL
└── value           TEXT/ VARCHAR DEFAULT ''
```

**Indexes**: `activity_logs(user_id)`, `activity_logs(zone_id)`, `activity_logs(created_at)`, `api_keys(key_hash)`

**PowerDNS data** (zones, records, statistics) is not stored locally — it is fetched live from the PowerDNS REST API and passed through as-is. GoZone is a stateless proxy for PowerDNS data. A local TTL cache (`internal/cache`) reduces repeated API calls and is invalidated on record mutations.

## Design Decisions

### Multi-Database Support

GoZone supports SQLite (default for single-node deployments), MySQL, and PostgreSQL. The `database.Dialect` interface abstracts driver-specific behavior: DSN parsing, parameter rebinding (e.g., `?` → `$n` for PostgreSQL), and migration locking (`GET_LOCK` for MySQL, `pg_advisory_lock` for PostgreSQL, no-op for SQLite). Migrations are identified by a truncated SHA-256 hash of their SQL content, making reordering safe, and are protected by a dialect-specific lock for multi-instance deployments.

### No ORM

All SQL queries are hand-written and inlined in handler/database methods. This avoids ORM complexity, makes queries auditable, and keeps the dependency tree small. The trade-off is more boilerplate and no compile-time query validation.

### Single Handler Struct

All HTTP handlers are methods on a single `Handler` struct holding shared dependencies (`DB`, `PDNS`, `Cfg`, `Tmpl`). This avoids passing dependencies through middleware or global state. The struct is created once at startup and shared across all routes.

### html/template (Embedded with //go:embed)

Templates are embedded in the binary at compile time via `//go:embed` and loaded via `template.ParseFS`. This simplifies deployment to a single binary with no external template files required. The template FuncMap includes `add`, `sub`, `urlquery`, `relativeName`, and `dict`.

### JWT for Web Sessions

The web UI uses JWT cookies (HttpOnly, SameSite=Lax) rather than server-side sessions. This keeps the server stateless — no session store needed. The JWT contains the user ID, username, and role, verified on every request with HMAC-SHA256.

### PowerDNS as Source of Truth

GoZone never stores DNS zones/records locally. All zone data is fetched live from the PowerDNS API. A generic TTL cache (`internal/cache`) wrapped around the PDNS client reduces repeated API calls for zone lists, zone info, statistics, and server info; record mutations invalidate affected cache entries. If PowerDNS is unreachable, the web UI shows errors. The health check endpoint (`/health/ready`) verifies this connectivity directly, bypassing the cache.

### Activity Logging

All user actions (login, zone creation, record updates) are logged to the `activity_logs` table in the configured database. This provides an audit trail without external infrastructure. Logs reference the user and zone by ID, with a human-readable `details` column.

### Input Validation

DNS record names, record content, SOA numeric fields, and zone kinds are validated in `internal/validators` before being sent to PowerDNS. This prevents invalid data from reaching the backend and provides meaningful error messages to users and API clients.

## Known Limitations

### Database-Specific Constraints

When using SQLite:

- **Single writer**: `SetMaxOpenConns(1)` serializes all writes. Under heavy write load (>100 writes/second), latency increases linearly.
- **No replication**: SQLite does not support master-slave or multi-primary replication.
- **No clustering**: A single SQLite file cannot be shared across multiple application instances. Horizontal scaling is not supported.
- **File-based**: The database is a single file on disk. Network file systems (NFS, CIFS) should not be used with SQLite.

MySQL and PostgreSQL deployments do not have these constraints and can use a normal connection pool.

### PowerDNS Dependency

- GoZone requires a running PowerDNS Authoritative Server with the REST API enabled. There is no offline or read-only mode.
- The PDNS client has a 30-second HTTP timeout. Slow or overloaded PowerDNS instances will cause request failures.
- DNS record content is validated in `internal/validators` before being sent to PowerDNS, but PowerDNS remains the authoritative source and may enforce additional rules.

### Authentication

- JWT tokens are HMAC-SHA256 with a configurable secret. There is no key rotation mechanism — changing the secret invalidates all existing sessions.
- API keys are SHA-256 hashed before comparison against the stored `key_hash`. The raw key is only shown once at creation time.
- The default admin password (`admin`/`admin`) should always be changed via `GOZONE_ADMIN_PASSWORD` at first startup.

### Web UI

- CSRF protection is implemented via gorilla/csrf middleware on all state-changing POST endpoints. Invalid CSRF tokens result in a redirect to `/login` with an error message.
- Cookies lack the `Secure` flag by default (set dynamically based on request). Enable TLS and use HTTPS in production.
- Templates are embedded at compile time via `//go:embed` and loaded with `template.ParseFS`, making deployment a single binary with no external template files required.

### Deployment

- **CGO required for SQLite**: The `mattn/go-sqlite3` driver requires a C compiler. Cross-compilation from macOS to Linux requires `CGO_ENABLED=1` and a cross-compilation toolchain. MySQL and PostgreSQL builds can use `CGO_ENABLED=0`.
- **CI/CD**: A GitHub Actions workflow (`.github/workflows/release.yml`) builds and publishes multi-architecture Docker images to GHCR on tag pushes matching `v*`.
- **Single process**: There is no support for multiple worker processes or load-balanced deployments with SQLite. MySQL/PostgreSQL deployments can be scaled horizontally behind a load balancer.
