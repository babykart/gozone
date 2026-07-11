# GoZone Architecture

This document describes the internal architecture of GoZone, a PowerDNS management interface written in Go. It covers system components, data flow, design decisions, and known limitations.

## Table of Contents

- [Component Diagram](#component-diagram)
- [Package Overview](#package-overview)
  - [Dependency Graph](#dependency-graph)
  - [Layer Responsibilities](#layer-responsibilities)
- [Startup Sequence](#startup-sequence)
- [Data Flow](#data-flow)
  - [Web UI: User Views Zones](#web-ui-user-views-zones)
  - [REST API: Create a Zone](#rest-api-create-a-zone)
  - [Login Brute-Force Protection](#login-brute-force-protection)
- [Authentication Flows](#authentication-flows)
  - [Client IP Resolution](#client-ip-resolution-global-before-auth)
  - [Login (Web UI)](#login-web-ui)
  - [Logout (Web UI)](#logout-web-ui)
  - [REST API (API Keys)](#rest-api-api-keys)
  - [Rate Limiting](#rate-limiting-defense-in-depth)
  - [JWT Revocation](#jwt-revocation)
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
│  │ (/login) │  │               │  │             │  │
│  └──────────┘  └───────────────┘  └─────────────┘  │
│                                                    │
│  Global middleware chain:                          │
│    RequestID → ClientIPFrom* → requestLogger →     │
│    Recoverer → Compress → SecurityHeaders →        │
│    ErrorHandler → CSRF                             │
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
       │(internal/db)  │ │  ┌────────────┐ │
       │  + login_at-  │ │  │cachedClient│ │
       │  tempts audit │ │  │ (TTL cache)│ │
       └───────────────┘ └──────┬────────┘-┘
                               │
                        ┌──────▼───────┐
                        │  PowerDNS    │
                        │ Authoritative│
                        └──────────────┘

Background goroutines (started by startPeriodicJob):
  • CleanupRevokedTokens  (every 1h)
  • PurgeActivityLogs     (every 24h, 90-day retention)
  • PurgeLoginAttempts    (every 1h, 24h retention)
```

## Package Overview

```
main.go           Minimal entry point: main() calls cmd.Execute()
cmd/              CLI tree (Cobra): root namespace, `server` (bootstrap, routing, wiring, periodic jobs, graceful shutdown), `unlock`
web/              Embedded HTML templates, CSS, JS via //go:embed

internal/
  cache/          Generic TTL cache with background eviction (wraps the PowerDNS client)
  config/         YAML configuration loading with GOZONE_ env var overrides + validation
  constants/      Application constants
  database/       Multi-dialect SQL layer (SQLite/MySQL/PostgreSQL), content-hash migrations, seeding, login_attempts purge
  errors/         HTTP-aware application errors with Unwrap support
  handlers/       HTTP handlers for Web UI, REST API, and health checks
  middleware/     JWT authentication, API key auth, admin guard, user context, rate limiting, client IP resolution
  models/         Shared data structures and JSON serialization
  pdns/           PowerDNS Authoritative Server REST API client + read-through TTL cache wrapper
  validators/     DNS and input validation helpers
```

### Dependency Graph

```
cmd        ──► config, database, handlers, middleware, pdns, web
handlers   ──► middleware, models, pdns, cache, validators, errors, database
middleware ──► models, database
pdns       ──► config, models, errors, cache
database   ──► config, models
handlers   ──► web (render-only; template.FuncMap is in cmd/server.go)
```

The `pdns` package wraps `*Client` in a `cachedClient` (internal/cache) — both implement the same `ZoneService` interface, so handlers depend on the interface and never on a concrete cache implementation.

### Layer Responsibilities

| Layer | Role |
|-------|------|
| `main.go` + `cmd` | `main.go` is a thin entry point (`main()` → `cmd.Execute()`). `cmd` holds the Cobra tree: the `server` subcommand bootstraps the app (load config, open DB, create PDNS client wrapped in cachedClient, seed admin user, parse templates, register routes, start periodic purge goroutines, start HTTP server with graceful shutdown on SIGINT/SIGTERM); `unlock` is the emergency DB recovery path |
| `handlers` | Business logic for each endpoint: parse input, call `ZoneService` interface (PDNS or cached), log activity, render templates or write JSON |
| `pdns` | HTTP client for PowerDNS REST API: zone CRUD, record management (single + filtered by `rrset_name`/`rrset_type`), DNSSEC rectification, statistics; typed errors map to HTTP status codes |
| `middleware` | Request pipeline: extract JWT/API key, load user from DB, inject into context, enforce admin role, rate limiting (per-IP / per-username / per-API-key), client IP resolution (ClientIPFrom* with trusted CIDR list), security headers |
| `database` | Multi-dialect connection factory with DSN validation, content-hash migrations with multi-instance locks, context-aware query methods, login lockout columns and audit table, periodic purge helpers |
| `models` | Pure data structures — no behavior, just struct tags for JSON and SQL; RRSet has a `Comments []Comment` field round-tripped through PowerDNS PATCH |
| `config` | Hierarchical config merging: defaults → YAML file → env vars; validates CIDR lists for trusted_proxies, bcrypt cost range, port range |
| `cache` | Generic TTL cache used by `cachedClient` to reduce PowerDNS API calls; goroutine-cleaned eviction per key |
| `validators` | DNS name, record content, SOA numeric fields, and zone kind validation |
| `errors` | `AppError` with HTTP status code and `Unwrap()` support for `errors.Is/As` |
| `web` | HTML templates, CSS, JS embedded into the binary via `//go:embed` (web/embed.go); loaded with `template.ParseFS` |
| `constants` | Application-wide constants (default bcrypt cost, session cookie name, max open conns) |

## Startup Sequence

1. Parse `-config` flag (default: `config.yaml`)
2. **`config.Load(path)`** — start with `DefaultConfig()`, overlay YAML file, apply `GOZONE_*` env vars, validate (port range, bcrypt cost, CIDR list, retention/batch sizes, login lock fields)
3. **`database.New(cfg)`** — validate DSN, create directory if needed, open SQL connection (SQLite uses `SetMaxOpenConns(1)`), run content-hash migrations with `Dialect.LockMigrations`
4. **`pdns.NewClient(cfg)`** — create HTTP client pointing to PowerDNS API
5. **`pdns.NewCachedClient(client)`** — wrap with TTL cache (zones, zone info, stats, server info, TSIG keys)
6. **`seedAdminUser(ctx, db, cfg)`** — if `users` table is empty, insert admin/admin (or password from `GOZONE_ADMIN_PASSWORD`)
7. **Start periodic purge goroutines** via `startPeriodicJob(ctx, name, interval, timeout, job)`:
   - `CleanupRevokedTokens` every 1h (30s timeout)
   - `PurgeActivityLogs` every 24h (5min timeout) — skipped when `activity.retention_days = 0`
   - `PurgeLoginAttempts` every 1h (30s timeout) — skipped when `login_lock.attempts_retention_hours = 0`
   - Each job receives a context derived from the parent; the returned `stop` function cancels it on shutdown
8. **`parseTemplates()`** — load `web/templates/*.html` via `template.ParseFS` from embedded filesystem (`web/embed.go`)
9. **`handlers.New(db, pdnsClient, cfg, tmpl)`** — wire handler with all dependencies
10. **Register routes** on chi router with global middleware chain (`RequestID → ClientIPFrom* → requestLogger → Recoverer → Compress → SecurityHeaders → ErrorHandler`) plus per-group chains (CSRF, Auth, APIKey, RequireAdmin)
11. **`http.ListenAndServe(addr, r)`** with **graceful shutdown** on SIGINT/SIGTERM:
    - `srv.Shutdown(ctx)` stops accepting new connections
    - Goroutine waits on `<-shutdownDone` before returning
    - Deferred `db.Close()` and `cachedClient.Close()` run only after in-flight requests drain
12. **`runServer(cfg) error`** returns errors so cleanup always executes before `logger.Fatal` in `main`; the `server` Cobra subcommand's `RunE` loads config then calls `runServer`, and `Execute()` propagates the error to `main`

## Data Flow

### Web UI: User Views Zones

```
Browser ──GET /zones──► chi Router
                          │
                          ▼ Auth middleware
                     ┌────────────────┐
                     │ Extract cookie │
                     │ Parse JWT      │
                     │ Check revoked  │
                     │ Load user (DB) │
                     │ Store in ctx   │
                     └───────┬────────┘
                             ▼
                      ListZones handler
                      ┌─────────────────────────────┐
                      │ pdns.ZoneService.ListZones  │── HTTP ──► PowerDNS ──► [Zone...]
                      │  (cachedClient wraps *Client│               (cache miss → PDNS)
                      │   for zone list caching)    │               (cache hit  → memory)
                      │ PDNS.ListRecs               │── HTTP ──► PowerDNS ──► [RRSet...]
                      │ getLogs (DB)                │── SQL  ──► Database ──► [ActivityLog...]
                      └───────┬─────────────────────┘
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

### Login Brute-Force Protection

```
Browser ──POST /login──► chi Router
                          │
                          ▼ per-IP RateLimiter (5/min, AND-compounded)
                          ▼ per-username RateLimiter (5/min)
                          ▼ CSRF middleware
                          ▼ Auth → LoginHandler
                          │
                          ├── Lookup user by username
                          ├── if missing: dummy bcrypt compare (constant-time)
                          ├── RecordLoginAttempt (login_attempts audit row)
                          │
                          ├── if found:
                          │     ├── UserLockStatus? reject if locked (no bcrypt)
                          │     ├── bcrypt compare
                          │     ├── wrong → IncrementFailedLogins
                          │     │           → if count >= max_failed_attempts:
                          │     │               → UPDATE users SET locked_until = now+lockout
                          │     ├── correct → Generate JWT, set cookie
                          │     │               → ResetFailedLogins
                          │     │               → INSERT activity_logs (login)
                          │     │               → INSERT login_attempts (success=1)
                          │     └── redirect /dashboard
                          │
                          ▼
                  303 redirect ──► Browser (cookie + Location)
```

## Authentication Flows

GoZone supports three authentication mechanisms (all populate
`middleware.UserContextKey`):

1. **Web UI** — JWT cookie + CSRF protection on every state-changing POST + optional admin guard
2. **Single Sign-On (OIDC)** — optional; delegates login to an external OpenID
   Connect provider, then issues the same JWT cookie as local login
3. **REST API** — API key (SHA-256 hashed) with rate-limiting

### Client IP Resolution (global, before auth)

```
chi.Middleware chain on every request
  │
  ▼
ClientIPFrom* middleware (cmd/server.go:clientIPMiddleware)
  │
  ├── TrustedProxies EMPTY
  │     → ClientIPFromRemoteAddr (TCP source only, fail-closed)
  │     → attacker in direct access cannot rotate X-Forwarded-For
  │
  └── TrustedProxies configured
        → ClientIPFromXFF(<CIDRs>) (walks XFF right-to-left)
        → first IP outside any trusted CIDR wins
        → stored in request context (NOT r.RemoteAddr)
  │
  ▼
chimw.GetClientIP(ctx) returns the resolved IP string
  → used by RateLimiter (key per-IP), LoginHandler (audit), requestLogger
```

### Login (Web UI)

```
POST /login (form: username + password + CSRF token)
  │
  ▼ CSRF + per-IP RateLimiter + per-username RateLimiter (AND-compounded)
  │
LoginHandler
  │
  ├── Read client IP from chimw.GetClientIP(ctx)
  ├── SELECT user WHERE username = ? AND enabled = 1
  │
  ├── User not found:
  │   ├── bcrypt compare against DUMMY hash (constant-time)
  │   ├── INSERT login_attempts (success=0, user_id=NULL)
  │   └── redirect /login?error=invalid_credentials
  │
  ├── User found:
  │   ├── SELECT locked_until → if in the future, reject (no bcrypt work)
  │   ├── bcrypt.CompareHashAndPassword(user.PasswordHash, password)
  │   │
  │   ├── Wrong password OR locked account:
  │   │   ├── INSERT login_attempts (success=0, user_id=user.ID)
  │   │   ├── IncrementFailedLogins:
  │   │   │   ├── UPDATE users SET failed_login_attempts = failed_login_attempts + 1
  │   │   │   └── if count >= max_failed_attempts:
  │   │   │       └── UPDATE users SET locked_until = now+lockout_duration
  │   │   └── redirect /login?error=invalid_credentials  ← SAME code as user-not-found
  │   │
  │   └── Correct password:
  │       ├── GenerateToken (HS256, JWT key derived from server.secret_key via HKDF-SHA256)
  │       ├── Set-Cookie: gozone_session=<JWT>; HttpOnly; SameSite=Strict
  │       ├── ResetFailedLogins (failed_login_attempts=0, locked_until=NULL)
  │       ├── INSERT activity_logs (action='login')
  │       └── INSERT login_attempts (success=1)
  │       └── redirect /dashboard

Subsequent Web UI requests:
  │
  ▼ chi middleware chain
  │
Auth middleware (on protected routes)
  ├── Extract from cookie "gozone_session"
  ├── Fallback: Authorization: Bearer <JWT>
  ├── ParseToken → Claims{UserID, Username, Role, AuthProvider, SessionID, jti}
  ├── CheckTokenRevoked (SELECT COUNT FROM revoked_tokens WHERE jti = ?)
  ├── loadUser(DB, UserID) → ensure enabled
  ├── applySessionPolicy (when idle/absolute configured):
  │     ├── SessionTracker.Touch(sid) → idle check
  │     ├── absolute cap check (SessionID-keyed firstSeen)
  │     └── transparent refresh near expiry (new jti, revoke old, preserved sid)
  └── context.WithValue(UserContextKey, user)

CSRF middleware (gorilla/csrf):
  ├── PlaintextHTTPRequest annotation for non-HTTPS (still verified)
  ├── Cookie + form token match required on every POST
  └── Mismatch → redirect /login?error=csrf_invalid + log
```

### Logout (Web UI)

```
POST /logout (form: CSRF token)
  │
  ▼ Auth middleware
  │
LogoutHandler
  ├── Parse JWT, extract jti + user.ID
  ├── RevokeToken(jti, user.ID, expires_at) → INSERT INTO revoked_tokens
  ├── INSERT activity_logs (action='logout')
  ├── Set-Cookie: gozone_session=; Expires=epoch
  └── redirect /login

Background: CleanupRevokedTokens (every 1h)
  └── DELETE FROM revoked_tokens WHERE expires_at <= now
```

### Single Sign-On (OpenID Connect)

Optional. Enabled by `oidc.enabled` + at least one `oidc.providers[]` entry
that successfully discovers (`/.well-known/openid-configuration`). Each
discovered provider becomes a `Sign in with <provider>` button on `/login`. See
[docs/SSO.md](./SSO.md) for provider setup; the flow is identical regardless of
provider.

```
GET /auth/oidc/<provider>/login (login button)
  │
  ▼ oidc.Service.AuthCodeURL
  ├── newStateToken: HMAC-signed state carrying {provider, nonce, PKCE verifier, exp}
  ├── code_challenge = S256(verifier)
  └── 302 → provider authorization endpoint
        ?response_type=code&client_id=…&redirect_uri=…&scope=openid…
        &state=<signed>&nonce=<nonce>&code_challenge=…&code_challenge_method=S256

… user authenticates at the provider …

GET /auth/oidc/<provider>/callback?code=…&state=…
  │  (rate-limited by the shared login limiter)
  ▼ oidc.Service.HandleCallback
  ├── verifyStateToken: HMAC signature + exp + provider match (else sso_error)
  ├── oauth2.Exchange(code, code_verifier) → {access_token, id_token, …}
  ├── idToken.Verify: JWKS signature + iss/aud/exp/nonce (coreos/go-oidc)
  └── normalize claims → {sub, iss, email, email_verified, preferred_username, name, Raw}
  │
  ▼ resolveSSOUser
  ├── FindUserByExternalIdentity(iss, sub)        ← existing link (external_identities)
  ├── else email link (only if email_verified):   FindUserByEmail → link identity
  ├── else auto_provision (if enabled):           CreateExternalUser + link
  └── syncSSOAttributes (IdP-authoritative):
        ├── role (role_claim + admin_role_values, last-admin guarded)
        └── groups (group_claim + group_mapping → add zone_group memberships, additive)
  │
  ▼ issueSSOSession
  ├── GenerateSessionToken(user, JWTKey, duration, provider)  ← AuthProvider embedded for RP logout
  ├── Set-Cookie gozone_session=<JWT>; SameSite=Lax (SSO callback is cross-site)
  └── INSERT activity_logs (action='sso_login')
  └── redirect /dashboard
```

Logout (RP-initiated): when the session's JWT carries an OIDC `auth_provider`
and the provider advertises `end_session_endpoint`, `POST /logout` clears the
local session + revokes the JWT, then 302s to the IdP end-session URL with
`post_logout_redirect_uri=https://<host>/login`. Local-login sessions skip the
IdP round-trip.

Session policy (applies to local **and** SSO sessions): when
`auth.idle_timeout_minutes` / `auth.absolute_session_timeout_hours` are set, the
`SessionTracker` (in-memory, keyed by the JWT `sid`) enforces an idle window
and an absolute refresh cap, transparently re-issuing the access JWT near its
expiry up to the absolute cap.

### REST API (API Keys)

```
Request with X-API-Key: gozone_<key>  (or Authorization: Bearer gozone_<key>)
  │
  ▼ chi middleware chain (CSRF skipped on /api/v1/*)
  │
APIKeyAuth middleware
  ├── Extract from X-API-Key (preferred) or Authorization Bearer
  ├── SELECT user_id, expires_at FROM api_keys WHERE key_hash = SHA256(key)
  ├── Check expiration
  ├── loadUser(DB, UserID) → ensure enabled
  ├── UPDATE api_keys SET last_used_at = NOW()
  ├── RateLimiter per API key (100/min)
  └── context.WithValue(UserContextKey, user)
```

### Rate Limiting (defense-in-depth)

The login endpoint gets three layers of protection — all three must allow:

| Layer | Backend | Limit | Scope |
|-------|---------|-------|-------|
| Per-IP | In-memory token bucket | 5/min | Resolved client IP (`chimw.GetClientIP(ctx)`) |
| Per-username | In-memory token bucket | 5/min (configurable) | Lowercased attempted username |
| Per-account | Persistent DB (`users.locked_until`) | After N failed attempts | Account ID |

The two in-memory limiters are AND-compounded on the route (`login_chain = append(login_chain, loginUsernameLimiter)`) so an attacker cannot bypass one by rotating the other dimension. The persistent DB lockout survives server restarts and applies across cluster instances.

### JWT Revocation

- `LogoutHandler` writes the JWT ID (`jti`) to `revoked_tokens`.
- `Auth` middleware checks `revoked_tokens` on every authenticated request.
- `CleanupRevokedTokens` (every 1h) deletes expired entries.
- The default `auth.session_duration_hours` (24h) bounds the worst case: a leaked token can only be replayed until it expires, even without logout.

## Database Schema

GoZone uses a configured SQL database (SQLite by default, MySQL and PostgreSQL supported) with the following tables. Schema is created and migrated by the dialect-specific migrations slice via content-hash versioning.

```
users
├── id                    INTEGER PK AUTOINCREMENT (SQLite) / SERIAL (Postgres) / AUTO_INCREMENT (MySQL)
├── username              TEXT/ VARCHAR UNIQUE NOT NULL
├── email                 TEXT/ VARCHAR UNIQUE NOT NULL
├── password_hash         TEXT/ VARCHAR NOT NULL                ← bcrypt hash, json:"-"
├── first_name            TEXT/ VARCHAR DEFAULT ''
├── last_name             TEXT/ VARCHAR DEFAULT ''
├── role                  TEXT/ VARCHAR DEFAULT 'user'          ← 'admin' or 'user'
├── enabled               INTEGER/ BOOLEAN DEFAULT 1
├── failed_login_attempts INTEGER DEFAULT 0                    ← auto-lockout threshold counter
├── locked_until          DATETIME/ TIMESTAMP                   ← NULL = not locked; non-NULL = locked until
├── created_at            DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP
└── updated_at            DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

activity_logs
├── id          INTEGER PK / SERIAL / AUTO_INCREMENT
├── user_id     INTEGER FK → users(id) ON DELETE SET NULL
├── zone_id     TEXT/ VARCHAR                                     ← PowerDNS zone ID (NULL for non-zone events)
├── action      TEXT/ VARCHAR NOT NULL                            ← login, logout, create_zone, update_record,
│                                                                   delete_record, create_user, update_user,
│                                                                   delete_user, lock_user, unlock_user, import_zone, etc.
├── details     TEXT/ VARCHAR DEFAULT ''
├── old_value   TEXT/ VARCHAR DEFAULT ''                           ← JSON snapshot before mutation
├── new_value   TEXT/ VARCHAR DEFAULT ''                           ← JSON snapshot after mutation
└── created_at  DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

api_keys
├── id           INTEGER PK / SERIAL / AUTO_INCREMENT
├── user_id      INTEGER FK → users(id) ON DELETE CASCADE
├── key_hash     TEXT/ VARCHAR UNIQUE NOT NULL                    ← SHA-256(raw_key), json:"-"
├── description  TEXT/ VARCHAR DEFAULT ''
├── last_used_at DATETIME/ TIMESTAMP
├── created_at   DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP
└── expires_at   DATETIME/ TIMESTAMP

settings
├── id    INTEGER PK / SERIAL / AUTO_INCREMENT
├── key   TEXT/ VARCHAR UNIQUE NOT NULL
└── value TEXT/ VARCHAR DEFAULT ''

revoked_tokens                                        ← JWT denylist for logout
├── jti         TEXT/ VARCHAR PRIMARY KEY                       ← JWT ID claim
├── user_id     INTEGER NOT NULL
├── expires_at  DATETIME/ TIMESTAMP NOT NULL
└── revoked_at  DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

login_attempts                                        ← login brute-force audit
├── id           INTEGER PK / SERIAL / AUTO_INCREMENT
├── username     TEXT/ VARCHAR NOT NULL                         ← attempted username (may not exist as a user)
├── user_id      INTEGER FK → users(id) ON DELETE SET NULL      ← NULL when username doesn't exist
├── ip_address   TEXT/ VARCHAR NOT NULL DEFAULT ''              ← client IP from ClientIPFrom* middleware
├── success      INTEGER/ SMALLINT NOT NULL DEFAULT 0           ← 1 = successful login
└── attempted_at DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

zone_groups                                           ← authorization grouping
├── id          INTEGER PK / SERIAL / AUTO_INCREMENT
├── name        TEXT/ VARCHAR UNIQUE NOT NULL
├── description TEXT/ VARCHAR DEFAULT ''
└── created_at  DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

zone_group_members
├── group_id  INTEGER NOT NULL FK → zone_groups(id) ON DELETE CASCADE
├── user_id   INTEGER NOT NULL FK → users(id)       ON DELETE CASCADE
└── PRIMARY KEY (group_id, user_id)

zone_group_zones
├── group_id  INTEGER NOT NULL FK → zone_groups(id) ON DELETE CASCADE
├── zone_id   TEXT/ VARCHAR NOT NULL                       ← PowerDNS zone ID
└── PRIMARY KEY (group_id, zone_id)

zone_templates                                          ← reusable DNS record sets
├── id          INTEGER PK / SERIAL / AUTO_INCREMENT
├── name        TEXT/ VARCHAR UNIQUE NOT NULL
├── description TEXT/ VARCHAR DEFAULT ''
├── is_builtin  INTEGER/ SMALLINT NOT NULL DEFAULT 0          ← 1 = seeded by GoZone, cannot be deleted
├── created_at  DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP
└── updated_at  DATETIME/ TIMESTAMP DEFAULT CURRENT_TIMESTAMP

zone_template_records
├── id           INTEGER PK / SERIAL / AUTO_INCREMENT
├── template_id  INTEGER NOT NULL FK → zone_templates(id) ON DELETE CASCADE
├── name         TEXT/ VARCHAR NOT NULL
├── type         TEXT/ VARCHAR NOT NULL
├── content      TEXT/ VARCHAR NOT NULL
├── ttl          INTEGER NOT NULL DEFAULT 3600
├── priority     INTEGER NOT NULL DEFAULT 0
└── disabled     INTEGER/ SMALLINT NOT NULL DEFAULT 0
```

**Indexes**:
- `activity_logs(user_id)`, `activity_logs(zone_id)`, `activity_logs(zone_id, created_at DESC)`, `activity_logs(created_at)`
- `api_keys(key_hash)`
- `revoked_tokens(expires_at)`
- `login_attempts(username, attempted_at)`, `login_attempts(ip_address, attempted_at)`, `login_attempts(user_id, attempted_at)`, `login_attempts(attempted_at)`
- `zone_group_members(user_id)`
- `zone_group_zones(group_id)`, `zone_group_zones(zone_id)`

**PowerDNS data** (zones, records, statistics) is not stored locally — it is fetched live from the PowerDNS REST API and passed through as-is. GoZone is a stateless proxy for PowerDNS data. A local TTL cache (`internal/cache`) wraps the PDNS client to reduce repeated API calls and is invalidated on record mutations.

## Design Decisions

### Multi-Database Support

GoZone supports SQLite (default for single-node deployments), MySQL, and PostgreSQL. The `database.Dialect` interface abstracts driver-specific behavior: DSN parsing, parameter rebinding (e.g., `?` → `$n` for PostgreSQL), migration locking (`GET_LOCK` for MySQL, `pg_advisory_lock` for PostgreSQL, no-op for SQLite), and dialect-aware `INSERT IGNORE` semantics (`INSERT OR IGNORE` SQLite, `INSERT IGNORE` MySQL, `ON CONFLICT DO NOTHING` PostgreSQL — exposed via `Dialect.InsertIgnore(table, columns, conflictColumns)`). The Postgres dialect requires `conflictColumns` to match an existing UNIQUE constraint or PRIMARY KEY on the target table (the older single-argument signature reused `columns` as the conflict target, masking the invariant and leaving it easy to fall back to the wrong index when columns ≠ unique constraint). SQLite and MySQL ignore `conflictColumns` because `INSERT OR IGNORE` / `INSERT IGNORE` catch any unique violation regardless of column. Migrations are identified by a truncated SHA-256 hash of their SQL content, making reordering safe, and are protected by a dialect-specific lock for multi-instance deployments.

### No ORM

All SQL queries are hand-written and inlined in handler/database methods. This avoids ORM complexity, makes queries auditable, and keeps the dependency tree small. The trade-off is more boilerplate and no compile-time query validation.

### Single Handler Struct

All HTTP handlers are methods on a single `Handler` struct holding shared dependencies (`DB`, `PDNS` — typed as the `pdns.ZoneService` interface, `Cfg`, `Tmpl`). This avoids passing dependencies through middleware or global state. The struct is created once at startup and shared across all routes.

### html/template (Embedded with //go:embed)

Templates are embedded in the binary at compile time via `//go:embed` (in `web/embed.go`) and loaded via `template.ParseFS`. This simplifies deployment to a single binary with no external template files required. The template FuncMap (registered in `cmd/server.go`) includes `add`, `sub`, `urlquery`, `relativeName`, and `dict`.

### JWT for Web Sessions

The web UI uses JWT cookies (HttpOnly, SameSite=Strict) rather than server-side sessions. This keeps the server stateless — no session store needed. The JWT contains the user ID, username, role, and a unique `jti` (random UUID) so it can be revoked on logout. The signing key is derived from `server.secret_key` via HKDF-SHA256, isolated from the CSRF sub-key. Revoked tokens are stored in the `revoked_tokens` table and pruned by `CleanupRevokedTokens` (every 1h).

### CSRF Protection

Every state-changing POST in the Web UI requires a gorilla/csrf token. The CSRF cookie is set on the first GET, the form embeds a hidden input, and the middleware compares them. Plaintext HTTP requests are annotated (`PlaintextHTTPRequest`) so the cookie can still be issued, but the comparison remains strict. Invalid tokens redirect to `/login?error=csrf_invalid` and log a warning.

### PowerDNS as Source of Truth

GoZone never stores DNS zones/records locally. All zone data is fetched live from the PowerDNS API. A `cachedClient` (defined in `internal/pdns/cached.go`, wrapping `*Client` via the `ZoneService` interface) provides a read-through TTL cache for frequently-read endpoints (zones, zone info, statistics, server info, TSIG keys) and is invalidated on record mutations. If PowerDNS is unreachable, the web UI shows errors. The health check endpoint (`/health/ready`) verifies this connectivity directly, bypassing the cache.

### Activity Logging

All user actions (login, lock/unlock, zone creation, record updates, API key creation) are logged to the `activity_logs` table in the configured database with structured `old_value`/`new_value` JSON snapshots for record mutations. This provides a full audit trail without external infrastructure. The dashboard /activity page exposes search, filters (action, date range, free text on `details`), pagination, and a non-admin visibility scope (`activityLogVisibilityClause`) so users only see their own logs. The periodic `PurgeActivityLogs` job (every 24h, 5min timeout) deletes entries older than `activity.retention_days` in batches of `activity.batch_size` to avoid long-running DELETE statements. Setting `retention_days=0` keeps logs forever and disables the job.

### RRSet Comments (PowerDNS `comments` field)

Every RRSet can carry PowerDNS-style comments (`models.Comment`) attached as metadata. GoZone exposes this through the web UI (zone view, dedicated edit page, inline editor), the CSV export/import (with a trailing `comment` column), and the REST API.

#### CommentPatch wire format

The `comments` field on PowerDNS's PATCH API is tri-state:

| Wire form | Meaning |
|-----------|---------|
| absent | preserve existing comments |
| `"comments":[]` | purge all comments |
| `"comments":[...]` | replace with these items |

Standard `encoding/json` cannot distinguish a nil slice from an empty slice under `omitempty`, which is why the field is wrapped in a custom `models.CommentPatch` type:

```go
type CommentPatch struct {
    Items []Comment
    Clear bool
}
```

`MarshalJSON` emits the right wire form based on `Clear` and the contents of `Items`; `UnmarshalJSON` normalises both `null` and `[]` to a nil `Items` slice and never sets `Clear`. This keeps the read-then-write round trip safe: a PDNS GET returns `comments:[]` for an RRSet with no comments, and a naive round trip must preserve them, not purge them.

The only way to obtain a clear patch is to set `Clear=true` on the struct directly. The handlers in `internal/handlers/records.go` build the patch via two helpers:

- `buildCommentPatch(text, clear)` — for single-record forms (`CreateRecord`, `UpdateRecord`, `InlineUpdateRecord`); reads the `comment` and `comment_clear` form fields.
- `buildCommentsPatch(existing, clear, newLines...)` — for batch create; merges user-provided lines with any existing comments read from PDNS, with deduplication against both the preserved list and earlier new lines.

#### Web UI clearing flow

The Edit Record page (`web/templates/record_edit.html`) and the inline editor on `zone_view.html` expose a `comment_clear=1` checkbox next to the textarea. When checked, GoZone sends `"comments":[]` to PowerDNS, which deletes every comment on that RRSet. When unchecked, the existing comments are preserved unless the textarea content changes (replace semantics). The CSV import path never sets `Clear`; an empty `comment` cell means "no comments for this RRSet", consistent with the preserve semantic.

#### API clearing flow

The PUT `/api/v1/zones/{zone_id}/records` endpoint accepts an additional GoZone-only boolean `clear_comments` (write-only, never returned by GET). The body shape is the RRSet as documented plus this single sentinel field; embedding is done via an unexported `apiRRSetUpdateRequest` wrapper so the RRSet fields stay flat on the wire:

```go
type apiRRSetUpdateRequest struct {
    models.RRSet
    ClearComments *bool `json:"clear_comments,omitempty"`
}
```

Behaviour:

- `clear_comments` absent or `false` → no purge, normal pass-through (Comments pointer is nil or holds Items). Sends preserve or replace semantics.
- `clear_comments: true` → handler sets `Comments = &CommentPatch{Clear: true}` and the `ClearComments` sentinel is **not** forwarded to PowerDNS (only the resulting `"comments":[]` reaches the upstream API). Any `comments` array supplied in the same body is discarded (the clear wins, mirroring the web form's `comment_clear` checkbox vs. textarea). This exclusivity is the only sane interpretation of an explicit purge marker; "clear then add" would require server-side fetch of the existing list and is out of scope.

The `*bool` (not `bool`) is what makes the absent-vs-false distinction possible. A plain `bool` could not tell "client didn't say" from "client said no" and would silently flip to "preserve" whenever the field was missing from the body — defeating the point of an explicit sentinel.

`CommentPatch.UnmarshalJSON` is intentionally unchanged: it still never sets `Clear`. This keeps the round-trip safety contract (PDNS GET returns `comments:[]` → naive PUT must preserve, not purge) intact for clients that don't use the new sentinel.

#### Comment patch semantics per code path

The `comments` field is treated differently depending on how the request reaches GoZone:

| Path | Helper used | Behaviour |
|------|-------------|-----------|
| Web form (`CreateRecord`, `UpdateRecord`, `InlineUpdateRecord`) | `buildCommentPatch(text, clear)` | Reads `comment` + `comment_clear` form fields; emits `nil` (preserve), `Items` patch (replace) or `Clear` patch (purge). |
| Web batch (`BatchCreateRecords`) | `buildCommentsPatch(existing, clear, newLines...)` | Fetches existing comments from PDNS, merges with new lines, **deduplicates** against both the preserved list and earlier new lines so replaying the same batch never grows the list. |
| CSV import (`parseCSVZone`) | direct `*CommentPatch` builder | Splits multi-line cells, dedupes via `appendIfMissing` per RRSet. |
| REST API create (`APICreateRecord`) | none — pass-through | The `comments` array is forwarded to PDNS **exactly as the client sent it** (no implicit dedup, no padding, no clearing). |
| REST API update (`APIUpdateRecord`) | optional `clear_comments` sentinel → `&CommentPatch{Clear: true}` | Same pass-through for the array, plus the `clear_comments:true` marker adds an explicit purge path. Sentinel is stripped before forwarding to PDNS. |

This split exists because the web UI drives a *merge* workflow (existing + user input → REPLACE) while the REST API exposes a *REPLACE* workflow (full new list → REPLACE). Documented in `API.md` (Records → comments array note + Clearing comments via the API block).

### Brute-Force Protection (defense-in-depth on /login)

The login endpoint is protected by three layers, all of which must allow:
1. **Per-IP rate limiter** — 5/min, in-memory token bucket keyed on the resolved client IP (fail-closed against XFF spoofing via chi's `ClientIPFrom*`)
2. **Per-username rate limiter** — 5/min, in-memory token bucket keyed on the lowercased attempted username
3. **Persistent per-account lockout** — `users.failed_login_attempts` and `users.locked_until` columns; locked accounts are rejected before any bcrypt work (no timing side channel)

Failed attempts (whether the username exists or not) are recorded in `login_attempts` for forensics and purged hourly. Admin can manually lock/unlock any user from `/users` — see LockUser/UnlockUser handlers and the `lock_user`/`unlock_user` activity log actions.

### Account-Enumeration Defence (identical error responses)

All three failure paths — unknown user, wrong password, locked account — return the **same** redirect target (`/login?error=invalid_credentials`) and the same generic banner ("Invalid username or password."). The mapping is centralised in `loginErrorMessages` so the raw query code cannot leak into the rendered template. An attacker who triggers a lockout by spraying wrong passwords at a guessed username observes no different signal than when guessing an unknown username — the constant-time dummy bcrypt compare (`internal/handlers/auth.go`) covers the timing channel.

### Client IP Spoofing Resistance

The deprecated `chimw.RealIP` middleware (vulnerable to XFF spoofing under direct internet exposure) is replaced by chi's non-mutating `ClientIPFrom*` variants. The resolved IP is stored in the request context (not in `r.RemoteAddr`) and read via `chimw.GetClientIP(ctx)`. When `server.trusted_proxies` is configured with a list of CIDR ranges, the middleware switches to `ClientIPFromXFF` and walks XFF right-to-left until the first IP that falls outside any trusted range. Leaving `trusted_proxies` empty is the recommended default for direct-internet exposure — an attacker in direct access cannot forge `X-Forwarded-For` to obtain a fresh rate-limit bucket.

### Input Validation

DNS record names, record content, SOA numeric fields, and zone kinds are validated in `internal/validators` before being sent to PowerDNS. This prevents invalid data from reaching the backend and provides meaningful error messages to users and API clients.

### Periodic Job Orchestration

Background purges (revoked JWTs, old activity logs, old login attempts) all share the `startPeriodicJob(ctx, name, interval, timeout, job)` helper in `cmd/server.go`. Each job runs once at startup, then on the configured interval, with a per-invocation timeout context. The returned `stop` function cancels the goroutine and is called via `defer` on shutdown so jobs do not outlive the process.

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

- JWT tokens are HMAC-SHA256 with a key derived from `server.secret_key` via HKDF-SHA256. There is no key rotation mechanism — changing the secret invalidates all existing sessions.
- API keys are SHA-256 hashed before comparison against the stored `key_hash`. The raw key is only shown once at creation time.
- The default admin password (`admin`/`admin`) is logged in the startup banner when the seed matches `config.DefaultAdminPassword`. There is no force-change on first login — set `GOZONE_ADMIN_PASSWORD` (or `admin.password` in YAML) at startup.
- No password policy (length, complexity). `CreateUser` / `UpdateUser` accept any non-empty password.

### Web UI

- CSRF protection is implemented via gorilla/csrf middleware on all state-changing POST endpoints. Invalid CSRF tokens result in a redirect to `/login?error=csrf_invalid` and a warning log.
- Cookies lack the `Secure` flag by default (set dynamically based on request). Enable TLS and use HTTPS in production. The CSRF cookie's `Secure` flag is configured once at startup via `server.secure_cookies` (`GOZONE_SECURE_COOKIES`).
- Templates are embedded at compile time via `//go:embed` and loaded with `template.ParseFS`, making deployment a single binary with no external template files required. A rebuild is required to change any template.
- All frontend event handlers are delegated via `data-action` (CSP `script-src 'self'` only — no `'unsafe-inline'`).

### Deployment

- **CGO required for SQLite**: The `mattn/go-sqlite3` driver requires a C compiler. Cross-compilation from macOS to Linux requires `CGO_ENABLED=1` and a cross-compilation toolchain. MySQL and PostgreSQL builds can use `CGO_ENABLED=0`.
- **CI/CD**: A GitHub Actions workflow (`.github/workflows/release.yml`) builds and publishes multi-architecture Docker images to GHCR on tag pushes matching `v*`.
- **Single process**: SQLite deployments cannot scale horizontally. MySQL/PostgreSQL deployments can be scaled behind a load balancer — all in-flight state is held in either PowerDNS or the database, not in the application process.
- **Helm chart**: A community-maintained Helm chart is available at [`babykart/helm-charts`](https://github.com/babykart/helm-charts) for Kubernetes deployments (`helm repo add babykart https://babykart.github.io/helm-charts && helm install gozone babykart/gozone`).
