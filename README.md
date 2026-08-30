# GoZone - PowerDNS Admin Interface in Go

[![License](https://img.shields.io/badge/License-MIT-blue)](https://opensource.org/licenses/MIT)

A clean web interface for managing PowerDNS authoritative DNS servers.

## Features

- **Zone Management**: List, create, edit, and delete DNS zones with pagination, search, and per-page controls
- **Record Management**: Full CRUD for all DNS record types (A, AAAA, CNAME, MX, TXT, SOA, etc.) with color-coded type badges and inline editing
- **RRSet Comments**: View, add, and edit PowerDNS comments per RRSet through the web UI, CSV import/export, and REST API
- **Brute-force Protection**: Per-IP and per-username login rate-limiters (compound AND), persistent per-account lockout after repeated failures, audit trail of every attempt, identical generic error response across unknown user / wrong password / locked account to block account enumeration
- **Single Sign-On (OIDC)**: Delegate login to OpenID Connect providers (Gitea, Google, GitLab, Keycloak, Authentik, Azure AD) with PKCE, JWKS ID-token verification, just-in-time provisioning, role/group mapping from claims, and RP-initiated logout
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
| `server.shutdown_timeout_seconds` | `GOZONE_SHUTDOWN_TIMEOUT` | `30` |
| `server.trusted_proxies` | `GOZONE_TRUSTED_PROXIES` | *empty* (TCP source IP only) | Comma-separated CIDR ranges whose X-Forwarded-For headers are trusted. Use `/32` for a single IPv4 host, `/128` for IPv6. Plain IPs without a prefix are rejected at startup. |
| `server.external_url` | `GOZONE_EXTERNAL_URL` | *empty* | Canonical base URL GoZone is served at (e.g. `https://dns.example.com`). When set, OIDC `redirect_uri` and `post_logout_redirect_uri` values are built from it instead of being derived from the client-controlled `Host` header (defense-in-depth; the IdP already validates both against its registered lists). Must be an absolute `http(s)` URL with a host and no path; validated and normalised to `scheme://host` at startup. When empty, both URLs are derived per-request from the resolved scheme and `Host` header. |

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
| `auth.max_api_keys_per_user` | `GOZONE_MAX_API_KEYS` | `10` |
| `auth.idle_timeout_minutes` | `GOZONE_IDLE_TIMEOUT_MINUTES` | `0` (disabled) |
| `auth.absolute_session_timeout_hours` | `GOZONE_ABSOLUTE_SESSION_TIMEOUT_HOURS` | `0` (disabled) |

`idle_timeout_minutes` forces re-authentication after that many minutes of inactivity (even if the JWT has not expired). `absolute_session_timeout_hours` caps the total session lifetime across transparent refreshes: while a session stays active and below the cap, the access JWT is silently refreshed near its expiry (the session "slides" up to the cap). For refresh to trigger it must be greater than `session_duration_hours`. Both apply to local **and** SSO sessions and are enforced cluster-wide via the `sessions` table (an in-memory cache coarsens writes, so cross-instance idle lags by at most ~1 minute). Leave both `0` for the classic behaviour: a session lives exactly `session_duration_hours`.

### Single Sign-On (OpenID Connect / OAuth2)

GoZone can delegate login to one or more external identity providers using
OpenID Connect (OIDC) — Authorization Code flow with PKCE (S256), a signed
`state` parameter (CSRF), a `nonce`, JWKS ID-token verification, just-in-time
user provisioning, role/group mapping from claims, and RP-initiated logout.
Built-in provider presets: **Gitea**, Google, GitLab, Keycloak, Authentik,
Azure AD (any other name is treated as a generic OIDC provider).

| YAML Path | Environment Variable | Default |
|-----------|---------------------|---------|
| `oidc.enabled` | `GOZONE_OIDC_ENABLED` | `false` |
| `oidc.allow_local_login` | `GOZONE_OIDC_ALLOW_LOCAL_LOGIN` | `true` |
| `oidc.auto_provision` | `GOZONE_OIDC_AUTO_PROVISION` | `false` |
| `oidc.require_verified_email` | `GOZONE_OIDC_REQUIRE_VERIFIED_EMAIL` | `true` |
| `oidc.default_role` | `GOZONE_OIDC_DEFAULT_ROLE` | `user` |
| `oidc.scopes` | `GOZONE_OIDC_SCOPES` | `[openid, profile, email]` |
| `oidc.role_claim` | `GOZONE_OIDC_ROLE_CLAIM` | *(none)* |
| `oidc.admin_role_values` | `GOZONE_OIDC_ADMIN_ROLE_VALUES` | `[]` |
| `oidc.group_claim` | `GOZONE_OIDC_GROUP_CLAIM` | *(none)* |
| `oidc.group_mapping` | *(YAML only)* | `{}` |
| `oidc.jwks_cache_ttl_minutes` | `GOZONE_OIDC_JWKS_CACHE_TTL_MINUTES` | `60` |

Each entry in `oidc.providers[]` needs `name`, `issuer_url`, `client_id`, and
`client_secret` (plus optional `display_name` and `scopes`). The redirect URI
to register at the provider is always
`https://<your-gozone-host>/auth/oidc/<name>/callback`.

Minimal example (Gitea):

```yaml
oidc:
  enabled: true
  auto_provision: true
  providers:
    - name: gitea
      issuer_url: "https://gitea.example.com"
      client_id: "gozone"
      client_secret: "<secret>"
```

A single provider can also be declared entirely from environment variables
(`GOZONE_OIDC_PROVIDER_NAME` / `_ISSUER_URL` / `_CLIENT_ID` / `_CLIENT_SECRET`).

> GoZone is an OIDC client and requires an `id_token`. Providers that only do
> OAuth2 without an id_token (e.g. GitHub user OAuth) cannot be used directly —
> front them with an OIDC-capable IdP (Dex/Keycloak/Authentik).

**Full setup instructions and per-provider examples (Gitea, Google, GitLab,
Keycloak, Authentik, Azure AD), role/group mapping, RP-initiated logout, and a
troubleshooting table live in [docs/SSO.md](./docs/SSO.md).**

### Password policy

A password complexity policy is enforced whenever a password is set or changed: user creation, the admin user-edit form, and `gozone user reset-password`. The initial admin seed is exempt (one-time bootstrap). Defaults are secure-by-default; relax them here or via the `GOZONE_PASSWORD_*` env vars.

| YAML Path | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| `password.min_length` | `GOZONE_PASSWORD_MIN_LENGTH` | `8` | Minimum length in runes. `0` disables the length check. |
| `password.max_length` | `GOZONE_PASSWORD_MAX_LENGTH` | `72` | Maximum length in **bytes** (bcrypt's hard limit). `0` disables the check; values above 72 are rejected at startup. |
| `password.require_uppercase` | `GOZONE_PASSWORD_REQUIRE_UPPERCASE` | `true` | Require at least one uppercase letter. |
| `password.require_lowercase` | `GOZONE_PASSWORD_REQUIRE_LOWERCASE` | `true` | Require at least one lowercase letter. |
| `password.require_digit` | `GOZONE_PASSWORD_REQUIRE_DIGIT` | `true` | Require at least one digit. |
| `password.require_special` | `GOZONE_PASSWORD_REQUIRE_SPECIAL` | `true` | Require at least one non-letter/non-digit character (punctuation, symbol, space). |
| `password.history_size` | `GOZONE_PASSWORD_HISTORY_SIZE` | `0` | Number of previous hashes retained per user to prevent reuse (the current password always counts as used). `0` disables history. |
| `password.max_age_days` | `GOZONE_PASSWORD_MAX_AGE_DAYS` | `0` | Maximum password age in days. `0` (default) means passwords never expire. When a password is older than this, the user is forced to change it on next login. |
| `password.expiry_warn_days` | `GOZONE_PASSWORD_EXPIRY_WARN_DAYS` | `0` | Show a dashboard "password expiring soon" warning this many days before expiry. `0` disables the warning. Only meaningful when `max_age_days > 0`. |

An admin/operator password reset (`UpdateUser`, `gozone user reset-password`) and admin user creation both flag the account `must_change_password`: on the next login the user is redirected to **Change Password** and the session is restricted to that page (plus `/logout`) until a new password is chosen. The same forced-change flow triggers when a password expires.

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

#### Recovering a locked admin

When the only admin account is locked (brute-force storm, manual lock, lost credentials, etc.) the Web UI is no longer reachable: the `Unlock` button on `/admin/users` requires another non-locked admin to act. The emergency recovery path is the `gozone user unlock` CLI subcommand, which opens the configured database directly and clears the lockout without going through the HTTP flow.

```bash
# Unlock by username (case-insensitive lookup; default config.yaml).
gozone user unlock admin

# Unlock by numeric user ID — handy when the username is unknown.
gozone user unlock 1

# Custom config path (e.g. when running outside the install directory).
gozone user unlock admin --config /etc/gozone/config.yaml
```

In containerised deployments, exec into the running container first:

```bash
# Docker Compose (service name: gozone, see docker-compose.yml).
docker compose exec gozone gozone user unlock admin

# Kubernetes (adjust the deployment name and namespace).
kubectl exec -n gozone deploy/gozone -- gozone user unlock admin
```

The action is **idempotent**: unlocking an already-unlocked user is a no-op on the database side but still writes an `unlock_user_cli` entry in the `activity_logs` table, so the audit trail always records the operator's intervention. Verify the unlock took effect by inspecting the user row:

```bash
# SQLite (default; adjust the path to match database.path in config.yaml)
sqlite3 /var/lib/gozone/gozone.db \
  "SELECT id, username, role, enabled, failed_login_attempts, locked_until FROM users WHERE id = 1;"

# PostgreSQL
psql -U gozone -d gozone \
  -c "SELECT id, username, role, enabled, failed_login_attempts, locked_until FROM users WHERE id = 1;"

# Recent unlock events from the audit trail
sqlite3 /var/lib/gozone/gozone.db \
  "SELECT id, user_id, action, created_at, substr(details, 1, 60) FROM activity_logs WHERE action LIKE 'unlock_user%' ORDER BY id DESC LIMIT 10;"
```

Common failure modes:

| Error | Cause | Fix |
|-------|-------|-----|
| `accepts 1 arg(s), received 0` | Target user argument omitted | Pass the id or username, e.g. `gozone user unlock admin`. |
| `user "ghost" not found` | Username typo or deleted account | Resolve the ID first with a `SELECT id, username FROM users` query. |
| `open database: ...` | Binary cannot reach the configured DB | Check `--config` points at the right file and the process has read/write access to the data directory. |

#### Resetting a forgotten password

The `gozone user reset-password` CLI subcommand sets a new bcrypt password hash directly in the database, bypassing the HTTP flow. It is the supported counterpart to `gozone user unlock` for the "admin password lost" case.

```bash
# Interactive prompt (no echo, with confirmation) — recommended.
gozone user reset-password admin

# Non-interactive: read the password from stdin (e.g. piped from a secret store).
gozone user reset-password admin < /run/secrets/gozone-admin-password

# Non-interactive flag (convenient but the value is visible in the process
# list and shell history; prefer the prompt or stdin).
gozone user reset-password admin --password 's3cret!'
```

Like `unlock`, the reset writes a `reset_password_cli` entry to `activity_logs` with `user_id = NULL` (the actor is the shell operator, identified as `user@host`) so the audit trail records every intervention.

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
| `logging.level` | `GOZONE_LOG_LEVEL` | `info` |

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

### High Availability / Multi-Instance Deployments

GoZone is stateless from the application's point of view: every piece of **durable** auth/security state lives in the shared database, so several instances can run behind a load balancer out of the box. A few protections are **per-node** (in-process), and this section documents which is which so operators can size their deployment and their expectations.

**Cluster-wide (shared via the database)** — identical on every instance, enforced consistently regardless of which instance handles a request:

- Users, roles, enable/disable and lock state; the persistent brute-force lockout (`locked_until`, `failed_login_attempts`) and manual admin locks (`manual_lock_until`).
- **Login rate limiting** — the per-IP (`5/min`) and per-username (`login_lock.username_rate_limit_per_minute`) limits on `/login` and the OIDC login/callback endpoints are enforced through the shared `rate_limit_counters` table: every replica draws from the same per-minute budget, so the ceiling does not scale with the instance count. The in-process limiter still runs in front as a cheap flood gate; the database counter is the authoritative budget. Window boundaries derive from each instance's clock, so small clock skew between replicas can shift a boundary slightly (the budget itself stays shared).
- Password policy, password history and password expiry.
- Session idle/absolute lifetime (the `sessions` table) and JWT revocation (`tokens_valid_after`, plus the per-`jti` `revoked_tokens` table).
- API keys, activity/login-attempt audit, and OIDC account linking (`external_identities`).

**Per-node (in-memory, NOT shared across instances):**

- **Anti-flood throttles** — API per-IP (`300/min`), API per-key (`100/min`) and readiness-probe (`120/min`) rate limiting. The effective ceiling scales with the instance count: with *N* instances a single client can sustain up to roughly *N×* the configured rate (one fresh bucket per instance). These are flood throttles rather than security budgets, and the readiness limiter in particular must not depend on the database it probes; login limiting (above) and account lockout cap the security-relevant traffic regardless of instance count.
- **OIDC `state` single-use store** — the anti-replay check for the SSO redirect is in-process. A captured `state` replayed at a *different* instance than the one that issued it could succeed within its 10-minute TTL. The existing mitigations (OAuth2 authorization-code single-use at the IdP, PKCE, and the `nonce` bound into the id_token) keep the practical risk negligible.
- **Session-tracker cache** — an in-memory cache coarsens idle/absolute writes, so cross-instance inactivity detection lags by at most ~1 minute; it always falls back to the shared `sessions` table, so the limit itself is still cluster-wide.

**Mitigations for stricter per-client guarantees:** enable session affinity ("sticky sessions") at the load balancer — hashing on the `gozone_session` cookie routes a given client to one instance, restoring single-node accounting for the per-node anti-flood throttles and pinning the OIDC `state` check to the issuing instance. This reduces horizontal spreading for that traffic, so weigh it against your load-balancing goals.

**Required for any multi-instance setup:**

- A **shared database** (PostgreSQL or MySQL). A per-node SQLite file is *not* shared and must not be used across instances.
- The **same `server.secret_key` on every instance.** The JWT, CSRF and OIDC keys are HKDF-derived from it; mismatched keys mean a session cookie minted by one instance is rejected by the others (and CSRF/OIDC flows break). See [Secret Key](#secret-key).

## Web UI

### Dashboard

Shows PowerDNS server status (connected/unreachable, version, daemon type), zone and user counts, query statistics, and recent activity logs.

### Zone View

Each zone page displays:
- **Records table** with color-coded type badges (A=blue, AAAA=violet, CNAME=orange, MX=pink, NS=cyan, etc.) and pagination by individual record rows (not RRSets), so the per-page limit always matches the number of visible table rows
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

PowerDNS is the source of truth for the zone list, so a zone deleted or renamed directly in PowerDNS leaves its group assignments orphaned. GoZone garbage-collects those grant rows automatically: hourly in the background, and immediately when an admin opens a group's edit page. The reconciliation is skipped whenever the PowerDNS zone list cannot be fetched — an unreachable PowerDNS is never interpreted as "all zones gone".

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

GoZone exposes a REST API under `/api/v1` for automation (zone and record CRUD, statistics, health). The complete endpoint reference — authentication, rate limiting, error envelope, every zone/record operation with payload schemas and curl examples — lives in [API.md](./docs/API.md).

## Commands

| Make | Just | Description |
|------|------|-------------|
| `make build` | `just build` | Build the binary |
| `make run` | `just run` | Build and run locally |
| `make test` | `just test` | Run tests (bypassing the result cache) |
| `make test-verbose` | `just test-verbose` | Run tests with verbose output |
| `make test-race` | `just test-race` | Run tests with the race detector (same flags as CI) |
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
./bin/gozone server --config config.yaml
```

## License

MIT — see LICENSE file.
