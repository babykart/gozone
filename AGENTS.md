# GoZone — Agents Instructions

## Language & Framework

- Go 1.26, chi v5 router, `html/template` server-side rendering
- Multi-dialect SQL layer: SQLite (mattn/go-sqlite3), MySQL (go-sql-driver/mysql), PostgreSQL (lib/pq)
- JWT (golang-jwt/jwt v5) + bcrypt for auth
- **Vendor mode**: dependencies are vendored (`vendor/`); `just update` runs `go mod vendor`. Never `go get` without re-vendoring.

## Build & Test

| Make command | Just command | Purpose |
|-------------|--------------|---------|
| `make build` | `just build` | Build binary to `./bin/gozone` |
| `make run` | `just run` | Build and start server |
| `make test` | `just test` | Run all tests (bypassing the result cache via `-count=1`) |
| `make test-verbose` | `just test-verbose` | Run tests with verbose output |
| `make test-race` | `just test-race` | Run tests with the race detector (same flags as CI) |
| `make test-js` | `just test-js` | Run frontend (app.js) unit tests via `node --test web/jstest/` |
| `make fmt` | `just fmt` | Format all Go source files |
| `make vet` | `just vet` | Run static analysis |
| `make clean` | `just clean` | Remove build artifacts and database |
| `make gosec` | `just gosec` | Run security static analysis |
| `make update` | `just update` | Update all dependencies + re-vendor |
| `make docker-up` | `just docker-up` | Start gozone + PowerDNS via docker-compose |

Run a single test: `go test -count=1 -run TestName -v ./internal/handlers/`
Run a single package: `go test -count=1 ./internal/config/`

Write co-located `*_test.go` when adding code. After any change, run `just fmt` then `just gosec` and fix every issue before considering the task complete.

CI (`.github/workflows/pr.yml`) runs: a `gofmt -l` check (excluding `vendor/`), `go vet`, the frontend unit tests (`node --test web/jstest/`), `go test -race -count=1`, gosec, and govulncheck. `just test-race` runs the exact same test flags as CI, so local parity is verifiable instead of memorised; plain `just test` skips the (slower) race detector. govulncheck is reachability-based and fails only when code actually calls a vulnerable path.

CI additionally runs the full suite against live `mysql:8` and `postgres:16` service containers (jobs `test-mysql` / `test-postgres`) with `go test -race -count=1 -tags dbmatrix ./...`: the `dbmatrix` build tag plus `GOZONE_TEST_DB_DRIVER`/`GOZONE_TEST_DB_DSN` redirects `testutil.NewTestDB` to `NewTestDBDialect`, which provisions a fresh per-test database on the server (the legacy `GOZONE_TEST_MYSQL_DSN`/`GOZONE_TEST_POSTGRES_DSN` also activate the database package's dialect integration tests). Plain local `go test ./...` ignores those variables and stays on in-memory SQLite; to reproduce a dialect job locally, run the same command with the tag and variables set against a reachable server.

Releases are git-cliff driven (`cliff.toml`): `just auto-gen-rel` (or `just gen-rel v0.x.y`) writes `CHANGELOG.md`, commits and signs tag `v0.x.y`; pushing a `v*` tag triggers `.github/workflows/release.yml` (multi-arch Docker image → ghcr.io + GitHub release).

## Security Analysis

gosec fails the build on findings, in CI and locally (no `-no-fail`): fix every reported issue before considering a task complete. Use `// #nosec Gxxx` annotations only for intentional suppressions
(e.g. HTTP response writes, timing side-channel mitigation) and document the reason inline.

## Architecture

- **Entrypoint**: `main.go` (repo root) is intentionally minimal — `main()` only calls `cmd.Execute()`. The CLI tree lives in package `cmd` (`cmd/`), built on **Cobra** (`spf13/cobra`). `cmd/root.go` defines the root command (a namespace: bare `gozone` prints help) and `Execute()`/`newRootCmd()`; `cmd/server.go` defines `gozone server` (cobra command `newServerCmd`) and `runServer(cfg *config.Config) error`, which wires the chi router, seeds admin, and serves — it also holds the HTTP helpers (`parseTemplates`, `relativeName`, the rate-limit/HTTPS middlewares). `cmd/user.go` defines the `gozone user` command tree (with `unlock` and `reset-password` subcommands); `cmd/version.go` defines `gozone version`. `--config`/`-c` is a persistent flag on the root, inherited by subcommands.
- **Handler pattern**: `Handler` struct in `internal/handlers/handler.go` holds `DB *database.DB`, `PDNS pdns.ZoneService`, `Cfg *config.Config`, `Tmpl *template.Template`, `Version version.Info`, `OIDC SSOService` — methods on Handler. `SSOService` (same file) is the handler-side interface; the concrete impl is `internal/oidc.Service`. `OIDC` is nil when SSO is unconfigured and the SSO handlers no-op (redirect to `/login`).
- **URL params**: uses Go 1.22+ `r.PathValue("name")`, **not** `chi.URLParam`
- **Templates & static files**: embedded via `//go:embed` in `web/embed.go`, loaded with `template.ParseFS`; template FuncMap lives in `cmd/server.go` (`parseTemplates`) and includes `add`, `sub`, `urlquery`, `relativeName`, `dict`, `assetVersion`. `assetVersion` returns a short content-hash of the bundled JS/CSS (`staticAssetVersion`) for cache-busting; bumping static assets flows through automatically.
- **Database**: migrations in `internal/database/database.go` and dialect files; content-hash versioning with `Dialect.LockMigrations` for multi-instance safety; exposed via `*database.DB` with raw SQL and context-aware methods (`ExecContext`, `QueryContext`, `QueryRowContext`, `BeginTx`)
- **Config**: YAML file + env var overrides with `GOZONE_` prefix. Default admin: `admin` / `admin` (override via `GOZONE_ADMIN_PASSWORD`). Without `server.secret_key` / `GOZONE_SECRET_KEY` a random key is generated per restart — invalidating all sessions and CSRF tokens; set it for stable local sessions. `server.trusted_proxies` entries **must be CIDR** (e.g. `10.0.0.0/8`, `192.0.2.1/32`) — plain IPs without `/` cause a startup panic in chi's `netip.MustParsePrefix`.
- **PowerDNS client**: `internal/pdns.Client` implements the `ZoneService` interface (`internal/pdns/service.go`); generic `doOK`/`doUnmarshal[T]` helpers handle HTTP status checks and JSON decoding; typed errors (`ErrNotFound`, `ErrValidation`, `ErrConflict`, `ErrUnauthorized`) map to correct HTTP status codes
- **Caching**: generic TTL cache in `internal/cache/cache.go`; `cachedClient` wraps `ZoneService` and caches zone lists, zone info, stats and server info; record mutations invalidate affected caches
- **Errors**: `internal/errors.AppError` carries an HTTP status code and supports `Unwrap()` for compatibility with `errors.Is/As`
- **CLI subcommand**: `gozone user` (in `user.go`, a Cobra subcommand tree) holds the emergency DB-recovery operations: `gozone user unlock <id|username>` clears account lockout, `gozone user reset-password <id|username>` sets a new bcrypt password (no-echo prompt via `golang.org/x/term`, piped stdin, or `--password`). Both write a `*_cli` `activity_logs` entry with `user_id = NULL` (actor = shell operator via `operatorIdentity()`). `gozone version` (in `version.go`) prints the version banner; `version`/`commit`/`buildDate` are ldflags-injected (`-X github.com/babykart/gozone/cmd.version=...`) and fall back to VCS metadata via `internal/version.Resolve` (`runtime/debug.ReadBuildInfo`) when unset — that package is the single source of truth consumed by both `cmd` and `internal/handlers`. Cobra's built-in `--version` flag (one-liner) is enabled via `rootCmd.Version`. Errors from `Execute()` are surfaced by `main()` via `logger.Fatal`; commands set `SilenceErrors`+`SilenceUsage` so cobra does not print to stderr.

## Record Content Normalization

The type-specific wire-format pipeline is in `internal/models/recordtype.go` (`recordTypeSpecs` map) and `internal/handlers/records.go` (`prepareRecordContent`). Four cases:

1. **Priority types** (MX, SRV): `JoinPriority` embeds priority into content, then `EnsureTrailingDot` dots the FQDN target (last field).
2. **Quoted types** (TXT, SPF): `QuoteContent` wraps content in double quotes with `\"` escaping.
3. **FQDN-target types** (CNAME, DNAME, NS, PTR, ALIAS, AFSDB, NAPTR): `EnsureTrailingDot` dots the entire content or last field.
4. **Multi-FQDN-field types** (SOA fields 0,1; RP fields 0,1; MINFO fields 0,1; NSEC field 0): `EnsureTrailingDotFields` dots specific space-separated fields by index.

Zone names and nameservers are canonicalised via `normalizeZoneName()` (lowercase + trailing dot) in both `CreateZone` (UI) and `APICreateZone` (API).

When adding a new record type to `GetRecordTypes()` (`internal/handlers/zones.go`), also add it to: `recordTypeWhitelist` (`internal/validators/validators.go`), `recordTypeSpecs` (`internal/models/recordtype.go`) if it has FQDN/priority/quoted semantics, and `ValidateRecordContent` (`internal/validators/validators.go`) if it needs content validation.

## Pagination Conventions

- Query params are **capitalized**: `Page`, `PerPage` (or `logPage`, `logPerPage` for activity log). Not lowercase.
- `PerPage=0` means "All". The per-page selector in `pagination.html` offers 10/20/30/40/50/All.
- `paginate[T]` is a generic slice paginator in `internal/handlers/zones.go`.
- Zone view paginates by **individual record rows** (`ZoneRecordRow`), not RRSets — a zone with 1 SOA + 10 NS records is 11 rows, not 2 items.

## Auth Patterns

| Layer | Auth Method |
|-------|-------------|
| Web session | JWT cookie validated against DB on every request |
| API | API key SHA-256 hash in `Authorization: Bearer <key>` header |
| Zone access | Fail-closed zone authorization via `internal/middleware/zoneauth.go` |

## Single Sign-On (OIDC)

- Delegated login is **off** unless `oidc.enabled` (`GOZONE_OIDC_ENABLED`) is set; the `internal/oidc` package is the concrete impl behind `Handler.OIDC SSOService`. `SSOService.Enabled()` gates the login-page provider buttons and the `/auth/oidc/*` handlers (no-op → `/login` when disabled).
- Flow: Authorization Code + PKCE (S256), AES-256-GCM encrypted `state` (confidentiality + CSRF), `nonce`, JWKS ID-token verification, just-in-time provisioning, role/group mapping from claims, RP-initiated logout. The `(issuer, subject)` pair is the link key to the local user; `oidc.Claims` exposes normalized fields plus `Raw` for config-driven dotted-path mapping (e.g. `realm_access.roles`).
- The shared `oauth2.Config` is **cloned per callback** (`cloneOAuth2Config`) so concurrent callbacks cannot race on `RedirectURL`.
- Built-in provider presets: Gitea, Google, GitHub, GitLab, Keycloak, Authentik, Azure AD (any other name = generic OIDC). The redirect URI is always `https://<host>/auth/oidc/<name>/callback`.
- Idle/absolute session timeouts apply to local **and** SSO sessions, enforced cluster-wide via the `sessions` table (in-memory cache coarsens writes to ~1 min). See README "Authentication" and `docs/SSO.md` for full provider setup.

## Password Policy

- `config.PasswordConfig` (`password:` in YAML, `GOZONE_PASSWORD_*` env) drives `validators.ValidatePassword(password, cfg.Password.Policy())` — min length (runes) + character-class requires + max length (**bytes**, default 72 = bcrypt's hard limit, `password.max_length` / `GOZONE_PASSWORD_MAX_LENGTH`, capped at 72 at load time). Secure-by-default (`min_length:8`, all four classes on). A zero policy accepts any non-empty password.
- Enforced at every password-set site: `CreateUser`, `UpdateUser` (when a new password is submitted), and `gozone user reset-password`. The initial admin seed (`SeedAdminUser`) is exempt (one-time bootstrap).
- Password history (`password.history_size`, default 0 = disabled): the `password_history` table + `*Tx` methods `PasswordHistoryReused`/`RecordPassword`/`PrunePasswordHistory` retain the last N hashes per user; the current password always counts as "used". History writes reuse-check happen inside the handler/CLI transaction.
- Password expiration (`password.max_age_days`, default 0 = no limit; `password.expiry_warn_days`, default 0): `users.password_changed_at` + `users.must_change_password` (migrated across dialects). `Login` (`passwordExpired`) flips `must_change_password` on expiry and redirects to `/change-password`. Every admin/operator password set (`CreateUser`, `UpdateUser`, `gozone user reset-password`) sets `must_change_password=1`; `SeedAdminUser` is exempt from the forced change but still sets `password_changed_at` (explicitly, seed time UTC) so the bootstrap password ages and expires like any other. The `Auth` middleware gate (`mustChangeAllowedPath`) restricts a forced-change session to `/change-password` + `/logout` until the self-service `ChangePassword` handler clears the flag. Dashboard shows a warning banner inside `expiry_warn_days`.
- Handler unit tests relax the policy (`h.Cfg.Password = config.PasswordConfig{}` in `newTestHandler`) so existing weak test passwords pass; dedicated policy/reuse/expiry tests build their own strict handler.

## Test Infrastructure

- **In-memory SQLite**: `testutil.NewTestDB(t)` auto-migrates the schema and auto-closes via `t.Cleanup`. Under the `dbmatrix` build tag (see CI notes above), the same call can provision a per-test database on a live MySQL/PostgreSQL server via `testutil.NewTestDBDialect` (unique CREATE DATABASE → migrations → DROP on cleanup; PostgreSQL DSNs must be URL-form).
- **Portable id retrieval**: test seeds must use `DB.ExecReturnID` (or the `insertReturnID` helper in `internal/handlers/handler_test.go`), never raw `Exec` + `result.LastInsertId()` — lib/pq does not implement `LastInsertId`, and those seeds would break the dialect matrix.
- **Mock PDNS**: `testutil.NewTestPDNSServer(t, handler)` returns an `httptest.Server` + `pdns.Client`. Handler controls responses; pass `nil` for 500 on all requests.
- **Handler tests**: `newTestHandler(t)` / `newTestHandlerWithPDNS(t, handler)` build a `Handler` with mock PDNS + in-memory DB + **stub templates** (defined inline in `handler_test.go:testTemplateSet()`, NOT the real embedded templates). The stub templates must be updated when handler data shapes change — e.g. when `.Records` changed from `[]RRSet` to `[]ZoneRecordRow`, the stub `zone_view.html` had to switch from `{{range .Records}}{{range .Records}}{{.Content}}` to `{{range .Records}}{{.Record.Content}}`.
- **FuncMap sync**: the test FuncMap in `testTemplateSet()` is a **subset** of the real one in `cmd/server.go:parseTemplates()`. If a new template func is added to `parseTemplates()`, it must also be added to `testTemplateSet()` or tests that render templates will fail.
- **`captureRRSets(t, &sent)`**: helper in `api_test.go` that decodes the PATCH body sent to the mock PDNS, so tests can assert exactly what PowerDNS received. Use this for content-normalization regression tests.
- **`relativeName`** lives in `cmd/server.go` (package cmd), so handler tests stub it out — the test FuncMap maps it to a no-op.
- **Admin routes**: every admin web route is registered in one place — `mountAdminRoutes` in `cmd/server.go` — and `TestAdminRoutesProtectedByRequireAdmin` (in `cmd/server_test.go`) walks that table to assert none escapes `middleware.RequireAdmin`. Add new admin routes to `mountAdminRoutes` so the invariant stays green.

## Key Constraints

- **CGO must be enabled** for SQLite builds (`CGO_ENABLED=1`); MySQL/PostgreSQL builds can run with `CGO_ENABLED=0`
- SQLite connection uses `SetMaxOpenConns(1)` — concurrent writes are serialized; not required for MySQL/PostgreSQL
- No ORM — raw SQL queries throughout
- All database methods support `context.Context`; legacy methods without context wrap `context.Background()`
- **DB-bound timestamps are always UTC** (`time.Now().UTC()`): SQLite serializes `time.Time` with its offset and compares the strings lexicographically, so mixed offsets skew `WHERE expires_at <= ?`-style comparisons. In-memory `Before`/`After`/`Sub` calls are timezone-agnostic and need no annotation.

## Frontend Conventions

- **JS unit tests**: pure-function and delegated-listener logic in `app.js` is tested under `web/jstest/` (`node --test`, no npm deps; the dir is NOT embedded in the binary). `app.js` loads inert under Node — its browser boot blocks are guarded on `typeof document` — and exposes the functions under test via a CommonJS export block that is dead code in browsers. Extend `web/jstest/app.test.js` (or add `*.test.js` siblings) when touching `filterOptions`, the delegated listeners or other testable logic; browser-level E2E (Playwright) is not yet in place.
- **No inline event handlers**: never add `onclick=`, `onchange=`, or `onsubmit=` to templates — they violate the Content-Security-Policy. Instead, use `data-action="action-name"` (and optionally `data-confirm="message"`) on the element, then handle via `initDelegatedListeners()` in `web/static/js/app.js`.
- **CSRF token (gorilla/csrf)**: every POST form MUST include `<input type="hidden" name="gorilla.csrf.Token" value="{{ .CSRFToken }}">`. JS-initiated POSTs must read `data-csrf="{{.CSRFToken}}"` and append `gorilla.csrf.Token` to the `FormData` (see existing `data-csrf` usage in templates and `app.js`). The CSRF middleware is configured with `csrf.Secure(false)` (static) and a per-request `csrfSecureCookieWriter` rewrites the `Secure` attribute from `middleware.IsHTTPS` — do not re-add `Secure` at the middleware level.
- **CSP**: `script-src 'self'` and `style-src 'self'` only (neither has `'unsafe-inline'`). Only `app.js` and `theme.js` are loaded. Former inline `style="..."` attributes are externalised to CSS classes; show/hide toggles in `app.js` use `classList` (`.hidden`), not `style.display=''`. JS CSSOM mutations (`element.style.foo`) remain allowed since CSP `style-src` governs document markup, not the CSSOM.
- **Layout partials**: use `{{template "app_layout_start" .}}` at the top and `{{template "app_layout_end" .}}` at the bottom of every authenticated page template. Never duplicate the `head`/`sidebar`/`topbar`/`main` wrapper directly.
- **User feedback**: use `showNotification(message, type)` (from `app.js`) for flash-style alerts. `alert()` is not used.
- **`dict` helper**: use `dict "key1" val1 "key2" val2` to pass parameters to template partials.
- **Badge classes**: record types use `badge-type-{{.Type}}` (e.g. `badge-type-A`, `badge-type-NS`); zone kinds use `badge-kind-{{.Kind}}` (Native/Master/Slave); DNSSEC status uses `badge-active` (green) / `badge-disabled` (red).

## Commit convention

Commits must always respect the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/#specification), with the repo's `[gozone]` marker after the scope: `type(scope): [gozone] short description` (see `git log` and `CONTRIBUTING.md`).

Messages must remain **concise and synthetic** — a one-line summary (≤ 72 chars on the subject line) plus a short body that lists the actual code/test/doc touchpoints. Avoid prose-style bodies, full code snippets, or rationale that belongs in the PR description rather than the commit log.

## Project context

- **`docs/API.md`** documents the REST API endpoints, payload schemas, and record content normalization behavior. **`docs/SSO.md`** covers OIDC provider setup; **`docs/ARCHITECTURE.md`** the system design. **`CONTRIBUTING.md`** has the full PR checklist (note: its "SQLite only" / "cmd: root, server, unlock" sections are stale — this file is current).
