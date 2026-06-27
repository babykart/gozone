# GoZone — Agents Instructions

## Language & Framework

- Go 1.26, chi v5 router, `html/template` server-side rendering
- Multi-dialect SQL layer: SQLite (mattn/go-sqlite3), MySQL (go-sql-driver/mysql), PostgreSQL (lib/pq)
- JWT (golang-jwt/jwt v5) + bcrypt for auth

## Build & Test

| Make command | Just command | Purpose |
|-------------|--------------|---------|
| `make build` | `just build` | Build binary to `./bin/gozone` |
| `make run` | `just run` | Build and start server |
| `make test` | `just test` | Run all tests |
| `make test-verbose` | `just test-verbose` | Run tests with verbose output |
| `make fmt` | `just fmt` | Format all Go source files |
| `make vet` | `just vet` | Run static analysis |
| `make clean` | `just clean` | Remove build artifacts and database |
| `make gosec` | `just gosec` | Run security static analysis |
| `make update` | `just update` | Update all dependencies |

Write co-located `*_test.go` when adding code. After any change, run `just fmt` then `just gosec` and fix every issue before considering the task complete.

## Security Analysis

After any code change, run `just fmt` (or `make fmt`) then `just gosec` (or `make gosec`) and fix every issue reported before
considering the task complete. Use `// #nosec Gxxx` annotations only for intentional suppressions
(e.g. HTTP response writes, timing side-channel mitigation) and document the reason inline.

## Architecture

- **Entrypoint**: `cmd/gozone/main.go` — wires chi router, loads config, seeds admin, starts server via `run() error`
- **Handler pattern**: `Handler` struct in `internal/handlers/handler.go` holds `DB *database.DB`, `PDNS pdns.ZoneService`, `Cfg *config.Config`, `Tmpl *template.Template` — methods on Handler
- **URL params**: uses Go 1.22+ `r.PathValue("name")`, **not** `chi.URLParam`
- **Templates & static files**: embedded via `//go:embed` in `web/embed.go`, loaded with `template.ParseFS`; template FuncMap lives in `cmd/gozone/main.go` and includes `add`, `sub`, `urlquery`, `relativeName`, `dict`
- **Database**: migrations in `internal/database/database.go` and dialect files; content-hash versioning with `Dialect.LockMigrations` for multi-instance safety; exposed via `*database.DB` with raw SQL and context-aware methods (`ExecContext`, `QueryContext`, `QueryRowContext`, `BeginTx`)
- **Config**: YAML file + env var overrides with `GOZONE_` prefix. Default admin: `admin` / `admin` (override via `GOZONE_ADMIN_PASSWORD`)
- **PowerDNS client**: `internal/pdns.Client` implements the `ZoneService` interface; generic `doOK`/`doUnmarshal[T]` helpers handle HTTP status checks and JSON decoding; typed errors (`ErrNotFound`, `ErrValidation`, `ErrConflict`, `ErrUnauthorized`) map to correct HTTP status codes
- **Caching**: generic TTL cache in `internal/cache/cache.go`; `cachedClient` wraps `ZoneService` and caches zone lists, zone info, stats and server info; record mutations invalidate affected caches
- **Errors**: `internal/errors.AppError` carries an HTTP status code and supports `Unwrap()` for compatibility with `errors.Is/As`

## Auth Patterns

| Layer | Auth Method |
|-------|-------------|
| Web session | JWT cookie validated against DB on every request |
| API | API key SHA-256 hash in `Authorization: Bearer <key>` header |
| Zone access | Fail-closed zone authorization via `internal/middleware/zoneauth.go` |

## Key Constraints

- **CGO must be enabled** for SQLite builds (`CGO_ENABLED=1`); MySQL/PostgreSQL builds can run with `CGO_ENABLED=0`
- SQLite connection uses `SetMaxOpenConns(1)` — concurrent writes are serialized; not required for MySQL/PostgreSQL
- No ORM — raw SQL queries throughout
- All database methods support `context.Context`; legacy methods without context wrap `context.Background()`

## Frontend Conventions

- **No inline event handlers**: never add `onclick=`, `onchange=`, or `onsubmit=` to templates — they violate the Content-Security-Policy. Instead, use `data-action="action-name"` (and optionally `data-confirm="message"`) on the element, then handle via `initDelegatedListeners()` in `web/static/js/app.js`.
- **CSP**: `script-src 'self'` only (no `'unsafe-inline'`). Only `app.js` is loaded. `style-src` allows `'unsafe-inline'` for dynamic styles.
- **Layout partials**: use `{{template "app_layout_start" .}}` at the top and `{{template "app_layout_end" .}}` at the bottom of every authenticated page template. Never duplicate the `head`/`sidebar`/`topbar`/`main` wrapper directly.
- **User feedback**: use `showNotification(message, type)` (from `app.js`) for flash-style alerts. `alert()` is not used.
- **`dict` helper**: use `dict "key1" val1 "key2" val2` to pass parameters to template partials.

## Commit convention

Commits must always respect the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/#specification).

Messages must remain **concise and synthetic** — a one-line summary (≤ 72 chars on the subject line) plus a short body that lists the actual code/test/doc touchpoints and references the relevant REVIEW.md entry. Avoid prose-style prose, full code snippets, or rationale that belongs in the PR description rather than the commit log.
