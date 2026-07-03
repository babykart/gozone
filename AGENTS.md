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
| `make test` | `just test` | Run all tests |
| `make test-verbose` | `just test-verbose` | Run tests with verbose output |
| `make fmt` | `just fmt` | Format all Go source files |
| `make vet` | `just vet` | Run static analysis |
| `make clean` | `just clean` | Remove build artifacts and database |
| `make gosec` | `just gosec` | Run security static analysis |
| `make update` | `just update` | Update all dependencies + re-vendor |

Run a single test: `go test -count=1 -run TestName -v ./internal/handlers/`
Run a single package: `go test -count=1 ./internal/config/`

Write co-located `*_test.go` when adding code. After any change, run `just fmt` then `just gosec` and fix every issue before considering the task complete.

## Security Analysis

After any code change, run `just fmt` (or `make fmt`) then `just gosec` (or `make gosec`) and fix every issue reported before
considering the task complete. Use `// #nosec Gxxx` annotations only for intentional suppressions
(e.g. HTTP response writes, timing side-channel mitigation) and document the reason inline.

Note: `gosec` runs with `-no-fail` (non-blocking exit code). An agent must read the output and fix
all reported issues regardless of the exit code.

## Architecture

- **Entrypoint**: `main.go` (repo root) is intentionally minimal — `main()` only calls `cmd.Execute()`. The CLI tree lives in package `cmd` (`cmd/`), built on **Cobra** (`spf13/cobra`). `cmd/root.go` defines the root command (a namespace: bare `gozone` prints help) and `Execute()`/`newRootCmd()`; `cmd/server.go` defines `gozone server` (cobra command `newServerCmd`) and `runServer(cfg *config.Config) error`, which wires the chi router, seeds admin, and serves — it also holds the HTTP helpers (`parseTemplates`, `relativeName`, the rate-limit/HTTPS middlewares). `cmd/unlock.go` defines the `unlock` subcommand. `--config`/`-c` is a persistent flag on the root, inherited by subcommands.
- **Handler pattern**: `Handler` struct in `internal/handlers/handler.go` holds `DB *database.DB`, `PDNS pdns.ZoneService`, `Cfg *config.Config`, `Tmpl *template.Template` — methods on Handler
- **URL params**: uses Go 1.22+ `r.PathValue("name")`, **not** `chi.URLParam`
- **Templates & static files**: embedded via `//go:embed` in `web/embed.go`, loaded with `template.ParseFS`; template FuncMap lives in `cmd/server.go` and includes `add`, `sub`, `urlquery`, `relativeName`, `dict`
- **Database**: migrations in `internal/database/database.go` and dialect files; content-hash versioning with `Dialect.LockMigrations` for multi-instance safety; exposed via `*database.DB` with raw SQL and context-aware methods (`ExecContext`, `QueryContext`, `QueryRowContext`, `BeginTx`)
- **Config**: YAML file + env var overrides with `GOZONE_` prefix. Default admin: `admin` / `admin` (override via `GOZONE_ADMIN_PASSWORD`). `server.trusted_proxies` entries **must be CIDR** (e.g. `10.0.0.0/8`, `192.0.2.1/32`) — plain IPs without `/` cause a startup panic in chi's `netip.MustParsePrefix`.
- **PowerDNS client**: `internal/pdns.Client` implements the `ZoneService` interface (`internal/pdns/service.go`); generic `doOK`/`doUnmarshal[T]` helpers handle HTTP status checks and JSON decoding; typed errors (`ErrNotFound`, `ErrValidation`, `ErrConflict`, `ErrUnauthorized`) map to correct HTTP status codes
- **Caching**: generic TTL cache in `internal/cache/cache.go`; `cachedClient` wraps `ZoneService` and caches zone lists, zone info, stats and server info; record mutations invalidate affected caches
- **Errors**: `internal/errors.AppError` carries an HTTP status code and supports `Unwrap()` for compatibility with `errors.Is/As`
- **CLI subcommand**: `gozone unlock --user <id|username>` (in `unlock.go`, a Cobra subcommand) clears account lockout directly via DB (emergency recovery when all admins are locked). `gozone version` (in `version.go`) prints the version banner; `version`/`commit`/`buildDate` are ldflags-injected (`-X github.com/babykart/gozone/cmd.version=...`) and fall back to VCS metadata (`runtime/debug.ReadBuildInfo`) when unset. Cobra's built-in `--version` flag (one-liner) is enabled via `rootCmd.Version`. Errors from `Execute()` are surfaced by `main()` via `logger.Fatal`; commands set `SilenceErrors`+`SilenceUsage` so cobra does not print to stderr.

## Record Content Normalization

The type-specific wire-format pipeline is in `internal/models/recordtype.go` (`recordTypeSpec` map) and `internal/handlers/records.go` (`prepareRecordContent`). Four cases:

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

## Test Infrastructure

- **In-memory SQLite**: `testutil.NewTestDB(t)` auto-migrates the schema and auto-closes via `t.Cleanup`.
- **Mock PDNS**: `testutil.NewTestPDNSServer(t, handler)` returns an `httptest.Server` + `pdns.Client`. Handler controls responses; pass `nil` for 500 on all requests.
- **Handler tests**: `newTestHandler(t)` / `newTestHandlerWithPDNS(t, handler)` build a `Handler` with mock PDNS + in-memory DB + **stub templates** (defined inline in `handler_test.go:testTemplateSet()`, NOT the real embedded templates). The stub templates must be updated when handler data shapes change — e.g. when `.Records` changed from `[]RRSet` to `[]ZoneRecordRow`, the stub `zone_view.html` had to switch from `{{range .Records}}{{range .Records}}{{.Content}}` to `{{range .Records}}{{.Record.Content}}`.
- **FuncMap sync**: the test FuncMap in `testTemplateSet()` is a **subset** of the real one in `main.go:parseTemplates()`. If a new template func is added to `parseTemplates()`, it must also be added to `testTemplateSet()` or tests that render templates will fail.
- **`captureRRSets(t, &sent)`**: helper in `api_test.go` that decodes the PATCH body sent to the mock PDNS, so tests can assert exactly what PowerDNS received. Use this for content-normalization regression tests.
- **`relativeName`** lives in `cmd/server.go` (package cmd), so handler tests stub it out — the test FuncMap maps it to a no-op.

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
- **Badge classes**: record types use `badge-type-{{.Type}}` (e.g. `badge-type-A`, `badge-type-NS`); zone kinds use `badge-kind-{{.Kind}}` (Native/Master/Slave); DNSSEC status uses `badge-active` (green) / `badge-disabled` (red).

## Commit convention

Commits must always respect the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/#specification).

Messages must remain **concise and synthetic** — a one-line summary (≤ 72 chars on the subject line) plus a short body that lists the actual code/test/doc touchpoints and references the relevant REVIEW.md entry. Avoid prose-style prose, full code snippets, or rationale that belongs in the PR description rather than the commit log.

## Project context

- **`docs/API.md`** documents the REST API endpoints, payload schemas, and record content normalization behavior.
