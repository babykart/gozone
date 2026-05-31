# GoZone — Agents Instructions

## Language & Framework

- Go 1.26, chi v5 router, `html/template` server-side rendering
- SQLite via mattn/go-sqlite3 — **CGO required** (`CGO_ENABLED=1`)
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
| `make deps` | `just deps` | Download and tidy dependencies |
| `make clean` | `just clean` | Remove build artifacts and database |
| `make gosec` | `just gosec` | Run security static analysis |
| `make update` | `just update` | Update all dependencies |

Write co-located `*_test.go` when adding code.

## Security Analysis

After any code change, run `just gosec` (or `make gosec`) and fix every issue reported before
considering the task complete. Use `// #nosec Gxxx` annotations only for intentional suppressions
(e.g. HTTP response writes, timing side-channel mitigation) and document the reason inline.

## Architecture

- **Entrypoint**: `cmd/gozone/main.go` — wires chi router, loads config, seeds admin, starts server
- **Handler pattern**: `Handler` struct in `internal/handlers/handler.go` holds `DB *sql.DB`, `PDNS *pdns.Client`, `Cfg *config.Config`, `Tmpl *template.Template` — methods on Handler
- **URL params**: uses Go 1.22+ `r.PathValue("name")`, **not** `chi.URLParam`
- **Templates & static files**: embedded via `//go:embed *` in `web/embed.go`, loaded with `template.ParseFS`
- **Database**: inline SQL migrations in `internal/database/database.go`. SQLite only, `SetMaxOpenConns(1)` — serialized writes
- **Config**: YAML file + env var overrides with `GOZONE_` prefix. Default admin: `admin` / `admin` (override via `GOZONE_ADMIN_PASSWORD`)

## Auth Patterns

| Layer | Auth Method |

## Key Constraints

- **CGO must be enabled** for sqlite3 driver — cross-compilation needs `CGO_ENABLED=1` + C compiler
- SQLite connection uses `SetMaxOpenConns(1)` — concurrent writes are serialized
- No CI/CD config exists — `.github/` absent
- No ORM — raw SQL queries throughout

## Commit convention

Commits must always respect the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/#specification).
