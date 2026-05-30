# GoZone — Agents Instructions

## Language & Framework

- Go 1.26, chi v5 router, `html/template` server-side rendering
- SQLite via mattn/go-sqlite3 — **CGO required** (`CGO_ENABLED=1`)
- JWT (golang-jwt/jwt v5) + bcrypt for auth

## Build & Test

| Command | Description |
|---------|-------------|
| `go build ./cmd/gozone` | Build binary |
| `go run ./cmd/gozone` | Run server |
| `go test ./...` | All tests |
| `go test -v ./...` | Verbose tests |
| `go fmt ./... && go vet ./...` | Lint + static analysis |
| `just deps` | `go mod download && go mod tidy` (order matters) |
| `just run` | Build + run |
| `just test` | `go test ./...` |
| `just fmt` / `just vet` | Format / vet |

Write co-located `*_test.go` when adding code.

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
