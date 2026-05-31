# Contributing to GoZone

Thank you for your interest in contributing to GoZone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Project Conventions](#project-conventions)
- [Writing Tests](#writing-tests)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Review Process](#review-process)

## Code of Conduct

Be respectful, constructive, and inclusive. Assume good intent in all interactions.

## Reporting Bugs

Before submitting a bug report:

1. **Search existing issues** to avoid duplicates.
2. **Ensure you are on the latest version** — the bug may already be fixed.

A good bug report includes:

```
**Version**: gozone version or git commit hash
**Platform**: OS, architecture, Go version
**PowerDNS version**: if the bug relates to zone/record operations
**Steps to reproduce**:
  1. Go to '...'
  2. Click on '...'
  3. See error
**Expected behavior**: what should have happened
**Actual behavior**: what happened instead
**Logs**: relevant server logs (trim secrets)
```

For security vulnerabilities, **do not open a public issue**. Contact the maintainers directly.

## Suggesting Features

1. **Check the roadmap** in [ROADMAP.md](ROADMAP.md) to see if the feature is already planned.
2. **Open an issue** with the `enhancement` label.
3. **Describe the use case** — what problem does this solve?
4. **Propose a design** if you have one — mention affected packages, API changes, and migration considerations.

## Development Setup

**Requirements**:

- Go 1.26+
- C compiler (gcc/clang) — required for the SQLite CGO driver
- PowerDNS Authoritative Server (optional, for integration testing)

```bash
git clone https://github.com/babykart/gozone.git
cd gozone
make deps   # or: just deps
make run    # or: just run
# Open http://localhost:8080 — admin / admin
```

### Environment

| Variable | Description | Default |
|----------|-------------|---------|
| `CGO_ENABLED` | Must be `1` for SQLite driver | `1` |
| `GOZONE_ADMIN_PASSWORD` | Initial admin password | `admin` |
| `GOZONE_SECRET_KEY` | JWT signing key | `change-me-to-a-random-secret` |

### Quick Reference

| Make command | Just command | Purpose |
|-------------|--------------|---------|
| `make build` | `just build` | Compile binary to `./bin/gozone` |
| `make run` | `just run` | Build and start server |
| `make test` | `just test` | Run all tests |
| `make test-verbose` | `just test-verbose` | Run tests with verbose output |
| `make fmt` | `just fmt` | Format all Go source files |
| `make vet` | `just vet` | Run static analysis |
| `make deps` | `just deps` | Download and tidy dependencies |
| `make clean` | `just clean` | Remove build artifacts and database |
| `make gosec` | `just gosec` | Run security static analysis |
| `make docker-up` | `just docker-up` | Start services with docker-compose |
| `make update` | `just update` | Update all dependencies |

## Code Standards

### Formatting

All code must pass `go fmt ./...` before submission. The project uses `tab` indentation as per standard Go conventions.

```bash
make fmt   # go fmt ./...
make vet   # go vet ./...
```

### Linting

Run `go vet` and `gosec` after every code change. All issues must be resolved before submitting a PR:

```bash
make vet     # or: just vet
make gosec   # or: just gosec
```

- **`gosec` is mandatory** — every reported HIGH or MEDIUM severity issue must be fixed.
- Use `// #nosec Gxxx` annotations only for intentional suppressions (e.g., HTTP response writes, timing side-channel mitigation) and document the reason inline.
- Failures from `just test` or `just gosec` block a PR from being merged.

Static analysis with `staticcheck` or `golangci-lint` is also encouraged but not required:

```bash
# Install and run gosec (recommended)
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...
# or
make gosec   # or: just gosec

# Install golangci-lint (optional)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
golangci-lint run ./...
```

### Security

- Never log or expose secrets, passwords, or API key hashes — models use `json:"-"` to prevent serialization
- Validate all user input at handler boundaries
- Use parameterized SQL queries exclusively — never string-concatenate query values
- The secret key must never be the default `change-me-to-a-random-secret` in production

## Project Conventions

### Architecture

GoZone follows a layered architecture:

```
cmd/gozone/main.go        Entry point, routing, wiring
internal/config/          Configuration (YAML + env vars)
internal/database/        SQLite connection and migrations
internal/handlers/          HTTP handlers (web UI + REST API)
internal/middleware/       JWT auth, API key auth, admin guard
internal/models/          Shared data structures
internal/pdns/            PowerDNS REST API client
web/templates/            Embedded Go HTML templates
web/static/               Embedded CSS, JavaScript
```

### Handler Pattern

All handlers are methods on the `Handler` struct (`internal/handlers/handler.go`) which holds shared dependencies:

```go
type Handler struct {
    DB   *sql.DB
    PDNS *pdns.Client
    Cfg  *config.Config
    Tmpl *template.Template
}
```

- **Web UI handlers** return rendered HTML via `h.render(w, template, data)`
- **API handlers** return JSON via `writeJSON(w, status, data)`
- **Error pages** use `h.renderError(w, message)`

### URL Parameters

Use Go 1.22+ `r.PathValue("name")` to extract URL path parameters — **not** `chi.URLParam`.

### Database

- **SQLite only** via `mattn/go-sqlite3` (requires CGO)
- No ORM — all queries are raw SQL in handler methods
- Writes are serialized: `SetMaxOpenConns(1)`
- Migrations are inline in `internal/database/database.go`
- New migrations should use `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`

### Auth Patterns

| Layer | Method |
|-------|--------|
| Web UI | JWT token in `gozone_session` cookie (HttpOnly, SameSite=Lax) |
| REST API | `X-API-Key` header or `Authorization: Bearer` |

### Naming

- Exported functions/types must have godoc comments starting with the name
- Unused imports are not allowed (`go vet` enforces this)
- Handler methods use descriptive names: `ListZones`, `CreateZone`, `ViewZone`

## Writing Tests

### Where to Put Tests

Tests are co-located with the source. For a file `foo.go`, create `foo_test.go` in the same package directory.

### Test Infrastructure

The project currently uses:

- **In-memory SQLite** (`:memory:`) for unit testing the database layer
- **`httptest.NewServer`** to mock the PowerDNS API
- Standard Go `testing` package — no external test framework

### Writing a New Test

1. **Model/utility tests** — write standard table-driven tests:

```go
func TestMyFeature(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "example.com", "example.com.", false},
        {"empty input", "", "", true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := MyFunc(tt.input)
            if (err != nil) != tt.wantErr {
                t.Fatalf("unexpected error: %v", err)
            }
            if got != tt.want {
                t.Errorf("got %q, want %q", got, tt.want)
            }
        })
    }
}
```

2. **Handler tests** — use `httptest` to mock the PowerDNS server and test endpoints:

```go
func TestMyHandler(t *testing.T) {
    h, _, cleanup := setupTestHandler(t)
    defer cleanup()
    // ... test h.SomeHandler(w, r)
}
```

### Coverage

Run tests with coverage:

```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

The project tracks coverage goals by package in [ROADMAP.md](ROADMAP.md).

## Commit Guidelines

GoZone follows the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`

**Examples**:

```
feat(handlers): [gozone] add batch record import endpoint
fix(middleware): [gozone] clear expired tokens from database
docs(readme): [gozone] add API configuration example
test(handlers): [gozone] cover IP validation
chore(deps): [gozone] bump golang-jwt to v5.2.3
refactor(pdns): [gozone] extract zone service interface
```

### Commit Best Practices

- Keep commits focused — one logical change per commit
- Write commit messages in imperative mood ("Add feature" not "Added feature")
- Reference issues in the footer: `Closes #42`

## Pull Request Process

1. **Fork the repository** and create a feature branch from `main`.
2. **Keep changes focused** — large PRs are harder to review; split into smaller ones.
3. **Follow the conventions** described in this document.
4. **Run tests locally** before pushing:

```bash
make fmt
make vet
make test
make gosec
```

5. **Update documentation** if your change affects user-facing behavior:

   - `README.md` for feature additions or configuration changes
   - `ROADMAP.md` if completing a planned task (check the box)
   - `CHANGELOG.md` for user-visible changes (follow existing format)

6. **Submit the PR** with a clear title and description:

```
## Summary
Brief explanation of the change.

## Motivation
Why is this needed? Link related issues.

## Changes
- Bullet list of what changed
- Highlight breaking changes

## Testing
- [ ] Added unit tests for new code
- [ ] All existing tests pass
- [ ] Manually tested with PowerDNS X.Y.Z

## Checklist
- [ ] Code follows project conventions
- [ ] godoc comments added for exported symbols
- [ ] No hardcoded secrets or credentials
- [ ] `go fmt ./... && go vet ./...` passes
- [ ] `go test ./...` passes
- [ ] `gosec ./...` passes with **zero** issues (use `// #nosec Gxxx` only with inline justification)
```

## Review Process

### For Contributors

- Respond to review comments constructively
- Push additional commits to the same branch — avoid force-pushing after review starts
- Request re-review after addressing feedback

### For Reviewers

- Verify code follows conventions (imports, naming, handler pattern)
- Check that new exported symbols have godoc comments
- Ensure new functionality has corresponding tests
- Confirm no secrets, hardcoded credentials, or sensitive data are present
- Validate SQL queries use parameterized placeholders (no string concatenation)
- Approve only when `go fmt`, `go vet`, `go test ./...`, and `gosec ./...` pass with zero issues

### After Merge

- Delete the feature branch
- If the change completes a ROADMAP.md item, check the box in a follow-up PR or let the maintainer handle it
