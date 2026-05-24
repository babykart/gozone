# ROADMAP - GoZone

List of tasks to improve the security, quality, and performance of GoZone.

## 🔴 Priority 1 - Security (Critical)

### Validation and Injection
- [x] **Validate SQLite DSN** (`internal/database/database.go:34`)
  - Use `url.Values` to build connection parameters
  - Validate file path before opening
  - Prevent DSN injection attacks

- [x] **Add strict input validation** for all handlers
  - `internal/handlers/zones.go:72-74`: Validate zone names (RFC 1035 regex)
  - `internal/handlers/records.go:43-47`: Validate record types (whitelist)
  - `internal/handlers/users.go:80-85`: Validate usernames and emails
  - Create `internal/validators/` package with reusable functions

### Authentication and Authorization
- [x] **Enforce strong secret key** (`internal/config/config.go:55`)
  - Error on startup if `SecretKey == "change-me-to-a-random-secret"`
  - Or generate a random 32+ byte key and display it on first startup
  - Document secret key generation in README

- [x] **Add CSRF protection** on all web forms
  - Install `github.com/gorilla/csrf` or equivalent
  - Add CSRF middleware in `cmd/gozone/main.go:76`
  - Add CSRF tokens to all HTML templates
  - Test that requests without CSRF tokens are rejected

- [x] **Enable Secure flag on cookies** (`internal/handlers/auth.go:73`)
  - Auto-detect environment (dev vs prod)
  - Force `Secure: true` in production
  - Add `SameSite=Strict` (already present, verify)
  - Document HTTPS configuration in README

### Endpoint Protection
- [x] **Implement rate limiting** on sensitive endpoints
  - Install `golang.org/x/time/rate`
  - Limit `/login` to 5 attempts per minute per IP
  - Limit `/api/v1/*` to 100 requests per minute per API key
  - Limit `/nic/update` to 10 requests per minute per user
  - Return HTTP 429 with `Retry-After` header

- [x] **Mask internal errors** in API responses
  - `internal/handlers/api.go`: Never expose `err.Error()` directly
  - Log detailed errors server-side with context
  - Return generic error messages to clients
  - Use standardized error codes (e.g., `{"error": "zone_not_found", "code": "ZONE_001"}`)

### Data Security
- [x] **Verify password hashes never leak**
  - Test that `json:"-"` works on `PasswordHash` and `KeyHash`
  - Add JSON serialization tests for all models
  - Check logs to ensure no hashes are logged

- [x] **Add HTTP security headers**
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Content-Security-Policy` (if applicable)
  - `Strict-Transport-Security` (in HTTPS production)

---

## 🟠 Priority 2 - Tests (High)

### Critical Coverage (< 50%)
- [x] **Test `APIKeyAuth()` completely** (`internal/middleware/auth_test.go`)
  - Valid API key via `X-API-Key` header
  - Fallback to `Authorization: Bearer`
  - Missing API key (401)
  - Invalid/unknown API key (401)
  - Expired API key (401 with `"api_key_expired"` message)
  - Update `last_used_at`
  - Disabled user with valid key (401)
  - Non-existent user for valid key (401)

- [x] **Test `Auth()` middleware completely** (`internal/middleware/auth_test.go`)
  - Successful authentication via cookie
  - Successful authentication via `Authorization: Bearer` header
  - Cookie preferred over header (precedence)
  - Invalid/expired token → cookie cleared + redirect
  - User not found in database after valid token
  - Disabled user rejected
  - `loadUser()`: success, error, enabled conversion

- [x] **Fix and test DynDNS completely** (`internal/dyndns/dyndns_test.go`)
  - Add in-memory database with bcrypt-hashed users to `setupTestHandler()`
  - Test complete flow: auth → validateUser → findZone → updateRecord → "good"
  - Test `validateUser()`: success, user not found, wrong password, disabled user
  - Test `findZone()`: exact match, subdomain match, trailing dot, no match
  - Test `updateRecord()`: success, PowerDNS error
  - Test IPv6 (AAAA records)
  - Test multiple hostnames (comma-separated)
  - Test fallback `myip` → `ip` → `RemoteAddr`
  - Test invalid IP (400)

### Insufficient Coverage (50-80%)
- [x] **Test PowerDNS error paths** for all API handlers
  - `APIListZones`: PowerDNS error → 500
  - `APIGetZone`: zone not found → 404
  - `APICreateZone`: PowerDNS error → 500
  - `APIDeleteZone`: PowerDNS error → 500
  - `APIListRecords`: PowerDNS error → 500, null response → empty slice
  - `APICreateRecord`: invalid JSON → 400, PowerDNS error → 500
  - `APIUpdateRecord`: invalid JSON → 400, PowerDNS error → 500
  - `APIDeleteRecord`: PowerDNS error → 500
  - `APIStats`: PowerDNS error → 500

- [x] **Test `EditRecordPage()`** (`internal/handlers/records_test.go`)
  - Successful rendering with matching record
  - Zone not found → error
  - Record not found (name/type mismatch) → error
  - Record retrieval error

- [ ] **Test `RectifyZone()` and `NotifyZone()`** (`internal/handlers/zones_test.go`)
  - Admin-only access (403 for non-admin)
  - Successful PowerDNS operation
  - PowerDNS error → error rendering
  - Activity log creation

- [ ] **Test `UpdateRecord()` in PowerDNS client** (`internal/pdns/client_test.go`)
  - Successful update (PATCH with REPLACE)
  - PowerDNS error

### Integration Tests
- [ ] **Create integration tests** (`internal/handlers/integration_test.go`)
  - Complete web flow: login → cookie → authenticated request → logout
  - Complete API flow: API key → endpoint → JSON response
  - Unauthenticated access → redirect to /login
  - Non-admin access to admin endpoints → 403
  - DynDNS: Basic Auth → update → verification

### Test Infrastructure
- [ ] **Create `internal/testutil/` package** with reusable helpers
  - `NewTestDB()`: in-memory database with migrations
  - `NewTestPDNSServer()`: mock HTTP server for PowerDNS
  - `NewTestHandler()`: handler configured for tests
  - `SeedTestUser()`: create test users
  - `SeedTestZone()`: create test zones

- [ ] **Introduce `ZoneService` interface** for PowerDNS client
  - Define interface in `internal/pdns/service.go`
  - Have `pdns.Client` implement the interface
  - Enable mocking without `httptest.Server`
  - Simplify handler tests

- [ ] **Add JSON serialization tests** for models
  - Verify `PasswordHash` never appears in JSON
  - Verify `KeyHash` never appears in JSON
  - Test deserialization of all types

---

## 🟡 Priority 3 - Architecture (Medium)

### Error Handling
- [ ] **Standardize error handling**
  - Create global error middleware in `internal/middleware/error.go`
  - Web UI: always use `h.renderError()` with `error.html` template
  - API: always use `writeJSON()` with standardized error codes
  - Log all errors with context (user ID, zone ID, request ID)
  - Define error codes: `ZONE_NOT_FOUND`, `UNAUTHORIZED`, `VALIDATION_ERROR`, etc.

- [ ] **Use SQL transactions** for multi-step operations
  - `internal/handlers/users.go:102-116`: User creation + activity log
  - `internal/handlers/zones.go:105-108`: Zone creation + activity log
  - `internal/handlers/records.go:82-85`: Record creation + activity log
  - Pattern: `tx, _ := db.Begin(); defer tx.Rollback(); ... tx.Commit()`

### Code Organization
- [ ] **Move `seedAdminUser()` to a testable package**
  - Create `internal/database/seed.go`
  - Export function: `func SeedAdminUser(db *sql.DB, cfg *config.Config) error`
  - Call from `main.go`
  - Test all paths: first startup, existing users, env var override

- [ ] **Eliminate code duplication**
  - `internal/handlers/zones.go:61-65, 115-119`: Duplicated admin check
  - `internal/handlers/users.go:19-22, 55-58, 69-72, 123-126, 160-163, 220-223`: Duplicated admin check
  - Use existing `RequireAdmin` middleware: `r.With(middleware.RequireAdmin).Post(...)`
  - Create helpers for repetitive patterns

- [ ] **Define constants for magic strings**
  - Create `internal/constants/constants.go`
  - `SessionCookieName = "gozone_session"`
  - `UserContextKey = "user"`
  - `DefaultBcryptCost = 12`
  - `MaxOpenConns = 1`
  - Replace all occurrences in code

### Structural Improvements
- [ ] **Add `internal/validators/` package**
  - `ValidateDomainName(name string) error`: RFC 1035 regex
  - `ValidateRecordType(recordType string) error`: whitelist
  - `ValidateIPAddress(ip string) error`: IPv4/IPv6
  - `ValidateEmail(email string) error`: email format
  - `ValidateUsername(username string) error`: alphanumeric + underscore

- [ ] **Add `internal/errors/` package**
  - Define custom error types: `NotFoundError`, `ValidationError`, `UnauthorizedError`
  - Implement `Error() string` and `HTTPStatus() int`
  - Use in handlers and error middleware

- [ ] **Migrate to structured logging**
  - Use `log/slog` (Go 1.21+) or `go.uber.org/zap`
  - Replace all `log.Printf()` with structured calls
  - Add contextual fields: `slog.With("user_id", userID, "zone_id", zoneID)`
  - Configure log levels (debug, info, warn, error)

---

## 🟢 Priority 4 - Performance (Low)

### HTTP Optimizations
- [x] **Add HTTP compression** (`cmd/gozone/main.go:62-66`)
  - Add `chimw.Compress(5)` to middleware chain
  - Test that responses are compressed
  - Verify static files aren't double-compressed

- [ ] **Configure connection pooling for PowerDNS client** (`internal/pdns/client.go:38`)
  ```go
  Transport: &http.Transport{
      MaxIdleConns:        100,
      MaxIdleConnsPerHost: 10,
      IdleConnTimeout:     90 * time.Second,
      DisableKeepAlives:   false,
  }
  ```

- [ ] **Embed templates with `//go:embed`** (`cmd/gozone/main.go:169-180`)
  - Add `//go:embed web/templates/*.html` to `main.go`
  - Use `embed.FS` to load templates
  - Eliminate startup parsing
  - Simplify deployment (single binary)

### Database Optimizations
- [ ] **Optimize `ListZones` to avoid N+1 queries** (`internal/handlers/zones.go:30-36`)
  - Option 1: Use PowerDNS endpoint that returns zones + records
  - Option 2: Cache record counts (TTL 5 min)
  - Option 3: Load counts in batch with single query

- [ ] **Add additional indexes** if needed
  - Analyze slow queries with `EXPLAIN QUERY PLAN`
  - Add indexes on frequently filtered columns
  - Document indexes in `internal/database/database.go`

- [ ] **Cache frequently accessed data**
  - Zone cache (TTL 1 min) with `sync.Map` or `github.com/patrickmn/go-cache`
  - PowerDNS statistics cache (TTL 30 sec)
  - Invalidate cache on create/update/delete

### Template Optimizations
- [ ] **Cache parsed templates**
  - Currently parsed on every startup
  - Use `sync.Once` to parse once
  - Or use `//go:embed` (see above)

---

## 🔵 Priority 5 - Code Quality (Low)

### Cleanup
- [ ] **Replace `intToStr()` with `strconv.Itoa()`** (`internal/handlers/dashboard.go:103-113`)
  - Remove custom function
  - Replace all calls with `strconv.Itoa(n)`
  - Fix bug with negative numbers

- [ ] **Remove unused variable** (`internal/handlers/users.go:255`)
  - Remove `var _ = sql.ErrNoRows`
  - Remove `database/sql` import if unused
  - Or use `sql.ErrNoRows` properly

- [ ] **Add TODO/FIXME comments** for known limitations
  - Document that SQLite doesn't scale horizontally
  - Document lack of clustering
  - Document DynDNS limitations (no wildcards, etc.)

### Documentation
- [x] **Improve inline documentation**
  - Add godoc comments for all exported functions
  - Document parameters and return values
  - Add examples for complex functions

- [x] **Create contribution guide** (`CONTRIBUTING.md`)
  - Code standards (gofmt, golint, go vet)
  - Review process
  - How to add tests
  - How to report bugs

- [x] **Document architecture** (`docs/ARCHITECTURE.md`)
  - Component diagram
  - Data flow
  - Design decisions
  - Known limitations

### Monitoring and Observability
- [ ] **Add Prometheus metrics**
  - Request count per endpoint
  - Request latency
  - Errors by type
  - Zone/record/user counts
  - PowerDNS response time

- [x] **Add detailed health checks**
  - `/health`: basic check (already present)
  - `/health/ready`: DB + PowerDNS check
  - `/health/live`: process check

- [ ] **Add distributed tracing**
  - Use `go.opentelemetry.io/otel`
  - Trace PowerDNS calls
  - Trace SQL queries
  - Export to Jaeger or Zipkin

---

## 📊 Tracking Metrics

### Test Coverage
- [ ] Reach > 80% on `internal/middleware` (currently 41%)
- [ ] Reach > 80% on `internal/dyndns` (currently 20.5%)
- [ ] Reach > 80% on `internal/handlers` (currently 67.5%)
- [ ] Reach > 90% on `internal/config` (currently 91.9%)
- [ ] Reach > 90% on `internal/pdns` (currently 73.8%)
- [ ] Overall coverage > 80% (currently 55.7%)

### Code Quality
- [ ] 0 `go vet` warnings
- [ ] 0 `golint` or `staticcheck` warnings
- [ ] 0 `gosec` security issues
- [ ] Build time < 30 seconds
- [ ] Test time < 60 seconds

### Performance
- [ ] Average response time < 100ms for API endpoints
- [ ] Average response time < 500ms for web pages
- [ ] Support 100 requests/second with SQLite
- [ ] Support 1000 requests/second with PostgreSQL (future)

---

## 🗓️ Suggested Roadmap

### Week 1-2: Security
- Fix all Priority 1 items
- Add security tests
- Security review by peer

### Week 3-4: Tests
- Complete all Priority 2 items
- Reach > 80% overall coverage
- Set up CI/CD with automatic tests

### Month 2: Architecture
- Implement Priority 3 items
- Refactor duplicated code
- Introduce interfaces and utility packages

### Month 3: Performance and Quality
- Optimize performance (Priority 4)
- Improve code quality (Priority 5)
- Complete documentation

### Future: Database Migration
- Evaluate PostgreSQL vs MySQL
- Create migration plan
- Implement multi-DB support
- Test migration in staging environment
- Migrate to production

---

## 📝 Notes

### Known SQLite Limitations
- No multi-writer support (hence `SetMaxOpenConns(1)`)
- No native replication
- No clustering
- Limited to ~100 writes/second under load
- Recommended only for development and small installations

### Alternatives to Consider
- **PostgreSQL**: Production-ready, excellent for DNS workloads
- **MySQL/MariaDB**: Good alternative, broad support
- **CockroachDB**: Horizontal distribution, PostgreSQL-compatible
- **TiDB**: Horizontal distribution, MySQL-compatible

### Useful References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Checklist](https://github.com/guardrailsio/awesome-golang-security)
- [PowerDNS API Documentation](https://doc.powerdns.com/authoritative/http-api/)
- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)
