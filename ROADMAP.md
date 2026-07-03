# ROADMAP - GoZone

Remaining tasks to improve the security, quality, and performance of GoZone.

## OpenID Connect / OAuth2

- [ ] **OAuth2 / OIDC provider configuration**
  - Configurable provider URL, client ID, client secret via `config.yaml` + env vars (`GOZONE_OIDC_*`)
  - Well-known discovery endpoint (`/.well-known/openid-configuration`) for automatic metadata retrieval
  - Support for standard providers: Google, GitHub, GitLab, Keycloak, Authentik, Azure AD

- [ ] **Login flow**
  - "Sign in with SSO" button on login page, redirects to provider authorization endpoint
  - Authorization code flow with PKCE (`S256`) for public clients
  - State parameter with HMAC signature to prevent CSRF
  - Nonce parameter for OpenID Connect ID token replay protection
  - Redirect URI validation against configured base URL

- [ ] **User mapping and provisioning**
  - Map OIDC claims to GoZone user attributes: `sub` → external ID, `email` → email, `preferred_username` → username, `name` → display name
  - Just-in-time (JIT) user provisioning: auto-create user on first login if allowed by config
  - Role mapping: map provider roles/groups/realm_access claims to GoZone roles (admin/user)
  - Group mapping: map provider groups/teams to GoZone zone groups
  - Existing local user linking by email match (prompt to connect accounts)

- [ ] **Session management**
  - JWT session issued after successful OIDC authentication, same as local login
  - Refresh token support with configurable TTL
  - Idle session timeout with forced re-authentication
  - Single logout (RP-Initiated Logout) with `end_session_endpoint` when available

- [ ] **Configuration options**
  - `oidc.enabled` — master switch for SSO
  - `oidc.allow_local_login` — keep local username/password login alongside SSO
  - `oidc.auto_provision` — create users on first SSO login
  - `oidc.default_role` — role assigned to auto-provisioned users
  - `oidc.scopes` — requested scopes (openid, profile, email, groups)
  - `oidc.claim_mappings` — custom claim-to-attribute mapping

- [ ] **Security**
  - Token signature verification with JWKS endpoint (`id_token_signing_alg_values_supported`)
  - Claims validation: `iss`, `aud`, `exp`, `iat`, `nbf`, `nonce`
  - JWKS caching with configurable TTL (default 1 hour)
  - Rate limiting on callback endpoint to prevent brute-force state guessing

## Monitoring and Observability

- [ ] **Add Prometheus metrics**
  - Request count per endpoint
  - Request latency
  - Errors by type
  - Zone/record/user counts
  - PowerDNS response time

- [ ] **Add distributed tracing**
  - Use `go.opentelemetry.io/otel`
  - Trace PowerDNS calls
  - Trace SQL queries
  - Export to Jaeger or Zipkin

## Password Enforcement

- [ ] **Password policy configuration**
  - Minimum length (default 8)
  - Require uppercase, lowercase, digits, special characters
  - Password history (prevent reuse of last N passwords)
  - Configurable via `config.yaml` + env vars (`GOZONE_PASSWORD_*`)

- [ ] **Password expiration**
  - Maximum password age (default 90 days)
  - Warn user N days before expiry
  - Force change on next login after expiry
  - Admin reset triggers forced change

- [x] **Account lockout**
  - [x] Lock account after N failed login attempts (default 5)
  - [x] Lockout duration (default 15 minutes) or admin unlock
  - [x] IP-based rate limiting on login endpoint
  - **Delivered in commit `25ea7fa` + follow-ups.** Layered defense: persistent DB lockout (`failed_login_attempts`, `locked_until`, `login_attempts` table × 4 indexes), per-IP chi token bucket, per-username AND-compounded limiter, last-admin exemption (`Tx.IsLastEnabledAdmin` resets the counter so a sliding-window attack still hits the lockout on the next failure), admin lock/unlock UI, CLI `gozone unlock --user <id|username>`. See REVIEW.md § *Brute-Force Protection* and § *Mineurs* for the full audit trail.

- [ ] **Password hashing**
  - Configurable bcrypt cost (currently hardcoded, make env-configurable)
  - Consider Argon2id support as future alternative

## CLI & Tooling

- [x] **CLI password reset (`gozone user reset-password`)**
  - Companion to `gozone user unlock`: open the configured database directly and set a new bcrypt password hash for a user (resolved by numeric ID or username, like `unlock`)
  - Same operator-audit trail as `unlock`: `user_id = NULL` and `operatorIdentity()` (`username@hostname`) recorded in `activity_logs` under the action `reset_password_cli`
  - Replaces the former recovery path documented in README.md, where operators had to hand-roll `UPDATE users SET password_hash = '<hash>' WHERE username = '<user>';` against the database
  - Accepts the new password via a no-echo prompt (with confirmation), piped stdin, or `--password`; hashed with the configured `auth.bcrypt_cost`
  - Idempotent on the audit side: re-running with the same hash is a data no-op but still logs the operator's intervention
  - **Delivered.** `unlock` and `reset-password` are now nested under a new `gozone user` parent command (`cmd/user.go`). Both take the target user as a positional `<id|username>` argument. Shared helpers extracted: `resolveUser` (replaces the per-command lookup; uses `errors.Is(err, sql.ErrNoRows)` — the m18 anti-pattern), `readPassword` (`--password` flag → no-echo TTY prompt via `golang.org/x/term` → piped stdin), `operatorIdentity`. `cmd/unlock.go` removed; `user.go` holds the parent + both subcommands + helpers. Vendored `golang.org/x/term` (+ `x/sys` indirect). Tests: `unlock_test.go` rewritten for the `user unlock <id>` path; `user_test.go` covers reset-password (flag, stdin pipe, not-found, empty rejected, audit log). README "Recovering a locked admin" updated to `gozone user unlock <id>`; the manual-SQL note replaced by a `gozone user reset-password` section. gosec clean, full suite green in vendor mode.

- [x] **Migrate the CLI to the Cobra framework**
  - Replace the hand-rolled `flag`-based dispatch in `cmd/gozone/main.go` (`run()` switch + per-subcommand `flag.FlagSet`) with `spf13/cobra`
  - Restructure into a root command (namespace: bare `gozone` prints help) plus subcommands: `server` (starts the HTTP server), existing `unlock`, the new `reset-password`, and future ones (`migrate`, `seed`, `version`, ...)
  - Generate shell completion (bash/zsh/fish) and uniform `--help` output; keep `--config` consistent across commands
  - Re-vendor with `just update` after adding the dependency (vendor mode — never `go get` without re-vendoring)
  - Keep `unlock` and `reset-password` as direct DB access (no PowerDNS/HTTP dependency), preserving emergency-recovery when the server or all admins are unreachable
  - **Delivered.** Repo layout restructured: a thin `main.go` at the repo root (`main()` → `cmd.Execute()`) plus a `cmd/` package (package `cmd`) holding the Cobra tree — `cmd/root.go` (root command = namespace, bare `gozone` prints help, persistent `--config`/`-c`, `Execute()`/`newRootCmd()`), `cmd/server.go` (`server` subcommand via `newServerCmd()` → `runServer`, plus the HTTP helpers: `parseTemplates`, `relativeName`, the rate-limit/HTTPS middlewares, periodic-job orchestrator), and `cmd/unlock.go` (`unlock` subcommand via `newUnlockCmd()`/`unlockUser()`). The former `cmd/gozone/main.go`/`server.go` were merged into `cmd/server.go`; tests moved to `cmd/` (`server_test.go`, `unlock_test.go`, `pagination_test.go`) as `package cmd`. Cobra + pflag + mousetrap vendored (`go mod tidy` + `go mod vendor`). `run()`/`runUnlock()` removed; tests rewritten to drive `newRootCmd()`+`SetArgs`+`Execute` and use `--config`/`--user` (pflag rejects single-dash long flags). Build path changed to `go build .` (Dockerfile, Makefile, justfile); `run` recipes and README "Building from Source" switched to `gozone server --config`. gosec clean, full suite green in vendor mode.

## Performance Targets

- [ ] Average response time < 100ms for API endpoints
- [ ] Average response time < 500ms for web pages
- [ ] Support 100 requests/second with SQLite
- [ ] Support 1000 requests/second with PostgreSQL (future)

---

## Notes

### Known SQLite Limitations
- No multi-writer support (hence `SetMaxOpenConns(1)`)
- No native replication
- No clustering
- Limited to ~100 writes/second under load
- Recommended only for development and small installations

### Useful References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Checklist](https://github.com/guardrailsio/awesome-golang-security)
- [PowerDNS API Documentation](https://doc.powerdns.com/authoritative/http-api/)
- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)
- [PowerDNS DNSSEC Guide](https://doc.powerdns.com/authoritative/dnssec/)
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
