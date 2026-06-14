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

### Password Enforcement

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

- [ ] **Account lockout**
  - Lock account after N failed login attempts (default 5)
  - Lockout duration (default 15 minutes) or admin unlock
  - IP-based rate limiting on login endpoint

- [ ] **Password hashing**
  - Configurable bcrypt cost (currently hardcoded, make env-configurable)
  - Consider Argon2id support as future alternative

## Activity Page and Retention

- [ ] **Dedicated activity page**
  - New route `GET /activity` with full-page view of all activity logs
  - Search field filtering by action, username, zone ID, and details text
  - Pagination (reuse existing `pagination.html` partial with `Prefix`)
  - Column sorting by date (default: most recent first)
  - Filter by action type (create_record, update_record, delete_record, etc.)
  - Filter by date range (from/to date pickers)

- [ ] **BIND-format diff display**
  - When an activity log involves record changes (create, update, delete), show a colorized BIND-format diff
  - Green for added records, red for removed records, yellow for modified records
  - Syntax highlighting for record types (A, AAAA, MX, CNAME, etc.), TTL, and content
  - Expandable diff rows inline in the activity table or on a detail page
  - Store before/after state in activity_logs for record mutations (add `old_value`/`new_value` JSON columns)

- [ ] **Automatic retention policy**
  - Configurable retention period via `config.yaml` + env vars (`GOZONE_ACTIVITY_RETENTION_DAYS`, default 90)
  - Background goroutine running daily to purge expired logs
  - `DELETE FROM activity_logs WHERE created_at < NOW() - INTERVAL ? DAY`
  - Retention job respects database dialect (SQLite `datetime`, PostgreSQL `NOW()`, MySQL `DATE_SUB`)
  - Configurable batch size to avoid locking the database on large purges (default 1000 rows per batch)
  - Log retention job execution (purged count, duration) via the logger
  - Admin UI setting to view current retention config and trigger manual purge

- [ ] **Activity page access control**
  - All authenticated users can view activity for zones they have access to
  - Admin users can view all activity across all zones
  - Zone-scoped filtering respects group-based zone authorization

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
