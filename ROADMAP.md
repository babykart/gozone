# ROADMAP - GoZone

Remaining tasks to improve the security, quality, and performance of GoZone.

> **Status as of 2026-06-27 (HEAD ahead of `e7a1963`, uncommitted).**
> One ROADMAP item is now **closed** — see the checkbox update under *Password Enforcement → Account lockout* below. Several other security / quality follow-ups tracked outside the ROADMAP (account-enumeration mitigation, last-admin lockout exemption + CLI unlock, RRSet comments UI + API + CSV, REST API `clear_comments` sentinel, `?name=` FQDN canonicalisation, `InsertIgnore` explicit conflict columns, per-page selector visibility on single-page lists, CSV / BIND export tweaks) have been delivered. See `REVIEW.md` for the full audit trail (suivi table + open items list).
>
> **Still open from this file:** everything in *OpenID Connect / OAuth2*, *Monitoring and Observability*, *Password policy / expiration / hashing*, and *Performance Targets*. The two security Majeurs still on REVIEW.md (default `admin`/`admin` password without forced change, no minimum-length policy) overlap with the *Password Enforcement* section below and remain to be addressed there.

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
