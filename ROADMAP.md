# ROADMAP - GoZone

Remaining tasks to improve the security, quality, and performance of GoZone.

## OpenID Connect / OAuth2

Delivered end-to-end: discovery, PKCE+state+nonce, JWKS ID-token verification
with operator-tunable cache TTL, JIT provisioning, role/group mapping,
RP-initiated logout, and idle/absolute session enforcement shared across
instances (DB-backed `sessions` table). See [docs/SSO.md](docs/SSO.md).

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
