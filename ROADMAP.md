# ROADMAP - GoZone

Remaining tasks to improve the security, quality, and performance of GoZone.

## Performance

### HTTP Optimizations

- [ ] **Configure connection pooling for PowerDNS client** (`internal/pdns/client.go`)
  ```go
  Transport: &http.Transport{
      MaxIdleConns:        100,
      MaxIdleConnsPerHost: 10,
      IdleConnTimeout:     90 * time.Second,
      DisableKeepAlives:   false,
  }
  ```

### Database Optimizations

- [ ] **Cache frequently accessed data**
  - Zone cache (TTL 1 min) with `sync.Map`
  - PowerDNS statistics cache (TTL 30 sec)
  - Invalidate cache on create/update/delete

## DNSSEC

- [ ] **Zone DNSSEC management**
  - Enable/disable DNSSEC per zone
  - View DNSSEC status (signed/unsigned) on zone page
  - Display active and inactive keys (KSK/ZSK) with metadata (algorithm, size, DS)
  - Activate/deactivate keys via PowerDNS API

- [ ] **Key operations**
  - Create new KSK and ZSK keys per zone
  - Delete deactivated keys
  - Set key active/inactive state
  - Export DS/DNSKEY records for parent zone configuration

- [ ] **DNSSEC algorithms**
  - Support for common algorithms (ECDSAP256SHA256, RSASHA256, etc.)
  - Display algorithm details in key table
  - Algorithm selection when creating new keys

- [ ] **Zone metadata for DNSSEC**
  - `NSEC3PARAM` metadata configuration (opt-out, iterations, salt)
  - `NSEC3NARROW` enable/disable via checkbox
  - `PRESIGNED` flag for externally signed zones
  - `PUBLISH-CDS` / `PUBLISH-CDNSKEY` controls

## Export / Import

- [ ] **Zone export in BIND format**
  - Generate RFC 1035-compliant zone file from PowerDNS records
  - Include `$ORIGIN`, `$TTL`, and SOA record header
  - Support all record types (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, etc.)
  - Download as `.zone` file via button on zone view page
  - Server-side generation in Go (no external tools)

- [ ] **Zone export in CSV format**
  - Export records as comma-separated values (name, type, content, ttl, priority, disabled)
  - Download as `.csv` file via button on zone view page
  - UTF-8 with BOM for Excel compatibility
  - Optional filter by record type

- [ ] **Import zone from BIND zone file**
  - Parse RFC 1035 zone file with `$ORIGIN`, `$TTL`, `$INCLUDE` directives
  - Validate all records before creation
  - Create new zone or add records to existing zone via PowerDNS API
  - Drag-and-drop or file picker in WebUI
  - Support for multi-record RRsets

- [ ] **Import zone from CSV file**
  - Parse CSV with columns: name, type, content, ttl, priority, disabled
  - Preview parsed records before import
  - Create new zone or add records to existing zone
  - Template download for CSV format reference

- [ ] **Export / Import API endpoints**
  - `GET /api/v1/servers/{server}/zones/{zone}/export?format=bind`
  - `GET /api/v1/servers/{server}/zones/{zone}/export?format=csv`
  - `POST /api/v1/servers/{server}/zones/{zone}/import?format=bind|csv`
  - `POST /api/v1/servers/{server}/zones/import?format=bind|csv` (create new zone)
  - Respect zone-level authorization (group access control)
  - Set appropriate `Content-Type` headers (`text/plain`, `text/csv`)

## Zone Templates

- [ ] **Define reusable zone templates**
  - Pre-populated record sets for common zone types (standard, mail, web, redirect)
  - Custom templates with user-defined records
  - Template variables (e.g. `{{IP}}`, `{{MX_HOST}}`, `{{TTL}}`)
  - Template storage in local database (not PowerDNS)

- [ ] **Template management UI**
  - CRUD pages for templates (list, create, edit, delete)
  - Visual record editor within template
  - Preview records before applying template
  - Clone existing zone as new template

- [ ] **Apply template on zone creation**
  - Select template from dropdown on zone create page
  - Replace variables with user-provided values
  - Batch-create all template records via PowerDNS API
  - Option to apply template to existing zone

- [ ] **Built-in templates**
  - `standard` — SOA + NS records only
  - `mail` — SOA + NS + MX + SPF + DKIM placeholders
  - `web` — SOA + NS + A/AAAA + CNAME www
  - `redirect` — SOA + NS + A + URL redirect record

## Code Quality

### Cleanup

- [ ] **Add TODO/FIXME comments** for known limitations

### Monitoring and Observability

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
