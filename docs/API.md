# GoZone REST API

All API endpoints are under `/api/v1` and require an API key. Keys are created via the Web UI at `/profile/api-keys` — the raw key is shown only once at creation time.

## Authentication

Pass the API key using one of two headers:

```bash
# Option 1: X-API-Key header (preferred)
X-API-Key: gozone_<base64-encoded-key>

# Option 2: Authorization Bearer header
Authorization: Bearer gozone_<base64-encoded-key>
```

All examples below use the `X-API-Key` header.

## Rate Limiting

API requests are rate-limited to **100 requests per minute** per API key. Exceeding the limit returns HTTP 429 with a `Retry-After` header.

## Error Responses

All errors return a JSON body:

```json
{
  "error": "human-readable label",
  "code": "ERROR_CODE",
  "message": "human-readable label"
}
```

| Error Code | HTTP Status | Meaning |
|------------|-------------|---------|
| `INVALID_JSON` | 400 | Malformed JSON body |
| `VALIDATION_ERROR` | 400 | Invalid input (domain name, record type, etc.) |
| `ZONE_NOT_FOUND` | 404 | Zone does not exist |
| `RECORD_NOT_FOUND` | 404 | Record does not exist |
| `CONFLICT` | 409 | Resource already exists |
| `UNAUTHORIZED` | 401 | Invalid or expired API key |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

## Zones

### List zones

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones
```

Response `200`:

```json
[
  {
    "id": "example.com.",
    "name": "example.com.",
    "kind": "Native",
    "serial": 2026062001,
    "dnssec": false,
    "masters": [],
    "account": "",
    "catalog": ""
  }
]
```

Non-admin users only see zones assigned to their groups.

### Get zone details

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones/example.com
```

Response `200`: single zone object (same format as list items).

### Create zone (admin only)

```bash
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"newzone.com","kind":"Native","nameservers":["ns1.example.com.","ns2.example.com."]}' \
  http://localhost:8080/api/v1/zones
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `name` | string | **yes** | — | Domain name (trailing dot optional — canonicalised to lowercase + trailing dot automatically) |
| `kind` | string | no | `"Native"` | `Native`, `Master`, `Slave`, `Producer`, `Consumer` |
| `nameservers` | string[] | no | — | List of NS hostnames |
| `masters` | string[] | no | — | Required for `Slave`/`Consumer` |
| `catalog` | string | no | — | Catalog zone name |

Response `201`: the created zone object.

### Delete zone (admin only)

```bash
curl -X DELETE \
  -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones/example.com
```

Response `200`:

```json
{"message": "zone deleted"}
```

## Records

### List records

Without query parameters, returns every RRSet in the zone as a JSON array:

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/zones/example.com/records
```

Response `200`:

```json
[
  {
    "name": "www.example.com.",
    "type": "A",
    "ttl": 300,
    "records": [
      {
        "name": "www.example.com.",
        "type": "A",
        "content": "1.2.3.4",
        "ttl": 300,
        "priority": 0,
        "disabled": false
      }
    ],
    "comments": []
  }
]
```

Pass the optional `name` and `type` query parameters to fetch a single RRSet (or all RRSets matching a name) without pulling the entire zone. They map to the PowerDNS API `rrset_name` / `rrset_type` query parameters:

```bash
# Every RRSet for a given name (any type)
curl -H "X-API-Key: gozone_yourkey" \
  "http://localhost:8080/api/v1/zones/example.com/records?name=www.example.com."

# One specific RRSet (name + type)
curl -H "X-API-Key: gozone_yourkey" \
  "http://localhost:8080/api/v1/zones/example.com/records?name=www.example.com.&type=A"
```

The `name` value is canonicalised against the zone the same way the write path does — trailing dot is added if missing (`www.example.com` → `www.example.com.`), the `@` shorthand resolves to the apex (`example.com.`), bare labels are expanded against the zone (`www` → `www.example.com.`), and the value is lowercased to match PowerDNS canonical names. Without this normalisation PowerDNS silently returns an empty list for names that are syntactically valid but missing the canonical trailing dot.

The response is always a JSON array (possibly empty when no match). `type` requires `name`; passing `type` alone returns `400 VALIDATION_ERROR`.

### Create record

```bash
# A record
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"www.example.com","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# MX record (priority is a separate field)
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com.","type":"MX","ttl":3600,"records":[{"content":"mail.example.com.","priority":10}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# SRV record (priority is a separate field; content is "weight port target")
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"_sip._tcp.example.com","type":"SRV","ttl":3600,"records":[{"content":"5 5060 sipserver.example.com.","priority":10}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# CNAME record
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"blog.example.com","type":"CNAME","ttl":300,"records":[{"content":"example.github.io."}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# TXT record (content is auto-quoted for PowerDNS)
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com.","type":"TXT","ttl":3600,"records":[{"content":"v=spf1 include:_spf.google.com ~all"}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# CAA record (value quoted per RFC 8659 presentation format; GoZone does not modify CAA content)
curl -X POST \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com.","type":"CAA","ttl":3600,"records":[{"content":"0 issue \"letsencrypt.org\""}]}' \
  http://localhost:8080/api/v1/zones/example.com/records
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | **yes** | Relative (`www`), absolute (`www.example.com.`), or `@` for apex |
| `type` | string | **yes** | Any valid DNS record type |
| `ttl` | int | **yes** | Time-to-live in seconds |
| `records` | array | **yes** | Array of record objects |
| `records[].content` | string | **yes** | Record content. FQDN targets (CNAME, DNAME, NS, PTR, ALIAS, AFSDB, NAPTR, MX, SRV) get a trailing dot appended automatically if missing. For multi-field types where the FQDN is not the last field (SOA mname/rname, RP mbox/txtname, MINFO rmailbx/emailbx, NSEC next_domain), per-field normalisation is applied. TXT/SPF content is auto-quoted. |
| `records[].priority` | int | no | For MX and SRV types |
| `records[].disabled` | bool | no | Default `false` |
| `comments` | array | no | Array of RRSet comments (see below) |
| `comments[].content` | string | **yes** | Comment text |
| `comments[].account` | string | no | Account name that added the comment; omitted from the request if not set (PowerDNS defaults it server-side) |
| `comments[].modified_at` | int | no | Unix timestamp; omitted from the request if not set (PowerDNS defaults it server-side) |

The `comments` array is omitted from the PATCH payload when left empty or absent, which tells PowerDNS to keep the RRSet's existing comments untouched. When provided, it *replaces* the entire comment list for the RRSet (PowerDNS `comments` semantics), so include every comment you want to keep. GoZone does not set a default `account` or `modified_at` — both fields are optional and PowerDNS fills in the server-side defaults when omitted.

> The REST API is a pass-through for the `comments` field: the array is forwarded to PowerDNS exactly as the client sent it, with no implicit deduplication, padding, or clearing. If you want to **add** a comment to an existing list, GET the RRSet first (returns the current `comments`), merge your additions client-side, and PUT the combined list back. The web UI's textarea + "Clear all comments" checkbox builds the patch for you on the form path; the API path leaves that work to the caller.
>
> **Clearing comments via the API.** The PUT body accepts an additional GoZone-only boolean `clear_comments` (write-only, never returned by GET). Setting `"clear_comments": true` purges every existing comment on the RRSet — it is the API counterpart of the web form's "Clear all comments" checkbox. The sentinel is exclusive: any `comments` array supplied in the same body is discarded. To replace existing comments atomically, GET → modify → PUT without the sentinel. `clear_comments` is consumed by GoZone and never reaches PowerDNS.

Response `201`:

```json
{"message": "record created"}
```

### Update record

```bash
# Replace the records for www.example.com.
curl -X PUT \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"www.example.com","type":"A","ttl":600,"records":[{"content":"5.6.7.8"}]}' \
  http://localhost:8080/api/v1/zones/example.com/records

# Purge every existing comment on the same RRSet (GoZone-only sentinel).
curl -X PUT \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"www.example.com","type":"A","ttl":600,"records":[{"content":"5.6.7.8"}],"clear_comments":true}' \
  http://localhost:8080/api/v1/zones/example.com/records
```

Response `200`:

```json
{"message": "record updated"}
```

### Delete record

```bash
curl -X DELETE \
  -H "X-API-Key: gozone_yourkey" \
  -H "Content-Type: application/json" \
  -d '{"name":"www.example.com","type":"A"}' \
  http://localhost:8080/api/v1/zones/example.com/records
```

Response `200`:

```json
{"message": "record deleted"}
```

## Statistics

```bash
curl -H "X-API-Key: gozone_yourkey" \
  http://localhost:8080/api/v1/stats
```

Response `200`:

```json
{
  "statistics": [
    {"name": "zone-cache-hits", "type": "Long", "value": 12345},
    {"name": "zone-cache-misses", "type": "Long", "value": 678}
  ],
  "zone_count": 3
}
```

`zone_count` reflects the number of zones visible to the authenticated user.

## Health Endpoints (no auth required)

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/health` | `{"status":"ok"}` |
| `GET` | `/health/ready` | PowerDNS connectivity check |
| `GET` | `/health/live` | Liveness probe |