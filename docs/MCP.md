# MCP — exposing GoZone to AI agents

GoZone embeds a [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server that lets agents (Claude Code, Claude Desktop, remote MCP
connectors) manage DNS zones and records **with exactly the rights of the API
key they use** — no more.

## Security model

The MCP endpoint is mounted behind the **same middleware stack as `/api/v1`**:

```
per-IP rate limit (pre-auth) → API key authentication → per-key rate limit
```

- Authentication is **by API key** (`X-API-Key: <key>` or `Authorization:
  Bearer <key>`). The web session cookie is never accepted on `/mcp`.
- The rate limiters are the **same instances** as `/api/v1`'s: a client
  alternating REST and MCP requests draws from a single budget.
- Zone authorization (fail-closed) and admin rights are re-checked in the
  service layer (`internal/dnsops`) shared with the REST API: a non-admin key
  only sees the zones of its groups; `create_zone`/`delete_zone` require an
  admin key.
- Every write is audited in `activity_logs` with the **`via MCP`** label and
  the key owner's `user_id`.
- The server is **stateless** (stateless Streamable HTTP): every request is
  authenticated independently — compatible with multi-instance deployments
  behind a load balancer.

## Enabling

```yaml
mcp:
  enabled: false            # GOZONE_MCP_ENABLED
  path: /mcp                # GOZONE_MCP_PATH
  read_only: true           # GOZONE_MCP_READ_ONLY
  allowed_origins: []       # GOZONE_MCP_ALLOWED_ORIGINS (CSV)
```

| Option | Default | Role |
|---|---|---|
| `enabled` | `false` | Mounts (or not) the endpoint. Disabled = route absent (404). |
| `path` | `/mcp` | Endpoint path. Validated: must not overlap `/api`, `/static`, `/health`, … |
| `read_only` | `true` | `true`: only the read-only tools are **registered** (they do not even appear in `tools/list`). Recommended for a first deployment. |
| `allowed_origins` | `[]` | Browser origins allowed to reach the endpoint (DNS-rebinding protection required by the Streamable HTTP spec). A request carrying an `Origin` not in the list is rejected (403). Clients without an `Origin` header (CLI agents) always pass. Empty = every present `Origin` is rejected. |

### Creating a dedicated API key

1. Web UI → **Profile → API Keys → Create** (see the README).
2. Recommendations: one key **per agent**, a dedicated non-admin user scoped
   by zone groups, a short expiry, and `read_only: true` to start with.

## Tools

| Tool | REST equivalent | Rights | Annotations |
|---|---|---|---|
| `list_zones` | `GET /api/v1/zones` | any user (filtered by groups) | read-only |
| `get_zone` (`zone`) | `GET /api/v1/zones/{id}` | zone access | read-only |
| `list_records` (`zone`, `name?`, `type?`) | `GET …/records` | zone access | read-only |
| `get_stats` | `GET /api/v1/stats` | any user | read-only |
| `list_record_types` | — | any user | read-only |
| `export_zone` (`zone`, `format: bind\|csv`) | web export | zone access | read-only |
| `create_record` (`zone`, `name`, `type`, `ttl?`, `records[]`) | `POST …/records` | zone access | write, not idempotent |
| `update_record` (`zone`, `name`, `type`, `ttl?`, `records[]`, `clear_comments?`) | `PUT …/records` | zone access | write, idempotent, **destructive** (REPLACE) |
| `delete_record` (`zone`, `name`, `type`) | `DELETE …/records` | zone access | **destructive**, idempotent |
| `create_zone` (`name`, `kind?`, `nameservers[]`) | `POST /api/v1/zones` | **admin** | write |
| `delete_zone` (`zone`) | `DELETE /api/v1/zones/{id}` | **admin** | **destructive** |

Conventions inherited from the REST API (repeated in every tool description,
because they are what prevents the most LLM mistakes):

- `zone` = the canonical zone ID returned by `list_zones` (lowercase +
  trailing dot, e.g. `example.com.`); `name` accepts `@`, a bare label
  (`www`), an FQDN without the trailing dot, or a full FQDN — canonicalisation
  happens server-side.
- MX/SRV: `priority` is a separate field of each record (embedded into the
  content at write time).
- TXT/SPF: bare content, quoting is automatic.
- `update_record` is a **REPLACE**: the submitted list becomes the whole set
  (`list_records` first, so nothing is lost).
- `export_zone` returns the whole zone as an RFC 1035 BIND zone file
  (`format=bind`, the default — identical to the `gozone://zones/{zone}`
  resource) or as CSV (one row per record, disabled records flagged);
  past 1 MiB the content is explicitly truncated with a banner naming the
  REST export endpoint.

Errors: an `isError: true` result + a `CODE: description` message with a
stable code (`ZONE_NOT_FOUND`, `FORBIDDEN`, `VALIDATION_ERROR`,
`RECORD_NOT_FOUND`, `CONFLICT`, `UPSTREAM_AUTH_ERROR`, `INTERNAL_ERROR`, …).
Never any internal detail (DSN, raw PowerDNS response) — the full cause goes
to the server logs.

## Resources

Resources (read-only, available whatever `read_only` is) let a client attach
GoZone context:

| URI | MIME | Content |
|---|---|---|
| `gozone://zones/{zone}` (template) | `text/dns` | Complete BIND export of the zone (RFC 1035: `$ORIGIN`, `$TTL`, records sorted SOA→NS→name; disabled records omitted). `{zone}` = the canonical zone ID returned by `list_zones`. Access requires a group grant (or an admin key) — refused fail-closed before any PowerDNS call. Beyond 1 MiB the content is **explicitly truncated** with a banner pointing at `GET /zones/{zone}/export?format=bind` for the full export. |
| `gozone://record-types` | `application/json` | JSON map of every supported type to its normalisation rules: separate `priority` field (MX/SRV), quoted content (TXT/SPF), FQDN target, FQDN/quoted field indices. Read this before creating or updating records. |

## Prompts

Two ready-made instruction templates (available whatever `read_only` is —
they only instruct; the write tools still enforce their gate):

| Prompt | Arguments | Content |
|---|---|---|
| `audit_zone` | `zone` (required) | Read-only zone review: walks the agent through `get_zone` + `list_records` and a checklist — SOA sanity (one SOA, refresh/retry/expire ratios), apex NS, CNAME forbidden at the apex and alongside other records (RFC 1034), TTL consistency, trailing-dot hygiene, SPF (one per name, lookup budget) and DMARC presence. Ends with a findings table and **proposed** fixes — never applies them. |
| `migrate_record` | `zone`, `name`, `type` (required) | Safe RRSet replacement procedure: read the current set first (`update_record` is a REPLACE — omitted records are deleted), show a before/after plan and wait for confirmation, apply with the full record list, verify with a re-read, and roll back with the list captured in step 1 if the verification disagrees. |

Arguments are validated (domain name, record name, record type) before the
prompt text is built.

## Client configuration

### Claude Code

```bash
claude mcp add --transport http gozone https://gozone.example.com/mcp \
  --header "X-API-Key: YOUR_API_KEY"
```

### OpenCode

GoZone authenticates by API key, not OAuth, so the server entry needs
`oauth: false` and the key in a header. Keep the key out of the file with an
environment substitution. In `opencode.json(c)` (project) or
`~/.config/opencode/opencode.json(c)` (global):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "gozone": {
        "type": "remote",
        "url": "https://gozone.example.com/mcp",
        "oauth": false,
        "headers": {
          "X-API-Key": "{env:GOZONE_MCP_API_KEY}"
        }
      }
    }
  }
}
```

Export the key in your shell profile, then verify the connection:

```bash
export GOZONE_MCP_API_KEY="YOUR_API_KEY"
opencode mcp list   # gozone must show as connected
```

Tools surface as `gozone_<tool>` (e.g. `gozone_list_zones`); inside OpenCode,
`/mcps` shows the server's state.

### Claude Desktop / any Streamable HTTP client

URL: `https://gozone.example.com/mcp`, header `X-API-Key: <key>` (or
`Authorization: Bearer <key>`).

### Clients that only support stdio

For clients without Streamable HTTP support, the CLI ships a local bridge
that speaks stdio and relays to the remote `/mcp` endpoint. The API key is
read from an environment variable (never a CLI argument, which would leak
via the process list):

```bash
export GOZONE_API_KEY="YOUR_API_KEY"
gozone mcp stdio --url https://gozone.example --api-key-env GOZONE_API_KEY
```

`--url` accepts the base URL (the default `/mcp` path is appended) or a full
endpoint URL. The bridge holds no session state and no business logic — it
forwards each newline-delimited JSON-RPC message as one authenticated HTTP
POST and writes responses back on stdout (logs go to stderr). A typical
client entry points at the bridge as a local command:

```json
{
  "mcpServers": {
    "gozone": {
      "command": "gozone",
      "args": ["mcp", "stdio", "--url", "https://gozone.example"]
    }
  }
}
```

### Verification

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npx @modelcontextprotocol/inspector
# transport: Streamable HTTP, URL: http://localhost:8080/mcp,
# header: X-API-Key: <key>
```

## Out of scope (v1)

DNSSEC (cryptokeys), TSIG keys, users/groups, zone import, metadata — no MCP
surface wider than the public API.
