# Single Sign-On (OpenID Connect / OAuth2)

GoZone can delegate authentication to one or more external identity providers
(IdPs) using OpenID Connect (OIDC). When enabled, a **"Sign in with &lt;provider&gt;"**
button appears on the login page next to (or instead of) the local
username/password form.

This document covers the concepts, the configuration reference, and concrete
setup examples for the common providers.

---

## How it works

GoZone implements the **OIDC Authorization Code flow with PKCE (S256)**:

1. The user clicks "Sign in with &lt;provider&gt;" → GoZone redirects the browser
   to the provider's authorization endpoint with a signed `state` parameter
   (HMAC, CSRF protection), a PKCE `code_challenge`, and a `nonce`.
2. The user authenticates at the provider and consents.
3. The provider redirects back to `/auth/oidc/<provider>/callback?code=…&state=…`.
4. GoZone verifies the `state` (signature + expiry + provider match), exchanges
   the code for tokens using the PKCE verifier, and **verifies the ID token**
   signature (JWKS) and claims (`iss`, `aud`, `exp`, `nonce`).
5. GoZone resolves the local user (existing link, email match, or just-in-time
   provisioning), optionally syncs role/groups from claims, and issues the same
   JWT session cookie as local login.

> GoZone is an **OIDC** client, not a plain OAuth2 client: it requires an
> `id_token`. Providers that only do OAuth2 without an id_token (notably
> GitHub user OAuth) cannot be used directly — see
> [Provider notes](#provider-notes).

The callback endpoint is rate-limited (shared with the login limiter) to
prevent brute-forcing of the `state` parameter.

---

## Prerequisites

- **HTTPS in production.** OIDC redirect URIs and cookies are HTTPS-oriented.
  Run GoZone behind a TLS-terminating reverse proxy and set
  `server.secure_cookies: true` (see the README HTTPS section).
- **A stable `server.secret_key`.** The OIDC `state` parameter is signed with a
  key derived from the master secret; an auto-generated ephemeral key
  invalidates in-flight SSO attempts on every restart.
- **The redirect URI** registered at the provider. It is always:

  ```
  https://<your-gozone-host>/auth/oidc/<provider-name>/callback
  ```

  where `<provider-name>` is the `name:` you give the provider in `config.yaml`.

---

## Configuration reference

All settings live under the top-level `oidc:` key in `config.yaml` and can be
overridden with `GOZONE_OIDC_*` environment variables.

| YAML path | Environment variable | Default | Description |
|-----------|----------------------|---------|-------------|
| `oidc.enabled` | `GOZONE_OIDC_ENABLED` | `false` | Master switch. |
| `oidc.allow_local_login` | `GOZONE_OIDC_ALLOW_LOCAL_LOGIN` | `true` | Keep the username/password form alongside SSO buttons. `false` hides the form (the `POST /login` endpoint stays wired). |
| `oidc.auto_provision` | `GOZONE_OIDC_AUTO_PROVISION` | `false` | Create a local user on first SSO login. `false` requires a pre-linked account. |
| `oidc.default_role` | `GOZONE_OIDC_DEFAULT_ROLE` | `user` | Role for auto-provisioned users (`admin` or `user`). |
| `oidc.scopes` | `GOZONE_OIDC_SCOPES` | `[openid, profile, email]` | Global fallback scopes (`openid` is always added). |
| `oidc.role_claim` | `GOZONE_OIDC_ROLE_CLAIM` | *(none)* | Dotted claim path inspected for role mapping (e.g. `groups`, `realm_access.roles`). Empty disables role mapping. |
| `oidc.admin_role_values` | `GOZONE_OIDC_ADMIN_ROLE_VALUES` | `[]` | Claim values (at `role_claim`) that grant the GoZone `admin` role. |
| `oidc.group_claim` | `GOZONE_OIDC_GROUP_CLAIM` | *(none)* | Dotted claim path inspected for zone-group mapping. Empty disables group mapping. |
| `oidc.group_mapping` | *(YAML only)* | `{}` | Maps an IdP claim value → a GoZone `zone_group` name. |
| `oidc.jwks_cache_ttl_minutes` | `GOZONE_OIDC_JWKS_CACHE_TTL_MINUTES` | `60` | How long a provider's signing keys are cached before a proactive background refresh (so key rotation is picked up without a verification miss). `0` disables proactive refresh (keys are still fetched on first use and on an unknown kid). |

### Per-provider fields (`oidc.providers[]`)

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique slug: URL key (`/auth/oidc/<name>/…`) and preset lookup (`gitea`, `google`, `gitlab`, `keycloak`, `authentik`, `azure`, or any custom name). |
| `issuer_url` | yes | Provider issuer; GoZone fetches `/.well-known/openid-configuration` from it. |
| `client_id` | yes | OAuth2 client ID registered at the provider. |
| `client_secret` | yes | OAuth2 client secret (GoZone is a confidential server-side client). |
| `display_name` | no | Overrides the button label (defaults to the preset display name). |
| `scopes` | no | Per-provider scope override (otherwise `oidc.scopes` / preset). |

---

## Minimal example (one provider)

```yaml
server:
  secret_key: "<openssl rand -hex 32>"
  secure_cookies: true            # behind HTTPS

oidc:
  enabled: true
  auto_provision: true
  default_role: "user"
  providers:
    - name: gitea
      issuer_url: "https://gitea.example.com"
      client_id: "gozone"
      client_secret: "<the secret shown when you register the OAuth2 app>"
```

Register the redirect URI `https://dns-admin.example.com/auth/oidc/gitea/callback`
at the provider, restart GoZone, and a "Sign in with Gitea" button appears on
`/login`.

### Env-only deployment (one provider, no YAML)

```bash
GOZONE_OIDC_ENABLED=true \
GOZONE_OIDC_AUTO_PROVISION=true \
GOZONE_OIDC_PROVIDER_NAME=gitea \
GOZONE_OIDC_ISSUER_URL=https://gitea.example.com \
GOZONE_OIDC_CLIENT_ID=gozone \
GOZONE_OIDC_CLIENT_SECRET=<secret> \
./gozone server
```

`GOZONE_OIDC_SCOPES`, `_ROLE_CLAIM`, `_ADMIN_ROLE_VALUES`, and `_GROUP_CLAIM`
are also honoured. `group_mapping` is YAML-only.

---

## Provider setup examples

The redirect URI is the same shape for every provider — only the host and the
provider name change:

```
https://dns-admin.example.com/auth/oidc/<name>/callback
```

> After registering the client, verify discovery is reachable before relying on
> a provider:
>
> ```bash
> curl -s https://<issuer_url>/.well-known/openid-configuration | head
> ```
>
> If the provider does not return a discovery document, GoZone skips it at
> startup with a `oidc provider discovery failed` warning.

### Gitea

Gitea can act as an OIDC provider (its OAuth2 provider supports the `openid`
scope and issues an `id_token`). Verify your Gitea version exposes the
discovery document at `/.well-known/openid-configuration`.

**At Gitea:**

1. *Site Administration → OAuth2 Applications* (or *User Settings →
   Applications → Register new OAuth2 application* for a user-scoped app).
2. **Redirect URI:** `https://dns-admin.example.com/auth/oidc/gitea/callback`
3. Note the **Client ID** and generated **Client Secret**.
4. Ensure the user has a verified primary email (GoZone maps it on first login).

```yaml
oidc:
  enabled: true
  auto_provision: true
  providers:
    - name: gitea
      issuer_url: "https://gitea.example.com"
      client_id: "<client-id>"
      client_secret: "<client-secret>"
```

To map Gitea organization/team membership onto GoZone roles or zone groups, add
the appropriate claim paths (see
[Role mapping](#role-mapping) and [Group mapping](#group-mapping)).

### Google

**At Google Cloud Console → APIs & Services → Credentials:**

1. *Create Credentials → OAuth client ID → Web application*.
2. **Authorized redirect URI:** `https://dns-admin.example.com/auth/oidc/google/callback`
3. Note the **Client ID** and **Client Secret**.

```yaml
oidc:
  enabled: true
  auto_provision: true
  providers:
    - name: google
      issuer_url: "https://accounts.google.com"
      client_id: "<client-id>.apps.googleusercontent.com"
      client_secret: "<client-secret>"
```

Google issues a verified `email` claim, so existing local accounts with the
same (verified) email are auto-linked on first SSO login when
`auto_provision: true`.

### GitLab (SaaS or self-hosted)

**At GitLab → User Preferences → Applications** (or a group/admin application):

1. **Redirect URI:** `https://dns-admin.example.com/auth/oidc/gitlab/callback`
2. **Scopes:** `openid`, `profile`, `email` (add `read_api` / groups-related
   scopes if you map GitLab groups to GoZone zone groups).

```yaml
oidc:
  enabled: true
  auto_provision: true
  providers:
    - name: gitlab
      issuer_url: "https://gitlab.com"            # or https://gitlab.example.com
      client_id: "<application-id>"
      client_secret: "<secret>"
```

GitLab exposes a `groups` claim when the application is configured to receive
it — use `group_claim: "groups"` to map teams.

### Keycloak

**At Keycloak → your realm → Clients → Create client:**

1. *Client type:* **OpenID Connect**, *Client authentication:* **On**
   (confidential).
2. **Valid redirect URIs:** `https://dns-admin.example.com/auth/oidc/keycloak/callback`
3. Under *Credentials*, copy the **Client secret**.

```yaml
oidc:
  enabled: true
  auto_provision: true
  role_claim: "realm_access.roles"          # Keycloak nested claim
  admin_role_values: ["gozone-admin"]
  providers:
    - name: keycloak
      issuer_url: "https://keycloak.example.com/realms/myrealm"
      client_id: "gozone"
      client_secret: "<client-secret>"
```

Keycloak is the canonical example for the **dotted claim path** feature:
`realm_access.roles` is decoded automatically (see
[Role mapping](#role-mapping)).

### Authentik

**At Authentik:**

1. *Admin interface → Applications → Providers → Create* → **OAuth2/OpenID
   Connect provider**.
2. *Authorization flow:* the explicit-consent (or implicit) flow.
3. Set the provider's **Redirect URI** /
   *Post logout redirect URIs* to:
   `https://dns-admin.example.com/auth/oidc/authentik/callback` (and
   `https://dns-admin.example.com/login` for RP-initiated logout).
4. Bind the provider to an **Application**.

```yaml
oidc:
  enabled: true
  auto_provision: true
  group_claim: "groups"
  group_mapping:
    "dns-admins": "admins"
    "dns-ops": "operations"
  providers:
    - name: authentik
      issuer_url: "https://authentik.example.com/application/o/gozone/"
      client_id: "<client-id>"
      client_secret: "<client-secret>"
```

Authentik puts group membership in the `groups` claim, which maps cleanly to
GoZone zone groups.

### Azure AD (Microsoft Entra ID)

**At Microsoft Entra ID → App registrations → New registration:**

1. **Redirect URI (Web):** `https://dns-admin.example.com/auth/oidc/azure/callback`
2. *Certificates & secrets → New client secret* → copy the **Value**.
3. Use the **v2.0** endpoint as the issuer (it has a stable discovery document).

```yaml
oidc:
  enabled: true
  auto_provision: true
  providers:
    - name: azure
      issuer_url: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<application-(client)-id>"
      client_secret: "<client-secret-value>"
```

> **Group claims:** Azure emits group **object IDs** (not names) in the
> `groups` claim by default, and the claim is only present when *Token
> Configuration → Add groups claim* is enabled. Map the object IDs in
> `group_mapping` accordingly, or configure Azure to emit group names.

### GitHub — not directly supported

GitHub's user OAuth2 apps do **not** issue an `id_token` and do not expose an
OIDC discovery document for user authentication. GoZone's flow requires both,
so GitHub cannot be configured directly as an `oidc.providers` entry.

To let users sign in with their GitHub identity, front GitHub with an
OIDC-capable IdP that federates GitHub and exposes OIDC:

- **Dex** (https://github.com/dexidp/dex) with the GitHub connector,
- **Keycloak** with a GitHub identity provider, or
- **Authentik** with a GitHub source.

Then register that IdP with GoZone (e.g. `name: dex`, `issuer_url: …`) using
the examples above.

---

## Role mapping

`role_claim` + `admin_role_values` make the **IdP authoritative** for a user's
GoZone role. On every SSO login GoZone reads the claim at the dotted path; if
it contains any value from `admin_role_values`, the user is promoted to
`admin`, otherwise they get `default_role`.

```yaml
oidc:
  role_claim: "realm_access.roles"     # or "groups", "roles", …
  admin_role_values: ["gozone-admins", "dns-admins"]
```

- Works with nested claims (Keycloak `realm_access.roles`) and top-level arrays
  (`groups`).
- A demotion `admin → user` that would remove the **last enabled admin** is
  refused (the user keeps `admin` and a warning is logged), so SSO role sync
  can never lock the instance out.

When `role_claim` is empty, role mapping is disabled and `default_role` alone
governs provisioning.

## Group mapping

`group_claim` + `group_mapping` add the user to GoZone `zone_group`s based on
IdP membership.

```yaml
oidc:
  group_claim: "groups"
  group_mapping:
    "dns-admins": "admins"        # IdP group → GoZone zone_group name
    "dns-ops":     "operations"
```

- **Additive only:** memberships are added, never auto-removed (revoke
  manually). This avoids revoking manually-granted memberships.
- The target `zone_group` **must already exist** (create it under *Groups* in
  the UI). A missing group is skipped with a warning.

---

## Single logout (RP-initiated)

When a session was established via SSO and the provider advertises an
`end_session_endpoint` (visible in its discovery document), GoZone's
`POST /logout` first clears the local session and revokes the JWT, then
redirects the browser to the IdP's end-session URL with
`post_logout_redirect_uri=https://<host>/login` so the IdP's SSO cookie is
cleared too. Local-login sessions skip the IdP round-trip and return to
`/login` as before.

Register `https://<host>/login` as a allowed *post-logout redirect URI* at
providers that require it (e.g. Authentik, Keycloak).

---

## Session policy (idle / absolute)

SSO sessions use the same JWT session as local login, so the session-lifetime
knobs apply to both (see README → Authentication):

```yaml
auth:
  session_duration_hours: 8         # access-token (JWT) lifetime
  idle_timeout_minutes: 30          # inactivity forces re-auth
  absolute_session_timeout_hours: 12 # sliding refresh cap; > session_duration_hours
```

When `absolute_session_timeout_hours` is set (and greater than
`session_duration_hours`), the access JWT is **transparently refreshed** near
its expiry while the session stays active and under the cap. Idle and absolute
state is persisted in the `sessions` table, so the limits are enforced
**cluster-wide** across multiple GoZone instances (an in-memory cache coarsens
writes, so cross-instance idle lags by at most ~1 minute).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `oidc provider discovery failed; skipping` at startup | `issuer_url` wrong, or the provider does not expose `/.well-known/openid-configuration` | `curl` the discovery URL; correct `issuer_url`; ensure the provider supports OIDC (GitHub user OAuth does not — see [GitHub](#github--not-directly-supported)). |
| No "Sign in with…" button on `/login` | `oidc.enabled: false`, or no provider could be discovered | Check the startup log; at least one provider must discover successfully. |
| `Single sign-on failed.` after the IdP redirect | `state` mismatch/expired, token verification failed, or the account is disabled / not provisioned | Verify clocks are in sync (JWT `exp`/`iat`); set `auto_provision: true` or pre-link the account; check the server log for the specific `oidc callback:` warning. |
| Provider returns an error about the redirect URI | The callback URL registered at the provider does not match `https://<host>/auth/oidc/<name>/callback` exactly (scheme/host/path) | Re-register the exact redirect URI; remember the `<name>` segment. |
| RP-initiated logout does not reach the IdP | The session was a local login, or the provider has no `end_session_endpoint` | Check the discovery document for `end_session_endpoint`; SSO logout only fires for SSO sessions. |
| Users not promoted to admin | `role_claim` / `admin_role_values` mismatch, or the claim is nested under a different path | Decode the ID token (e.g. `jwt.io`) to confirm the claim path and exact values (case-sensitive). |

---

## See also

- [ROADMAP.md](../ROADMAP.md) — OpenID Connect / OAuth2 section (status & notes).
- [docs/ARCHITECTURE.md](./ARCHITECTURE.md) — Authentication flows.
- [docs/API.md](./API.md) — the REST API uses API keys, not SSO sessions.
