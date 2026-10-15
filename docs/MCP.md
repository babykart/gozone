# MCP — exposer GoZone aux agents IA

GoZone embarque un serveur [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) qui permet aux agents (Claude Code, Claude Desktop, connecteurs distants)
de gérer zones et enregistrements DNS **avec exactement les droits de la clé
API utilisée** — pas plus.

## Principe de sécurité

L'endpoint MCP est monté derrière la **même pile middleware que `/api/v1`** :

```
rate limit par IP (pré-auth) → authentification par clé API → rate limit par clé
```

- Authentification **par clé API** (`X-API-Key: <clé>` ou `Authorization: Bearer <clé>`).
  Le cookie de session web n'est jamais accepté sur `/mcp`.
- Les limiters sont **les mêmes instances** que ceux de `/api/v1` : un client qui
  alterne REST et MCP puise dans un seul budget.
- L'autorisation par zone (fail-closed) et les droits admin sont re-vérifiés
  dans la couche service (`internal/dnsops`) partagée avec l'API REST : une clé
  non-admin ne voit que les zones de ses groupes ; `create_zone`/`delete_zone`
  exigent une clé admin.
- Chaque écriture est auditée dans `activity_logs` avec le libellé **`via MCP`**
  et le `user_id` du propriétaire de la clé.
- Le serveur est **sans état** (stateless Streamable HTTP) : chaque requête est
  authentifiée indépendamment — compatible multi-instance derrière un load
  balancer.

## Activation

```yaml
mcp:
  enabled: false            # GOZONE_MCP_ENABLED
  path: /mcp                # GOZONE_MCP_PATH
  read_only: true           # GOZONE_MCP_READ_ONLY
  allowed_origins: []       # GOZONE_MCP_ALLOWED_ORIGINS (CSV)
```

| Option | Défaut | Rôle |
|---|---|---|
| `enabled` | `false` | Monte (ou non) l'endpoint. Désactivé = route absente (404). |
| `path` | `/mcp` | Chemin de l'endpoint. Validé : ne doit pas chevaucher `/api`, `/static`, `/health`, … |
| `read_only` | `true` | `true` : seuls les tools lecture sont **enregistrés** (ils n'apparaissent même pas dans `tools/list`). Recommandé pour un premier déploiement. |
| `allowed_origins` | `[]` | Origins navigateurs autorisés (protection DNS-rebinding exigée par la spec Streamable HTTP). Une requête portant un `Origin` non listé est rejetée (403). Les clients sans en-tête `Origin` (CLI, agents) passent toujours. Vide = tout `Origin` présent est rejeté. |

### Créer une clé API dédiée

1. Interface web → **Profile → API Keys → Create** (voir le README).
2. Recommandations : une clé **par agent**, utilisateur dédié non-admin
   restreint par groupes de zones, expiration courte, `read_only: true`
   pour commencer.

## Tools

| Tool | Équivalent REST | Droits | Annotations |
|---|---|---|---|
| `list_zones` | `GET /api/v1/zones` | tout utilisateur (filtré par groupes) | read-only |
| `get_zone` (`zone`) | `GET /api/v1/zones/{id}` | accès zone | read-only |
| `list_records` (`zone`, `name?`, `type?`) | `GET …/records` | accès zone | read-only |
| `get_stats` | `GET /api/v1/stats` | tout utilisateur | read-only |
| `list_record_types` | — | tout utilisateur | read-only |
| `create_record` (`zone`, `name`, `type`, `ttl?`, `records[]`) | `POST …/records` | accès zone | écriture, non idempotent |
| `update_record` (`zone`, `name`, `type`, `ttl?`, `records[]`, `clear_comments?`) | `PUT …/records` | accès zone | écriture, idempotent, **destructive** (REPLACE) |
| `delete_record` (`zone`, `name`, `type`) | `DELETE …/records` | accès zone | **destructive**, idempotent |
| `create_zone` (`name`, `kind?`, `nameservers[]`) | `POST /api/v1/zones` | **admin** | écriture |
| `delete_zone` (`zone`) | `DELETE /api/v1/zones/{id}` | **admin** | **destructive** |

Conventions héritées de l'API REST (documentées dans chaque description de
tool, car c'est ce qui évite le plus d'erreurs côté LLM) :

- `zone` = l'ID canonique renvoyé par `list_zones` (minuscule + point final,
  ex. `example.com.`) ; `name` accepte `@`, un label nu (`www`), un FQDN sans
  le point final, ou un FQDN complet — la canonicalisation est faite côté
  serveur.
- MX/SRV : `priority` en champ séparé de chaque enregistrement (incrusté dans
  le contenu au moment de l'écriture).
- TXT/SPF : contenu nu, le quoting est automatique.
- `update_record` est un **REPLACE** : la liste soumise remplace l'ensemble
  (`list_records` d'abord pour ne rien perdre).

Erreurs : résultat `isError: true` + message `CODE: description` avec un code
stable (`ZONE_NOT_FOUND`, `FORBIDDEN`, `VALIDATION_ERROR`, `RECORD_NOT_FOUND`,
`CONFLICT`, `UPSTREAM_AUTH_ERROR`, `INTERNAL_ERROR`, …). Jamais de détail
interne (DSN, réponse brute PowerDNS) — la cause complète part dans les logs
serveur.

## Configuration client

### Claude Code

```bash
claude mcp add --transport http gozone https://gozone.example.com/mcp \
  --header "X-API-Key: VOTRE_CLE_API"
```

### Claude Desktop / autre client Streamable HTTP

URL : `https://gozone.example.com/mcp`, en-tête `X-API-Key: <clé>` (ou
`Authorization: Bearer <clé>`).

### Vérification

Le [MCP Inspector](https://github.com/modelcontextprotocol/inspector) :

```bash
npx @modelcontextprotocol/inspector
# transport: Streamable HTTP, URL: http://localhost:8080/mcp,
# header: X-API-Key: <clé>
```

## Hors périmètre (v1)

DNSSEC (cryptokeys), clés TSIG, utilisateurs/groupes, import de zone,
métadonnées — pas de surface MCP plus large que l'API publique. Les
resources/prompts MCP (export BIND en contexte, audit de zone) sont prévus
en phase ultérieure (voir `MCP_PLAN.md`).
