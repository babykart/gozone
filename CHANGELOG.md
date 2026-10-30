
## [v1.0.1] - 2026-10-30

### 🐛 Bug Fixes

- **(api)** ([86e7b3d](https://github.com/babykart/gozone/commit/86e7b3d88bdfbb7f83095b07829c32a4439f7988)) - [gozone] consistent statuses and error envelope - ([babykart](https://github.com/babykart))
- **(apikeys)** ([b836882](https://github.com/babykart/gozone/commit/b8368822e27d014968e3644b2d2508415f0e816d)) - [gozone] serialize concurrent creations per owner - ([babykart](https://github.com/babykart))
- **(auth)** ([35ec2b2](https://github.com/babykart/gozone/commit/35ec2b24681b2bf9917f84c2e198baf3ce759bff)) - [gozone] monotonic credential version closes rotation race - ([babykart](https://github.com/babykart))
- **(auth)** ([b54d1f9](https://github.com/babykart/gozone/commit/b54d1f97eb383a038e201fca5948b927d069deaf)) - [gozone] close the same-second window for API keys - ([babykart](https://github.com/babykart))
- **(authz)** ([03feaf0](https://github.com/babykart/gozone/commit/03feaf04f11aec3495939fef65c6b17bfa6ddba4)) - [gozone] canonicalize zone_id at the route entry - ([babykart](https://github.com/babykart))
- **(cmd)** ([efc17cc](https://github.com/babykart/gozone/commit/efc17cc7d7c0243f44bb757c0613185beb62487e)) - [gozone] fail startup on a mistyped --config path - ([babykart](https://github.com/babykart))
- **(database)** ([dab80c4](https://github.com/babykart/gozone/commit/dab80c46b7af1951818316bdef9242a0830aa712)) - [gozone] record MySQL migrations only after all statements succeed - ([babykart](https://github.com/babykart))
- **(database)** ([72dc07b](https://github.com/babykart/gozone/commit/72dc07b6c27bef6804569bc858a5d22f0f365b54)) - [gozone] stop logging the connection string at startup - ([babykart](https://github.com/babykart))
- **(database)** ([7039513](https://github.com/babykart/gozone/commit/7039513e75285088f246ba3c93a125f21c3643bb)) - [gozone] override an existing TimeZone in postgres URL DSNs - ([babykart](https://github.com/babykart))
- **(database)** ([5a22015](https://github.com/babykart/gozone/commit/5a22015c7d73e4850cf7152ccc5ed7faba118141)) - [gozone] create the real target dir for SQLite file: URIs - ([babykart](https://github.com/babykart))
- **(database)** ([c65225d](https://github.com/babykart/gozone/commit/c65225d32b29a3b80161704dc9613c5e3e153068)) - [gozone] reuse check covers the current password - ([babykart](https://github.com/babykart))
- **(dnsops)** ([c41666c](https://github.com/babykart/gozone/commit/c41666cc1934dd58efefad4921d4d110457e09b1)) - [gozone] coordinate per-zone writes across instances - ([babykart](https://github.com/babykart))
- **(dnsops)** ([f50b04b](https://github.com/babykart/gozone/commit/f50b04b4a153a7dc1174ba5fbbfa826d90daaa32)) - [gozone] add missing zonelock_test - ([babykart](https://github.com/babykart))
- **(dnsops)** ([d94130a](https://github.com/babykart/gozone/commit/d94130a49076ab4e5e65685898be7380d7ee16cf)) - [gozone] snapshot SRV read-path keeps weight and priority - ([babykart](https://github.com/babykart))
- **(export)** ([f3d3bb1](https://github.com/babykart/gozone/commit/f3d3bb1d39d5c53d72b948e5887645a457ee6d02)) - [gozone] neutralize spreadsheet formula triggers in CSV - ([babykart](https://github.com/babykart))
- **(import)** ([2def6f4](https://github.com/babykart/gozone/commit/2def6f42da6dbe6ea418040712d48ee574b3d20c)) - [gozone] reject partial zone imports - ([babykart](https://github.com/babykart))
- **(import)** ([3ac82ef](https://github.com/babykart/gozone/commit/3ac82ef01908111a143a7cdbbc2d889b0ad1aa8b)) - [gozone] serialize zone import behind the shared per-zone lock - ([babykart](https://github.com/babykart))
- **(import)** ([a625007](https://github.com/babykart/gozone/commit/a625007f73fc50aff28a0f6d51bcad2643fb5b6a)) - [gozone] resolve relative BIND RDATA names against - ([babykart](https://github.com/babykart))
- **(mcp)** ([5a74083](https://github.com/babykart/gozone/commit/5a74083bdb4479e285e0b24f1f2a6c308466dc1d)) - [gozone] truncate CSV exports at complete record boundaries - ([babykart](https://github.com/babykart))
- **(oidc)** ([fbddb34](https://github.com/babykart/gozone/commit/fbddb34e17a3b0e6ab74a7d5f774c490a6a1271a)) - [gozone] delete the stored id token at logout, always - ([babykart](https://github.com/babykart))
- **(oidc)** ([a42d515](https://github.com/babykart/gozone/commit/a42d5155af33c50a99355df54c37ef1bdb0d7245)) - [gozone] refuse a conflicting external-identity link - ([babykart](https://github.com/babykart))
- **(records)** ([ec293b2](https://github.com/babykart/gozone/commit/ec293b201acfe354d0b85880df8b9bb72b7d28ae)) - [gozone] reject stale record edits - ([babykart](https://github.com/babykart))
- **(server)** ([f7e2f0e](https://github.com/babykart/gozone/commit/f7e2f0ed0abc79bbde59675e64952db852ee736c)) - [gozone] bound startup, readiness and shutdown paths - ([babykart](https://github.com/babykart))
- **(tsig)** ([2b37fa4](https://github.com/babykart/gozone/commit/2b37fa408938f2e116b67fc980468f3e7868f674)) - [gozone] serialize keep-secret update per key - ([babykart](https://github.com/babykart))
- **(web)** ([79964ab](https://github.com/babykart/gozone/commit/79964ab6e6b7278bbf7ac4f81eeef87b59627ab4)) - [gozone] sync RRSet TTL and comments across inline-edit rows - ([babykart](https://github.com/babykart))
- **(web)** ([7654055](https://github.com/babykart/gozone/commit/7654055d4f7c82ac3aa62e319c7daa06c20f1fa2)) - [gozone] reachable no-JS record edit with per-row identity - ([babykart](https://github.com/babykart))
- **(web)** ([2e70c91](https://github.com/babykart/gozone/commit/2e70c913518cb2193b2b6fbb8507a628aaef8528)) - [gozone] gate DNSSEC key actions behind the admin block - ([babykart](https://github.com/babykart))
- **(web)** ([b3e4518](https://github.com/babykart/gozone/commit/b3e451881198d4ea5133d3fec330ddd6fb191031)) - [gozone] keep the bulk-delete summary across the reload - ([babykart](https://github.com/babykart))
- **(zones)** ([989a966](https://github.com/babykart/gozone/commit/989a96636a70fa5eace1dd8cd5f5d9e8c74b8df4)) - [gozone] validate the selected template before zone creation - ([babykart](https://github.com/babykart))
- **(zones)** ([4faa2ea](https://github.com/babykart/gozone/commit/4faa2ea581d07e1f0be0ebebb6b3a5782ebfb5c2)) - [gozone] expose and validate masters on all create surfaces - ([babykart](https://github.com/babykart))

### 📚 Documentation

- ([c91de36](https://github.com/babykart/gozone/commit/c91de36cee8e97be6861e95f8b96dbddc269ee25)) - [gozone] align README, SSO guide, Dockerfile and architecture docs - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(database)** ([f2dbc62](https://github.com/babykart/gozone/commit/f2dbc622ff76861cf668bba967221c060f449c2d)) - [gozone] portable id retrieval in all test seeds - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
