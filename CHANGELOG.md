
## [v0.16.0] - 2026-07-12

### 🚀 Features

- **(auth)** ([eb5f0ab](https://github.com/babykart/gozone/commit/eb5f0ab8567454c406f648820bd3f34776731889)) - [gozone] add OpenID Connect/OAuth2 SSO - ([babykart](https://github.com/babykart))
- **(auth)** ([590a168](https://github.com/babykart/gozone/commit/590a168703cdbaa066b4a1747f3fcb205db488f1)) - [gozone] OIDC role/group claim mapping and RP-initiated logout - ([babykart](https://github.com/babykart))
- **(auth)** ([1ea7ecb](https://github.com/babykart/gozone/commit/1ea7ecb5a907fe1cf9629fbe514f6f65315bd6e1)) - [gozone] idle session timeout and transparent session refresh - ([babykart](https://github.com/babykart))
- **(auth)** ([3532deb](https://github.com/babykart/gozone/commit/3532deb46929cb0e8a3e4f6d921cf8e10add505c)) - [gozone] DB-backed shared idle/absolute session enforcement - ([babykart](https://github.com/babykart))
- **(docker)** ([ad04fab](https://github.com/babykart/gozone/commit/ad04fabac652f07a3c8c9a54a4de4ace9be5fc2b)) - [gozone] add image-level HEALTHCHECK, drop compose duplicate - ([babykart](https://github.com/babykart))
- **(frontend)** ([3ed0742](https://github.com/babykart/gozone/commit/3ed07420fd8a5c807cf5124445c14d12bf888276)) - [gozone] accessibility: skip link, label associations, custom confirm modal - ([babykart](https://github.com/babykart))
- **(oidc)** ([4a3428b](https://github.com/babykart/gozone/commit/4a3428b6d5d157cca81ad89ef742509133b5a7cc)) - [gozone] operator-tunable JWKS cache TTL with proactive rotation - ([babykart](https://github.com/babykart))

### 💼 Other

- ([7ad4838](https://github.com/babykart/gozone/commit/7ad4838a7f3ed710e620cb1b8dde0a3fae989c5f)) - Merge pull request #31 from babykart/feat/oidc-oauth2-auth

Add OpenID Connect / OAuth2 - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(api)** ([e3089b1](https://github.com/babykart/gozone/commit/e3089b1b108d3236ecefa3ac119fe70df4fe535c)) - [gozone] merge POST /records into existing RRSet instead of replacing - ([babykart](https://github.com/babykart))
- **(db)** ([5dd0e3d](https://github.com/babykart/gozone/commit/5dd0e3dc52d53e7c297fdc86d9f2c2e7520aa3cd)) - [gozone] use INSERT ... RETURNING for portable row-id retrieval - ([babykart](https://github.com/babykart))
- **(db)** ([aa02d7c](https://github.com/babykart/gozone/commit/aa02d7c1b644b9a1d445d5f3bb2a9351c83c44b5)) - [gozone] scan MySQL GET_LOCK return value before running migrations - ([babykart](https://github.com/babykart))
- **(db)** ([cbacdcd](https://github.com/babykart/gozone/commit/cbacdcdc950b516f0887230c8be3f21d0ba57c06)) - [gozone] acquire admin-set lock before target row in IsLastEnabledAdmin - ([babykart](https://github.com/babykart))
- **(db)** ([cf7e288](https://github.com/babykart/gozone/commit/cf7e2880cca5e3cd23703029480f9f2176927187)) - [gozone] skip placeholders inside SQL literals in rebindDollar - ([babykart](https://github.com/babykart))
- **(db)** ([c0c9ac4](https://github.com/babykart/gozone/commit/c0c9ac42b4f6041a56f6e5ce3402fb35a6384cd2)) - [gozone] index case-insensitive email lookup via generated email_lc column - ([babykart](https://github.com/babykart))
- **(db)** ([ddd67bf](https://github.com/babykart/gozone/commit/ddd67bf811507240f31997f82e95a07b82680351)) - [gozone] use isNoRows helper instead of raw sql.ErrNoRows comparison - ([babykart](https://github.com/babykart))
- **(db)** ([dc56fde](https://github.com/babykart/gozone/commit/dc56fde15cb87b961033e939f8e317a71b8a6bd6)) - [gozone] record seed admin password history and make bootstrap race-safe - ([babykart](https://github.com/babykart))
- **(db)** ([4246b67](https://github.com/babykart/gozone/commit/4246b67b4b786fe73853740ca9ed05db51ef5d9d)) - [gozone] use UTC cutoff in CleanupRevokedTokens to match JWT-exp writes - ([babykart](https://github.com/babykart))
- **(db)** ([877ec79](https://github.com/babykart/gozone/commit/877ec7973597a79962937e2e1628dac02354e867)) - [gozone] read FailedLoginStats count and last in one consistent query - ([babykart](https://github.com/babykart))
- **(frontend)** ([2ee7cfa](https://github.com/babykart/gozone/commit/2ee7cfa20a1c08bd2cb79d5f2db074bc0250dc54)) - [gozone] cache-bust app.js/style.css via content-hash query param - ([babykart](https://github.com/babykart))
- **(handlers)** ([f2df513](https://github.com/babykart/gozone/commit/f2df513a5b3d7fe749969e5dbd99bbfd68eebf9e)) - [gozone] validate record type/content in templates and imports - ([babykart](https://github.com/babykart))
- **(handlers)** ([75c03e3](https://github.com/babykart/gozone/commit/75c03e3857a0ec67ee39cc3d4d0926e701c3b0ef)) - [gozone] buffer template render and avoid leaking internal errors - ([babykart](https://github.com/babykart))
- **(handlers)** ([4381e6c](https://github.com/babykart/gozone/commit/4381e6cbb9b28ba1cdaeb26721fd9c6494cc9048)) - [gozone] return 500 and log error on PowerDNS failure in EditRecordPage - ([babykart](https://github.com/babykart))
- **(handlers)** ([b80ac2e](https://github.com/babykart/gozone/commit/b80ac2e84f0cfaaea23925dab161c9d49f75b2be)) - [gozone] reject empty email in UpdateUser for consistency with CreateUser - ([babykart](https://github.com/babykart))
- **(handlers)** ([5ab152b](https://github.com/babykart/gozone/commit/5ab152bce39276734d5f61be13f17c021a320667)) - [gozone] surface friendly error on duplicate username/email in CreateUser - ([babykart](https://github.com/babykart))
- **(handlers)** ([a769604](https://github.com/babykart/gozone/commit/a769604b256e4b7c9cc277024eb40c44b35b98e0)) - [gozone] surface DELETE failure in DeleteGroup instead of silent redirect - ([babykart](https://github.com/babykart))
- **(handlers)** ([52192ae](https://github.com/babykart/gozone/commit/52192ae5d48743255cd61f2d653e93fb698807b9)) - [gozone] align bulk-delete activity log format with rrsetSnapshot - ([babykart](https://github.com/babykart))
- **(handlers)** ([5901d76](https://github.com/babykart/gozone/commit/5901d76638279a63a941f60fd04a28a19166ac14)) - [gozone] clamp totalPages to 1 for empty result sets - ([babykart](https://github.com/babykart))
- **(handlers)** ([3c80f4a](https://github.com/babykart/gozone/commit/3c80f4a4eb541b48c04ca7c26e4211846f44866d)) - [gozone] validate group member existence before insertion - ([babykart](https://github.com/babykart))
- **(handlers)** ([8dd77f6](https://github.com/babykart/gozone/commit/8dd77f6abf374cae88ccfc1e42a318611ea662a5)) - [gozone] reset page to 1 when pagination is disabled - ([babykart](https://github.com/babykart))
- **(middleware)** ([f897775](https://github.com/babykart/gozone/commit/f8977754f2980682a9946b586f15b016180ca7f4)) - [gozone] propagate cross-instance idle session denial - ([babykart](https://github.com/babykart))
- **(middleware)** ([cc9a9f4](https://github.com/babykart/gozone/commit/cc9a9f4ab4cbd6d30c46458921edb5bd8b170238)) - [gozone] bind session/API-key timestamps to UTC - ([babykart](https://github.com/babykart))
- **(oidc)** ([2b72dba](https://github.com/babykart/gozone/commit/2b72dba19738a833ba8b92fb1c1594f0b00561de)) - [gozone] send nonce in authorization request so SSO login works - ([babykart](https://github.com/babykart))
- **(oidc)** ([7437edb](https://github.com/babykart/gozone/commit/7437edbf826eba418336038ce20873f85246b3b2)) - [gozone] clone oauth2.Config per request to eliminate RedirectURL race - ([babykart](https://github.com/babykart))
- **(records)** ([b543e39](https://github.com/babykart/gozone/commit/b543e398fd38487f3ee4110b8f58bca60364c3fe)) - [gozone] reject invalid TTL/priority in BatchCreateRecords - ([babykart](https://github.com/babykart))
- **(security)** ([2f2a426](https://github.com/babykart/gozone/commit/2f2a42664d7222d2e353134fa4268f0ff43e4be9)) - [gozone] derive CSRF cookie Secure flag per-request from TLS context - ([babykart](https://github.com/babykart))
- **(security)** ([9c22389](https://github.com/babykart/gozone/commit/9c22389c6cec56988d8a107a1b5551a935810aac)) - [gozone] enforce server-side single-use for OIDC state tokens - ([babykart](https://github.com/babykart))
- **(templates)** ([f118d43](https://github.com/babykart/gozone/commit/f118d43ca2ce6078b0f058939cb4a2a473fe562e)) - [gozone] guard nil-pointer deref on .Comments.Items in zone_view and record_edit - ([babykart](https://github.com/babykart))
- **(validators)** ([800cfa0](https://github.com/babykart/gozone/commit/800cfa009faeea9b1fb647055158f079f92a5afe)) - [gozone] reject SOA content with extra fields - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(deploy)** ([98d221a](https://github.com/babykart/gozone/commit/98d221a7e0ff90c94499f7577d483307b81c875a)) - [gozone] warn about default secrets in docker-compose.yml - ([babykart](https://github.com/babykart))
- **(oidc)** ([f2b3a34](https://github.com/babykart/gozone/commit/f2b3a345f8cc6fc79fb4db50e39ee6c8b0311850)) - [gozone] document SSO and add provider configuration examples - ([babykart](https://github.com/babykart))
- **(oidc)** ([a871fd0](https://github.com/babykart/gozone/commit/a871fd068ec8318753220b010b19dd5ca7ea583b)) - [gozone] document SameSite=Lax choice for the SSO session cookie - ([babykart](https://github.com/babykart))
- **(roadmap)** ([0e01b9b](https://github.com/babykart/gozone/commit/0e01b9b9ad8ae63b02b1700effa40b05071a1820)) - [gozone] trim completed OIDC items, keep follow-ups as todos - ([babykart](https://github.com/babykart))

### ⚡ Performance

- **(cache)** ([c5fdeba](https://github.com/babykart/gozone/commit/c5fdebae2a1121a411fb696600cd31857c9f1161)) - [gozone] proactively evict expired entries on Get - ([babykart](https://github.com/babykart))
- **(handlers)** ([4044caf](https://github.com/babykart/gozone/commit/4044caf779011a61e84bee7686553b2af041db73)) - [gozone] hoist loop-invariant pagination bounds in ListTSIGKeys - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(cmd)** ([821f1bd](https://github.com/babykart/gozone/commit/821f1bddc0c1fbbce51f5ed1f3316a37979e802d)) - [gozone] lock admin routing table behind RequireAdmin - ([babykart](https://github.com/babykart))
- **(handlers)** ([160ff29](https://github.com/babykart/gozone/commit/160ff29de010a2aea871db31cdc3865e83550f71)) - [gozone] lock transactional audit for delete/demote - ([babykart](https://github.com/babykart))
- **(oidc)** ([1cbca2e](https://github.com/babykart/gozone/commit/1cbca2ee85d3d166d290a7d69fd648274d14246e)) - cover singleflight panic recovery, OIDC nonce - ([babykart](https://github.com/babykart))

### 🌀 Miscellaneous Tasks

- **(pr)** ([982ebd8](https://github.com/babykart/gozone/commit/982ebd877434b11567a451c986c2a451e57ddf13)) - [gozone] add govulncheck and test coverage reporting to PR checks - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
