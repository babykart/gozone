
## [v0.19.0] - 2026-10-04

### 🚀 Features

- **(sso)** ([d20f31e](https://github.com/babykart/gozone/commit/d20f31ee817984e828daa5c095119372fe2dd372)) - [gozone] gate new email links and provisioning on allowed_email_domains - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(a11y)** ([acf2cbc](https://github.com/babykart/gozone/commit/acf2cbcbfb70089bd22c744f2c5fe02cd67f6f85)) - [gozone] label inline fields, aria-current nav, handle clipboard rejections - ([babykart](https://github.com/babykart))
- **(activity)** ([05f8a64](https://github.com/babykart/gozone/commit/05f8a64cbe36c17052c81f053f436007d1a0c41d)) - [gozone] cap the All activity-log view at 1000 rows to prevent unbounded snapshot fetches - ([babykart](https://github.com/babykart))
- **(api)** ([1371c61](https://github.com/babykart/gozone/commit/1371c61c7636a1e122ac5008e8e524b7aafa9b0b)) - [gozone] log all REST mutations to the activity trail with before/after snapshots - ([babykart](https://github.com/babykart))
- **(api)** ([c461fae](https://github.com/babykart/gozone/commit/c461fae44c751ea4d1b4bafffc6812d6ada743f6)) - [gozone] resolve absent/zero TTL from the existing RRSet (default 3600) and reject negative TTL on record create/update - ([babykart](https://github.com/babykart))
- **(api)** ([5401103](https://github.com/babykart/gozone/commit/5401103b157a25b1732d8e1060c40be84d16bdb5)) - [gozone] map PowerDNS auth failures to 502 UPSTREAM_AUTH_ERROR, not 401 - ([babykart](https://github.com/babykart))
- **(api)** ([03a8a5e](https://github.com/babykart/gozone/commit/03a8a5e49f8211e93b2ca97e4589e458c113b985)) - [gozone] consistent error statuses for inline/bulk edits and missing zones - ([babykart](https://github.com/babykart))
- **(api)** ([8e218fc](https://github.com/babykart/gozone/commit/8e218fc82a30477d7bfa9074edc4389f4901964f)) - [gozone] surface zone-list failures in stats instead of zone_count 0 - ([babykart](https://github.com/babykart))
- **(audit)** ([048cd22](https://github.com/babykart/gozone/commit/048cd225608ae17f6e4a7aba85d97cdbddc75dda)) - [gozone] log every group and template mutation to the activity trail - ([babykart](https://github.com/babykart))
- **(auth)** ([8632478](https://github.com/babykart/gozone/commit/86324788622191945b0cc4d139eadc34518b1af1)) - [gozone] block JWT replay after idle/absolute session denial - ([babykart](https://github.com/babykart))
- **(auth)** ([79e68b4](https://github.com/babykart/gozone/commit/79e68b42d354d93b95b847a0674d2def4e1b8ba6)) - [gozone] refuse API keys of manually locked owners and keys predating the tokens_valid_after rotation cutoff - ([babykart](https://github.com/babykart))
- **(auth)** ([e6628be](https://github.com/babykart/gozone/commit/e6628be728ee07a5a95cfd53dca9b9b5a1167f07)) - [gozone] send RP-initiated logout through a meta-refresh interstitial so CSP form-action cannot block the IdP end-session redirect - ([babykart](https://github.com/babykart))
- **(auth)** ([f16f7d1](https://github.com/babykart/gozone/commit/f16f7d1854eab8f1dbca432dd3f7a713ae9e99c2)) - [gozone] refuse POST /login when allow_local_login is false with SSO on - ([babykart](https://github.com/babykart))
- **(auth)** ([8576d5c](https://github.com/babykart/gozone/commit/8576d5cd9672393f147bf31fa35c2342f70a2a51)) - [gozone] store passwords verbatim (no silent space trimming) - ([babykart](https://github.com/babykart))
- **(build)** ([510e936](https://github.com/babykart/gozone/commit/510e9360c472202eb5a6cda9049ca6d82fccc0a7)) - [gozone] require git-cliff only in release recipes - ([babykart](https://github.com/babykart))
- **(build)** ([9c2253d](https://github.com/babykart/gozone/commit/9c2253dc2d68be0b2a20a5f44986e2a3894a67c9)) - [gozone] gofmt -s in fmt targets, fail make staticcheck/gosec when tool missing - ([babykart](https://github.com/babykart))
- **(cli)** ([4cd2c01](https://github.com/babykart/gozone/commit/4cd2c01809b7df52f3f29a1e8fbd61e71615d923)) - [gozone] resolve the --version flag like the version subcommand - ([babykart](https://github.com/babykart))
- **(config)** ([9c8863f](https://github.com/babykart/gozone/commit/9c8863f7e0a0df0cd31d49c5e62ffdf076ffacb8)) - [gozone] strict YAML, driver aliases, lockout/retention coupling, require_secret_key - ([babykart](https://github.com/babykart))
- **(database)** ([315d1e3](https://github.com/babykart/gozone/commit/315d1e3451aeda604442255fc37376500edc3d05)) - [gozone] unbreak SQLite upgrade on populated users - ([babykart](https://github.com/babykart))
- **(database)** ([c3d9342](https://github.com/babykart/gozone/commit/c3d9342516f838652b2ba1230db1860c10b9c7b0)) - [gozone] make session cutoffs UTC and second-aligned - ([babykart](https://github.com/babykart))
- **(database)** ([599ba08](https://github.com/babykart/gozone/commit/599ba08f5fc3e19abbe70358697a71627d3a8f80)) - [gozone] make PrunePasswordHistory run on MySQL - ([babykart](https://github.com/babykart))
- **(database)** ([01b3dd4](https://github.com/babykart/gozone/commit/01b3dd41ecee8ab8a80117e22ae76815ce8e4d90)) - [gozone] drop the untracked-populated-database shortcut so missing tables and columns are migrated instead of silently skipped - ([babykart](https://github.com/babykart))
- **(database)** ([340e5e3](https://github.com/babykart/gozone/commit/340e5e32cf60a982d3252c6599e646b73905da1e)) - [gozone] atomic per-dialect rate-limit upsert replacing the deadlock-prone - ([babykart](https://github.com/babykart))
- **(database)** ([2e95eb0](https://github.com/babykart/gozone/commit/2e95eb03a180185d6006f47d40d6b3ee22d26c94)) - [gozone] append SQLite DSN pragmas by concatenation so the file path is opened verbatim - ([babykart](https://github.com/babykart))
- **(database)** ([2f68380](https://github.com/babykart/gozone/commit/2f683808ea3dededfb569d16ddeeabb0f91db08f)) - [gozone] claim migration versions in-transaction to survive concurrent instances - ([babykart](https://github.com/babykart))
- **(database)** ([5a5428c](https://github.com/babykart/gozone/commit/5a5428c73a66e66a0fee3fe5396b6cbb0bb9a3fd)) - [gozone] bounded, pgbouncer-safe migration locks - ([babykart](https://github.com/babykart))
- **(database)** ([6989df6](https://github.com/babykart/gozone/commit/6989df6219e69977cf706c263b5b7e1a4f532ccf)) - [gozone] tolerate already-exists per statement and name the revoked_tokens FK - ([babykart](https://github.com/babykart))
- **(database)** ([dbff090](https://github.com/babykart/gozone/commit/dbff090fcb657131888065c323c806e38d5ccd29)) - [gozone] close the pool when New fails at ping or migrate - ([babykart](https://github.com/babykart))
- **(database)** ([e59cbe4](https://github.com/babykart/gozone/commit/e59cbe4f87bd9e459ada7e5a238cc88f1bf26a4e)) - [gozone] redact quoted PostgreSQL passwords entirely in sanitizeDSN - ([babykart](https://github.com/babykart))
- **(database)** ([98e7398](https://github.com/babykart/gozone/commit/98e7398aa4727261911392d40264bbf7dc1113e8)) - [gozone] drop UNIQUE-duplicating indexes, add rate-limit purge index - ([babykart](https://github.com/babykart))
- **(export)** ([0a67902](https://github.com/babykart/gozone/commit/0a679029ffdce535cbc1d2dd3f2e807fb7c3e2bd)) - [gozone] preserve multi-string TXT/SPF wire form through CSV export/import round-trip - ([babykart](https://github.com/babykart))
- **(groups)** ([ebe452a](https://github.com/babykart/gozone/commit/ebe452ae67b5ecb4aa21d8b29275ac89ab073cf0)) - [gozone] guard grant reconciliation against empty/cached zone lists - ([babykart](https://github.com/babykart))
- **(import)** ([306c4f8](https://github.com/babykart/gozone/commit/306c4f89522cadbeb5fb43455b185aa988cde14f)) - [gozone] track BIND parentheses by quote-aware depth counter so same-line pairs close and quoted parens stay literal - ([babykart](https://github.com/babykart))
- **(import)** ([4388ed7](https://github.com/babykart/gozone/commit/4388ed78638398e6fe53159e78796f80a540928b)) - [gozone] resolve CSV record names against the zone (relative names and @) like the BIND path instead of appending a bare trailing dot - ([babykart](https://github.com/babykart))
- **(oidc)** ([57982ab](https://github.com/babykart/gozone/commit/57982ab5d55ddf153233d63041b125493d01fd1e)) - [gozone] enforce the manual admin lock (fail-closed) on SSO callback like local login - ([babykart](https://github.com/babykart))
- **(oidc)** ([b470d33](https://github.com/babykart/gozone/commit/b470d33e22b9561219e76c0a7fdffc7f052cd39b)) - [gozone] bind the OIDC state to the browser via a short-lived HttpOnly cookie to block login CSRF - ([babykart](https://github.com/babykart))
- **(oidc)** ([e832c2c](https://github.com/babykart/gozone/commit/e832c2c88b839e6995b5824d1c46dabb2dd61ca7)) - [gozone] drop the github preset — GitHub user OAuth issues no id_token - ([babykart](https://github.com/babykart))
- **(pagination)** ([a5befda](https://github.com/babykart/gozone/commit/a5befda69eb652e257e2dc8b2ad1572eadbb3002)) - [gozone] clamp log pages to the last page before offset math - ([babykart](https://github.com/babykart))
- **(pdns)** ([b43cee7](https://github.com/babykart/gozone/commit/b43cee7d96578cebfceeb09dec33a80e52014c30)) - [gozone] close cache store TOCTOU and detach singleflight fetch from leader context - ([babykart](https://github.com/babykart))
- **(rate-limit)** ([f71c751](https://github.com/babykart/gozone/commit/f71c751e8b695d034bc48a85f81d681245139b19)) - [gozone] key the IP fallback on the host, not host:port - ([babykart](https://github.com/babykart))
- **(records)** ([c50cf5d](https://github.com/babykart/gozone/commit/c50cf5df5c24f4f11185b7939cbb175e4f7ffbae)) - [gozone] canonicalize record type to uppercase at every entry point (API, forms, batch, delete, templates) - ([babykart](https://github.com/babykart))
- **(records)** ([668f76e](https://github.com/babykart/gozone/commit/668f76e792067d9fade5462a7451310789b13ce6)) - [gozone] serialize per-zone read-modify-write record mutations with an in-process zone lock - ([babykart](https://github.com/babykart))
- **(records)** ([de85222](https://github.com/babykart/gozone/commit/de85222820590f66fab9dec957cdc2abafc7db5e)) - [gozone] answer 409 on edits whose original_content no longer matches a multi-record RRSet instead of silently appending a duplicate - ([babykart](https://github.com/babykart))
- **(records)** ([399e2d7](https://github.com/babykart/gozone/commit/399e2d72b1e3ab493b30f614321f32fb7fa32de0)) - [gozone] auto-quote CAA value, HINFO cpu/os and URI target in wire format and accept quoted-with-spaces CAA values plus issuemail/issuevmc tags - ([babykart](https://github.com/babykart))
- **(records)** ([7b5f3ac](https://github.com/babykart/gozone/commit/7b5f3acb27cbae64d845baf2c79569633fdb4903)) - [gozone] resync inline edit row with server-normalized record - ([babykart](https://github.com/babykart))
- **(records)** ([b99ad91](https://github.com/babykart/gozone/commit/b99ad917f834ef190258220729e544504bb5b647)) - [gozone] deduplicate merged records on create (web and API) like the batch path - ([babykart](https://github.com/babykart))
- **(records)** ([86db1d4](https://github.com/babykart/gozone/commit/86db1d43326347b528a3581b7d782a27cc2030dd)) - [gozone] inherit RRSet TTL on empty create/edit and reject conflicting batch TTLs - ([babykart](https://github.com/babykart))
- **(security)** ([0e10d76](https://github.com/babykart/gozone/commit/0e10d7632f398e989780cf73aac4171591871dbf)) - [gozone] serve all rendered pages with Cache-Control: no-store - ([babykart](https://github.com/babykart))
- **(security)** ([5bc80c1](https://github.com/babykart/gozone/commit/5bc80c1f96ebd576e47f4eba93f06e7628d72e2f)) - [gozone] reject protocol-relative paths in error-page backURL - ([babykart](https://github.com/babykart))
- **(security)** ([43aacdb](https://github.com/babykart/gozone/commit/43aacdb7c399770af09532a58b7cefa79784f84a)) - [gozone] restrict zone cache flush to admins (global blast radius) - ([babykart](https://github.com/babykart))
- **(security)** ([79309e6](https://github.com/babykart/gozone/commit/79309e6d91e503ecdcec643d694417d428d79399)) - [gozone] secure session timeout defaults and indefinite manual admin lock - ([babykart](https://github.com/babykart))
- **(security)** ([820f29c](https://github.com/babykart/gozone/commit/820f29c3d29dd663e9dc87b0f3592be52bf14bf2)) - [gozone] fail closed on nil user in zone filters - ([babykart](https://github.com/babykart))
- **(server)** ([5bf03ba](https://github.com/babykart/gozone/commit/5bf03ba5c1074f42ba6179fc9ed2d64de0c53763)) - [gozone] ordered shutdown: defer job stops early, wait in-flight runs, force close on drain timeout - ([babykart](https://github.com/babykart))
- **(templates)** ([2a85dab](https://github.com/babykart/gozone/commit/2a85dab1013b5b6124756d49e6e72ed1bbe9d95b)) - [gozone] group template RRs into one RRSet per name+type - ([babykart](https://github.com/babykart))
- **(templates)** ([78ce55c](https://github.com/babykart/gozone/commit/78ce55c5afb1129985a285e4a3ef796723edc4d5)) - [gozone] merge template records into existing zone RRSets instead of silently replacing them - ([babykart](https://github.com/babykart))
- **(ui)** ([7d3d536](https://github.com/babykart/gozone/commit/7d3d536a7bea6546204e77c64183fe743561235e)) - [gozone] carry the batch per-row Clear-all-comments flag - ([babykart](https://github.com/babykart))
- **(ui)** ([78aabd5](https://github.com/babykart/gozone/commit/78aabd563c614e40ecec6ee9f3beb64a7519c71e)) - [gozone] keep activity filters across pagination - ([babykart](https://github.com/babykart))
- **(ui)** ([2d8ef6b](https://github.com/babykart/gozone/commit/2d8ef6beda146454dbd3ddbaea584b2f69c19f06)) - [gozone] guard localStorage access so blocked storage cannot kill the page - ([babykart](https://github.com/babykart))
- **(ui)** ([f5d6f90](https://github.com/babykart/gozone/commit/f5d6f90be8d0fdd9f454cbd0b3fd532f7d53d847)) - [gozone] respect the selected TSIG algorithm when generating key material - ([babykart](https://github.com/babykart))
- **(ui)** ([a377783](https://github.com/babykart/gozone/commit/a3777836b3b6b5548226730aa853a1af5ee98b46)) - [gozone] cancel stale notification timers and drive visibility via classList - ([babykart](https://github.com/babykart))
- **(users)** ([91aed71](https://github.com/babykart/gozone/commit/91aed7189e76517c1a69598cf30c9e330869edbf)) - [gozone] enforce case-insensitive username/email uniqueness via lowercased generated columns and lowercase normalization at every write site - ([babykart](https://github.com/babykart))
- **(validators)** ([bdb7818](https://github.com/babykart/gozone/commit/bdb78188204ae3e3162982887c8686be6c57b4cd)) - [gozone] accept the root label . as MX (null MX), SRV target and NAPTR replacement - ([babykart](https://github.com/babykart))
- **(validators)** ([2212fa5](https://github.com/babykart/gozone/commit/2212fa58f4cd64fb97eb0067b283d82d288df763)) - [gozone] reject bare single-label record targets instead of dotting them into TLDs - ([babykart](https://github.com/babykart))
- **(validators)** ([7ca8ac5](https://github.com/babykart/gozone/commit/7ca8ac51b23888a1b995149e814f74822671e3a7)) - [gozone] validate TXT/SPF content - ([babykart](https://github.com/babykart))
- **(zones)** ([4325ece](https://github.com/babykart/gozone/commit/4325ece393babd013b0eabb28f878974b5c7f7a1)) - [gozone] purge group zone grants immediately on zone delete instead of waiting for the hourly reconciliation - ([babykart](https://github.com/babykart))
- **(zones)** ([15c647c](https://github.com/babykart/gozone/commit/15c647c8a3171002feb17bcb3c286281513773ac)) - [gozone] validate metadata kind on delete against the create whitelist - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(readme)** ([ce3f557](https://github.com/babykart/gozone/commit/ce3f55771c2327c316ac6385ec8ff6b30ee6ec8b)) - [gozone] document GOZONE_BCRYPT_COST and describe the OIDC state as encrypted - ([babykart](https://github.com/babykart))
- ([851b2c3](https://github.com/babykart/gozone/commit/851b2c3b21e10dc3927203caa85ec2e4e4e1628e)) - [gozone] align test FuncMap docs with reality and add the missing relativeName stub - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(database)** ([774341c](https://github.com/babykart/gozone/commit/774341c8a5b493356274ec728b0504f88bd25965)) - [gozone] route generic suites through the dialect matrix, drop LastInsertId - ([babykart](https://github.com/babykart))
- ([7a323f7](https://github.com/babykart/gozone/commit/7a323f7b8472eaf92a1fc21b858b88f857e9eb24)) - [gozone] cover cache sweep directly and make TestStartPeriodicJob race-stable - ([babykart](https://github.com/babykart))
- ([b8635d1](https://github.com/babykart/gozone/commit/b8635d1fc7a61e343712b238ef16d4e59b0fdff7)) - [gozone] close sensitive-path coverage gaps (SSO role guard, OIDC login, PatchRecords, bulk/per-page JS) - ([babykart](https://github.com/babykart))

### 🌀 Miscellaneous Tasks

- **(cleanup)** ([1506b81](https://github.com/babykart/gozone/commit/1506b81ea5030e33d7e68353093beb4159daaebd)) - [gozone] drop dead code (unused handlers, duplicated URL check, dead route, console.log) - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
