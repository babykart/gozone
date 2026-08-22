
## [v0.17.0] - 2026-08-22

### 🚀 Features

- **(api-keys)** ([868a4ad](https://github.com/babykart/gozone/commit/868a4ada10bce185318f1d28c8b89475ce442b74)) - [gozone] optional expiry and per-user cap for API keys - ([babykart](https://github.com/babykart))
- **(config)** ([1b0691d](https://github.com/babykart/gozone/commit/1b0691dfacb10e0b99f42a470855a319a0fca762)) - [gozone] add GOZONE_LOG_LEVEL environment override - ([babykart](https://github.com/babykart))
- **(groups)** ([7b3d5e1](https://github.com/babykart/gozone/commit/7b3d5e15ef876132203fc48f2e99fef08fce900a)) - [gozone] filter member and zone selects on the group form - ([babykart](https://github.com/babykart))
- **(password)** ([4c1ef46](https://github.com/babykart/gozone/commit/4c1ef460b2983e1c8b3e46c48f0416adcc440ba8)) - [gozone] enforce bcrypt's 72-byte limit with a clear error - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(api)** ([31aec77](https://github.com/babykart/gozone/commit/31aec77a737382dbf4b1be60955c317d51a8b98d)) - [gozone] JSON envelope for middleware rejections on /api/v1 - ([babykart](https://github.com/babykart))
- **(auth)** ([64c76a6](https://github.com/babykart/gozone/commit/64c76a62ce442718edd9999db2796d69269ea95b)) - [gozone] guard the nil ExpiresAt dereference in Logout - ([babykart](https://github.com/babykart))
- **(database)** ([43e6223](https://github.com/babykart/gozone/commit/43e62231bbc290f23ee95b8ba2240bf9d0d3dea5)) - [gozone] redact passwords in URL-form DSNs at startup - ([babykart](https://github.com/babykart))
- **(docker)** ([44e041d](https://github.com/babykart/gozone/commit/44e041dbbc474967e480f7808e1c5f1128f5f73b)) - [gozone] targeted source COPY so vendor layer caching is real - ([babykart](https://github.com/babykart))
- **(export)** ([3a45bb1](https://github.com/babykart/gozone/commit/3a45bb16c3df20eb996de81950c495a267cd6223)) - [gozone] make sortRRSets a strict weak ordering - ([babykart](https://github.com/babykart))
- **(groups)** ([f593bc7](https://github.com/babykart/gozone/commit/f593bc713a0a214d66d2fe9b7505cbfed9dc5d29)) - [gozone] batch the member-existence IN lookup past driver limits - ([babykart](https://github.com/babykart))
- **(handlers)** ([a5718b1](https://github.com/babykart/gozone/commit/a5718b1f48a25b89ff7135609c765e0fc036612c)) - [gozone] type-check row ids before binding INTEGER columns - ([babykart](https://github.com/babykart))
- **(handlers)** ([a3f6878](https://github.com/babykart/gozone/commit/a3f687878609c09e05ea25a049cf7468d06d4d6f)) - [gozone] surface zone-access lookup failures as 500 - ([babykart](https://github.com/babykart))
- **(handlers)** ([6d5c4a6](https://github.com/babykart/gozone/commit/6d5c4a67aa951c2f66ee283b5823da65ee5d9899)) - [gozone] propagate request context through group/zone helpers - ([babykart](https://github.com/babykart))
- **(handlers)** ([54a13b3](https://github.com/babykart/gozone/commit/54a13b3ae1b7d2566fc7e9886a0411be4d9eab9a)) - [gozone] escape LIKE wildcards in user search terms - ([babykart](https://github.com/babykart))
- **(oidc)** ([af56342](https://github.com/babykart/gozone/commit/af56342a31d952f4d233b4d2f11cb09396479e32)) - [gozone] return SSO providers in configuration order - ([babykart](https://github.com/babykart))
- **(oidc)** ([361f40f](https://github.com/babykart/gozone/commit/361f40f003f157f484211b17a87bf7ca1cbc9703)) - [gozone] intersect IdP-advertised signing algs with accepted set - ([babykart](https://github.com/babykart))
- **(oidc)** ([b70030e](https://github.com/babykart/gozone/commit/b70030ef2a5f4dc2c5b0bb40246035437e6ae0cd)) - [gozone] tolerate non-boolean email_verified claims - ([babykart](https://github.com/babykart))
- **(oidc)** ([43aa314](https://github.com/babykart/gozone/commit/43aa3147a9faa19e390ce74e1f06769a8b927720)) - [gozone] honor external_url for the post-logout redirect - ([babykart](https://github.com/babykart))
- **(records)** ([ae41254](https://github.com/babykart/gozone/commit/ae4125457d48ceb5426195892f70399688ef61c8)) - [gozone] keep existing RRSet TTL when adding a record - ([babykart](https://github.com/babykart))
- **(security)** ([c512bff](https://github.com/babykart/gozone/commit/c512bffc9d013fa0fb3a5503c3dbda3417feac59)) - [gozone] bound the per-username rate-limit bucket key - ([babykart](https://github.com/babykart))
- **(security)** ([adf3627](https://github.com/babykart/gozone/commit/adf3627c48bb7c51f7a077814fbedfc7bdf978fa)) - [gozone] rate-limit the unauthenticated readiness endpoint - ([babykart](https://github.com/babykart))
- **(seed)** ([06b43a0](https://github.com/babykart/gozone/commit/06b43a04efebcbfe8ade71df8eafbd4545315499)) - [gozone] record the bootstrap password's age anchor explicitly - ([babykart](https://github.com/babykart))
- **(templates)** ([df37b1b](https://github.com/babykart/gozone/commit/df37b1b42685860778db113f8cbecdf3fc5d178f)) - [gozone] make template variable substitution deterministic - ([babykart](https://github.com/babykart))
- **(templates)** ([b458f77](https://github.com/babykart/gozone/commit/b458f77b29936212fe24b1855bd04c2b4cc68372)) - [gozone] validate records at template apply time - ([babykart](https://github.com/babykart))
- **(tsigkeys)** ([d59a854](https://github.com/babykart/gozone/commit/d59a85454ad3ec984ba0da5ecddcca250bf93737)) - [gozone] reveal server-generated TSIG secrets once - ([babykart](https://github.com/babykart))
- **(validators)** ([96d133a](https://github.com/babykart/gozone/commit/96d133aaa79ae73c5dc7b9ec95c060d48bed6b16)) - [gozone] reject IPv4-mapped literals as IPv4 content - ([babykart](https://github.com/babykart))

### 🚜 Refactor

- **(internal)** ([27e2526](https://github.com/babykart/gozone/commit/27e25265addb999d32fbeafbc22fb59f1be4c55c)) - [gozone] remove production-dead code kept alive by tests - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(ai)** ([2bab595](https://github.com/babykart/gozone/commit/2bab595acfd9b548a93a4d72faabdaf89f7607dd)) - [gozone] update AGENTS.md - ([babykart](https://github.com/babykart))
- **(config)** ([53f09c9](https://github.com/babykart/gozone/commit/53f09c94ce5560efd5df1f44045a7b146d14a6e6)) - [gozone] complete Load's env-var inventory, lock it with a test - ([babykart](https://github.com/babykart))
- **(docker)** ([dc47377](https://github.com/babykart/gozone/commit/dc47377332bc3202c69fc89ac6cd3cc0229597bf)) - [gozone] align healthcheck comments with the liveness probe - ([babykart](https://github.com/babykart))

### ⚡ Performance

- **(activity)** ([1b78870](https://github.com/babykart/gozone/commit/1b78870c6dd791b26c46fc82206e48a71d552b9d)) - [gozone] single summary log entry for imports and batches - ([babykart](https://github.com/babykart))
- **(api)** ([161ab27](https://github.com/babykart/gozone/commit/161ab27d4597251a40375dc40bd722ee1a88e398)) - [gozone] coarsen api_keys.last_used_at writes - ([babykart](https://github.com/babykart))
- **(groups)** ([282dc91](https://github.com/babykart/gozone/commit/282dc9109e4ec9307a9c40fca0d35ee894ffff0b)) - [gozone] cap and server-search the group form dropdowns - ([babykart](https://github.com/babykart))

### 🌀 Miscellaneous Tasks

- **(build)** ([4d5b829](https://github.com/babykart/gozone/commit/4d5b829b66389155bade3862425712b1af0e3053)) - [gozone] make local test targets match CI flags - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
