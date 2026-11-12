
## [v1.2.0] - 2026-11-12

### ⚙️  Build Tasks

- **(docker)** ([0acc6cd](https://github.com/babykart/gozone/commit/0acc6cdc1a5fe0a5f32711084cabd79290e5f720)) - [gozone] bump alpine to 3.24 - ([babykart](https://github.com/babykart))

### 🚀 Features

- **(cli)** ([33a68c6](https://github.com/babykart/gozone/commit/33a68c68e6a56f6090ec7f996bba4fbea6df3f23)) - [gozone] default emergency user commands to non-migrating opens - ([babykart](https://github.com/babykart))
- **(config)** ([cdba4c1](https://github.com/babykart/gozone/commit/cdba4c19c888119b6ce2cf8d9aa962ffaeceb791)) - [gozone] add global per-username login rate limit - ([babykart](https://github.com/babykart))
- **(config)** ([e62e228](https://github.com/babykart/gozone/commit/e62e228b523d76533836aca654f5959d3b657510)) - [gozone] add configurable zone cache TTL - ([babykart](https://github.com/babykart))
- **(database)** ([1b8a7de](https://github.com/babykart/gozone/commit/1b8a7de9d1254296453d0230e68026d9db8572e6)) - [gozone] export NewWithOpener for driver interception - ([babykart](https://github.com/babykart))
- **(database)** ([ce0de03](https://github.com/babykart/gozone/commit/ce0de039ecad289e22d7f99e453fca9468d66a4a)) - [gozone] add duplicate-safe insert across dialects - ([babykart](https://github.com/babykart))
- **(database)** ([b570109](https://github.com/babykart/gozone/commit/b570109ccbfd0eb8366806f16427e5bd61f535de)) - [gozone] add no-migration opens, pool size config and legacy version guard - ([babykart](https://github.com/babykart))
- **(oidc)** ([e44ffd6](https://github.com/babykart/gozone/commit/e44ffd602b134145b33808cb40f41924b82fa6c6)) - [gozone] consume sso states cluster-wide - ([babykart](https://github.com/babykart))

### 💼 Other

- ([4e99df8](https://github.com/babykart/gozone/commit/4e99df838b01b09865c5ca6aa0a62e6629d5e42a)) - Merge branch 'workflow/fix-stats-info-leak' - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(api)** ([0e04d39](https://github.com/babykart/gozone/commit/0e04d39b17c0d5594926869f386ec33a1d8e6b3d)) - [gozone] name the missing record on write-stage 404s - ([babykart](https://github.com/babykart))
- **(audit)** ([226d755](https://github.com/babykart/gozone/commit/226d7551d0b0fe075edb7b5d462c01aa90470b94)) - [gozone] keep the audit row when the client disconnects - ([babykart](https://github.com/babykart))
- **(auth)** ([270a5e0](https://github.com/babykart/gozone/commit/270a5e04d5f483ebedddebd9b0a8e1f7998e42ea)) - [gozone] rate-limit login per username and source IP - ([babykart](https://github.com/babykart))
- **(auth)** ([4c98afa](https://github.com/babykart/gozone/commit/4c98afa460abf2905bd2750d60a5d6b4efb1b0bf)) - [gozone] reject same-as-current password on change - ([babykart](https://github.com/babykart))
- **(auth)** ([fe1ea2e](https://github.com/babykart/gozone/commit/fe1ea2e2194373836f62f4ea50d3a6c326ba9698)) - [gozone] write CLI reset-password audit after commit - ([babykart](https://github.com/babykart))
- **(auth)** ([f6313e4](https://github.com/babykart/gozone/commit/f6313e48e6a20b74e6d8b9dc9001074d79db7988)) - [gozone] preserve session identity on password change - ([babykart](https://github.com/babykart))
- **(auth)** ([54fd7c1](https://github.com/babykart/gozone/commit/54fd7c14e6f2b3efe63e76b26d8d13117a417831)) - [gozone] rate-limit change-password attempts - ([babykart](https://github.com/babykart))
- **(auth)** ([46baee1](https://github.com/babykart/gozone/commit/46baee1f749e300dc24cb96ff3a31b4499b2ddab)) - [gozone] give SSO routes a dedicated per-IP rate limit - ([babykart](https://github.com/babykart))
- **(auth)** ([beccc59](https://github.com/babykart/gozone/commit/beccc59ffd1e6d47ffe9974de8498830544dba0f)) - [gozone] align login failure timing and bcrypt cost bands - ([babykart](https://github.com/babykart))
- **(cmd)** ([86c381a](https://github.com/babykart/gozone/commit/86c381ac8ba14c1faef6511ae7e61cb002d275ec)) - [gozone] cache only successful static responses - ([babykart](https://github.com/babykart))
- **(config)** ([90a6bd9](https://github.com/babykart/gozone/commit/90a6bd9821afd6b477e33e4f8b3f9af85b645c3e)) - [gozone] accept an empty or comments-only config file - ([babykart](https://github.com/babykart))
- **(config)** ([4a5c725](https://github.com/babykart/gozone/commit/4a5c72599f4913a6167951ca227fc0425571a2c8)) - [gozone] reject unsatisfiable password length policy - ([babykart](https://github.com/babykart))
- **(config)** ([7980cfa](https://github.com/babykart/gozone/commit/7980cfad4d88fdec12dbb2d4a1bc578cfbeac1cb)) - [gozone] require external url when oidc is enabled - ([babykart](https://github.com/babykart))
- **(database)** ([a14ae34](https://github.com/babykart/gozone/commit/a14ae349a6fce338e2988809dd244d81024fdfc3)) - [gozone] upsert SSO ID tokens atomically per dialect - ([babykart](https://github.com/babykart))
- **(database)** ([21449e1](https://github.com/babykart/gozone/commit/21449e1d42a0a8a3e1886e597170bb5d674527c3)) - [gozone] exempt PG lock transactions from idle timeout - ([babykart](https://github.com/babykart))
- **(database)** ([5ef472f](https://github.com/babykart/gozone/commit/5ef472f8cd463b32f1f857aa2a4798f86945d54d)) - [gozone] normalize purge cutoffs and make duplicate inserts FK-fatal - ([babykart](https://github.com/babykart))
- **(dnsops)** ([76b5954](https://github.com/babykart/gozone/commit/76b595440d0278d9ed5217cc5463e3c4e28fe0ca)) - [gozone] reject conflicting embedded MX/SRV priority - ([babykart](https://github.com/babykart))
- **(dnsops)** ([b39fd1c](https://github.com/babykart/gozone/commit/b39fd1c316602293c5d2faf9c7cd666463a7d995)) - [gozone] match RRSets case-insensitively on merges - ([babykart](https://github.com/babykart))
- **(dnsops)** ([69afb0a](https://github.com/babykart/gozone/commit/69afb0a783ad4e886cd8fc93f76cb2baba7af812)) - [gozone] bound zone lock state with a hashed semaphore pool - ([babykart](https://github.com/babykart))
- **(dnsops)** ([8b1c7d6](https://github.com/babykart/gozone/commit/8b1c7d6785c87d89358ab4edecd5f51d6724f660)) - [gozone] gate record TTLs and validate zone nameservers - ([babykart](https://github.com/babykart))
- **(dnsops)** ([bd22503](https://github.com/babykart/gozone/commit/bd225036da1cf1fedda21506d72a971088620bee)) - [gozone] own RRSet comment metadata at the service layer - ([babykart](https://github.com/babykart))
- **(groups)** ([ab82676](https://github.com/babykart/gozone/commit/ab82676cf7df7fe8571e7f55c1d6b25a78ec5002)) - [gozone] make group association audits transactional - ([babykart](https://github.com/babykart))
- **(handlers)** ([4bf5b08](https://github.com/babykart/gozone/commit/4bf5b08271373234c6a99346f820c73ea7e70086)) - [gozone] map record priority conflicts to validation errors - ([babykart](https://github.com/babykart))
- **(handlers)** ([21273be](https://github.com/babykart/gozone/commit/21273be05fd68eca99e166125044975f517f5ed3)) - [gozone] match RRSets case-insensitively on merges and deletes - ([babykart](https://github.com/babykart))
- **(handlers)** ([8cadd3d](https://github.com/babykart/gozone/commit/8cadd3d137b84096f24fbcb92c4787ee08e486f9)) - [gozone] cap zone view All page size at 1000 rows - ([babykart](https://github.com/babykart))
- **(handlers)** ([158db7d](https://github.com/babykart/gozone/commit/158db7d482fb428d2e4ba83b315ae52d7c229eec)) - [gozone] merge BIND/CSV imports into existing record sets - ([babykart](https://github.com/babykart))
- **(handlers)** ([593ee2b](https://github.com/babykart/gozone/commit/593ee2b2a003fb4efb18da740466ab611e27c4c1)) - [gozone] scope operator activity view to zone entries - ([babykart](https://github.com/babykart))
- **(handlers)** ([1b937fb](https://github.com/babykart/gozone/commit/1b937fba8033ae10ed36526ea13c81f3032cff05)) - [gozone] deduplicate records on web edit - ([babykart](https://github.com/babykart))
- **(handlers)** ([a58611e](https://github.com/babykart/gozone/commit/a58611e304039bb56ddadebb75312af468c2e711)) - [gozone] keep no-store on error pages - ([babykart](https://github.com/babykart))
- **(handlers)** ([405c85b](https://github.com/babykart/gozone/commit/405c85bd7acb985df0914abe76cf786b7915f720)) - [gozone] fail dashboard closed on zone-list outage - ([babykart](https://github.com/babykart))
- **(handlers)** ([b56ab88](https://github.com/babykart/gozone/commit/b56ab88aa197984bb770d28c9e890928df212f74)) - [gozone] surface activity filter warnings and all-view cap - ([babykart](https://github.com/babykart))
- **(handlers)** ([863e255](https://github.com/babykart/gozone/commit/863e2555c1f034c77279e74ea62a32d9b51432ec)) - [gozone] harden bind import quoting and directives - ([babykart](https://github.com/babykart))
- **(handlers)** ([20a7f86](https://github.com/babykart/gozone/commit/20a7f868cec9705e2268b1962b9fd763c1cfb263)) - [gozone] surface invalid ids, priorities and template record failures - ([babykart](https://github.com/babykart))
- **(handlers)** ([052ac7f](https://github.com/babykart/gozone/commit/052ac7fa1bf24f677aa1b411810445c5792c43c9)) - [gozone] bound record TTLs at form, batch and import intakes - ([babykart](https://github.com/babykart))
- **(logger)** ([1cc71d3](https://github.com/babykart/gozone/commit/1cc71d3785f1ab43d733ef0301887cc57d96512b)) - [gozone] make the default logger swap-safe - ([babykart](https://github.com/babykart))
- **(mcpserver)** ([e46f44b](https://github.com/babykart/gozone/commit/e46f44ba5bb8975df959f0e3fce2a2cd9d403f27)) - [gozone] map priority conflicts to validation errors - ([babykart](https://github.com/babykart))
- **(mcpserver)** ([4533134](https://github.com/babykart/gozone/commit/45331343dcaff33ba1e064ed4d99280947c0382b)) - [gozone] accept underscore and slash zone identifiers - ([babykart](https://github.com/babykart))
- **(middleware)** ([0976f4a](https://github.com/babykart/gozone/commit/0976f4a3c5634ec8d17580b23c1464f9e4621687)) - [gozone] harden session tokens, api key policy and rate limit keys - ([babykart](https://github.com/babykart))
- **(middleware)** ([2d0c496](https://github.com/babykart/gozone/commit/2d0c496b16df9f13509a628e5905895358da6a6c)) - [gozone] trust the rightmost forwarded proto value - ([babykart](https://github.com/babykart))
- **(migrations)** ([c7cdc1b](https://github.com/babykart/gozone/commit/c7cdc1be1bf7187a928fc450e6e82cea36fd5312)) - [gozone] guard migration statements with savepoints - ([babykart](https://github.com/babykart))
- **(oidc)** ([d81b372](https://github.com/babykart/gozone/commit/d81b3723a0c55c5841b2c1bbab6292d435c93cf7)) - [gozone] parse id tokens as compact JWS - ([babykart](https://github.com/babykart))
- **(pdns)** ([d8c184b](https://github.com/babykart/gozone/commit/d8c184be5033d6cb64b758c3c6e055469244251e)) - [gozone] honor caller context while waiting on singleflight - ([babykart](https://github.com/babykart))
- **(sso)** ([64b742e](https://github.com/babykart/gozone/commit/64b742e23194b98240799ac6c8055325df9671e3)) - [gozone] map operator role values in SSO role claim - ([babykart](https://github.com/babykart))
- **(sso)** ([a4facc4](https://github.com/babykart/gozone/commit/a4facc4c71b6c9cf00a9dfc9fc2b8f5912ec1bf5)) - [gozone] audit SSO group membership additions - ([babykart](https://github.com/babykart))
- **(stats)** ([cbc3f58](https://github.com/babykart/gozone/commit/cbc3f589f51ae74abf3cf4f42e23c9d90bebba17)) - [gozone] withhold ring and map statistics from non-DNS-admins - ([babykart](https://github.com/babykart))
- **(ui)** ([7e99e6b](https://github.com/babykart/gozone/commit/7e99e6b08f7f849d25fbd24016301372979b2f90)) - [gozone] reload only on stale inline-edit conflicts - ([babykart](https://github.com/babykart))
- **(ui)** ([cef2fb6](https://github.com/babykart/gozone/commit/cef2fb6e49cbee0c542777cae50594bc372360ed)) - [gozone] disable pagination boundary links accessibly - ([babykart](https://github.com/babykart))
- **(users)** ([e00befa](https://github.com/babykart/gozone/commit/e00befa80a935a8fe93fa722add947853f1d9a3b)) - [gozone] record role and enabled transitions in update audit - ([babykart](https://github.com/babykart))
- **(validators)** ([5593296](https://github.com/babykart/gozone/commit/559329601d3935e50561b1b789d398f52ed12d4a)) - [gozone] tighten HINFO, CAA and TTL record validation - ([babykart](https://github.com/babykart))
- **(zones)** ([fc99e14](https://github.com/babykart/gozone/commit/fc99e14a88892617d31e1e1b7180466cee80d54b)) - [gozone] canonicalize zone IDs for admins and form deletes - ([babykart](https://github.com/babykart))
- **(zones)** ([9efe71d](https://github.com/babykart/gozone/commit/9efe71d9fc9e2092def7d9bff9943eca8dbd5277)) - [gozone] bound zone lock waits, 409 ZONE_BUSY on contention - ([babykart](https://github.com/babykart))
- **(zones)** ([b3d6547](https://github.com/babykart/gozone/commit/b3d6547ef6e7ada988f04097f34ad00eeda56b35)) - [gozone] audit successful zone NOTIFY requests - ([babykart](https://github.com/babykart))

### 🚜 Refactor

- **(config)** ([2b231b3](https://github.com/babykart/gozone/commit/2b231b3a7429cbb96f7cc85013acbec5098649fd)) - [gozone] consolidate trusted proxy parsing - ([babykart](https://github.com/babykart))
- **(dnsops)** ([17e003f](https://github.com/babykart/gozone/commit/17e003f039a459515cfe5bc3a265ceecdd19ebe7)) - [gozone] converge web record writes onto the service - ([babykart](https://github.com/babykart))
- **(handlers)** ([bbc27c2](https://github.com/babykart/gozone/commit/bbc27c2fa9b7ea8f164ab3e0665732d9e3564516)) - [gozone] route zone exports through the service - ([babykart](https://github.com/babykart))
- **(handlers)** ([f7eb06e](https://github.com/babykart/gozone/commit/f7eb06e8f642603a9076595b945e2a7caf1f5a6d)) - [gozone] collapse viewzone fetch goroutines into a helper - ([babykart](https://github.com/babykart))
- **(handlers)** ([bdc6892](https://github.com/babykart/gozone/commit/bdc689237bd59d3baaa2d842940d2260fae7a9ad)) - [gozone] deduplicate record content doc comment - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(api)** ([c8be4e5](https://github.com/babykart/gozone/commit/c8be4e56b50ea62c4b2c632d0b098cfd6d005f9b)) - [gozone] document SRV embedded priority consistency rule - ([babykart](https://github.com/babykart))
- **(api)** ([2b32c15](https://github.com/babykart/gozone/commit/2b32c1540695c784a9c123b9005a3af402a51d7e)) - [gozone] document TTL range and server-owned comment metadata - ([babykart](https://github.com/babykart))
- **(auth)** ([3ff2c62](https://github.com/babykart/gozone/commit/3ff2c62d1e74f3ddb41e1b4911e6e920065f3b30)) - [gozone] document dedicated SSO rate-limit budget - ([babykart](https://github.com/babykart))
- **(readme)** ([3eab6da](https://github.com/babykart/gozone/commit/3eab6daf586030d1d073caf2af93a79b21c7cd2e)) - [gozone] document import merge and replace modes - ([babykart](https://github.com/babykart))
- **(readme)** ([b9ec36f](https://github.com/babykart/gozone/commit/b9ec36f155d857d79a9311866dde366513687c1f)) - [gozone] document zone cache TTL setting - ([babykart](https://github.com/babykart))
- **(sso)** ([7cd8a0b](https://github.com/babykart/gozone/commit/7cd8a0ba0b75e06370e13065e653d48be733cb1e)) - [gozone] require external url and document cluster state consumption - ([babykart](https://github.com/babykart))
- ([f5341d7](https://github.com/babykart/gozone/commit/f5341d70d1374d30f375e8c658a26c2f8a23f04c)) - [gozone] qualify CLI audit writes as best-effort - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(handlers)** ([0e716af](https://github.com/babykart/gozone/commit/0e716afeafff362c74d5cae3c997cd7758a0ff48)) - [gozone] parallelize independent tests - ([babykart](https://github.com/babykart))
- ([c42faad](https://github.com/babykart/gozone/commit/c42faadb3cd089403f6712c86350083d9b39d344)) - [gozone] characterize zone id, lock and intake error paths - ([babykart](https://github.com/babykart))

### 🌀 Miscellaneous Tasks

- ([28434d1](https://github.com/babykart/gozone/commit/28434d1b9876a391d415a4242715a7dbc8cf08be)) - [gozone] raise coverage floor and report dialect coverage - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
