
## [v0.13.0] - 2026-07-01

### ⚙️  Build Tasks

- **(docker)** ([e06a675](https://github.com/babykart/gozone/commit/e06a675539eacc950cc1a099afc259d9b93287a7)) - [gozone] tighten Dockerfile deps/ownership and pin pdns image - ([babykart](https://github.com/babykart))

### 🚀 Features

- **(config)** ([bc48eb1](https://github.com/babykart/gozone/commit/bc48eb1a60d753409492da2e9ed09beb50f89fe8)) - [gozone] make graceful shutdown timeout configurable - ([babykart](https://github.com/babykart))
- **(middleware)** ([286cd6d](https://github.com/babykart/gozone/commit/286cd6d291c72c005968ed6c95b849da2fad779d)) - [gozone] cap request body size to prevent OOM - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(api)** ([946bbfb](https://github.com/babykart/gozone/commit/946bbfb5e11af5393f4a0ab3bad233f7a977e554)) - [gozone] rate-limit by IP before APIKeyAuth to prevent DB DoS - ([babykart](https://github.com/babykart))
- **(auth)** ([4cf08b0](https://github.com/babykart/gozone/commit/4cf08b0693f696072511b5a4774a6a1bdcd29bda)) - [gozone] close timing oracle on locked accounts - ([babykart](https://github.com/babykart))
- **(auth)** ([927c0b6](https://github.com/babykart/gozone/commit/927c0b64a544f5dd9f89547c6ab4bcea822a7d7f)) - [gozone] extend lockout window on further failures - ([babykart](https://github.com/babykart))
- **(auth)** ([a777887](https://github.com/babykart/gozone/commit/a7778877d4d3bcf1398de908cb1addf989252611)) - [gozone] add CSRF error banner so users see a message - ([babykart](https://github.com/babykart))
- **(auth)** ([ef71814](https://github.com/babykart/gozone/commit/ef7181423428abaf54a82370cec4972e0dd3a9c9)) - [gozone] restrict JWT verification to HS256 only - ([babykart](https://github.com/babykart))
- **(cli)** ([2c09c9b](https://github.com/babykart/gozone/commit/2c09c9b507a60a2a6e247b286098e8b43f9978ce)) - [gozone] log correct actor identity in unlock activity log - ([babykart](https://github.com/babykart))
- **(config)** ([dc42e62](https://github.com/babykart/gozone/commit/dc42e621932da56372f8eaa9266aa16d4ec76881)) - [gozone] harden secret key placeholder detection and enforce min length - ([babykart](https://github.com/babykart))
- **(config)** ([3257361](https://github.com/babykart/gozone/commit/325736101b0ecb0b116ee7dd1fc85a68004e99c6)) - [gozone] fail fast on invalid env overrides instead of silent fallback - ([babykart](https://github.com/babykart))
- **(config)** ([3d32ca9](https://github.com/babykart/gozone/commit/3d32ca91f4a038f98f26ad25bc2ec515630b73d8)) - [gozone] validate host, pdns url/server_id, dsn, log level, admin user - ([babykart](https://github.com/babykart))
- **(config)** ([15b693e](https://github.com/babykart/gozone/commit/15b693e3c59c22fe6ccf77ba8c7b8578b78d539f)) - [gozone] validate host, pdns url/server_id, dsn, log level, admin user - ([babykart](https://github.com/babykart))
- **(database)** ([743b593](https://github.com/babykart/gozone/commit/743b5935f8dd9d3b577fc191f07764d96dfa203b)) - [gozone] route RevokeToken through InsertIgnore for MySQL compatibility - ([babykart](https://github.com/babykart))
- **(database)** ([5830123](https://github.com/babykart/gozone/commit/58301231ca4bbeaf846808eb1b381210f3dfa3da)) - [gozone] use dialect-specific timestamp type for schema_migrations - ([babykart](https://github.com/babykart))
- **(database)** ([32315d5](https://github.com/babykart/gozone/commit/32315d548f99cc752b06248a5169db186e510a84)) - [gozone] pin single connection for migration lock lifecycle - ([babykart](https://github.com/babykart))
- **(database)** ([21de95c](https://github.com/babykart/gozone/commit/21de95cb368e7fa847532d9501eb7bad7d912ce8)) - [gozone] remove unusedwrite warnings in database_test.go - ([babykart](https://github.com/babykart))
- **(database)** ([89b88d8](https://github.com/babykart/gozone/commit/89b88d89b9563066cf3f1162a41b48505ed05bf3)) - [gozone] complete connection pool tuning with idle conns and lifetime - ([babykart](https://github.com/babykart))
- **(database)** ([1a8e823](https://github.com/babykart/gozone/commit/1a8e823eb0637405e1a4af2f2ad5d1fd5d8a008e)) - [gozone] run each migration in a transaction - ([babykart](https://github.com/babykart))
- **(database)** ([f2aaafe](https://github.com/babykart/gozone/commit/f2aaafe369d945207e33a1ab855908b44e81d21a)) - [gozone] detect wrapped sql.ErrNoRows via errors.Is - ([babykart](https://github.com/babykart))
- **(database)** ([c9d999a](https://github.com/babykart/gozone/commit/c9d999a7562142d33981c124529482e8628bffab)) - [gozone] detect wrapped sql.ErrNoRows via errors.Is - ([babykart](https://github.com/babykart))
- **(database)** ([670bd51](https://github.com/babykart/gozone/commit/670bd515dcebb80b18e233a67ee4100eb22f5ef7)) - [gozone] make IncrementFailedLogins atomic in one transaction - ([babykart](https://github.com/babykart))
- **(database)** ([01ba0f7](https://github.com/babykart/gozone/commit/01ba0f741912689d8fd54352c9aaad3abc2f5284)) - [gozone] redact passwords in MySQL unix-socket DSNs - ([babykart](https://github.com/babykart))
- **(database)** ([f65eb07](https://github.com/babykart/gozone/commit/f65eb0777d01c4a6ab6cc1e4d97c9be150bb6f91)) - [gozone] add DESC to MySQL idx_activity_logs_zone_created index - ([babykart](https://github.com/babykart))
- **(database)** ([5a172e5](https://github.com/babykart/gozone/commit/5a172e58c2f98ab99dc8b7650f6c9f03579e8c7c)) - [gozone] tolerate re-running edited migrations - ([babykart](https://github.com/babykart))
- **(docker)** ([2f9533a](https://github.com/babykart/gozone/commit/2f9533a58fd705667c73841c3388b4efafb973dc)) - [gozone] stop exposing PowerDNS API port and restrict allow_from - ([babykart](https://github.com/babykart))
- **(docker)** ([2168192](https://github.com/babykart/gozone/commit/2168192b85ad9c462b5a5f7d7e1e165b675a26b8)) - [docker] add .dockerignore to prevent secrets leaking into image - ([babykart](https://github.com/babykart))
- **(export)** ([c7bfd87](https://github.com/babykart/gozone/commit/c7bfd8744f76fedb86271d9c985f0fc77c5b49fd)) - [gozone] rename findSOATTY typo to findSOATTL - ([babykart](https://github.com/babykart))
- **(handlers)** ([80d832e](https://github.com/babykart/gozone/commit/80d832e4b9a28774cbfcdb654323d0837d4e0fb0)) - [gozone] remove double WriteHeader in import/export error paths - ([babykart](https://github.com/babykart))
- **(handlers)** ([7468091](https://github.com/babykart/gozone/commit/7468091bebc6f9b6adf75ded307adc9434dfaae6)) - [gozone] log PDNS errors swallowed by InlineUpdateRecord - ([babykart](https://github.com/babykart))
- **(handlers)** ([8abb25a](https://github.com/babykart/gozone/commit/8abb25adc7c28548121ea1828eb4f2fae32bdaab)) - [gozone] log filterZonesForUser errors instead of swallowing - ([babykart](https://github.com/babykart))
- **(handlers)** ([4c6060d](https://github.com/babykart/gozone/commit/4c6060d4f89084f16555f29dc8ff03aa9650ea5a)) - [gozone] normalize/validate record name before delete - ([babykart](https://github.com/babykart))
- **(handlers)** ([745f8e1](https://github.com/babykart/gozone/commit/745f8e1803b4449eb22a3c7c9c43fe8aaad3a2f5)) - [gozone] report BIND lines skipped during zone import - ([babykart](https://github.com/babykart))
- **(handlers)** ([1373238](https://github.com/babykart/gozone/commit/1373238d34b3811a2ebeefaf683d0895aaeb8cc9)) - [gozone] deduplicate records within a batch create - ([babykart](https://github.com/babykart))
- **(handlers)** ([549ca39](https://github.com/babykart/gozone/commit/549ca39244a63d67d2b7b6808b98a57a069af51f)) - [gozone] stop leaking internal errors from health/ready - ([babykart](https://github.com/babykart))
- **(handlers)** ([13425e6](https://github.com/babykart/gozone/commit/13425e606fde6127219eb30695bb6ea19a4c9ae9)) - [gozone] validate metadata kind and crypto/TSIG algorithms - ([babykart](https://github.com/babykart))
- **(handlers)** ([7b7020e](https://github.com/babykart/gozone/commit/7b7020e6bab21d98e3e5c42a99b441b09789ce73)) - [gozone] fail-closed when login lockout status is uncheckable - ([babykart](https://github.com/babykart))
- **(import)** ([18eecde](https://github.com/babykart/gozone/commit/18eecde425b7bd71454488b0055b3c32b5417287)) - [gozone] route CSV/BIND imports through prepareRecordContent - ([babykart](https://github.com/babykart))
- **(log)** ([2404d4d](https://github.com/babykart/gozone/commit/2404d4d6ae451ae64cd1e102885d0159789779b9)) - [gozone] exclude empty base scaffold from templates-loaded count - ([babykart](https://github.com/babykart))
- **(main)** ([e1f2a43](https://github.com/babykart/gozone/commit/e1f2a43d4475e92c484249e3459a9a7d7547099f)) - [gozone] split bind and serve to prevent goroutine leak on bind failure - ([babykart](https://github.com/babykart))
- **(main)** ([e9194f0](https://github.com/babykart/gozone/commit/e9194f0fddf1db2ab6d8c3c450dd9fc9bc44f088)) - [gozone] fix relativeName apex, case-sensitivity, and label boundary - ([babykart](https://github.com/babykart))
- **(main)** ([8499c5f](https://github.com/babykart/gozone/commit/8499c5f62e82381f1260357239f9e0ce54b81f12)) - [gozone] add Cache-Control and disable directory listing on /static - ([babykart](https://github.com/babykart))
- **(main)** ([ae3958e](https://github.com/babykart/gozone/commit/ae3958ee8deb97abee45ef575d53e16f87d09a8e)) - [gozone] log request ID in requestLogger and ErrorHandler - ([babykart](https://github.com/babykart))
- **(middleware)** ([8a915a9](https://github.com/babykart/gozone/commit/8a915a9492f6dd63558b30ae98d1bca053549d1c)) - [gozone] add Close() to RateLimiter to stop cleanup goroutine - ([babykart](https://github.com/babykart))
- **(middleware)** ([5b4c565](https://github.com/babykart/gozone/commit/5b4c565e8154f7f180c5cf0fcecf2c7a30cc4d5d)) - [gozone] handle multi-hop X-Forwarded-Proto chains - ([babykart](https://github.com/babykart))
- **(middleware)** ([89d1b2d](https://github.com/babykart/gozone/commit/89d1b2dc1fcd8d9e076d7068fd3552804e6f2c4b)) - [gozone] stop empty usernames bypassing the login rate limiter - ([babykart](https://github.com/babykart))
- **(middleware)** ([cbd8406](https://github.com/babykart/gozone/commit/cbd840629a809e1ed66aa8b68d4300871ad98d3e)) - [gozone] only stamp api_key last_used_at on successful auth - ([babykart](https://github.com/babykart))
- **(middleware)** ([1fabd3f](https://github.com/babykart/gozone/commit/1fabd3f18b520b0cdc764f0aae5595d021ff737c)) - [gozone] use request context for auth DB calls - ([babykart](https://github.com/babykart))
- **(middleware)** ([800b229](https://github.com/babykart/gozone/commit/800b229dd6db9c92494416b85d47a7cf2a53f669)) - [gozone] slash-bound /api/ prefix so /apikey-help is not API - ([babykart](https://github.com/babykart))
- **(models)** ([558492e](https://github.com/babykart/gozone/commit/558492ef8d97d140493b3e967b9c843de52bad66)) - [gozone] escape backslashes in QuoteContent for lossless TXT round-trip - ([babykart](https://github.com/babykart))
- **(models)** ([af1d167](https://github.com/babykart/gozone/commit/af1d16754c9a5fc0f6c3645c8f909407309a352d)) - [gozone] stop treating single-quote as already-quoted in QuoteConten - ([babykart](https://github.com/babykart))
- **(models)** ([9126061](https://github.com/babykart/gozone/commit/91260610a5461eb2aedbfb155c45b36c1be7d066)) - [gozone] only strip a valid 16-bit priority prefix in JoinPriority - ([babykart](https://github.com/babykart))
- **(pdns)** ([d49b24b](https://github.com/babykart/gozone/commit/d49b24b48305c6db31e14ce243dc6424776df08a)) - [gozone] path-escape all URL segments to prevent traversal - ([babykart](https://github.com/babykart))
- **(pdns)** ([a6545ea](https://github.com/babykart/gozone/commit/a6545ea8d7c1d18149d7a2e45644b44222efb656)) - [gozone] cap response body size to prevent OOM - ([babykart](https://github.com/babykart))
- **(pdns)** ([c4dad80](https://github.com/babykart/gozone/commit/c4dad802b9e0bae38119edc91acbc9ac2ebe8fe7)) - [gozone] add per-phase transport timeouts (dial/TLS/headers) - ([babykart](https://github.com/babykart))
- **(pdns)** ([7aaeb12](https://github.com/babykart/gozone/commit/7aaeb1263851d23c3dd4a5d6a6d9379e824ec5f0)) - [gozone] single-flight cache misses + generation-guarded repopulation - ([babykart](https://github.com/babykart))
- **(pdns)** ([c05da97](https://github.com/babykart/gozone/commit/c05da978424c0c3276994e90d469837f08e646e0)) - [gozone] extract clean message from PDNS error body - ([babykart](https://github.com/babykart))
- **(pdns)** ([3a3a3b2](https://github.com/babykart/gozone/commit/3a3a3b23f82fa35ad1c88bc1e74f99ff25491bec)) - [gozone] build PATCH body with a priority-less record type - ([babykart](https://github.com/babykart))
- **(security)** ([d4f2f50](https://github.com/babykart/gozone/commit/d4f2f5055d85e778f2904c7c4789f20efcc1b014)) - [gozone] verify RemoteAddr is a trusted proxy before honoring XFF - ([babykart](https://github.com/babykart))
- **(security)** ([e408648](https://github.com/babykart/gozone/commit/e4086483d13b327d775e29316cdb25298b0e605d)) - [gozone] harden CSP with object-src, base-uri, frame-ancestors, form-action - ([babykart](https://github.com/babykart))
- **(security)** ([81e0033](https://github.com/babykart/gozone/commit/81e00332e6c6d44ae3a7ca139a35d7f802909796)) - [gozone] drop deprecated X-XSS-Protection header - ([babykart](https://github.com/babykart))
- **(security)** ([7a6544d](https://github.com/babykart/gozone/commit/7a6544d4241a6ab7bcbb20dcb6bc0a1b9f2539da)) - [gozone] gate X-Forwarded-Proto behind trusted proxies - ([babykart](https://github.com/babykart))
- **(test)** ([ff866c6](https://github.com/babykart/gozone/commit/ff866c6beff20cc10ff82ffb8585e22b6545f185)) - [gozone] drop duplicated journal_mode check in TestNewInMemory - ([babykart](https://github.com/babykart))
- **(ui)** ([41e5fac](https://github.com/babykart/gozone/commit/41e5fac19f233f613ca7d3c8295a425a83f33c27)) - [gozone] add autocomplete attributes to login form fields - ([babykart](https://github.com/babykart))
- **(ui)** ([149f41e](https://github.com/babykart/gozone/commit/149f41ef38629a0d026d8a567c7389e9b21f194f)) - [gozone] use :focus-visible and restore HCM-visible focus outlines - ([babykart](https://github.com/babykart))
- **(ui)** ([1682c56](https://github.com/babykart/gozone/commit/1682c562619172794378f2afe32868f96b4eca8a)) - [gozone] surface clear error on expired session in inline record edit - ([babykart](https://github.com/babykart))
- **(ui)** ([93407e7](https://github.com/babykart/gozone/commit/93407e7b997597fe9cf48ef2b50abc8f963a77cf)) - [gozone] replace hamburger/power glyphs with inline SVG icons - ([babykart](https://github.com/babykart))
- **(users)** ([cbb880d](https://github.com/babykart/gozone/commit/cbb880de70aa49c642343aedfc86550c074f680c)) - [gozone] move last-admin guard inside UpdateUser transaction - ([babykart](https://github.com/babykart))
- **(validators)** ([9d69184](https://github.com/babykart/gozone/commit/9d6918460efc6e31aa8e4b9fbf5d92df7da31fbb)) - [gozone] validate content for all whitelisted record types - ([babykart](https://github.com/babykart))
- **(validators)** ([dbedb39](https://github.com/babykart/gozone/commit/dbedb39243f1402177c7a485172a39a81cc865c0)) - [gozone] enforce wildcard label position in ValidateDNSName - ([babykart](https://github.com/babykart))
- **(validators)** ([ad1aff9](https://github.com/babykart/gozone/commit/ad1aff90f2590e92daa4e247a3d498f497161615)) - [gozone] validate SRV weight/port and MX/SRV priority ranges - ([babykart](https://github.com/babykart))
- **(validators)** ([4299ce6](https://github.com/babykart/gozone/commit/4299ce6b74b3953017d4853034e86452df69517f)) - [gozone] apply >0 check to all SOA timers, not just serial - ([babykart](https://github.com/babykart))
- **(web)** ([fa36905](https://github.com/babykart/gozone/commit/fa36905435e418ad07b7913db06460da7c288844)) - [gozone] associate labels with inputs in record/template forms - ([babykart](https://github.com/babykart))
- **(web)** ([b78dac5](https://github.com/babykart/gozone/commit/b78dac51348a0ba7e401aac8c808d003e46478df)) - [gozone] add screen-reader captions to all data tables - ([babykart](https://github.com/babykart))
- **(zones)** ([f37ffdf](https://github.com/babykart/gozone/commit/f37ffdf80aecee4fc0f6f1d6077ae785f8890676)) - [gozone] add panic recovery to ViewZone goroutines - ([babykart](https://github.com/babykart))

### 🚜 Refactor

- **(build)** ([cf9e679](https://github.com/babykart/gozone/commit/cf9e679d6bd78f739fdfa6d9f9d52988464700b4)) - [gozone] embed only templates and static in web.FS - ([babykart](https://github.com/babykart))
- **(main)** ([243be6e](https://github.com/babykart/gozone/commit/243be6e407fb382fbc009017aca4d28e12aba67d)) - [gozone] split defer f()() into named stop var for periodic job - ([babykart](https://github.com/babykart))
- **(middleware)** ([b933f1c](https://github.com/babykart/gozone/commit/b933f1cd65adfc600ee9be7e869e7461956317a0)) - [gozone] remove redundant Recoverer, add stack trace to ErrorHandler - ([babykart](https://github.com/babykart))
- **(test)** ([ef73690](https://github.com/babykart/gozone/commit/ef736905c7011676987b5089dc1cc0fceb8c2e1b)) - [gozone] use t.Setenv for GOZONE_ADMIN_PASSWORD in seed test - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(ai)** ([2357a2f](https://github.com/babykart/gozone/commit/2357a2fbf1cea21a3ee869eef7ab26f2fdf715fa)) - [gozone] update AGENTS.md - ([babykart](https://github.com/babykart))
- **(main)** ([acf3576](https://github.com/babykart/gozone/commit/acf35762bd2f46c08f9b2bc3d47ecf1d28d4a6ee)) - [gozone] document /login vs /api rate-limit ordering asymmetry - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(database)** ([59d758e](https://github.com/babykart/gozone/commit/59d758e4b50b022331bc3f9ead02d589909bc881)) - [gozone] add MySQL/PostgreSQL integration tests for dialect bugs - ([babykart](https://github.com/babykart))

### 🌀 Miscellaneous Tasks

- **(repo)** ([3801361](https://github.com/babykart/gozone/commit/3801361ed146362dbac46373eb3524b4e2988f13)) - [gozone] expand .gitignore to prevent secrets and artifacts from being committed - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
