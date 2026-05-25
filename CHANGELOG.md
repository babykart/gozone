
## [v0.1.0] - 2026-05-25

### 🚀 Features

- **(database)** ([23e5864](https://github.com/babykart/gozone/commit/23e5864bdf1a9aab9618e11fd819aaf0613d27ad)) - [gozone] add multi-db support - ([babykart](https://github.com/babykart))
- **(docker)** ([1490245](https://github.com/babykart/gozone/commit/1490245553171b43ac0e2c9293399f9d2e545d62)) - [gozone] add user/group nonroot - ([babykart](https://github.com/babykart))
- **(handlers)** ([9217012](https://github.com/babykart/gozone/commit/92170120dac3239ae07b9b0efa1bd287659327a5)) - [gozone] add detailed health checks - ([babykart](https://github.com/babykart))
- **(handlers)** ([29d6287](https://github.com/babykart/gozone/commit/29d6287b771db197aacbb98a9f3202d427660023)) - [gozone] add strict input validation for zones, records & users - ([babykart](https://github.com/babykart))
- **(handlers)** ([ce2e4a7](https://github.com/babykart/gozone/commit/ce2e4a7c26384df2c1ee8fe4449fd7eb544e56df)) - [gozone] use SQL transactions for users - ([babykart](https://github.com/babykart))
- **(html)** ([899aa85](https://github.com/babykart/gozone/commit/899aa85436a41b617ba41834441abd8f893bc9d4)) - [gozone] embed templates with //go:embed - ([babykart](https://github.com/babykart))
- **(just)** ([c6591b1](https://github.com/babykart/gozone/commit/c6591b1151770e363876103050752c7516e38079)) - [gozone] add auto-gen-rel, gen-release & gen-tag recipes - ([babykart](https://github.com/babykart))
- **(logger)** ([7de8f90](https://github.com/babykart/gozone/commit/7de8f9083da415ac310100a9744ba0ff049f954e)) - [gozone] migrate to structured logging - ([babykart](https://github.com/babykart))
- **(web)** ([408b3a9](https://github.com/babykart/gozone/commit/408b3a9bb60d2f301e70447546ffbeee354f11dc)) - [gozone] add API keys management for user - ([babykart](https://github.com/babykart))

### 💼 Other

- **(api)** ([6834c3b](https://github.com/babykart/gozone/commit/6834c3b98502fafd360c6aeb58c7e8076ff70d5d)) - [gozone] mask internal errors in API responses - ([babykart](https://github.com/babykart))
- **(auth)** ([b7eb58b](https://github.com/babykart/gozone/commit/b7eb58b5856dd8244c5fdb028eb0ab099036ee6d)) - [gozone] add enforce strong secret key - ([babykart](https://github.com/babykart))
- **(auth)** ([2b51f70](https://github.com/babykart/gozone/commit/2b51f705af85c9089b50eb9127f1c67a7db83d77)) - [gozone] add CSRF protection - ([babykart](https://github.com/babykart))
- **(auth)** ([87204b9](https://github.com/babykart/gozone/commit/87204b937c6f424a908eef65a4fa45b5635f3a9d)) - [gozone] enable Secure flag on cookies - ([babykart](https://github.com/babykart))
- **(auth)** ([6efb797](https://github.com/babykart/gozone/commit/6efb797e308592dcfd48d75add3238d2b6139a66)) - [gozone] implement rate limiting on sensitive endpoints - ([babykart](https://github.com/babykart))
- **(data)** ([8ec2fea](https://github.com/babykart/gozone/commit/8ec2fea8cfea874cefb45b8627803349441cc8a4)) - [gozone] verify password hashes never leak - ([babykart](https://github.com/babykart))
- **(http)** ([d397c3c](https://github.com/babykart/gozone/commit/d397c3c801a39bb228126c9a6fff64fe4c90d8bc)) - [gozone] add HTTP security headers - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(ai)** ([02861f5](https://github.com/babykart/gozone/commit/02861f5b6575135fe7b79087ef2423104821b98a)) - [gozone] update AGENTS.md - ([babykart](https://github.com/babykart))
- **(auth)** ([6cd931b](https://github.com/babykart/gozone/commit/6cd931b0013da37c2ed17777f5f0c3077a5836f7)) - [gozone] mark non-TLS requests as plaintext - ([babykart](https://github.com/babykart))
- **(auth)** ([f654b14](https://github.com/babykart/gozone/commit/f654b14c681eb8b7b5283fd74ba874d3a971e5cb)) - [gozone] fix G124 gosec - ([babykart](https://github.com/babykart))
- **(constants)** ([4e1641e](https://github.com/babykart/gozone/commit/4e1641ef1c56147aed1d72c766f66c89ab8d4d15)) - [gozone] add internal/constants - ([babykart](https://github.com/babykart))
- **(contributing)** ([d7d8f41](https://github.com/babykart/gozone/commit/d7d8f41eb62c941a5713d3bf2eb760f67d212de3)) - [gozone] add gosec - ([babykart](https://github.com/babykart))
- **(dashboard)** ([80091d0](https://github.com/babykart/gozone/commit/80091d0ad1abdffb9b91bbe1d76f9f7cfc122a10)) - [gozone] replace intToStr() with strconv.Itoa() - ([babykart](https://github.com/babykart))
- **(database)** ([bd5a9dd](https://github.com/babykart/gozone/commit/bd5a9dd9ae61697af61c7e3e6ff156be4bd681f3)) - [gozone] safely append parameters to the DSN - ([babykart](https://github.com/babykart))
- **(database)** ([d679a71](https://github.com/babykart/gozone/commit/d679a71e51e447d99db6f3a375744a8c6f0497c8)) - [gozone] fix G301 gosec - ([babykart](https://github.com/babykart))
- **(gosec)** ([fab7a1b](https://github.com/babykart/gozone/commit/fab7a1b4a3c8936e67b7bd29723dc84c70128e28)) - [gozone] exclude G304, G705 & G710 - ([babykart](https://github.com/babykart))
- **(http)** ([eacac72](https://github.com/babykart/gozone/commit/eacac726ff13dd0ffd87e88f01ceeced2fc40c86)) - [gozone] fix G114 gosec - ([babykart](https://github.com/babykart))
- **(just)** ([56e8557](https://github.com/babykart/gozone/commit/56e8557ffb2898f2658a2a67ad31c44aa5192bf2)) - [gozone] fix path in run recipe - ([babykart](https://github.com/babykart))
- **(just)** ([fb1a6f9](https://github.com/babykart/gozone/commit/fb1a6f9ae14f348dc8fb37dc76e187aa8ad7eaba)) - [gozone] update clean recipe - ([babykart](https://github.com/babykart))
- **(just)** ([1ae4ab0](https://github.com/babykart/gozone/commit/1ae4ab053a29f440e4886e148cd36d00dd621ada)) - [gozone] update clean recipe - ([babykart](https://github.com/babykart))
- **(just)** ([4098176](https://github.com/babykart/gozone/commit/4098176c94b8c1cdc20acffee1dda5395816528c)) - [gozone] add update recipe - ([babykart](https://github.com/babykart))
- **(just)** ([aea8ece](https://github.com/babykart/gozone/commit/aea8ece0bfe41f7221de05c8698d36f2bb54c29e)) - [gozone] add gosec recipe - ([babykart](https://github.com/babykart))
- **(just)** ([bc38c1a](https://github.com/babykart/gozone/commit/bc38c1a5ea230613e27f0fe371cfaa3fde625177)) - [gozone] exclude directories for gosec - ([babykart](https://github.com/babykart))
- ([de50f8b](https://github.com/babykart/gozone/commit/de50f8b4840af43172a35130da0b07a47c7e93a2)) - [gozone] update ROADMAP.md - ([babykart](https://github.com/babykart))
- ([9994605](https://github.com/babykart/gozone/commit/99946052850fe0b4f63269dd3cdc6ad888e01631)) - [gozone] update ROADMAP.md - ([babykart](https://github.com/babykart))

### 🚜 Refactor

- ([61a6313](https://github.com/babykart/gozone/commit/61a63138f3b82f3dc31e596d1676014fe60c11c4)) - [gozone] add internal/errors & standardize error handling - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(internal)** ([575354b](https://github.com/babykart/gozone/commit/575354b805aa1e008d8ff55c759d7fff7751bf03)) - [gozone] add godoc comments for all expoted functions - ([babykart](https://github.com/babykart))
- ([c233833](https://github.com/babykart/gozone/commit/c233833414e562771bfb8a95a8ca18d4bdde9c96)) - [gozone] add docs/ARCHITECTURE.md - ([babykart](https://github.com/babykart))

### ⚡ Performance

- **(http)** ([bf251c3](https://github.com/babykart/gozone/commit/bf251c30266773c53d69db641c2fcf16c35f71e4)) - [gozone] add HTTP compression - ([babykart](https://github.com/babykart))
- **(http)** ([3189a84](https://github.com/babykart/gozone/commit/3189a8412f6de94b4335ced5e70801340ac71180)) - [gozone] optimize ListZones to avoid N+1 queries - ([babykart](https://github.com/babykart))
- **(sql)** ([d548fe8](https://github.com/babykart/gozone/commit/d548fe89335be97622735e06d3050b5973d2b29c)) - [gozone] add additional indexes - ([babykart](https://github.com/babykart))

### 🎨 Styling

- ([1b68a37](https://github.com/babykart/gozone/commit/1b68a371e8cdc62cd3e3810ef1b6111c6303436c)) - [gozone] move seedAdminUser() to a testable package - ([babykart](https://github.com/babykart))
- ([96f5641](https://github.com/babykart/gozone/commit/96f5641184fb77e3c03b47c630517be349df1ec2)) - [gozone] define constants for magic strings & eliminate code duplication - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(api)** ([76fa8fc](https://github.com/babykart/gozone/commit/76fa8fc489344224bcedebb7608ab6b9ebb919f4)) - [gozone] test PowerDNS error paths - ([babykart](https://github.com/babykart))
- **(auth)** ([41cfe54](https://github.com/babykart/gozone/commit/41cfe54fe27c37224d8fa7159bc2ee1ee7bc2102)) - [gozone] Test APIKeyAuth() completely - ([babykart](https://github.com/babykart))
- **(auth)** ([1a7d7cf](https://github.com/babykart/gozone/commit/1a7d7cf432a0b3c10cbce1a176ebd3ce26175017)) - [gozone] test Auth() middleware completely - ([babykart](https://github.com/babykart))
- **(dyndns)** ([fcaba50](https://github.com/babykart/gozone/commit/fcaba50aaee0373636e4615fdb6707f97c087074)) - [gozone] fix and test DynDNS completely - ([babykart](https://github.com/babykart))
- **(handlers)** ([0d7ab97](https://github.com/babykart/gozone/commit/0d7ab973025b50ee7bc47efbfa470fc5fbb896c6)) - [gozone] add integration tests - ([babykart](https://github.com/babykart))
- **(infra)** ([8a9af80](https://github.com/babykart/gozone/commit/8a9af80d1849fb0448345c2b2566ab49325da666)) - [gozone] create internal/testutil package - ([babykart](https://github.com/babykart))
- **(infra)** ([2be1de9](https://github.com/babykart/gozone/commit/2be1de91ecbad550e40f4677e7ff34b5486f8c25)) - [gozone] introduce ZoneService interface - ([babykart](https://github.com/babykart))
- **(infra)** ([8d399ff](https://github.com/babykart/gozone/commit/8d399ff518f113e2461664fd438eb3581ecc38d3)) - [gozone] check PasswordHash & KeyHash never appears in JSON - ([babykart](https://github.com/babykart))
- **(pdns)** ([d898c46](https://github.com/babykart/gozone/commit/d898c46f4a5dd8abe3bd62257623339711cdb2fb)) - [gozone] test UpdateRecord() in PowerDNS client - ([babykart](https://github.com/babykart))
- **(records)** ([956991c](https://github.com/babykart/gozone/commit/956991cc97cd05f5661c6ee3604671d7c31da672)) - [gozone] test EditRecordPage() - ([babykart](https://github.com/babykart))
- **(zones)** ([d539445](https://github.com/babykart/gozone/commit/d539445b0c4f713b4869e0c518e11569b19e853a)) - [gozone] test RectifyZone() and NotifyZone() - ([babykart](https://github.com/babykart))

### 🌀 Miscellaneous Tasks

- **(ai)** ([cccfaa0](https://github.com/babykart/gozone/commit/cccfaa04e7f1106d9b27867f9e46d9bd795ea1cb)) - [gozone] add AGENTS.md - ([babykart](https://github.com/babykart))
- **(repo)** ([19598b8](https://github.com/babykart/gozone/commit/19598b85a7b571285363677b1406aca715b684b5)) - [gozone] add git-cliff configuration - ([babykart](https://github.com/babykart))
- **(repo)** ([c59f4da](https://github.com/babykart/gozone/commit/c59f4daa7a8b8d9a7370564e5f248aed4a37b60e)) - [gozone] add justfile - ([babykart](https://github.com/babykart))
- **(repo)** ([3b453ab](https://github.com/babykart/gozone/commit/3b453abfb34fd08972deb72347e93450186309e8)) - [gozone] add release github workflow - ([babykart](https://github.com/babykart))
- **(repo)** ([c54df73](https://github.com/babykart/gozone/commit/c54df73e8e86d9928dbfe74e92fc9c762d98f15c)) - [gozone] add docker stuff - ([babykart](https://github.com/babykart))
- **(repo)** ([a758a7a](https://github.com/babykart/gozone/commit/a758a7a02f0eca762c41e421fb8b79b5b10f76a9)) - [gozone] add config file - ([babykart](https://github.com/babykart))
- **(repo)** ([da31fb6](https://github.com/babykart/gozone/commit/da31fb6ee19cd781048f3a49407f6596627fed0d)) - [gozone] add golang stuff - ([babykart](https://github.com/babykart))
- **(repo)** ([3349f37](https://github.com/babykart/gozone/commit/3349f370cb083f3062e1f91f1b1407d2f8806196)) - [gozone] add web files - ([babykart](https://github.com/babykart))
- **(repo)** ([30a7557](https://github.com/babykart/gozone/commit/30a7557919cd165206a9080191e8061046c4f1c7)) - [gozone] add CONTRIBUTING.md - ([babykart](https://github.com/babykart))
- **(repo)** ([b56abbf](https://github.com/babykart/gozone/commit/b56abbf9ffe75d49eae984b414bb61a1ee14dba2)) - [gozone] add ROADMAP.md - ([babykart](https://github.com/babykart))
- **(vendor)** ([9932a62](https://github.com/babykart/gozone/commit/9932a6230d560f7bdc31360d908911ac862daab5)) - [gozone] add vendor - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
