
## [v0.9.0] - 2026-06-14

### 🚀 Features

- **(database)** ([6364c0c](https://github.com/babykart/gozone/commit/6364c0cae9c094374232a944f9c32191d8b94524)) - [gozone] add context.Context support to DB and Tx methods - ([babykart](https://github.com/babykart))
- **(validators)** ([0f4195f](https://github.com/babykart/gozone/commit/0f4195fe5991ba7d412c860f332188279f1b5a32)) - [gozone] strengthen DNS input validation - ([babykart](https://github.com/babykart))
- **(web)** ([a43322f](https://github.com/babykart/gozone/commit/a43322f8385aa7a434cf907b49d13ffd645dc038)) - [gozone] replace emoji theme toggle with inline SVG sun/moon icons - ([babykart](https://github.com/babykart))
- **(web)** ([072c33c](https://github.com/babykart/gozone/commit/072c33c431d8002a7de3c4ec8265db3be4f8b25b)) - [gozone] add independent pagination to dashboard and zone activity logs - ([babykart](https://github.com/babykart))

### 💼 Other

- **(docker)** ([b04737a](https://github.com/babykart/gozone/commit/b04737afd5ef0a6ce4ca88cc55bbee3db0a30d43)) - [gozone] add HEALTHCHECK to docker-compose using /health/ready endpoint - ([babykart](https://github.com/babykart))
- ([78f8e9c](https://github.com/babykart/gozone/commit/78f8e9cfa00d9759bef59269ee49751886972495)) - Merge pull request #17 from smalinet/fix/mx-srv-priority-zero

fix(records): [gozone] extract zero priority from MX/SRV record content - ([babykart](https://github.com/babykart))
- ([de8632f](https://github.com/babykart/gozone/commit/de8632f19b09f0257cba01f15039514588e4ebfe)) - Merge pull request #18 from smalinet/fix/mx-srv-priority-export-template

fix(templates): [gozone] embed MX/SRV priority and validate zone temp… - ([babykart](https://github.com/babykart))
- ([b2f1363](https://github.com/babykart/gozone/commit/b2f13635bb700df7e47329fc2698213c50cd3840)) - Merge pull request #19 from smalinet/refactor/record-type-codec

refactor(records): [gozone] centralize MX/SRV priority and TXT/SPF qu… - ([babykart](https://github.com/babykart))
- ([d8a3b39](https://github.com/babykart/gozone/commit/d8a3b3929bd4ed7bb4c7bcb251e265bf8e83e6a6)) - Merge pull request #20 from smalinet/fix/api-rest-priority-records

fix(api): [gozone] embed MX/SRV priority and normalize names on record write - ([babykart](https://github.com/babykart))
- ([25cacae](https://github.com/babykart/gozone/commit/25cacae2aae44971d96d78efca6ee60c7ef0b1d3)) - Merge pull request #21 from smalinet/fix/robustness

fix(server): [gozone] harden BIND import, batch records and shutdown & return proper HTTP status codes on error pages - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(api)** ([4bc256f](https://github.com/babykart/gozone/commit/4bc256f621a4c0e3eb849d79d3f9439f34625f41)) - [gozone] embed MX/SRV priority and normalize names on record write - ([smalinet](https://github.com/smalinet))
- **(api)** ([ff39272](https://github.com/babykart/gozone/commit/ff39272505d8a608b7ce528d54c76854760316b2)) - [gozone] stop leaking raw API key in URL and request logs - ([babykart](https://github.com/babykart))
- **(api)** ([9825f2d](https://github.com/babykart/gozone/commit/9825f2d3ef38c197499f80073846106a78d4bac5)) - [gozone] add missing api_keys_test - ([babykart](https://github.com/babykart))
- **(database)** ([7730688](https://github.com/babykart/gozone/commit/77306886ee944214b2951261fa62508cb8949c11)) - [gozone] parse MySQL DSN with mysql.ParseDSN to avoid double query strings - ([babykart](https://github.com/babykart))
- **(database)** ([77a163f](https://github.com/babykart/gozone/commit/77a163f83431b0900fafb9cf64fd025819d7f505)) - [gozone] rebind placeholders in Tx.Query and Tx.QueryRow - ([babykart](https://github.com/babykart))
- **(database)** ([7a69795](https://github.com/babykart/gozone/commit/7a69795e14e62a252d07c4d82a62914b3faff9cb)) - [gozone] use content-hash migration versions and cluster-wide migration lock - ([babykart](https://github.com/babykart))
- **(errors)** ([03871f0](https://github.com/babykart/gozone/commit/03871f0dfbb0c81fbd4263190a9f16eff2cb4e70)) - [gozone] add error wrapping support to AppError - ([babykart](https://github.com/babykart))
- **(frontend)** ([5f757ca](https://github.com/babykart/gozone/commit/5f757ca9450ba46cfadb2abac820691ab83f3667)) - [gozone] handle HTTP errors and improve accessibility - ([babykart](https://github.com/babykart))
- **(handlers)** ([1175c99](https://github.com/babykart/gozone/commit/1175c993f80596d8a6949bc6a827dca39021ba5a)) - [gozone] return proper HTTP status codes on error pages - ([smalinet](https://github.com/smalinet))
- **(handlers)** ([3726006](https://github.com/babykart/gozone/commit/372600605eb3555b1598a842685677c904192363)) - [gozone] make ViewZone record sort comparator a strict weak ordering - ([babykart](https://github.com/babykart))
- **(health)** ([e79431b](https://github.com/babykart/gozone/commit/e79431b4825d93e27febe52e9966c25601f0aaa7)) - [gozone] bypass PowerDNS cache in readiness probe - ([babykart](https://github.com/babykart))
- **(pdns)** ([40f735d](https://github.com/babykart/gozone/commit/40f735ded5c1891d947d17aeb6ad399ecf317040)) - [gozone] invalidate zone and stats caches after record mutations - ([babykart](https://github.com/babykart))
- **(pdns)** ([a557490](https://github.com/babykart/gozone/commit/a557490c208e140af6d0d43cf1db26863c942ab6)) - type PowerDNS errors and map them to correct HTTP status codes - ([babykart](https://github.com/babykart))
- **(pdns)** ([b26d4a7](https://github.com/babykart/gozone/commit/b26d4a7a6008b0a8b2175e496a1a91a8a74d8942)) - add pdns/errors files - ([babykart](https://github.com/babykart))
- **(ratelimit)** ([d1a63b3](https://github.com/babykart/gozone/commit/d1a63b3b739316f691d0e49e17b9dd981d1cf26e)) - [gozone] hash and truncate key in rate-limit exceeded log - ([babykart](https://github.com/babykart))
- **(records)** ([d19589e](https://github.com/babykart/gozone/commit/d19589e19004b257e64bb929499ce70f2f90b2f3)) - [gozone] extract zero priority from MX/SRV record content - ([smalinet](https://github.com/smalinet))
- **(roadmap)** ([82b571c](https://github.com/babykart/gozone/commit/82b571c82eb46af8ca88636136d5415dda0dbc0c)) - [gozone] update Password Enforcement title - ([babykart](https://github.com/babykart))
- **(server)** ([ed53b83](https://github.com/babykart/gozone/commit/ed53b8341fe610a1b2dda50dca0d1ab1325cf5b8)) - [gozone] harden BIND import, batch records and shutdown - ([smalinet](https://github.com/smalinet))
- **(templates)** ([1bafc60](https://github.com/babykart/gozone/commit/1bafc6066058d130ec75eb716de186ce68cdc960)) - [gozone] embed MX/SRV priority and validate zone templates - ([smalinet](https://github.com/smalinet))

### 🚜 Refactor

- **(cmd)** ([b7a8a0c](https://github.com/babykart/gozone/commit/b7a8a0cae9aa57dc37ad56132ce42503cffa83a6)) - [gozone] restructure main into run() error to preserve defers - ([babykart](https://github.com/babykart))
- **(records)** ([104f015](https://github.com/babykart/gozone/commit/104f0153a1dd39d5bb4ea624c4d9cbd68ec2bf5c)) - [gozone] centralize MX/SRV priority and TXT/SPF quoting - ([smalinet](https://github.com/smalinet))
- **(web)** ([caedbbf](https://github.com/babykart/gozone/commit/caedbbfff284bf3150cad7301dc764c6a3255e7d)) - [gozone] move profile, theme toggle and logout from sidebar to top bar - ([babykart](https://github.com/babykart))
- ([8301449](https://github.com/babykart/gozone/commit/83014499d3b5b3aa0a51a3a8d09eadcc233ec90d)) - [gozone] factorize duplicated patterns across handlers, pdns client and templates - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(ai)** ([f6e1650](https://github.com/babykart/gozone/commit/f6e16504bd6776b9bb44bdb27f36b64368a363c2)) - [gozone] update AGENTS.md - ([babykart](https://github.com/babykart))
- **(roadmap)** ([d159fcb](https://github.com/babykart/gozone/commit/d159fcb95221e3acff4ac6fadda2bffcefd6e092)) - [gozone] add activity page, BIND diff, and retention policy to roadmap - ([babykart](https://github.com/babykart))
- ([a7517e1](https://github.com/babykart/gozone/commit/a7517e1a7d5af250bc2f21be7c5e77a4bb92a325)) - [gozone] update README.md - ([babykart](https://github.com/babykart))
- ([b743bba](https://github.com/babykart/gozone/commit/b743bbaa4cae6b64532debc0781ffcbd1332df52)) - [gozone] update docs/ARCHITECTURE.md - ([babykart](https://github.com/babykart))

### 🌀 Miscellaneous Tasks

- **(docker)** ([9419850](https://github.com/babykart/gozone/commit/94198502162bbe51a213920ca59e25714ab0180f)) - [gozone] remove obsolete version field from docker-compose.yml - ([babykart](https://github.com/babykart))
- ([d4562f6](https://github.com/babykart/gozone/commit/d4562f6f6fa9af75030150f87a19e245a7748c84)) - [gozone] add GitHub Actions workflow for pull request checks - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
