
## [v0.2.0] - 2026-05-30

### 🚀 Features

- **(main)** ([5a0b01d](https://github.com/babykart/gozone/commit/5a0b01dec754d62ad48b1a6b39fd58b18206dc65)) - [gozone] add group authorization - ([babykart](https://github.com/babykart))
- **(repo)** ([9aef54c](https://github.com/babykart/gozone/commit/9aef54cdfcb016c4fed5d2211f57301c6d8a3a2b)) - [gozone] add Makefile - ([babykart](https://github.com/babykart))
- **(web)** ([7fdf540](https://github.com/babykart/gozone/commit/7fdf54070153c32ed61df9bbf0b4195b39f51007)) - [gozone] add dark/light theme - ([babykart](https://github.com/babykart))
- **(web)** ([2620ff0](https://github.com/babykart/gozone/commit/2620ff021fc7e0ad3645c2b0ea900120cd8fcab9)) - [gozone] add navbar & pdns status - ([babykart](https://github.com/babykart))

### ◀️ Revert

- ([cde020a](https://github.com/babykart/gozone/commit/cde020ac119248e7d32b9bec2d96be40e6f6acb5)) - [gozone] remove DynDNS - ([babykart](https://github.com/babykart))

### 💼 Other

- ([8fdb79a](https://github.com/babykart/gozone/commit/8fdb79a02a154ca61994d0f89674b499529d0a91)) - Merge pull request #1 from smalinet/fix/default-secret-key-detection

fix(config): [gozone] auto-generate a secret when the well-know place… - ([babykart](https://github.com/babykart))
- ([991d401](https://github.com/babykart/gozone/commit/991d40168fce8cf1aec2432bf226aa43c0e97eb4)) - Merge pull request #2 from smalinet/fix/csrf-secure-flag

fix(config): [gozone] add CSRF secure_cookies flag - ([babykart](https://github.com/babykart))
- ([474b0a7](https://github.com/babykart/gozone/commit/474b0a7bba2c527460fd9162a9c699a094016f73)) - Merge pull request #3 from smalinet/fix/no-log-secret-key

fix(config): [gozone] for security secret_key must not be in the log - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(auth)** ([b2a13d0](https://github.com/babykart/gozone/commit/b2a13d02e160f78956e2b0198775fbab883e62f1)) - [gozone] add dummyHash to avoid an exploitable timing difference - ([babykart](https://github.com/babykart))
- **(config)** ([d1b07d6](https://github.com/babykart/gozone/commit/d1b07d6e3c0826191e896f908035dddcd0d2e863)) - [gozone] auto-generate a secret when the well-know placeholder is detected - ([Stephane Malinet](https://github.com/Stephane Malinet))
- **(config)** ([c84d35b](https://github.com/babykart/gozone/commit/c84d35b37777d04c9bac4eb2e66e8360d8c05851)) - [gozone] add CSRF secure_cookies flag - ([Stephane Malinet](https://github.com/Stephane Malinet))
- **(config)** ([bb477b5](https://github.com/babykart/gozone/commit/bb477b5deb4cba925979871e31263f9841e347f1)) - [gozone] for security secret_key must not be in the log - ([Stephane Malinet](https://github.com/Stephane Malinet))
- **(config)** ([3dcc8d7](https://github.com/babykart/gozone/commit/3dcc8d702d027752828b38d923df6880fe455927)) - [gozone] add deriveKeys for JWT & CSRF - ([babykart](https://github.com/babykart))
- **(config)** ([cc4e570](https://github.com/babykart/gozone/commit/cc4e5709a17f385041a33bb3d4425413f4f56960)) - [gozone] replace parseIntOr by strconv.Atoi + logger.Warn - ([babykart](https://github.com/babykart))
- **(gosec)** ([3d37bae](https://github.com/babykart/gozone/commit/3d37baedb99ada0edf3a1a94fa1fb74ca037732b)) - [gozone] updates based on gosec report - ([babykart](https://github.com/babykart))
- **(handlers)** ([6ae2677](https://github.com/babykart/gozone/commit/6ae26775ebcabb27790107861c3540258cd4e213)) - [gozone] catch all db errors - ([babykart](https://github.com/babykart))
- **(main)** ([47d82e5](https://github.com/babykart/gozone/commit/47d82e515c2fe9d8b0d253394be5fb4f5ec9d8a2)) - [gozone] add group authorization - ([babykart](https://github.com/babykart))
- **(main)** ([2cc3964](https://github.com/babykart/gozone/commit/2cc39646a18b63f84456a72547d76d97ab352f37)) - [gozone] add fileServer for staticFS - ([babykart](https://github.com/babykart))
- **(main)** ([3a76f80](https://github.com/babykart/gozone/commit/3a76f8042dd61d275e5752f425b55f8e8fd6db33)) - [gozone] remove useless eq & ne - ([babykart](https://github.com/babykart))
- **(pdns)** ([bb986a5](https://github.com/babykart/gozone/commit/bb986a5423675c2c40d38e52d90633917e302e49)) - [gozone] avoid double unmarshal - ([babykart](https://github.com/babykart))
- **(records)** ([b466d91](https://github.com/babykart/gozone/commit/b466d91bafc1fef8f8da928099073b454f05f832)) - [gozone] validate record before send it to pdns - ([babykart](https://github.com/babykart))
- **(repo)** ([113d474](https://github.com/babykart/gozone/commit/113d474acaee86937eea03ab45162d4f5cf9834e)) - [gozone] fix CHANGELOG.md - ([babykart](https://github.com/babykart))
- **(repo)** ([55fc135](https://github.com/babykart/gozone/commit/55fc1356ab49680060ca78045690a937a0251334)) - [gozone] generate CHANGELOG.md - ([babykart](https://github.com/babykart))
- **(web)** ([e95947a](https://github.com/babykart/gozone/commit/e95947a7aa0cd5a103834cb534b608f38d20f690)) - [gozone] embed static files in the binary - ([babykart](https://github.com/babykart))
- **(web)** ([1a08d95](https://github.com/babykart/gozone/commit/1a08d95051c198ac9166eae83726c89d6dc062b0)) - [gozone] move html templates to web - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(architecture)** ([3aa2745](https://github.com/babykart/gozone/commit/3aa2745e433799568e3936a3cc2a223ed0440461)) - [gozone] update ARCHITECTURE.md - ([babykart](https://github.com/babykart))
- **(architecture)** ([18e0a0d](https://github.com/babykart/gozone/commit/18e0a0dc9da9617585fbb7f3614e6afe1bce58cf)) - [gozone] update Authentication Flows in ARCHITECTURE.md - ([babykart](https://github.com/babykart))
- **(middleware)** ([ec5de4c](https://github.com/babykart/gozone/commit/ec5de4c5f7a25c5f285e563b469a1749c262a7d5)) - [gozone] comment empty zoneID behavior - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(groups)** ([d0a5351](https://github.com/babykart/gozone/commit/d0a535151ef8d96ecbc9d614c3396b86c60fed73)) - [gozone] add tests for groups - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
