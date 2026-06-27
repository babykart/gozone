
## [v0.12.0] - 2026-06-27

### 🚀 Features

- **(api)** ([34eaf0d](https://github.com/babykart/gozone/commit/34eaf0dd6aa275f4c42db51b9295d2774eefbe3f)) - [gozone] filter /api/v1/zones/{zone}/records by name and type - ([babykart](https://github.com/babykart))
- **(api)** ([dd269e1](https://github.com/babykart/gozone/commit/dd269e160015bd02805b6f8bcdbe40b0ad937a68)) - [gozone] expose clear_comments sentinel for RRSet comment purge - ([babykart](https://github.com/babykart))
- **(export)** ([4fec51c](https://github.com/babykart/gozone/commit/4fec51caea1c3e086ae7ab57f7a5d50a30a8a71b)) - [gozone] include comments in CSV export/import - ([babykart](https://github.com/babykart))
- **(records)** ([871f51d](https://github.com/babykart/gozone/commit/871f51d9ef22b51e10987e06430017264cc41cb7)) - [gozone] add RRSet comment support (PowerDNS comments API) - ([babykart](https://github.com/babykart))
- **(records)** ([7b1c62d](https://github.com/babykart/gozone/commit/7b1c62d10a37f35133d6fd532f6d1094647235a9)) - [gozone] allow clearing all RRSet comments via the UI - ([babykart](https://github.com/babykart))
- **(users)** ([da4cf8d](https://github.com/babykart/gozone/commit/da4cf8d97585e48b80052d24422408d65a35c4f9)) - [gozone] admin lock/unlock user accounts from the web UI - ([babykart](https://github.com/babykart))

### 💼 Other

- **(auth)** ([25ea7fa](https://github.com/babykart/gozone/commit/25ea7fa7009377df663b0233d909b967957542a5)) - [gozone] close login rate-limit bypass and add account lockout - ([babykart](https://github.com/babykart))
- **(auth)** ([2d3b3dd](https://github.com/babykart/gozone/commit/2d3b3dd502d5f4d9195a17f0d0b89cad7a50baa4)) - [gozone] exempt last admin from auto-lockout + add CLI unlock - ([babykart](https://github.com/babykart))

### 🐛 Bug Fixes

- **(api)** ([a64a325](https://github.com/babykart/gozone/commit/a64a32596406c62092c6135e0f8ac3a701744e5d)) - [gozone] normalise the records-list name query param to a FQDN - ([babykart](https://github.com/babykart))
- **(auth)** ([4bd12a1](https://github.com/babykart/gozone/commit/4bd12a16dc9fa4c75e83a12120287802382a8175)) - [gozone] return identical error on locked/wrong/unknown login - ([babykart](https://github.com/babykart))
- **(docker)** ([03b1bb3](https://github.com/babykart/gozone/commit/03b1bb3089315d3bc6ae2d6b8d6af8ca8b4ffae6)) - [gozone] standardize config flag - ([babykart](https://github.com/babykart))
- **(export)** ([61cc806](https://github.com/babykart/gozone/commit/61cc806f0a687e1eeed05a65037ea6e278dd7ed4)) - [gozone] exclude disabled records from BIND zone file output - ([babykart](https://github.com/babykart))
- **(web)** ([6dc6d78](https://github.com/babykart/gozone/commit/6dc6d7814ec4f450ecc09f699f4cec8935c883bc)) - [gozone] always render the per-page size selector - ([babykart](https://github.com/babykart))

### 🚜 Refactor

- **(db)** ([cf1a74b](https://github.com/babykart/gozone/commit/cf1a74bb1ed4ec0cd1d911d1e583798a0d7874d4)) - [gozone] split InsertIgnore columns and conflict-target columns - ([babykart](https://github.com/babykart))
- **(ui)** ([28330ca](https://github.com/babykart/gozone/commit/28330caefbc753df0a86206a6a71f396fa910293)) - [gozone] move Prio column between TTL and Content in zone view - ([babykart](https://github.com/babykart))

### 📚 Documentation

- **(readme)** ([8b5b680](https://github.com/babykart/gozone/commit/8b5b6803faba6c315d548ccd74198a46dd58ff93)) - add Kubernetes Helm chart installation instructions - ([babykart](https://github.com/babykart))
- **(readme)** ([bc3fd19](https://github.com/babykart/gozone/commit/bc3fd199f83585c51e1e7ee6e0e11011d59dcbea)) - [gozone] add RRSet Comments - ([babykart](https://github.com/babykart))
- **(readme)** ([82c16ac](https://github.com/babykart/gozone/commit/82c16acc35899f07cbb715945cbd5ee5a0fe15fb)) - [gozone] clarify that RRSet comment has no default account/modified_at - ([babykart](https://github.com/babykart))
- **(readme)** ([1b78fff](https://github.com/babykart/gozone/commit/1b78fff75ea94b181b084f30f423a7038429ea14)) - document brute-force protection and admin lock/unlock - ([babykart](https://github.com/babykart))
- **(readme)** ([2ac82ae](https://github.com/babykart/gozone/commit/2ac82ae1cf229b2b3544addf5e5231a71dc60890)) - [gozone] document gozone unlock CLI for locked-admin recovery - ([babykart](https://github.com/babykart))
- **(roadmap)** ([a7f2e82](https://github.com/babykart/gozone/commit/a7f2e82e6a723fc57b49cf6ffcb8d4ca08c91bd0)) - [gozone] update ROADMAP.md - ([babykart](https://github.com/babykart))
- **(roadmap)** ([b7d3d77](https://github.com/babykart/gozone/commit/b7d3d776b68bc0d384946645c0050d505b714aa1)) - [gozone] update ROADMAP.md - ([babykart](https://github.com/babykart))
- ([e7a1963](https://github.com/babykart/gozone/commit/e7a19638c6f87f859f8d830afa6441105e737b2e)) - refresh ARCHITECTURE.md to match current code - ([babykart](https://github.com/babykart))
- ([515ed25](https://github.com/babykart/gozone/commit/515ed253ac890fa82bd23fc623f39d0f0be24108)) - split REST API reference into dedicated docs/API.md - ([babykart](https://github.com/babykart))

### 🧪 Testing

- **(api)** ([62d1a84](https://github.com/babykart/gozone/commit/62d1a8488de449b1752d4c0b0918dd0e39f4c0b9)) - [gozone] pin the REST comments path to pass-through semantics - ([babykart](https://github.com/babykart))

<!-- generated by git-cliff -->
