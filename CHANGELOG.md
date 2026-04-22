# Changelog

All notable changes to `pyjwt-rs` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
on the **distribution** axis (`pyproject.toml` / `Cargo.toml` version). The
`jwt_rs.__version__` field tracks the PyJWT compatibility target separately and
is documented in `VERSIONING.md`.

## [1.2.2](https://github.com/StatPan/pyjwt-rs/compare/v1.2.1...v1.2.2) (2026-04-22)


### CI

* **release:** fix windows wheel target for publish matrix ([#18](https://github.com/StatPan/pyjwt-rs/issues/18)) ([f2962d9](https://github.com/StatPan/pyjwt-rs/commit/f2962d97c46280a16f044ddca2650cb7326d69c3))
* **release:** force node24 for release-please action ([#15](https://github.com/StatPan/pyjwt-rs/issues/15)) ([9d4a161](https://github.com/StatPan/pyjwt-rs/commit/9d4a1616c44b004566d19d315d2777f96199d49f))

## [1.2.1](https://github.com/StatPan/pyjwt-rs/compare/v1.2.0...v1.2.1) (2026-04-21)


### Bug Fixes

* **release:** automate versioning with release-please ([#13](https://github.com/StatPan/pyjwt-rs/issues/13)) ([390139b](https://github.com/StatPan/pyjwt-rs/commit/390139b3ece4c487080d0d52e6512aafea9f3677))


### CI

* **release:** publish with PyPI API token ([4d4a27c](https://github.com/StatPan/pyjwt-rs/commit/4d4a27ce1bfd4d5cb0dc9ee8922bc47f565989c6))
* **release:** restore PyPI API token publish fallback ([3289c4f](https://github.com/StatPan/pyjwt-rs/commit/3289c4ff95ab8e202159ec8b9f9f7c498d16d1e9))
* **release:** restore PyPI trusted publishing, bump download-artifact ([ccb6fd6](https://github.com/StatPan/pyjwt-rs/commit/ccb6fd62fdf12c2223874bd5f4dc15a5bddce53f))

## [Unreleased]

### Changed

- Added `Release Please` automation so release PRs now own distribution
  version bumps and `CHANGELOG.md` generation from conventional commits.
- Split the OS-specific wheel/sdist matrix into a reusable release workflow
  so both manual releases and release-please-created tags go through the
  same build and publish path.
- Added PR title validation to enforce Conventional Commits and make
  squash-merged PR titles usable as releasable commits on `main`.

## [1.2.0] - 2026-04-21

## [1.1.3] - 2026-04-21

### Fixed

- `before-script-linux` installed `perl-FindBin` as a separate package,
  which does not exist on manylinux2014 (CentOS 7) where those modules
  are bundled into `perl-core`. Drop the individual module names and
  install only `perl-core` + `perl-IPC-Cmd`.

## [1.1.2] - 2026-04-21

### Fixed

- Manylinux wheel builds failed because the vendored OpenSSL build requires
  a full Perl stack (`IPC::Cmd`, `FindBin`, `File::Compare`, `File::Copy`)
  that the stock manylinux image does not ship. Added a
  `before-script-linux` hook to the release workflow that installs
  `perl-core` and the needed Perl modules before invoking maturin.

## [1.1.1] - 2026-04-21

### Fixed

- Release wheel builds on Linux (manylinux), Windows, and macOS x86_64 were
  failing because `openssl-sys` could not locate OpenSSL in the CI
  environment. Wheel jobs now build against a vendored OpenSSL via a new
  `vendored-openssl` crate feature. `v1.1.0` was tagged but never uploaded
  to PyPI; `v1.1.1` is the first successful release.

## [1.1.0] - 2026-04-21

### Performance

- HS256 `encode` 0.33× → **1.45×**, `decode` 0.29× → **1.82×** vs PyJWT.
- RS256 `decode` 0.94× → **2.18×**; `encode` stays at ~60× win.
- ES256 `encode` 1.39× → **2.82×**.
- All 12 tracked hot paths now ≥ 1.0× vs PyJWT.

### Added

- `[profile.release]` in `Cargo.toml` with `lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`, `strip = "symbols"` — enables cross-crate inlining through
  the OpenSSL FFI path.
- Direct HMAC backend (`hmac` + `sha2`) replacing the `jsonwebtoken` indirection
  for `HS256` / `HS384` / `HS512`.
- `StoredKey::Hmac` variant; `hmac_sign_raw` / `hmac_verify_raw` Python exports.
- Raw-bytes sign/verify helpers for every backend
  (`sign_rsa_raw`, `sign_ec_raw`, `sign_ed_raw`, and their verify counterparts) —
  eliminates the base64 encode/decode round trip on the handle hot path.
- `rust_encode_token` — one-shot FFI encode (payload base64, signing-input
  assembly, sign, signature base64, and final concat all done in Rust).
- `rust_decode_and_verify` — one-shot FFI decode + signature verify; keeps
  `signing_input` and intermediate allocations inside Rust.
- Pre-built default-header base64 cache in `api_jws.py` keyed by algorithm.
- `docs/benchmark.svg` — auto-generated speedup chart.
- `scripts/plot_benchmark.py` — SVG chart generator (no external plotting lib).
- `.pre-commit-config.yaml` — refreshes `README.md` bench block and
  `docs/benchmark.svg` when source files change.
- `[project.optional-dependencies.bench]` extra (`pyjwt`).

### Changed

- `PyJWS.encode` fast path now routes HMAC through `rust_encode_token` as well,
  removing the previous HMAC-specific branch.
- `PyJWS.decode_complete` fast path merges segment-split and signature
  verification into a single FFI call when a single-algorithm `algorithms` list
  is provided and the key is not a `PyJWK`.
- `PyJWT.decode_complete` avoids redundant option-dict allocation when called
  with `options=None` (the common path).
- `PyJWT.encode` skips `payload.copy()` when no datetime-typed claim is present.
- `_validate_claims` short-circuits `sub` / `jti` checks when the claim is
  absent; defers `time.time()` lookup until a time-bound claim actually needs
  it.
- `scripts/update_readme_bench.py` now also invokes `plot_benchmark.render(...)`
  so a single bench run updates both the README table and the SVG chart.

### Compatibility

- PyJWT compatibility target: unchanged at `2.12.1`.
- 320 tests pass, 4 skipped — same as `1.0.0`. No public API changes.

## [1.0.0] - 2026-04

### Added

- Initial release of `pyjwt-rs`: PyO3 extension implementing PyJWT 2.12.1 API on
  top of Rust + OpenSSL.
- Algorithms: `HS256`/`384`/`512`, `RS256`/`384`/`512`, `PS256`/`384`/`512`,
  `ES256`/`384`/`512`/`256K`, `EdDSA` (`Ed25519`, `Ed448`), `none`.
- JWK / JWKS support (`PyJWK`, `PyJWKSet`, `PyJWKClient` with HTTP caching).
- Prepared key handle cache to avoid re-parsing PEM keys across `encode` /
  `decode` calls.
- Drop-in import: `import jwt_rs as jwt`.
- Benchmark harness (`scripts/benchmark_same_api.py`,
  `scripts/benchmark_decode_components.py`) and auto-updated README block.

[Unreleased]: https://github.com/StatPan/pyjwt-rs/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/StatPan/pyjwt-rs/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/StatPan/pyjwt-rs/releases/tag/v1.0.0
