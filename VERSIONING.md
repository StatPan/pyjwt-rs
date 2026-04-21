# Versioning

`pyjwt-rs`는 두 가지 버전 축을 가집니다.

## 1. Distribution Version

배포 버전은 `pyproject.toml`과 `Cargo.toml`의 `version`을 기준으로 합니다.

- Python package: `pyproject.toml`
- Rust crate: `Cargo.toml`

이 버전은 `pyjwt-rs` 자체 릴리스 버전입니다.

현재 기준:

- `pyjwt-rs`: `1.0.0`

## 2. Compatibility Version

`python/jwt_rs/__init__.py`의 `__version__`은 `PyJWT` 호환 표면을 따릅니다.

현재 기준:

- `jwt_rs.__version__`: `2.12.1`

이 값은 `pyjwt-rs` 패키지 버전이 아니라, 목표 호환 기준인 `PyJWT 2.12.1`을 나타냅니다.

## Release Rule

릴리스 시에는 아래를 구분해서 관리합니다.

1. `pyjwt-rs` 기능/성능/패키징 변경
   `pyproject.toml`과 `Cargo.toml` 버전을 올립니다.
2. `PyJWT` 호환 기준 업데이트
   `jwt_rs.__version__`과 관련 compatibility 문서를 함께 갱신합니다.

## Sanity Check

릴리스 전에는 최소한 아래를 확인합니다.

```bash
uv run pytest -q
uv run --with pyjwt python scripts/benchmark_same_api.py --iterations 150 --warmup 20
```
