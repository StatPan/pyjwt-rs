# pyjwt-rs

`jwt_rs`는 `PyJWT` 호환을 목표로 하는 Rust 기반 Python 확장 모듈입니다.

핵심 목표는 두 가지입니다.

- 같은 코드에 `import jwt_rs as jwt`만 바꿔서 동작할 것
- Rust 코어로 주요 공개키 JWT workload에서 `PyJWT`보다 더 빠를 것

## Current Status

현재 공개 표면은 `PyJWT` 스타일을 유지합니다.

- `encode(payload, key, algorithm="HS256", headers=None)`
- `decode(token, key, algorithms=None, options=None, audience=None, issuer=None, leeway=0)`
- `decode_complete(...)`
- `get_unverified_header(token)`
- `PyJWS`, `PyJWK`, algorithm registry

현재 지원 알고리즘:

- HMAC: `HS256`, `HS384`, `HS512`
- RSA: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`
- EC: `ES256`, `ES384`, `ES512`, `ES256K`
- `EdDSA`

테스트 상태:

- `320 passed, 4 skipped`

## Usage

```python
import jwt_rs as jwt

token = jwt.encode({"sub": "alice"}, "secret", algorithm="HS256")
claims = jwt.decode(token, "secret", algorithms=["HS256"])
header = jwt.get_unverified_header(token)
```

## Performance

성능 목표는 `모든 경로 일괄 2배`가 아니라, 먼저 `실사용 공개키 경로`에서 `PyJWT`를 확실히 추월하는 것입니다.

아래 블록은 benchmark 스크립트로 자동 생성됩니다. 수동으로 적지 않습니다.

<!-- BENCHMARK:START -->
_Auto-generated from `scripts/benchmark_same_api.py` on `2026-04-21T04:49:00+00:00` using `--iterations 150 --warmup 20`._

현재 same-API benchmark 기준:

| Case | encode | decode | decode_complete |
| --- | ---: | ---: | ---: |
| `hs256` | `1.52x` | `1.96x` | `1.95x` |
| `rs256` | `58.86x` | `2.02x` | `2.03x` |
| `es256` | `2.89x` | `1.79x` | `1.78x` |
| `eddsa` | `1.54x` | `1.04x` | `1.11x` |

좋은 구간:
- `rs256.encode`: `jwt_rs`가 `PyJWT` 대비 `58.86x`
- `es256.encode`: `jwt_rs`가 `PyJWT` 대비 `2.89x`
- `es256.decode`: `jwt_rs`가 `PyJWT` 대비 `1.79x`
- `eddsa.encode`: `jwt_rs`가 `PyJWT` 대비 `1.54x`

아직 미달인 구간:
- 현재 주요 추적 경로는 모두 `PyJWT` 이상입니다.

해석:
- `1.00x` 초과면 `jwt_rs`가 빠릅니다.
- `2.00x` 이상이면 README 목표인 `PyJWT 대비 2배`를 넘긴 것입니다.
- 현재 목표는 특히 공개키 경로에서 이 값을 끌어올리는 것입니다.
<!-- BENCHMARK:END -->

벤치 재현 명령:

```bash
uv run --with pyjwt python scripts/benchmark_same_api.py --iterations 150 --warmup 20
```

README 자동 갱신 명령:

```bash
uv run python scripts/update_readme_bench.py
```

## Development

```bash
source "$HOME/.cargo/env"
cd pyjwt-rs
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
uv run --with maturin maturin develop
uv run pytest -q
```

## Notes

- Python은 호환 인터페이스를 담당하고, 코어 sign/verify hot path는 Rust가 담당합니다.
- 현재 공개키 알고리즘 경로는 Rust 내부 OpenSSL backend를 사용합니다.
- `options={"verify_signature": False}` 경로는 별도 insecure decode 흐름을 사용합니다.
- 완전한 `PyJWT` parity를 목표로 하지만, 성능 최적화를 위해 내부 구현은 `PyJWT`와 다릅니다.
- 배포 버전과 `PyJWT` 호환 버전 구분은 [VERSIONING.md](/home/statpan/workspace/pypi_lib/pyjwt-rs/VERSIONING.md:1) 에 정리했습니다.
