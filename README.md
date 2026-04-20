# pyjwt-rs

`PyJWT` 대체를 목표로 하는 Rust 기반 Python 확장 모듈입니다.

현재 포함 기능:

- `encode(payload, key, algorithm="HS256", headers=None)`
- `decode(token, key, algorithms=None, options=None, audience=None, issuer=None, leeway=0)`
- `get_unverified_header(token)`

초기 구현 범위:

- HMAC: `HS256`, `HS384`, `HS512`
- RSA: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`
- EC: `ES256`, `ES384`
- `EdDSA`

## 개발환경

```bash
source "$HOME/.cargo/env"
cd pyjwt-rs
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
maturin develop
pytest
```

## 사용 예시

```python
import rust_pyjwt as jwt

token = jwt.encode({"sub": "alice"}, "secret", algorithm="HS256")
claims = jwt.decode(token, "secret", algorithms=["HS256"])
header = jwt.get_unverified_header(token)
```

## 주의

- `options={"verify_signature": False}` 는 `jsonwebtoken::insecure_decode` 경로를 사용합니다.
- 완전한 `PyJWT` API 호환이 아니라, 대체 이행을 위한 핵심 API부터 맞춰둔 상태입니다.

