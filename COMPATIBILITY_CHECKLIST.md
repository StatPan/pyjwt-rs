# PyJWT 2.12.1 Compatibility Checklist

기준 버전: `PyJWT 2.12.1`

기준 소스 범위:

- 공개 export: `jwt_rs/__init__.py`
- JWT API: `jwt_rs/api_jwt.py`
- JWS API: `jwt_rs/api_jws.py`
- JWK API: `jwt_rs/api_jwk.py`
- JWKS client: `jwt_rs/jwks_client.py`
- 알고리즘 계층: `jwt_rs/algorithms.py`

상태 표기:

- `[x]` 완료
- `[-]` 부분 구현
- `[ ]` 미구현

## 1. Package Surface

- [x] `import jwt_rs as jwt` 로 주요 공개 API export 제공
  근거: [python/jwt_rs/__init__.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/__init__.py:1)
- [x] `__version__ = "2.12.1"` 제공
  근거: [python/jwt_rs/__init__.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/__init__.py:30)
- [x] `PyJWS`, `PyJWT`, `PyJWK`, `PyJWKSet`, `PyJWKClient` export
  근거: [python/jwt_rs/__init__.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/__init__.py:1)
- [x] 예외 타입 export
  근거: [python/jwt_rs/__init__.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/__init__.py:9)
- [x] 경고 타입 export
  근거: [python/jwt_rs/__init__.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/__init__.py:27)
- [x] `jwt_rs.algorithms` 모듈 자체 호환
  근거: [python/jwt_rs/algorithms.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/algorithms.py:1)

## 2. Top-Level JWT API

- [x] `encode(payload, key, algorithm, headers, json_encoder, sort_headers)`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:63)
- [x] `decode(jwt, key, algorithms, options, verify, detached_payload, audience, subject, issuer, leeway, **kwargs)`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:181)
- [x] `decode_complete(...)`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:111)
- [x] `get_unverified_header(jwt)`
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:259)
- [x] `decode_complete()` 가 `header` / `payload` / `signature` 반환
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:235)

## 3. Encode Behavior

- [x] payload가 `dict`가 아니면 `TypeError`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:72)
- [x] `exp` / `iat` / `nbf` 의 `datetime` 자동 변환
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:78)
- [x] `iss` 가 문자열이 아니면 `TypeError`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:82)
- [x] `headers["alg"]` 우선 처리
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:130)
- [x] `sort_headers` 반영
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:153)
- [x] detached payload (`b64=False`) 지원
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:148)
- [x] `json_encoder` 호환
  payload / header 모두 `json.dumps(..., cls=json_encoder)` 경로를 사용하며,
  datetime claim 변환 이후의 payload 값과 비표준 header 값에 대한 회귀 테스트를 추가해 동작을 고정함

## 4. Decode / Validation Behavior

- [x] `verify_signature=True` 이고 `algorithms` 미지정 시 에러
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:216)
- [x] `verify_signature=False` 경로 지원
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:138)
- [x] `require` claim 검증
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:259)
- [x] `verify_exp`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:289)
- [x] `verify_nbf`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:281)
- [x] `verify_iat`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:273)
- [x] `verify_aud`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:300)
- [x] `verify_iss`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:334)
- [x] `verify_sub`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:261)
- [x] `verify_jti`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:270)
- [x] `strict_aud`
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:313)
- [x] `leeway` 에 `float` / `timedelta` 지원
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:228)
- [x] deprecated `verify` 경고 처리
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:135)
- [x] unsupported `kwargs` warning 처리
  근거: [python/jwt_rs/api_jwt.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwt.py:125)

## 5. Header Validation

- [x] `kid` 타입 검증
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:343)
- [x] `crit` 헤더 검증
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:347)
- [x] `b64` critical extension 지원
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:338)

## 6. Supported Algorithms

- [x] `none`
- [x] `HS256`
- [x] `HS384`
- [x] `HS512`
- [x] `RS256`
- [x] `RS384`
- [x] `RS512`
- [x] `PS256`
- [x] `PS384`
- [x] `PS512`
- [x] `ES256`
- [x] `ES384`
- [x] `ES512`
- [x] `ES256K`
- [x] `EdDSA`
  근거: [src/lib.rs](/home/statpan/workspace/pypi_lib/pyjwt-rs/src/lib.rs:1)

- [x] `ES521` backward-compat alias
  근거: [python/jwt_rs/algorithms.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/algorithms.py:513)

## 7. Rust Backend Coverage

- [x] `HS*`는 Rust native hash/HMAC 경로 사용
  근거: [src/lib.rs](/home/statpan/workspace/pypi_lib/pyjwt-rs/src/lib.rs:1)
- [x] `RS*` / `PS*`는 Rust 내부 OpenSSL `PKey` sign/verify 경로 사용
  근거: [src/lib.rs](/home/statpan/workspace/pypi_lib/pyjwt-rs/src/lib.rs:1)
- [x] `ES256` / `ES384` / `ES512` / `ES256K`는 Rust 내부 OpenSSL EC sign/verify 경로 사용
  근거: [src/lib.rs](/home/statpan/workspace/pypi_lib/pyjwt-rs/src/lib.rs:1)
- [x] `EdDSA`는 Rust 내부 OpenSSL Ed25519/Ed448 sign/verify 경로 사용
  근거: [src/lib.rs](/home/statpan/workspace/pypi_lib/pyjwt-rs/src/lib.rs:1)

## 8. Exceptions and Warnings

- [x] `PyJWTError`
- [x] `InvalidTokenError`
- [x] `DecodeError`
- [x] `InvalidSignatureError`
- [x] `ExpiredSignatureError`
- [x] `InvalidAudienceError`
- [x] `InvalidIssuerError`
- [x] `InvalidIssuedAtError`
- [x] `ImmatureSignatureError`
- [x] `InvalidKeyError`
- [x] `InvalidAlgorithmError`
- [x] `MissingRequiredClaimError`
- [x] `InvalidSubjectError`
- [x] `InvalidJTIError`
- [x] `PyJWKError`
- [x] `PyJWKSetError`
- [x] `PyJWKClientError`
- [x] `PyJWKClientConnectionError`
  근거: [python/jwt_rs/exceptions.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/exceptions.py:1)

- [x] `RemovedInPyjwt3Warning`
- [x] `InsecureKeyLengthWarning`
  근거: [python/jwt_rs/warnings.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/warnings.py:1)

- [-] key-length enforcement 완전 호환
  HMAC warning은 맞췄지만, upstream의 모든 알고리즘별 minimum-length enforcement 경로를 동일하게 맞춘 것은 아님

## 9. PyJWK

- [x] `PyJWK.from_dict()`
- [x] `PyJWK.from_json()`
- [x] `kty` / `alg` / `crv` 기준 알고리즘 추론
- [x] `key_type`, `key_id`, `public_key_use` 속성
  근거: [python/jwt_rs/api_jwk.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwk.py:37)

- [x] `oct` JWK 파싱
- [x] `RSA` JWK 파싱
- [x] `EC` JWK 파싱
- [x] `OKP` (`Ed25519`) JWK 파싱
  근거: [python/jwt_rs/api_jwk.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwk.py:85)

- [x] `Algorithm` 객체 호환
  `PyJWK.Algorithm` 이 실제 `jwt.algorithms.Algorithm` 구현체를 가리킴
  근거: [python/jwt_rs/api_jwk.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwk.py:60)
- [ ] `PyJWK` 가 실제 cryptography key object를 그대로 노출하는 호환성
  현재는 내부적으로 PEM bytes 중심

## 10. PyJWKSet

- [x] `PyJWKSet.from_dict()`
- [x] `PyJWKSet.from_json()`
- [x] iterable 지원
- [x] `kid` 조회 (`__getitem__`)
  근거: [python/jwt_rs/api_jwk.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jwk.py:170)

- [-] unusable key skip behavior 검증
  구현은 있으나 upstream edge case를 충분히 대조하지는 않음

## 11. PyJWKClient / JWKS

- [x] JWKS fetch
- [x] headers / timeout / ssl_context 지원
- [x] JWK Set cache
- [x] LRU key cache
- [x] `get_jwk_set()`
- [x] `get_signing_keys()`
- [x] `get_signing_key(kid)`
- [x] `get_signing_key_from_jwt(token)`
  근거: [python/jwt_rs/jwks_client.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/jwks_client.py:1), [python/jwt_rs/jwk_set_cache.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/jwk_set_cache.py:1)

- [-] HTTP/network error surface 전수 대조
  대표 경로는 맞췄지만 upstream와 완전 동일한 예외 메시지/모든 edge case 검증은 아직 없음

## 12. JWS Algorithm Registry

- [x] `register_algorithm(name, obj)` custom algorithm 객체를 실제 sign/verify 경로에 연결
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:44)
- [x] `unregister_algorithm(name)`
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:52)
- [x] `get_algorithm_by_name(name)` 가 실제 알고리즘 객체 반환
  근거: [python/jwt_rs/api_jws.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/api_jws.py:63)

## 13. Missing Modules / Surfaces

- [x] `jwt.algorithms` module
- [x] `get_default_algorithms()`
- [x] `Algorithm` base class hierarchy
- [x] `HMACAlgorithm`, `RSAAlgorithm`, `RSAPSSAlgorithm`, `ECAlgorithm`, `OKPAlgorithm`, `NoneAlgorithm`
- [x] algorithm-level `to_jwk()` / `from_jwk()`
- [x] `has_crypto`, `requires_cryptography` compatibility surface
  근거: [python/jwt_rs/algorithms.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/python/jwt_rs/algorithms.py:1)

## 14. Test Coverage

- [x] public API roundtrip tests
- [x] detached payload test
- [x] JWK decode tests
- [x] JWKS client fetch test
- [x] `ES512` / `ES256K` roundtrip tests
- [x] custom algorithm registry tests
- [x] algorithm module tests
  근거: [tests/test_pyjwt_compat.py](/home/statpan/workspace/pypi_lib/pyjwt-rs/tests/test_pyjwt_compat.py:1)

- [ ] upstream `PyJWT` test suite 직접 포팅 / 실행
- [ ] error message parity regression suite

## Summary

- 완료: 상단 JWT/JWS/JWK/JWKS 핵심 기능, 알고리즘 객체 계층, custom algorithm registry, 주요 알고리즘
- 부분: key-length enforcement parity, 일부 edge-case parity, cryptography key object 그대로 노출하는 세부 호환
- 미구현: upstream test suite 직접 포팅과 메시지 수준 회귀 정리

`모든 기능`을 목표로 한다면 다음 우선순위가 맞습니다.

1. upstream test suite 직접 대조/포팅
2. 에러 메시지와 edge case parity 정리
3. cryptography key object 노출/acceptance 세부 차이 정리
