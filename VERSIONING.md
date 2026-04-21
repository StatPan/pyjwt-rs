# Versioning

`pyjwt-rs`는 두 가지 버전 축을 가집니다.

## 1. Distribution Version

배포 버전은 아래 세 곳에 동일하게 유지됩니다.

- `pyproject.toml` → `[project] version`
- `Cargo.toml` → `[package] version`
- `python/jwt_rs/__init__.py` → `__pyjwt_rs_version__`

현재 기준:

- `pyjwt-rs`: `1.2.1` <!-- x-release-please-version -->

## 2. Compatibility Version

`python/jwt_rs/__init__.py`의 `__version__`은 `PyJWT` 호환 표면을 따릅니다.

현재 기준:

- `jwt_rs.__version__`: `2.12.1`

이 값은 `pyjwt-rs` 패키지 버전이 아니라, 목표 호환 기준인 `PyJWT 2.12.1`을 나타냅니다.

## Release Rule

릴리스 시에는 아래를 구분해서 관리합니다.

1. `pyjwt-rs` 기능/성능/패키징 변경
   `pyproject.toml`, `Cargo.toml`, `__pyjwt_rs_version__` 세 곳의 버전을 함께 올리고
   `CHANGELOG.md`에 엔트리를 추가합니다.
2. `PyJWT` 호환 기준 업데이트
   `jwt_rs.__version__`과 `COMPATIBILITY_CHECKLIST.md`를 함께 갱신합니다.

## Release

기본 릴리스 경로는 이제 `release-please`입니다.

1. PR 제목을 Conventional Commits 형식으로 맞춥니다.
2. PR은 가능하면 **squash merge** 합니다.
3. `main`에 releasable commit (`feat`, `fix`, `deps`, `docs`)가 쌓이면
   `Release Please` 워크플로가 release PR을 열거나 갱신합니다.
4. release PR에는 `Cargo.toml`, `pyproject.toml`,
   `__pyjwt_rs_version__`, `CHANGELOG.md`가 자동 반영됩니다.
5. release PR을 merge하면 Git tag / GitHub release가 생성되고, 같은 자동화
   흐름에서 wheel/sdist build + PyPI publish까지 이어집니다.

수동 스크립트 `scripts/release.py`는 fallback 전용입니다. 자동화가 깨졌거나,
강제로 특정 버전을 찍어야 할 때만 사용합니다.

## PyPI Publishing 세팅 (1회성)

현재 publish 경로는 `PYPI_API_TOKEN` 기반입니다.

1. PyPI에서 project-scoped API token 생성
2. GitHub repo Settings → Secrets and variables → Actions
3. `PYPI_API_TOKEN` secret 추가

GitHub 쪽 환경 보호(선택): repo Settings → Environments → `pypi` 환경을 만들고
수동 승인(required reviewers)을 걸어두면 publish job이 승인 대기 상태로 멈춥니다.
