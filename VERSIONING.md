# Versioning

`pyjwt-rs`는 두 가지 버전 축을 가집니다.

## 1. Distribution Version

배포 버전은 아래 세 곳에 동일하게 유지됩니다.

- `pyproject.toml` → `[project] version`
- `Cargo.toml` → `[package] version`
- `python/jwt_rs/__init__.py` → `__pyjwt_rs_version__`

현재 기준:

- `pyjwt-rs`: `1.1.2`

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

릴리스는 `scripts/release.py`가 end-to-end로 처리합니다.

```bash
# SemVer bump (권장)
uv run --extra bench python scripts/release.py patch           # 1.1.0 -> 1.1.1
uv run --extra bench python scripts/release.py minor           # 1.1.0 -> 1.2.0
uv run --extra bench python scripts/release.py major           # 1.1.0 -> 2.0.0

# 명시적 버전
uv run --extra bench python scripts/release.py 1.2.3

# 바로 push까지 (GitHub Actions가 PyPI 업로드 트리거)
uv run --extra bench python scripts/release.py minor --push

# 미리보기
uv run --extra bench python scripts/release.py minor --dry-run
```

스크립트가 수행하는 순서:

1. 워킹 트리가 clean이고 `main` 브랜치인지 확인 (`--allow-dirty`, `--force`로 우회 가능).
2. 태그 `vX.Y.Z`가 아직 로컬에 없는지 확인.
3. `Cargo.toml`, `pyproject.toml`, `__pyjwt_rs_version__` 버전을 일괄 갱신.
4. `CHANGELOG.md`의 `[Unreleased]` 블록을 새 버전 섹션으로 승격하고 compare 링크 갱신.
5. `scripts/update_readme_bench.py`로 README 벤치 표 + `docs/benchmark.svg` 재생성.
6. `pytest -q` 실행.
7. 관련 파일을 staging하고 `release: vX.Y.Z` 커밋 + annotated 태그 생성.
8. `--push`일 경우 `git push` + `git push origin vX.Y.Z`로 태그까지 송신.

`--push` 없이 실행하면 마지막에 `git push --follow-tags` 안내만 출력하고 멈춥니다 —
직접 로그 확인 후 푸시하고 싶을 때 씁니다.

태그가 origin으로 올라가면 `.github/workflows/release.yml`이 자동으로 sdist + 모든
플랫폼 wheels를 빌드하고 PyPI trusted publishing으로 업로드합니다.

## PyPI Trusted Publishing 세팅 (1회성)

PyPI 쪽에서 한 번만 설정합니다.

1. <https://pypi.org/manage/account/publishing/> 이동.
2. "Add a new pending publisher" 선택.
3. 필드:
   - PyPI project name: `pyjwt-rs`
   - Owner: GitHub 오너 아이디
   - Repository: `pyjwt-rs`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
4. 첫 릴리스 태그가 푸시되면 이 trusted publisher로 프로젝트가 생성됩니다.

GitHub 쪽 환경 보호(선택): repo Settings → Environments → `pypi` 환경을 만들고
수동 승인(required reviewers)을 걸어두면 릴리스 workflow가 publish 단계에서
일시 정지하며 승인을 기다립니다.
