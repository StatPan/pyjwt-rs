# Releasing pyjwt-rs

이 문서는 `pyjwt-rs`를 PyPI에 릴리스하는 전체 흐름을 정리합니다.

혼동 방지를 위해 순서는 **위에서 아래로** 한 번만 따라가면 됩니다.

---

## 0. 1회성 사전 세팅 (첫 릴리스 전에만)

### 0-1. PyPI pending publisher 등록

1. <https://pypi.org/manage/account/publishing/> 접속 (PyPI 로그인 필요).
2. **Add a new pending publisher** 클릭.
3. 필드 값:

   | 필드 | 값 |
   | --- | --- |
   | PyPI project name | `pyjwt-rs` |
   | Owner | `StatPan` |
   | Repository name | `pyjwt-rs` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

4. 저장. 첫 번째 릴리스 태그가 푸시되면 이 설정대로 PyPI 프로젝트가 자동 생성됩니다.

### 0-2. GitHub 환경(환경 보호) 생성

1. <https://github.com/StatPan/pyjwt-rs/settings/environments>
2. **New environment** → 이름 `pypi`.
3. (선택) **Required reviewers**에 본인 추가 → publish 직전에 수동 승인 버튼이 생김. 실수 방지용으로 권장.
4. 저장.

### 0-3. `main` 브랜치 보호 (선택)

Settings → Branches → `main`에 "require PR", "require checks", "require linear history" 등을 걸어두면 안전합니다. 필수는 아님.

---

## 1. 일반 릴리스 흐름 (1.1.0 이후부터)

앞으로는 `scripts/release.py` 한 번으로 끝납니다.

```bash
# 패치 릴리스 (1.1.0 -> 1.1.1)
uv run --extra bench python scripts/release.py patch

# 마이너 릴리스 (1.1.0 -> 1.2.0)
uv run --extra bench python scripts/release.py minor

# 메이저 릴리스 (1.1.0 -> 2.0.0)
uv run --extra bench python scripts/release.py major

# 명시적 버전
uv run --extra bench python scripts/release.py 1.2.3
```

플래그:

- `--dry-run` — 무엇을 할지만 출력, 파일은 안 건드림. 먼저 실행해서 계획 확인 권장.
- `--push` — 커밋 + 태그까지 바로 push. 없으면 로컬에서 멈추고 `git push --follow-tags` 명령만 안내.
- `--allow-dirty` — 워킹 트리가 clean이 아니어도 진행. 기본은 막음.
- `--skip-tests`, `--skip-bench` — 각각 `pytest`, 벤치 재생성을 건너뜀.

스크립트가 내부적으로 수행:

1. 브랜치 = `main`, 워킹 트리 clean, 태그 중복 없음을 검증.
2. `Cargo.toml` + `pyproject.toml` + `__pyjwt_rs_version__` 3곳의 버전을 **한 번에** 갱신.
3. `CHANGELOG.md`의 `[Unreleased]` 블록을 `[X.Y.Z] - YYYY-MM-DD` 섹션으로 승격하고, 하단 compare 링크를 갱신.
4. `scripts/update_readme_bench.py` 실행 → README 벤치 표 + `docs/benchmark.svg` 자동 재생성.
5. `pytest -q` 실행.
6. 위 파일들을 staging 후 `release: vX.Y.Z` 커밋 + annotated 태그 `vX.Y.Z` 생성.
7. `--push`면 바로 push.

태그가 origin에 도달하면 `.github/workflows/release.yml`이 자동으로:

- 모든 플랫폼(Linux x86_64/aarch64, macOS x86_64/arm64, Windows x64) × Python 3.10–3.13 휠 빌드
- sdist 빌드
- PyPI trusted publishing(OIDC)으로 업로드. **API 토큰 없음.**

---

## 2. 릴리스 진행 상황 확인

- Actions: <https://github.com/StatPan/pyjwt-rs/actions>
- PyPI 페이지: <https://pypi.org/project/pyjwt-rs/>
- 설치 테스트:

  ```bash
  pip install pyjwt-rs==X.Y.Z
  python -c "import jwt_rs; print(jwt_rs.__pyjwt_rs_version__)"
  ```

---

## 3. 실패했을 때

### 3-1. 워크플로가 publish 단계에서 실패

가장 흔한 원인: **PyPI pending publisher가 아직 등록되지 않았거나 환경 이름이 `pypi`가 아님**.
수정 후 Actions 화면에서 failed job의 **Re-run jobs** 버튼으로 재시도 가능.

### 3-2. PyPI에 이미 같은 버전이 올라간 경우

PyPI는 **같은 버전 재업로드를 금지**합니다. 해결:

1. 해당 버전을 "yanked" 처리 (PyPI 웹에서). yank된 버전은 새 설치에서 제외되지만 lockfile에 pin된 기존 사용자는 계속 받을 수 있음.
2. 다음 패치 버전으로 bump 후 재릴리스:

   ```bash
   uv run --extra bench python scripts/release.py patch --push
   ```

### 3-3. 태그는 찍었는데 push 전에 문제를 발견

```bash
git tag -d vX.Y.Z            # 로컬 태그 삭제
git reset --soft HEAD^       # 릴리스 커밋 되돌리기 (변경은 staging에 남음)
```

파일 수정 후 다시 `scripts/release.py` 실행.

### 3-4. push까지 끝난 뒤 PyPI 업로드 전에 취소하고 싶음

빠르게 GitHub Actions 화면에서 running workflow의 **Cancel workflow** 버튼 클릭. publish job 이전이면 안전하게 중단 가능.

---

## 4. 버전 축 두 개 (중요)

- `pyproject.toml.version` / `Cargo.toml.version` / `jwt_rs.__pyjwt_rs_version__` = **distribution 버전**.
  `pyjwt-rs` 자체 릴리스 번호. 스크립트가 세 곳을 동기화함.
- `jwt_rs.__version__` = **PyJWT 호환 버전**. `PyJWT 2.12.1` API 호환을 유지하는 한 고정.
  PyJWT 상류가 새 버전을 내면 `COMPATIBILITY_CHECKLIST.md`와 같이 업데이트.

자세한 이유는 `VERSIONING.md` 참고.
