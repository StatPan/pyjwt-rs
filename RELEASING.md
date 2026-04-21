# Releasing pyjwt-rs

이 문서는 `pyjwt-rs`를 PyPI에 릴리스하는 전체 흐름을 정리합니다.

혼동 방지를 위해 순서는 **위에서 아래로** 한 번만 따라가면 됩니다.

---

## 0. 1회성 사전 세팅 (첫 릴리스 전에만)

### 0-1. PyPI API token 등록

1. PyPI에서 project-scoped API token 생성.
2. GitHub repo Settings → Secrets and variables → Actions로 이동.
3. `PYPI_API_TOKEN` secret 추가.

### 0-2. GitHub 환경(환경 보호) 생성

1. <https://github.com/StatPan/pyjwt-rs/settings/environments>
2. **New environment** → 이름 `pypi`.
3. (선택) **Required reviewers**에 본인 추가 → publish 직전에 수동 승인 버튼이 생김. 실수 방지용으로 권장.
4. 저장.

### 0-3. `main` 브랜치 보호 (선택)

Settings → Branches → `main`에 "require PR", "require checks", "require linear history" 등을 걸어두면 안전합니다. 필수는 아님.

---

## 1. 일반 릴리스 흐름

기본 경로는 `Release Please`입니다. 사람이 직접 버전을 고르지 않습니다.

1. 기능/수정 PR 제목을 Conventional Commits 형식으로 작성합니다.
   예: `fix(jwk): align unusable-key skip behavior`
2. PR은 가능하면 **squash merge** 합니다.
   `Release Please`는 기본적으로 `main`의 merge된 commit 제목을 읽어 다음 버전과
   release notes를 계산합니다.
3. `main`에 releasable commit이 쌓이면 `Release Please` 워크플로가 release PR을
   자동으로 열거나 갱신합니다.
4. release PR에는 아래가 자동 반영됩니다.
   - `Cargo.toml`
   - `pyproject.toml`
   - `python/jwt_rs/__init__.py` 의 `__pyjwt_rs_version__`
   - `CHANGELOG.md`
5. release PR을 merge하면 GitHub release + tag가 생성되고, 같은 자동화 흐름에서
   빌드 매트릭스와 PyPI publish가 이어집니다.

현재 기준 releasable commit type:

- `feat`
- `fix`
- `deps`
- `docs`

`build`, `ci`, `test`, `chore` 같은 제목은 Conventional Commits 검증은 통과해도,
기본적으로는 새 릴리스를 만들지 않습니다. 배포 영향이 있는 경우에는 PR 제목을
실제 releasable 의미에 맞게 잡아야 합니다.

### 수동 fallback

`scripts/release.py`는 fallback입니다. 자동 릴리스가 깨졌거나, 강제로 특정 버전을
생성해야 하는 경우에만 사용합니다.

```bash
uv run --extra bench python scripts/release.py patch
uv run --extra bench python scripts/release.py minor
uv run --extra bench python scripts/release.py major
uv run --extra bench python scripts/release.py 1.2.3
```

이 스크립트는 버전 파일 동기화, `CHANGELOG.md` 승격, strict pytest gate,
annotated tag 생성까지 처리합니다.

### 배포 매트릭스 수동 검증

자동 릴리스와 별개로, wheel/sdist 매트릭스를 먼저 보고 싶으면 GitHub Actions의
`Release` workflow를 `workflow_dispatch`로 실행해서 `publish = false`로 검증할 수 있습니다.

### 왜 플랫폼당 1개 휠인가 (abi3)

`Cargo.toml`의 PyO3가 `abi3-py310` feature로 빌드되기 때문에 각 휠은
**Python stable ABI (PEP 384)** 바이너리입니다. 한 휠이 `cp310-abi3-*` 태그로
나오고, 이 하나가 **CPython 3.10, 3.11, 3.12, 3.13 및 앞으로 나올 3.x 전부**에
설치됩니다.

그래서:

- 릴리스 매트릭스가 20 jobs → 5 jobs로 줄어듦 (4×).
- Python 3.14/3.15 나와도 재빌드·재릴리스 필요 없음.
- `pip install pyjwt-rs`가 사용자의 Python 버전에 상관없이 이미 만들어둔 휠을 받음.

제약:

- `requires-python = ">=3.10"` 필수 (pyproject에 이미 선언됨).
- PyO3의 abi3 미지원 API는 사용 불가 (현재 코드베이스 호환됨 — 324 tests 통과).
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

가장 흔한 원인:

- PyPI API token secret이 없거나 잘못됨
- release-please가 만든 tag/ref 기준으로 빌드가 깨짐

수정 후 Actions 화면에서 failed job의 **Re-run jobs** 버튼으로 재시도 가능.

### 3-2. PyPI에 이미 같은 버전이 올라간 경우

PyPI는 **같은 버전 재업로드를 금지**합니다. 해결:

1. 해당 버전을 "yanked" 처리 (PyPI 웹에서). yank된 버전은 새 설치에서 제외되지만 lockfile에 pin된 기존 사용자는 계속 받을 수 있음.
2. 다음 패치 버전 release PR을 생성/병합하거나, 필요 시 수동 fallback 사용:

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
  `pyjwt-rs` 자체 릴리스 번호. 기본적으로 `Release Please`가 세 곳을 동기화함.
- `jwt_rs.__version__` = **PyJWT 호환 버전**. `PyJWT 2.12.1` API 호환을 유지하는 한 고정.
  PyJWT 상류가 새 버전을 내면 `COMPATIBILITY_CHECKLIST.md`와 같이 업데이트.

자세한 이유는 `VERSIONING.md` 참고.
