#!/usr/bin/env python3
"""Release automation for pyjwt-rs.

End-to-end flow:
  1. Validate working tree state (clean, on main).
  2. Bump the three distribution-version files.
  3. Promote CHANGELOG's [Unreleased] block to the new version.
  4. Regenerate README benchmark block + docs/benchmark.svg.
  5. Run pytest.
  6. Commit, tag (annotated), and optionally push (which triggers PyPI publish).

Usage:
  python scripts/release.py patch                 # 1.1.0 -> 1.1.1
  python scripts/release.py minor                 # 1.1.0 -> 1.2.0
  python scripts/release.py major                 # 1.1.0 -> 2.0.0
  python scripts/release.py 1.2.3                 # explicit
  python scripts/release.py minor --push          # auto-push commit + tag
  python scripts/release.py minor --dry-run       # plan only, no writes
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARGO_TOML = ROOT / "Cargo.toml"
PYPROJECT = ROOT / "pyproject.toml"
INIT_PY = ROOT / "python" / "jwt_rs" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"
VERSIONING = ROOT / "VERSIONING.md"


# --- shell helpers --------------------------------------------------------


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    kwargs: dict = {"cwd": str(ROOT), "text": True}
    if capture:
        kwargs["capture_output"] = True
    return subprocess.run(cmd, check=check, **kwargs)


def git(*args: str, capture: bool = True) -> str:
    result = run(["git", *args], capture=capture)
    return (result.stdout or "").strip()


# --- version parsing ------------------------------------------------------


VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse_version(s: str) -> tuple[int, int, int]:
    m = VERSION_RE.match(s)
    if not m:
        raise ValueError(f"not a valid semver triple: {s!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def fmt_version(v: tuple[int, int, int]) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}"


def bump(current: tuple[int, int, int], kind: str) -> tuple[int, int, int]:
    major, minor, patch = current
    if kind == "major":
        return (major + 1, 0, 0)
    if kind == "minor":
        return (major, minor + 1, 0)
    if kind == "patch":
        return (major, minor, patch + 1)
    raise ValueError(f"unknown bump kind: {kind}")


def current_distribution_version() -> tuple[int, int, int]:
    text = CARGO_TOML.read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise RuntimeError("could not find version in Cargo.toml")
    return parse_version(m.group(1))


# --- file edits -----------------------------------------------------------


def replace_once(path: Path, pattern: str, repl: str, *, label: str) -> None:
    text = path.read_text()
    new, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    if n != 1:
        raise RuntimeError(f"{label}: pattern not matched exactly once in {path}")
    path.write_text(new)


def update_version_files(new_version: str) -> None:
    replace_once(
        CARGO_TOML,
        r'^(version\s*=\s*)"[^"]+"',
        rf'\1"{new_version}"',
        label="Cargo.toml version",
    )
    replace_once(
        PYPROJECT,
        r'^(version\s*=\s*)"[^"]+"',
        rf'\1"{new_version}"',
        label="pyproject.toml version",
    )
    replace_once(
        INIT_PY,
        r'^(__pyjwt_rs_version__\s*=\s*)"[^"]+"',
        rf'\1"{new_version}"',
        label="__pyjwt_rs_version__",
    )
    # Documentation — VERSIONING.md stays in sync for readers but isn't fatal.
    try:
        replace_once(
            VERSIONING,
            r"(`pyjwt-rs`:\s*`)[^`]+(`)",
            rf"\g<1>{new_version}\g<2>",
            label="VERSIONING.md current version",
        )
    except RuntimeError as err:
        print(f"warn: {err}", file=sys.stderr)


def promote_changelog(new_version: str, today: str) -> None:
    text = CHANGELOG.read_text()
    unreleased_header = "## [Unreleased]"
    if unreleased_header not in text:
        raise RuntimeError("CHANGELOG.md is missing '## [Unreleased]' section")

    # Insert a fresh empty Unreleased above the promoted section.
    new_section_header = f"## [{new_version}] - {today}"
    promoted = text.replace(
        unreleased_header,
        f"{unreleased_header}\n\n{new_section_header}",
        1,
    )

    # Update link references at the bottom of the file.
    # Replace `[Unreleased]: ...compare/vOLD...HEAD` with new version links.
    old_version = fmt_version(current_distribution_version())
    link_pattern = re.compile(r"^\[Unreleased\]:\s*(.+/compare/)v[^\s.]+\.\.\.HEAD\s*$", re.MULTILINE)
    compare_url_match = link_pattern.search(promoted)
    if compare_url_match:
        base = compare_url_match.group(1)
        new_links = (
            f"[Unreleased]: {base}v{new_version}...HEAD\n"
            f"[{new_version}]: {base}v{old_version}...v{new_version}"
        )
        promoted = link_pattern.sub(new_links, promoted)

    CHANGELOG.write_text(promoted)


# --- preflight ------------------------------------------------------------


def ensure_clean_tree(allow_dirty: bool) -> None:
    status = git("status", "--porcelain")
    if status and not allow_dirty:
        print("working tree not clean. Use --allow-dirty to override.", file=sys.stderr)
        print(status, file=sys.stderr)
        sys.exit(1)


def ensure_branch(required: str, force: bool) -> None:
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch != required and not force:
        print(
            f"on branch '{branch}', expected '{required}'. Use --force to override.",
            file=sys.stderr,
        )
        sys.exit(1)


def ensure_tag_free(tag: str) -> None:
    existing = git("tag", "--list", tag)
    if existing:
        print(f"tag '{tag}' already exists locally", file=sys.stderr)
        sys.exit(1)


# --- workflow steps -------------------------------------------------------


def run_bench_refresh(skip: bool) -> None:
    if skip:
        print("[skip] bench refresh")
        return
    print("[step] refreshing README bench + docs/benchmark.svg")
    run([sys.executable, "scripts/update_readme_bench.py"])


def run_tests(skip: bool) -> None:
    if skip:
        print("[skip] pytest")
        return
    print("[step] running strict pytest gate")
    run([sys.executable, "scripts/pytest_gate.py"])


def stage_and_commit(new_version: str, dry_run: bool) -> None:
    files = [
        "Cargo.toml",
        "pyproject.toml",
        "python/jwt_rs/__init__.py",
        "CHANGELOG.md",
        "VERSIONING.md",
        "README.md",
        "docs/benchmark.svg",
    ]
    existing = [f for f in files if (ROOT / f).exists()]
    if dry_run:
        print(f"[dry-run] would `git add {' '.join(existing)}`")
        print(f"[dry-run] would `git commit -m 'release: v{new_version}'`")
        return
    run(["git", "add", *existing])
    run(["git", "commit", "-m", f"release: v{new_version}"])


def create_tag(new_version: str, dry_run: bool) -> None:
    tag = f"v{new_version}"
    if dry_run:
        print(f"[dry-run] would `git tag -a {tag} -m 'pyjwt-rs {tag}'`")
        return
    run(["git", "tag", "-a", tag, "-m", f"pyjwt-rs {tag}"])


def maybe_push(new_version: str, push: bool, dry_run: bool) -> None:
    if dry_run:
        if push:
            print(f"[dry-run] would `git push && git push origin v{new_version}`")
        else:
            print("[dry-run] next step: `git push --follow-tags`")
        return
    if not push:
        print()
        print(f"commit + tag v{new_version} created locally.")
        print("push when ready:")
        print("    git push --follow-tags")
        return
    print("[step] pushing branch + tag")
    run(["git", "push"])
    run(["git", "push", "origin", f"v{new_version}"])
    print()
    print(f"pushed. Watch the release workflow: https://github.com/StatPan/pyjwt-rs/actions")


# --- CLI ------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Release pyjwt-rs to PyPI.")
    parser.add_argument(
        "bump_or_version",
        help="'major' / 'minor' / 'patch' (SemVer bump) or an explicit '1.2.3' version.",
    )
    parser.add_argument("--push", action="store_true", help="Push commit + tag after success.")
    parser.add_argument("--dry-run", action="store_true", help="Plan only, write nothing.")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow unclean working tree.")
    parser.add_argument("--force", action="store_true", help="Allow non-main branch.")
    parser.add_argument("--branch", default="main", help="Required branch (default: main).")
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--skip-bench", action="store_true")
    args = parser.parse_args()

    current = current_distribution_version()
    if args.bump_or_version in ("major", "minor", "patch"):
        new = bump(current, args.bump_or_version)
    else:
        new = parse_version(args.bump_or_version)

    new_version = fmt_version(new)
    if new <= current:
        print(
            f"new version {new_version} is not greater than current {fmt_version(current)}",
            file=sys.stderr,
        )
        sys.exit(1)

    today = dt.date.today().isoformat()
    tag = f"v{new_version}"

    print(f"pyjwt-rs release: {fmt_version(current)} -> {new_version} (tag {tag}, date {today})")
    print(f"cwd: {ROOT}")
    print()

    ensure_clean_tree(args.allow_dirty)
    ensure_branch(args.branch, args.force)
    ensure_tag_free(tag)

    if args.dry_run:
        print("[dry-run] would update version files, promote CHANGELOG, refresh bench, test, commit, tag")
        maybe_push(new_version, args.push, dry_run=True)
        return

    print("[step] updating version files")
    update_version_files(new_version)

    print("[step] promoting CHANGELOG")
    promote_changelog(new_version, today)

    run_bench_refresh(args.skip_bench)
    run_tests(args.skip_tests)

    stage_and_commit(new_version, dry_run=False)
    create_tag(new_version, dry_run=False)
    maybe_push(new_version, args.push, dry_run=False)


if __name__ == "__main__":
    main()
