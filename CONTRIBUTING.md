# Contributing

## Quality Bar

`pyjwt-rs` is release-gated. Changes must satisfy all of the following:

- No unexpected `pytest` warnings. The test gate runs with `-W error`.
- No unexpected `pytest` skips. Any intentional skip must be recorded in `.quality/pytest-allowlist.json`.
- No Rust compiler warnings in CI or release wheel builds.
- Public compatibility gaps must be tracked in GitHub issues before code lands.

Run the same gate locally:

```bash
uv run python scripts/pytest_gate.py
cargo check --release
uv run --with maturin maturin develop --release
```

## Workflow

Every code change follows `Issue -> Branch -> PR -> Merge`.

- Open or link a GitHub issue before changing behavior.
- Use branch names in the form `issue-<number>-<slug>`.
- Keep each PR scoped to a single issue whenever possible.
- PR titles must follow Conventional Commits. The repo validates this in CI.
- Prefer **squash merge** so the PR title becomes the releasable commit on `main`.
- Releasable prefixes for the automated release flow are `feat`, `fix`, `deps`, and `docs`.
- If a change affects compatibility, packaging, release safety, or warnings/skips, document that in the PR.
- Release automation changes must be validated with `Release Please` and `Release` workflow runs before merging when possible.

## Milestones

Release hardening work is tracked under the GitHub milestone `v1.2.0 Hardening`.

- `release-blocker` issues must be closed before the release tag is pushed.
- Non-blocking gaps may remain open only if they are publicly documented and linked from a GitHub issue.

## Public Tracking

Do not hide gaps behind local notes.

- Known compatibility gaps belong in `COMPATIBILITY_CHECKLIST.md` and GitHub issues.
- Release blockers belong in GitHub issues with the `release-blocker` label.
- Test skips and warning exemptions belong in versioned repo files, not ad-hoc local state.
