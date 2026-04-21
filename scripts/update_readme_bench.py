from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plot_benchmark  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
README_PATH = ROOT / "README.md"
BENCH_SCRIPT = ROOT / "scripts" / "benchmark_same_api.py"
START_MARKER = "<!-- BENCHMARK:START -->"
END_MARKER = "<!-- BENCHMARK:END -->"

DEFAULT_ITERATIONS = 150
DEFAULT_WARMUP = 20


def run_benchmark() -> dict:
    command = [
        sys.executable,
        str(BENCH_SCRIPT),
        "--iterations",
        str(DEFAULT_ITERATIONS),
        "--warmup",
        str(DEFAULT_WARMUP),
        "--json",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    start = result.stdout.find("{")
    if start == -1:
        raise RuntimeError("benchmark output did not contain JSON")
    return json.loads(result.stdout[start:])


def summarize_case(speedups: dict[str, float], case: str) -> str:
    encode = speedups[f"{case}.encode"]
    decode = speedups[f"{case}.decode"]
    decode_complete = speedups[f"{case}.decode_complete"]
    return (
        f"| `{case}` | `{encode:.2f}x` | `{decode:.2f}x` | `{decode_complete:.2f}x` |"
    )


def build_benchmark_block(data: dict) -> str:
    speedups = data["speedups"]
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    highlights: list[str] = []
    for metric in ("rs256.encode", "es256.encode", "es256.decode", "eddsa.encode"):
        value = speedups[metric]
        if value >= 1.0:
            highlights.append(f"- `{metric}`: `jwt_rs`가 `PyJWT` 대비 `{value:.2f}x`")
    if not highlights:
        highlights.append("- 현재는 `PyJWT`를 이기는 주요 경로가 없습니다.")

    gaps: list[str] = []
    for metric in ("rs256.decode", "eddsa.decode", "hs256.encode", "hs256.decode"):
        value = speedups[metric]
        if value < 1.0:
            gaps.append(f"- `{metric}`: 아직 `PyJWT`보다 느림 (`{value:.2f}x`)")
    if not gaps:
        gaps.append("- 현재 주요 추적 경로는 모두 `PyJWT` 이상입니다.")

    lines = [
        START_MARKER,
        f"_Auto-generated from `scripts/benchmark_same_api.py` on `{generated_at}` using `--iterations {DEFAULT_ITERATIONS} --warmup {DEFAULT_WARMUP}`._",
        "",
        "현재 same-API benchmark 기준:",
        "",
        "| Case | encode | decode | decode_complete |",
        "| --- | ---: | ---: | ---: |",
        summarize_case(speedups, "hs256"),
        summarize_case(speedups, "rs256"),
        summarize_case(speedups, "es256"),
        summarize_case(speedups, "eddsa"),
        "",
        "좋은 구간:",
        *highlights,
        "",
        "아직 미달인 구간:",
        *gaps,
        "",
        "해석:",
        "- `1.00x` 초과면 `jwt_rs`가 빠릅니다.",
        "- `2.00x` 이상이면 README 목표인 `PyJWT 대비 2배`를 넘긴 것입니다.",
        "- 현재 목표는 특히 공개키 경로에서 이 값을 끌어올리는 것입니다.",
        END_MARKER,
    ]
    return "\n".join(lines)


def update_readme(block: str) -> None:
    readme = README_PATH.read_text()
    start = readme.find(START_MARKER)
    end = readme.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise RuntimeError("README benchmark markers not found")
    end += len(END_MARKER)
    updated = readme[:start] + block + readme[end:]
    README_PATH.write_text(updated)


def main() -> None:
    data = run_benchmark()
    block = build_benchmark_block(data)
    update_readme(block)
    print("README benchmark section updated.")
    chart_path = plot_benchmark.render(data["speedups"])
    print(f"Benchmark chart updated: {chart_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
