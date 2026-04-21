"""Modern SVG speedup chart for jwt_rs vs PyJWT (no plotting lib dependency)."""
from __future__ import annotations

import math
import re
import subprocess
import sys
from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BENCH_SCRIPT = ROOT / "scripts" / "benchmark_same_api.py"
DEFAULT_OUTPUT = ROOT / "docs" / "benchmark.svg"

CASES = [
    ("hs256", "encode"),
    ("hs256", "decode"),
    ("hs256", "decode_complete"),
    ("rs256", "encode"),
    ("rs256", "decode"),
    ("rs256", "decode_complete"),
    ("es256", "encode"),
    ("es256", "decode"),
    ("es256", "decode_complete"),
    ("eddsa", "encode"),
    ("eddsa", "decode"),
    ("eddsa", "decode_complete"),
]

# Layout constants
WIDTH = 1040
ROW_H = 38
ROW_GAP = 6
LEFT_PAD = 220
RIGHT_PAD = 80
TITLE_H = 110
FOOTER_H = 60
AXIS_H = 34
BAR_H = ROW_H - ROW_GAP

# Palette (dark GitHub-esque)
BG = "#0d1117"
PANEL = "#111826"
FG = "#e6edf3"
MUTED = "#8b949e"
GRID = "#1f2937"
BASELINE = "#8b949e"
COLOR_FAST = ("#7ef00a", "#4ac40a")   # ≥2x
COLOR_OK = ("#58a6ff", "#2f6fd4")     # 1–2x
COLOR_SLOW = ("#ff6b6b", "#c13838")   # <1x


def run_benchmark() -> dict[str, float]:
    result = subprocess.run(
        [sys.executable, str(BENCH_SCRIPT), "--iterations", "300", "--warmup", "40"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    speedups: dict[str, float] = {}
    in_block = False
    for line in result.stdout.splitlines():
        if line.startswith("[speedup"):
            in_block = True
            continue
        if in_block:
            match = re.match(r"^\s*([a-z0-9]+\.[a-z_]+)\s+([\d.]+)x\s*$", line)
            if match:
                speedups[match.group(1)] = float(match.group(2))
    return speedups


def _pick_ticks(max_val: float) -> list[float]:
    candidates = [0.5, 1, 2, 5, 10, 20, 50, 100, 200]
    ticks = [t for t in candidates if t <= max_val * 1.6]
    if 1 not in ticks:
        ticks.append(1)
        ticks.sort()
    return ticks


def _color_for(v: float) -> tuple[str, str]:
    if v >= 2.0:
        return COLOR_FAST
    if v >= 1.0:
        return COLOR_OK
    return COLOR_SLOW


def render(speedups: dict[str, float], output: Path = DEFAULT_OUTPUT) -> Path:
    values = [speedups[f"{alg}.{op}"] for alg, op in CASES]
    max_val = max(values)

    # Log-scale x-mapping.
    x_min = 0.5
    x_max = max_val * 1.35
    log_min = math.log10(x_min)
    log_max = math.log10(x_max)

    bar_area_x0 = LEFT_PAD
    bar_area_x1 = WIDTH - RIGHT_PAD
    bar_area_w = bar_area_x1 - bar_area_x0

    def x_for(v: float) -> float:
        v = max(v, x_min)
        return bar_area_x0 + (math.log10(v) - log_min) / (log_max - log_min) * bar_area_w

    plot_top = TITLE_H
    plot_bot = plot_top + len(CASES) * ROW_H
    height = plot_bot + AXIS_H + FOOTER_H

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" '
        f'width="{WIDTH}" height="{height}" role="img" '
        f'aria-label="jwt_rs vs PyJWT speedup chart">'
    )
    # Definitions: gradients + glow filter
    parts.append("<defs>")
    for name, (c0, c1) in (("gfast", COLOR_FAST), ("gok", COLOR_OK), ("gslow", COLOR_SLOW)):
        parts.append(
            f'<linearGradient id="{name}" x1="0%" y1="0%" x2="100%" y2="0%">'
            f'<stop offset="0%" stop-color="{c1}"/>'
            f'<stop offset="100%" stop-color="{c0}"/>'
            f"</linearGradient>"
        )
    parts.append(
        '<filter id="glow" x="-30%" y="-30%" width="160%" height="160%">'
        '<feGaussianBlur stdDeviation="2.2" result="b"/>'
        '<feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>'
        "</filter>"
    )
    parts.append("</defs>")

    # Background
    parts.append(f'<rect width="{WIDTH}" height="{height}" fill="{BG}"/>')

    # System font stack (use &apos; so attribute quoting stays intact)
    font = (
        "-apple-system, BlinkMacSystemFont, &apos;Segoe UI&apos;, Inter, Roboto, "
        "&apos;Helvetica Neue&apos;, Arial, sans-serif"
    )

    # Title
    parts.append(
        f'<text x="32" y="52" fill="{FG}" font-family="{font}" '
        f'font-size="28" font-weight="700" letter-spacing="-0.5">jwt_rs vs PyJWT</text>'
    )
    parts.append(
        f'<text x="32" y="82" fill="{MUTED}" font-family="{font}" '
        f'font-size="13" font-weight="400">Same-API speedup · higher is better · log scale</text>'
    )

    # Alternating row-group shading (per algorithm group of 3).
    for block_idx in range(len(CASES) // 3):
        if block_idx % 2 != 0:
            continue
        y0 = plot_top + block_idx * 3 * ROW_H
        parts.append(
            f'<rect x="{bar_area_x0 - 140}" y="{y0}" '
            f'width="{WIDTH - (bar_area_x0 - 140) - 24}" height="{3 * ROW_H}" '
            f'fill="{PANEL}" rx="6"/>'
        )

    # Gridlines for ticks
    ticks = _pick_ticks(max_val)
    for t in ticks:
        gx = x_for(t)
        is_base = abs(t - 1.0) < 1e-9
        stroke = BASELINE if is_base else GRID
        dash = ' stroke-dasharray="4 4"' if is_base else ""
        parts.append(
            f'<line x1="{gx:.2f}" y1="{plot_top - 8}" x2="{gx:.2f}" y2="{plot_bot + 4}" '
            f'stroke="{stroke}" stroke-width="{1.4 if is_base else 1}" {dash}/>'
        )

    # Baseline label
    base_x = x_for(1.0)
    parts.append(
        f'<text x="{base_x + 6:.2f}" y="{plot_top - 12}" fill="{BASELINE}" '
        f'font-family="{font}" font-size="11" font-weight="600">PyJWT · 1.00×</text>'
    )

    # Rows
    prev_alg = None
    for idx, ((alg, op), v) in enumerate(zip(CASES, values)):
        y = plot_top + idx * ROW_H
        center_y = y + ROW_H / 2
        bar_y = y + (ROW_H - BAR_H) / 2

        # Algorithm label (only on first row of each group)
        if alg != prev_alg:
            parts.append(
                f'<text x="{bar_area_x0 - 150}" y="{center_y + 4:.2f}" fill="{FG}" '
                f'font-family="{font}" font-size="14" font-weight="700" '
                f'letter-spacing="0.5">{alg.upper()}</text>'
            )
            prev_alg = alg

        # Operation label — right-aligned flush to bar start
        parts.append(
            f'<text x="{bar_area_x0 - 12}" y="{center_y + 4:.2f}" fill="{MUTED}" '
            f'font-family="{font}" font-size="12" text-anchor="end">{escape(op)}</text>'
        )

        # Bar
        bar_x0 = x_for(x_min)
        bar_x1 = x_for(v)
        width = max(2.0, bar_x1 - bar_x0)
        grad_id = "gfast" if v >= 2.0 else ("gok" if v >= 1.0 else "gslow")
        filter_attr = ' filter="url(#glow)"' if v >= 2.0 else ""
        parts.append(
            f'<rect x="{bar_x0:.2f}" y="{bar_y:.2f}" '
            f'width="{width:.2f}" height="{BAR_H}" rx="4" '
            f'fill="url(#{grad_id})"{filter_attr}/>'
        )

        # Value label
        parts.append(
            f'<text x="{bar_x1 + 10:.2f}" y="{center_y + 4:.2f}" fill="{FG}" '
            f'font-family="{font}" font-size="12" font-weight="700">{v:.2f}×</text>'
        )

    # Axis ticks
    for t in ticks:
        gx = x_for(t)
        parts.append(
            f'<text x="{gx:.2f}" y="{plot_bot + 20}" fill="{MUTED}" '
            f'font-family="{font}" font-size="11" text-anchor="middle">{t:g}×</text>'
        )
    parts.append(
        f'<text x="{(bar_area_x0 + bar_area_x1) / 2:.2f}" y="{plot_bot + 44}" '
        f'fill="{MUTED}" font-family="{font}" font-size="11" text-anchor="middle">'
        f'Speedup vs PyJWT (PyJWT = 1.00×)</text>'
    )

    # Legend (top-right)
    legend_y = 56
    legend_items = [
        ("≥ 2× faster", "gfast"),
        ("1× – 2×", "gok"),
        ("< 1×", "gslow"),
    ]
    lx = WIDTH - 32
    for label, grad in reversed(legend_items):
        sw = 12
        tx = lx
        parts.append(
            f'<text x="{tx}" y="{legend_y}" fill="{MUTED}" font-family="{font}" '
            f'font-size="11" text-anchor="end">{escape(label)}</text>'
        )
        parts.append(
            f'<rect x="{tx - 80 - sw - 4}" y="{legend_y - 10}" '
            f'width="{sw}" height="10" rx="2" fill="url(#{grad})"/>'
        )
        lx -= 110

    # Footer
    parts.append(
        f'<text x="32" y="{height - 24}" fill="{MUTED}" font-family="{font}" '
        f'font-size="10.5">benchmark_same_api.py · 300 iters · 40 warmup · '
        f'OpenSSL backend · Python {sys.version_info.major}.{sys.version_info.minor}</text>'
    )

    parts.append("</svg>")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(parts), encoding="utf-8")
    return output


def main() -> None:
    speedups = run_benchmark()
    out = render(speedups)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
