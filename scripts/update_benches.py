#!/usr/bin/env python3
"""Record Criterion results from CI and rebuild the benchmark report."""

from __future__ import annotations

import argparse
import html
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Measurement:
    name: str
    median_nanoseconds: float
    elements_per_second: float

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "Measurement":
        return cls(
            name=str(value["name"]),
            median_nanoseconds=float(value["median_nanoseconds"]),
            elements_per_second=float(value["elements_per_second"]),
        )


@dataclass(frozen=True)
class Result:
    pr: int
    commit: str
    recorded_at: str
    measurements: tuple[Measurement, ...]

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "Result":
        raw_measurements = value["measurements"]
        if not isinstance(raw_measurements, list):
            raise ValueError("measurements must be a list")
        return cls(
            pr=int(value["pr"]),
            commit=str(value["commit"]),
            recorded_at=str(value["recorded_at"]),
            measurements=tuple(Measurement.from_dict(item) for item in raw_measurements),
        )


def read_criterion_results(criterion_root: Path) -> tuple[Measurement, ...]:
    measurements = []
    for estimates_path in criterion_root.glob("**/new/estimates.json"):
        benchmark_path = estimates_path.with_name("benchmark.json")
        if not benchmark_path.is_file():
            continue
        estimates = json.loads(estimates_path.read_text(encoding="utf-8"))
        benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
        median_nanoseconds = float(estimates["median"]["point_estimate"])
        throughput = benchmark.get("throughput") or {}
        elements = throughput.get("Elements")
        if elements is None:
            continue
        measurements.append(
            Measurement(
                name=str(benchmark["full_id"]),
                median_nanoseconds=median_nanoseconds,
                elements_per_second=float(elements) * 1_000_000_000 / median_nanoseconds,
            )
        )
    if not measurements:
        raise ValueError(f"no Criterion element-throughput results found in {criterion_root}")
    return tuple(sorted(measurements, key=lambda measurement: measurement.name))


def load_results(results_root: Path) -> list[Result]:
    results = []
    for path in results_root.glob("pr-*/result.json"):
        results.append(Result.from_dict(json.loads(path.read_text(encoding="utf-8"))))
    return sorted(results, key=lambda result: result.pr)


def render_svg(results: list[Result]) -> str:
    width, height = 800, 280
    left, right, top, bottom = 70, 25, 25, 65
    plot_width = width - left - right
    plot_height = height - top - bottom
    rates = [
        measurement.elements_per_second
        for result in results
        for measurement in result.measurements
    ]
    maximum = max(rates, default=1)
    minimum = min(rates, default=0)
    padding = max((maximum - minimum) * 0.1, maximum * 0.05, 1)
    low, high = max(0, minimum - padding), maximum + padding
    names = sorted({measurement.name for result in results for measurement in result.measurements})
    colours = ["#0969da", "#1a7f37", "#bf8700", "#8250df", "#cf222e"]

    def point(index: int, rate: float) -> tuple[float, float]:
        x = left + (plot_width / max(len(results) - 1, 1)) * index
        y = top + plot_height * (high - rate) / (high - low)
        return x, y

    series = []
    for name_index, name in enumerate(names):
        colour = colours[name_index % len(colours)]
        values = []
        for result_index, result in enumerate(results):
            for measurement in result.measurements:
                if measurement.name == name:
                    values.append((point(result_index, measurement.elements_per_second), result, measurement))
        polyline = " ".join(f"{x:.1f},{y:.1f}" for (x, y), _, _ in values)
        series.append(f'  <polyline stroke="{colour}" points="{polyline}"/>')
        series.extend(
            f'  <circle fill="{colour}" cx="{x:.1f}" cy="{y:.1f}" r="4"><title>'
            f'{html.escape(measurement.name)}, PR #{result.pr}: '
            f'{measurement.elements_per_second:,.0f} elements/s'
            f"</title></circle>"
            for (x, y), result, measurement in values
        )
    labels = "\n".join(
        f'  <text x="{point(index, low)[0]:.1f}" y="{height - 42}" text-anchor="middle">#{result.pr}</text>'
        for index, result in enumerate(results)
    )
    legend = "\n".join(
        f'  <text x="{left + (index % 2) * 350}" y="{height - 20 + (index // 2) * 15}" '
        f'fill="{colours[index % len(colours)]}">{html.escape(name)}</text>'
        for index, name in enumerate(names)
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
  <title id="title">Historical in-memory throughput benchmarks</title>
  <desc id="desc">Elements per second for retained pull request Criterion results.</desc>
  <style>text {{ font: 12px sans-serif; fill: #57606a }} .axis {{ stroke: #8c959f }} polyline {{ fill: none; stroke-width: 2 }}</style>
  <line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{height - bottom}"/>
  <line class="axis" x1="{left}" y1="{height - bottom}" x2="{width - right}" y2="{height - bottom}"/>
  <text x="12" y="{top + plot_height / 2:.1f}" transform="rotate(-90 12 {top + plot_height / 2:.1f})" text-anchor="middle">elements/s</text>
  <text x="{left - 8}" y="{top + 4}" text-anchor="end">{round(high):,}</text>
  <text x="{left - 8}" y="{height - bottom + 4}" text-anchor="end">{round(low):,}</text>
{chr(10).join(series)}
{labels}
{legend}
</svg>
"""


def render_markdown(results: list[Result]) -> str:
    rows = "\n".join(
        f"| [#{result.pr}](https://github.com/freshtonic/pg-proto/pull/{result.pr}) "
        f"| `{html.escape(result.commit[:12])}` | {html.escape(result.recorded_at)} "
        f"| `{html.escape(measurement.name)}` | {measurement.median_nanoseconds / 1_000_000:.3f} "
        f"| {measurement.elements_per_second:,.0f} |"
        for result in results
        for measurement in result.measurements
    )
    if not rows:
        rows = "| — | — | — | — | — | — |"
    return f"""# Benchmark history

This report is generated by `scripts/update_benches.py`. Each pull request retains
one result, which is replaced when that pull request's benchmarks run again.

![Historical in-memory throughput benchmarks](benchmark-results/history.svg)

| Pull request | Commit | Recorded (UTC) | Benchmark | Median time (ms) | Elements/s |
| ---: | :--- | :--- | :--- | ---: | ---: |
{rows}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-root", type=Path, required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--recorded-at")
    parser.add_argument("--results-root", type=Path, default=Path("benchmark-results"))
    parser.add_argument("--report", type=Path, default=Path("BENCHES.md"))
    args = parser.parse_args()

    recorded_at = args.recorded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = Result(
        args.pr,
        args.commit,
        recorded_at,
        read_criterion_results(args.criterion_root),
    )
    result_dir = args.results_root / f"pr-{args.pr}"
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "result.json").write_text(
        json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    results = load_results(args.results_root)
    (args.results_root / "history.svg").write_text(render_svg(results), encoding="utf-8")
    args.report.write_text(render_markdown(results), encoding="utf-8")


if __name__ == "__main__":
    main()
