#!/usr/bin/env python3
"""
Generates a coverage-over-time graph based on seed metadata (seed_meta.csv).

Example CSV headers (see output/zlib/seed_meta.csv):
    seed_path,duration_since_start,cumulative_branch_coverage

Usage:
    python scripts/cntg_coverage-over-time.py output/<lib>/seed_meta.csv \
        -o output/<lib>/coverage_over_time.png

Notes:
    - Expects at least two columns: time (default: duration_since_start) and
      coverage (default: cumulative_branch_coverage).
    - Time is plotted in minutes by default; use --time-unit seconds to keep seconds.
    - Saves a PNG if -o/--output is provided; otherwise shows an interactive window.
"""

import argparse
import csv
from pathlib import Path
from typing import List, Tuple

import matplotlib.pyplot as plt


def read_series(
    csv_path: Path,
    time_col: str,
    cov_col: str,
) -> Tuple[List[float], List[float]]:
    xs: List[float] = []
    ys: List[float] = []
    with csv_path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        # Validate required columns early
        if time_col not in reader.fieldnames or cov_col not in reader.fieldnames:
            raise SystemExit(
                f"CSV missing required columns: '{time_col}' and/or '{cov_col}'.\n"
                f"Found columns: {reader.fieldnames}"
            )
        for row in reader:
            try:
                t = float(row[time_col])
                c = float(row[cov_col])
            except (TypeError, ValueError) as e:
                # Skip malformed rows but keep going
                continue
            xs.append(t)
            ys.append(c)
    if not xs:
        raise SystemExit("No valid data rows parsed from CSV.")
    return xs, ys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plot coverage over time from CNTG seed metadata (CSV)."
    )
    parser.add_argument(
        "csv",
        type=Path,
        help="Path to seed_meta.csv (e.g., output/<lib>/seed_meta.csv)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output PNG path. If omitted, displays the figure interactively.",
    )
    parser.add_argument(
        "--time-col",
        default="duration_since_start",
        help="CSV column for time values (default: duration_since_start)",
    )
    parser.add_argument(
        "--cov-col",
        default="cumulative_branch_coverage",
        help="CSV column for coverage values (default: cumulative_branch_coverage)",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Plot title (default: inferred from CSV path)",
    )
    parser.add_argument(
        "--time-unit",
        choices=["seconds", "minutes"],
        default="minutes",
        help="Unit for X axis (default: minutes)",
    )
    parser.add_argument(
        "--line-label",
        default=None,
        help="Legend label for the line (default: library name inferred from path)",
    )

    args = parser.parse_args()

    if not args.csv.exists():
        raise SystemExit(f"CSV not found: {args.csv}")

    xs, ys = read_series(args.csv, args.time_col, args.cov_col)

    # Convert time if needed
    if args.time_unit == "minutes":
        xs = [x / 60.0 for x in xs]
        x_label = "Time (minutes)"
    else:
        x_label = "Time (seconds)"

    # Infer a name from the path if not provided
    inferred_name = args.csv.parent.name  # typically the <lib> folder under output/
    line_label = args.line_label or inferred_name

    # Title
    default_title = f"Coverage Over Time ({inferred_name})"
    title = args.title or default_title

    plt.figure(figsize=(8, 4.5))
    plt.plot(xs, ys, label=line_label, color="#1f77b4", linewidth=2.0)
    plt.xlabel(x_label)
    plt.ylabel("Cumulative Branch Coverage (%)")
    plt.title(title)
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    if line_label:
        plt.legend()

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(args.output, dpi=200)
        print(f"Saved figure to: {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
