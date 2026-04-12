#!/usr/bin/env python3
"""Print a per-tool recall summary from a benchmark JSON result file."""

import json
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: summarize_benchmark.py <result.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    results = data.get("results", [])
    tools = sorted(set(r["tool_name"] for r in results))

    print()
    print("Per-tool recall on vulnerable scenarios (tn-clean excluded):")
    print(f"{'Tool':<15} {'TP':>4} {'FN':>4} {'Recall':>8}")
    print("-" * 35)

    for t in tools:
        tp = sum(
            1
            for r in results
            if r["tool_name"] == t
            and r["detection_label"] == "TP"
            and not r.get("is_true_negative")
        )
        fn = sum(
            1
            for r in results
            if r["tool_name"] == t
            and r["detection_label"] == "FN"
            and not r.get("is_true_negative")
        )
        total = tp + fn
        recall = tp / total * 100 if total else 0
        print(f"{t:<15} {tp:>4} {fn:>4} {recall:>7.0f}%")

    print()
    print(f"Full JSON output: {sys.argv[1]}")


if __name__ == "__main__":
    main()
