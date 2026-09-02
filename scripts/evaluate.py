# scripts/evaluate.py
# Runs the frozen labelled evaluation set and reports accuracy with intervals.

"""
Measures whether the engine is right, not whether its parts agree.

The verdict log tracks agreement between the score and the agent, and two
components can concur while both are wrong. Accuracy needs labels, which is what
tests/evaluation_set.json holds.

Report the interval, not the point estimate. A 7-of-10 run once got read as "70%
against a historical 32%" when the two intervals were [40, 89] and [20, 47] and
the rates were indistinguishable. Detecting a shift that size needs roughly 26
cases per group.

Spends VirusTotal quota, one investigation per case, so it is a deliberate run
rather than part of the test suite. Use --types or --truth to run a slice.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import json
import time
from collections import defaultdict

from core.agent import run_agent
from core.disagreement import _wilson
from core.risk import extract_dissent, resolve_risk_level, score_level, verdict_source

EVAL_SET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "tests", "evaluation_set.json")

# HIGH and MEDIUM both count as flagged: an analyst looks at either, and reading
# MEDIUM as a miss would punish the engine for being uncertain when it is.
FLAGGED = {"HIGH", "MEDIUM"}
CLEARED = {"LOW", "UNKNOWN"}


def is_correct(resolved: str, truth: str) -> bool:
    if truth == "malicious":
        return resolved in FLAGGED
    if truth == "benign":
        return resolved in CLEARED
    return resolved == "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the labelled evaluation set.")
    parser.add_argument("--types", help="Comma-separated indicator types to include.")
    parser.add_argument("--truth", help="Comma-separated labels to include.")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N cases.")
    parser.add_argument("--output", help="Write per-case results to JSON.")
    args = parser.parse_args()

    cases = json.load(open(EVAL_SET, encoding="utf-8"))["cases"]
    if args.types:
        keep = {t.strip() for t in args.types.split(",")}
        cases = [c for c in cases if c["type"] in keep]
    if args.truth:
        keep = {t.strip() for t in args.truth.split(",")}
        cases = [c for c in cases if c["truth"] in keep]
    if args.limit:
        cases = cases[:args.limit]

    print(f"{len(cases)} case(s). One investigation each, so this spends quota.\n")
    print(f"  {'indicator':38} {'truth':10} {'score':>7} {'final':8} {'by':9} ok")

    rows = []
    for case in cases:
        seed = case["indicator"]
        try:
            result = run_agent(seed, deep=False)
        except Exception as e:
            print(f"  {seed[:36]:38} {case['truth']:10} FAILED {type(e).__name__}: {str(e)[:40]}")
            rows.append({**case, "error": str(e)[:120], "correct": None})
            continue

        resolved = resolve_risk_level(result)
        row = {
            **case,
            "score": result.get("context_score"),
            "score_level": score_level(result),
            "dissent": extract_dissent(result.get("summary", "")),
            "resolved": resolved,
            "decided_by": verdict_source(result),
            "correct": is_correct(resolved, case["truth"]),
        }
        rows.append(row)
        print(f"  {seed[:36]:38} {case['truth']:10} {row['score']:7} {resolved:8} "
              f"{row['decided_by']:9} {'Y' if row['correct'] else 'N'}")
        time.sleep(1)

    scored = [r for r in rows if r.get("correct") is not None]
    hits = [r for r in scored if r["correct"]]

    print(f"\n  accuracy {len(hits)}/{len(scored)} = {len(hits)/len(scored):.0%} "
          f"  95% CI {_wilson(len(hits), len(scored))}" if scored else "\n  no cases scored")

    by_truth = defaultdict(lambda: {"n": 0, "hits": 0})
    for r in scored:
        by_truth[r["truth"]]["n"] += 1
        by_truth[r["truth"]]["hits"] += 1 if r["correct"] else 0
    for truth, v in sorted(by_truth.items()):
        print(f"    {truth:10} {v['hits']}/{v['n']}  CI {_wilson(v['hits'], v['n'])}")

    # The score decides now, so the question is no longer what the agent added
    # but what ignoring it costs. A dissent that was right is recall given up; a
    # dissent that was wrong is the non-determinism no longer being paid for.
    # Measure this every run: dissent is the only channel left for a compromised
    # legitimate site, and if it never turns out right the channel is dead.
    dissents = [r for r in scored if r["decided_by"] == "dissent"]
    would_fix = [r for r in dissents if not r["correct"] and is_correct(r["dissent"], r["truth"])]
    would_break = [r for r in dissents if r["correct"] and not is_correct(r["dissent"], r["truth"])]
    print(f"\n  agent dissented  {len(dissents)}/{len(scored)}  "
          f"would have fixed {len(would_fix)}, would have broken {len(would_break)}")
    for r in would_fix:
        print(f"     RECALL LOST  {r['indicator'][:32]:34} scored {r['resolved']}, "
              f"dissent {r['dissent']}, truth {r['truth']}")
    for r in would_break:
        print(f"     ignored well {r['indicator'][:32]:34} scored {r['resolved']}, "
              f"dissent {r['dissent']}, truth {r['truth']}")

    misses = [r for r in scored if not r["correct"]]
    if misses:
        print("\n  misses:")
        for r in misses:
            print(f"     {r['indicator'][:34]:36} truth {r['truth']:10} got {r['resolved']:8} {r.get('note','')[:44]}")

    if args.output:
        json.dump(rows, open(args.output, "w"), indent=1)
        print(f"\n  per-case results written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
