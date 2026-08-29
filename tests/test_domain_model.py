# tests/test_domain_model.py
# Regression test for scoring. Run: PYTHONPATH=. python tests/test_domain_model.py

"""
Pins scoring behaviour against real pivot results with known ground truth.

Two classes of regression this catches, both of which have already happened:

  - A model served a feature matrix it was not fitted on. FEATURE_COLUMNS grew
    from 7 to 14 while the IP model stayed at 7, and every infrastructure score
    raised ValueError for a full commit.
  - A retrain that quietly starts calling legitimate businesses malicious. The
    first domain model scored a legitimate hosting provider at p=1.000 because
    its benign class was 114 household-name domains.

The fixture carries real pivot results so extract_features is exercised too, not
just the model. Licensed source blocks are stripped from it — they never feed a
feature, and the fixture is published.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.graph_scorer import GraphScorer
from core.risk import BASE_RATES, DOMAIN_BAND_PRECISION, IP_BAND_PRECISION
from core.temporal_scorer import TemporalScorer
from core.scorer import ConfidenceScorer

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "reality_check.json")

# Ground truth, and what it means. "benign" here is a claim about the
# infrastructure, not about everything ever served from it — see eversxcellence
# below, where those two answers differ.
CONFIRMED_MALICIOUS = {
    "briansclub.cm",    # carding marketplace, long-lived, zero VirusTotal detections
    "shhsift.click",    # newly registered, invoice-themed path, VT 4/55
}

# Cases the model is known to get wrong, recorded rather than asserted so the
# suite stays honest about what it cannot do. Listing one here is a decision,
# not a way to silence a failure.
KNOWN_LIMITATIONS = {
    "thekinsmenservers.com": (
        "Legitimate hosting provider scored MEDIUM. Bulk hosting is structurally "
        "similar to attacker infrastructure because attackers rent bulk hosting."
    ),
    "eversxcellence.co.za": (
        "Legitimate 2019 business, but independently reported as ClickFix-compromised. "
        "Scored benign because its infrastructure is benign; the maliciousness is in "
        "served content, which no feature here observes."
    ),
}

# Scores recorded from the model this test was written against. The bound is
# wide enough to survive a retrain on more data and narrow enough that a
# collapsing or inverting model fails loudly.
BASELINE = {
    "eversxcellence.co.za": 0.288,
    "thekinsmenservers.com": 0.615,
    "briansclub.cm": 0.963,
    "shhsift.click": 0.953,
    "93.123.39.37": 0.872,
}
DRIFT_TOLERANCE = 0.20

failures: list[str] = []
notes: list[str] = []


def check(condition: bool, description: str) -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {description}")
    if not condition:
        failures.append(description)


def main() -> int:
    scorer = ConfidenceScorer()
    entries = {e["indicator"]: e for e in json.load(open(FIXTURE, encoding="utf-8"))}

    if scorer.domain_gb is None:
        # Domain models are gitignored, so a fresh clone has none until it
        # trains one. Skipping beats failing on a checkout that is fine.
        print("SKIP: no domain model installed. Train one with:")
        print("  python core/trainer.py --dataset domain --data data/training_data_domains_v2.csv \\")
        print("      --tag v2c --exclude harmless_votes,malicious_ratio,malicious_votes,urlhaus_listed")
        return 0

    print("\n-- every indicator type scores without raising --")
    scores = {}
    for indicator, entry in entries.items():
        try:
            result = scorer.score_any(entry)
            scores[indicator] = result
            check("error" not in result, f"{entry['type']:6} {indicator[:34]} scored")
        except Exception as e:
            check(False, f"{entry['type']:6} {indicator[:34]} raised {type(e).__name__}: {e}")

    print("\n-- domains use the domain model, not the IP model --")
    for indicator, entry in entries.items():
        if entry.get("type") == "domain" and indicator in scores:
            model = scores[indicator].get("model", "")
            check(model.startswith("domain_"), f"{indicator[:34]} routed to {model or 'nothing'}")

    print("\n-- confirmed malicious infrastructure is flagged --")
    for indicator in sorted(CONFIRMED_MALICIOUS):
        score = scores.get(indicator, {}).get("confidence_score")
        check(score is not None and score >= 0.5, f"{indicator} flagged (p={score})")

    print("\n-- an indicator no source has seen is UNKNOWN, never LOW --")
    empty = scorer.score_any({
        "indicator": "0" * 64, "type": "hash",
        "results": {"virustotal": {"error": "404"}, "malwarebazaar": {"found": False},
                    "mitre": {"found": False}},
    })
    check(empty.get("risk_level") == "UNKNOWN", f"unseen hash -> {empty.get('risk_level')}")

    print("\n-- scores have not drifted from the recorded baseline --")
    for indicator, expected in BASELINE.items():
        actual = scores.get(indicator, {}).get("confidence_score")
        if actual is None:
            check(False, f"{indicator} produced no score")
            continue
        drift = abs(actual - expected)
        check(drift <= DRIFT_TOLERANCE,
              f"{indicator[:34]:34} {actual:.3f} vs {expected:.3f} baseline (drift {drift:.3f})")

    print("\n-- domain scores carry the measured meaning of their band --")
    for indicator, entry in entries.items():
        if entry.get("type") != "domain" or indicator not in scores:
            continue
        result = scores[indicator]
        expected = DOMAIN_BAND_PRECISION.get(result.get("risk_level"))
        check(result.get("band_precision") == expected,
              f"{indicator[:30]:30} {result.get('risk_level'):6} carries {result.get('band_precision')}")

    # Guards the semantics rather than the number. If a retrain ever makes LOW
    # mean "clear", that is a claim this model has never been able to support —
    # one in five LOW indicators is malicious and no threshold repairs it.
    check(DOMAIN_BAND_PRECISION["LOW"] >= 0.10,
          f"LOW still documented as non-clearing ({DOMAIN_BAND_PRECISION['LOW']:.0%} malicious)")
    check(DOMAIN_BAND_PRECISION["HIGH"] > DOMAIN_BAND_PRECISION["MEDIUM"] > DOMAIN_BAND_PRECISION["LOW"],
          "band precisions are ordered HIGH > MEDIUM > LOW")

    # IP scores carry their own bands, measured on a set with a different prior.
    # The base rate travels with them because a precision without it is not
    # readable: 94% on the IP model is weaker evidence than 89% on the domain
    # model, and only lift over the prior shows that.
    for indicator, entry in entries.items():
        if entry.get("type") != "ipv4" or indicator not in scores:
            continue
        result = scores[indicator]
        check(result.get("band_precision") == IP_BAND_PRECISION.get(result.get("risk_level")),
              f"{indicator[:30]:30} {result.get('risk_level'):6} carries {result.get('band_precision')}")
        check(result.get("band_base_rate") == BASE_RATES["ip"],
              f"{indicator[:30]:30} carries its base rate {result.get('band_base_rate')}")

    check(IP_BAND_PRECISION["HIGH"] / BASE_RATES["ip"] < DOMAIN_BAND_PRECISION["HIGH"] / BASE_RATES["domain"],
          "IP HIGH is weaker lift than domain HIGH despite the larger percentage")

    # The suite previously scored only through ConfidenceScorer, so the blending
    # layers were never exercised and a bug there went unseen for as long as it
    # existed: two layers holding no data cut shhsift.click from 0.9529 to
    # 0.5003, turning a confirmed malicious domain into MEDIUM.
    print("\n-- blending amplifies, and never subtracts --")
    graph, temporal = GraphScorer(), TemporalScorer()
    confident = 0.9529

    check(graph.blend_scores(confident, 0.0) == confident,
          f"graph floor holds: {confident} + no data -> {graph.blend_scores(confident, 0.0)}")
    check(temporal.blend_with_ml(confident, 0.0) == confident,
          f"temporal floor holds: {confident} + no data -> {temporal.blend_with_ml(confident, 0.0)}")

    both = temporal.blend_with_ml(graph.blend_scores(confident, 0.0), 0.0)
    check(both == confident, f"both layers empty leaves the score intact: {both}")

    # The floor must not cost the layers their actual purpose.
    check(graph.blend_scores(0.4, 0.9) > 0.4,
          f"graph still amplifies when corroborated: 0.4 + 0.9 -> {graph.blend_scores(0.4, 0.9)}")
    check(temporal.blend_with_ml(0.4, 0.9) > 0.4,
          f"temporal still amplifies when corroborated: 0.4 + 0.9 -> {temporal.blend_with_ml(0.4, 0.9)}")
    check(graph.blend_scores(0.98, 1.0) <= 1.0, "blend stays within 1.0")

    print("\n-- known limitations (recorded, not asserted) --")
    for indicator, reason in KNOWN_LIMITATIONS.items():
        score = scores.get(indicator, {}).get("confidence_score")
        print(f"  NOTE  {indicator} p={score}")
        print(f"        {reason}")
        notes.append(indicator)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"OK: all checks passed ({len(notes)} known limitation(s) recorded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
