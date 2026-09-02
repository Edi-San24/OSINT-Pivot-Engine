# tests/test_domain_model.py
# Regression test for scoring. Run: PYTHONPATH=. python tests/test_domain_model.py

"""
Pins scoring behaviour against real pivot results with known ground truth.

Three classes of regression this catches, all of which have already happened:

  - A model served a feature matrix it was not fitted on. FEATURE_COLUMNS grew
    from 7 to 14 while the IP model stayed at 7, and every infrastructure score
    raised ValueError for a full commit.
  - A retrain that quietly starts calling legitimate businesses malicious. The
    first domain model scored a legitimate hosting provider at p=1.000 because
    its benign class was 114 household-name domains.
  - The LLM moving the verdict. It used to overrule the score, so the same
    investigation resolved differently on repeat runs. The verdict checks run
    before the model gate, because determinism does not depend on a model.

The fixture carries real pivot results so extract_features is exercised too, not
just the model. Licensed source blocks are stripped from it — they never feed a
feature, and the fixture is published.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.graph_scorer import GraphScorer
from core.risk import (
    DOMAIN_BAND_PRECISION,
    enforce_verdict,
    extract_dissent,
    extract_threat_level,
    resolve_risk_level,
    verdict_source,
)
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
    "93.123.39.37": 0.283,
}
DRIFT_TOLERANCE = 0.20

failures: list[str] = []
notes: list[str] = []


def check(condition: bool, description: str) -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {description}")
    if not condition:
        failures.append(description)


def check_verdict_is_deterministic(scorer: ConfidenceScorer) -> None:
    """
    Pins the one thing about the verdict that was never true before: two runs
    over the same data reach the same level.

    The agent used to overrule the score, and it is non-deterministic. On a
    byte-identical 0.157 dizaynholding.com drew LOW on one run and MEDIUM on the
    next; raspberryhillsshop.com drew HIGH on one run and emitted no THREAT LEVEL
    line at all on the next. Needs no model and no quota, so it runs on a fresh
    clone where the rest of this suite skips.
    """
    print("\n-- the summary cannot move the verdict --")
    scored = {"insufficient_data": False, "pivot_count": 3, "context_score": 0.157,
              "indicator_type": "domain", "risk_thresholds": [0.7, 0.4]}

    levels = {
        claim: resolve_risk_level({**scored, "summary": summary})
        for claim, summary in {
            "HIGH": "THREAT LEVEL: HIGH — bad.\n\nDISSENT: none",
            "MEDIUM": "THREAT LEVEL: MEDIUM — unclear.\n\nDISSENT: none",
            "UNKNOWN": "THREAT LEVEL: UNKNOWN — cannot say.\n\nDISSENT: none",
            "no line": "ASSESSMENT:\nNothing structured came back.",
            "dissenting": "THREAT LEVEL: LOW — quiet.\n\nDISSENT: HIGH one sentence.",
        }.items()
    }
    check(set(levels.values()) == {"LOW"},
          f"a 0.157 domain resolves LOW whatever the summary claims: {levels}")

    # Absence still outranks the score, in the one direction that matters.
    blind = {**scored, "insufficient_data": True,
             "summary": "THREAT LEVEL: HIGH — bad.\n\nDISSENT: none"}
    check(resolve_risk_level(blind) == "UNKNOWN",
          f"a run that collected nothing stays UNKNOWN against a HIGH summary "
          f"-> {resolve_risk_level(blind)}")

    print("\n-- dissent is recorded, and is not a verdict --")
    dissenting = {**scored, "summary": "THREAT LEVEL: LOW — quiet.\n\nDISSENT: HIGH served content."}
    check(extract_dissent(dissenting["summary"]) == "HIGH",
          f"a stated dissent is readable -> {extract_dissent(dissenting['summary'])}")
    check(verdict_source(dissenting) == "dissent",
          f"and is reported as dissent -> {verdict_source(dissenting)}")
    check(resolve_risk_level(dissenting) == "LOW",
          f"while the level stays scored -> {resolve_risk_level(dissenting)}")

    concurring = {**scored, "summary": "THREAT LEVEL: LOW — quiet.\n\nDISSENT: none"}
    check(verdict_source(concurring) == "concur",
          f"'none' is a stated read, not a missing one -> {verdict_source(concurring)}")
    # A saved investigation from before the dissent line stated no read at all,
    # which is different from having agreed.
    silent = {**scored, "summary": "THREAT LEVEL: LOW — quiet."}
    check(verdict_source(silent) == "scorer",
          f"an absent dissent line is not agreement -> {verdict_source(silent)}")

    print("\n-- the THREAT LEVEL line is written, never parsed for the verdict --")
    repaired = enforce_verdict("ASSESSMENT:\nNo level line was produced.", "MEDIUM")
    check(extract_threat_level(repaired) == "MEDIUM",
          f"a missing line is inserted -> {extract_threat_level(repaired)}")
    overwritten = enforce_verdict("THREAT LEVEL: HIGH — looks like a phishing kit.", "LOW")
    check(extract_threat_level(overwritten) == "LOW",
          f"a line stating the wrong level is corrected -> {extract_threat_level(overwritten)}")
    check("phishing kit" in overwritten,
          "and the model's own sentence survives the correction")

    # The override was carrying real recall on URLs, and it was covering a bug
    # rather than adding judgement: score_from_evidence read urlhaus url_count,
    # which query_url does not return, so a URL URLhaus names scored zero from
    # URLhaus. Removing the override without this would have lost the recall.
    print("\n-- a URL URLhaus names is HIGH from evidence alone --")
    listed_url = scorer.score_any({
        "indicator": "http://190.123.46.208/Okami.x86", "type": "url",
        "results": {"urlhaus": {"found": True, "url_status": "online",
                                "threat": "malware_download"}},
    })
    check(listed_url.get("risk_level") == "HIGH",
          f"a URLhaus listing alone flags the URL it names "
          f"(p={listed_url.get('confidence_score')})")

    unlisted_url = scorer.score_any({
        "indicator": "http://example.com/index.html", "type": "url",
        "results": {"urlhaus": {"found": False}, "threatfox": {"found": False},
                    "virustotal": {"malicious_votes": 0, "harmless_votes": 60},
                    "otx": {"pulse_count": 0}},
    })
    check(unlisted_url.get("risk_level") == "LOW",
          f"and a URL it does not name is not "
          f"(p={unlisted_url.get('confidence_score')})")


def main() -> int:
    scorer = ConfidenceScorer()
    entries = {e["indicator"]: e for e in json.load(open(FIXTURE, encoding="utf-8"))}

    # Before the model gate on purpose: none of this needs a model, and the
    # verdict has to be reproducible on a fresh clone too.
    check_verdict_is_deterministic(scorer)

    if scorer.domain_gb is None:
        # Domain models are gitignored, so a fresh clone has none until it
        # trains one. Skipping beats failing on a checkout that is fine, but the
        # model-free checks above still have to be able to fail.
        print("\nSKIP: no domain model installed. Train one with:")
        print("  python core/trainer.py --dataset domain --data data/training_data_domains_v2.csv \\")
        print("      --tag v2c --exclude harmless_votes,malicious_ratio,malicious_votes,urlhaus_listed")
        if failures:
            print(f"\nFAILED: {len(failures)} check(s) before the model gate")
            for f in failures:
                print(f"  - {f}")
            return 1
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

    # Addresses are scored from evidence rather than by a model, so they carry
    # no band precision. The IP model was retired after its benign class was
    # found to be built by resolving domains, which made every benign row a
    # mature multi-service host and every malicious row a minimal box from a
    # feed. dns_record_count scored AUC 0.139 and total_open_ports 0.299, both
    # inverted, both artefacts of that sampling rather than facts about
    # addresses.
    print("\n-- addresses are scored from evidence, not by a model --")
    for indicator, entry in entries.items():
        if entry.get("type") != "ipv4" or indicator not in scores:
            continue
        result = scores[indicator]
        check(result.get("band_precision") is None,
              f"{indicator[:30]:30} carries no band precision")
        check(bool(result.get("sources_answered")),
              f"{indicator[:30]:30} names which sources answered: "
              f"{result.get('sources_answered')}")

    # A source with nothing to report must not vote innocent. Averaging the
    # sources dragged a ThreatFox confidence-100 C2 to 0.475 MEDIUM because
    # URLhaus answered "not found", and URLhaus tracks malware URLs rather than
    # C2 addresses, so its silence about one says nothing.
    quiet = scorer.score_any({
        "indicator": "45.33.8.196", "type": "ipv4",
        "results": {"threatfox": {"found": True, "max_confidence": 100},
                    "urlhaus": {"found": False},
                    "virustotal": {"malicious_votes": 0, "harmless_votes": 60},
                    "otx": {"pulse_count": 0}},
    })
    check(quiet.get("risk_level") == "HIGH",
          f"a confidence-100 listing stays HIGH when other sources are quiet "
          f"(p={quiet.get('confidence_score')})")

    # Absence must not read as a verdict, in either direction. An unregistered
    # domain produces an all-zero feature vector, which the model resolved as
    # 0.7507 HIGH because it is indistinguishable from a domain registered
    # today. Reserved space cannot host anything, so "checked, nothing found"
    # misdescribes it.
    # The model cannot see a compromised legitimate site, and the agent is not a
    # reliable backstop: on one run it overrode raspberryhillsshop.com to HIGH
    # and on the next it emitted no THREAT LEVEL line, so a ThreatFox
    # confidence-100 ClearFake domain resolved LOW on a 0.1394 score.
    print("\n-- feed evidence floors the model, and only upward --")
    listed = scorer.score_any({
        "indicator": "compromised.example", "type": "domain",
        "results": {"whois": {"creation_date": "2019-04-15"},
                    "dns": {"a": ["1.2.3.4"], "nameservers": ["a.ns", "b.ns"], "mx": ["mail"]},
                    "threatfox": {"found": True, "max_confidence": 100},
                    "urlhaus": {"found": False},
                    "virustotal": {"malicious_votes": 2, "harmless_votes": 53},
                    "otx": {"pulse_count": 0}},
    })
    check(listed.get("risk_level") == "HIGH",
          f"a confidence-100 listing floors a benign-looking domain to HIGH "
          f"(model said {listed.get('model_score')}, result {listed.get('confidence_score')})")

    unlisted = scorer.score_any({
        "indicator": "ordinary.example", "type": "domain",
        "results": {"whois": {"creation_date": "2015-01-01"},
                    "dns": {"a": ["1.2.3.4"], "nameservers": ["a.ns", "b.ns"], "mx": ["mail"]},
                    "threatfox": {"found": False}, "urlhaus": {"found": False},
                    "virustotal": {"malicious_votes": 0, "harmless_votes": 60},
                    "otx": {"pulse_count": 0}},
    })
    check("model_score" not in unlisted,
          "an unlisted domain is left to the model, with no floor applied")

    print("\n-- absence is reported as absence, not as a verdict --")
    nothing = scorer.score_any({
        "indicator": "does-not-exist-abc987xyz.example", "type": "domain",
        "results": {"whois": {"creation_date": "unknown"}, "dns": {},
                    "virustotal": {"malicious_votes": 0, "harmless_votes": 0},
                    "threatfox": {"found": False}, "urlhaus": {"found": False},
                    "passivedns": {"record_count": 0}},
    })
    check(nothing.get("risk_level") == "UNKNOWN",
          f"a domain with an all-zero feature vector -> {nothing.get('risk_level')} "
          f"(p={nothing.get('confidence_score')})")

    reserved = scorer.score_any({
        "indicator": "192.0.2.55", "type": "ipv4",
        "results": {"threatfox": {"found": False}, "urlhaus": {"found": False},
                    "virustotal": {"malicious_votes": 0, "harmless_votes": 0},
                    "otx": {"pulse_count": 0}},
    })
    check(reserved.get("risk_level") == "UNKNOWN",
          f"RFC 5737 documentation space -> {reserved.get('risk_level')}")

    silent = scorer.score_any({
        "indicator": "45.33.8.197", "type": "ipv4",
        "results": {"threatfox": {"error": "x"}, "urlhaus": {"error": "x"},
                    "virustotal": {"error": "x"}, "otx": {"error": "x"}},
    })
    check(silent.get("risk_level") == "UNKNOWN",
          f"an address no source answered on -> {silent.get('risk_level')}")

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
