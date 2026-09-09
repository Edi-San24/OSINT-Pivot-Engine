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
  - The LLM moving the verdict. The score decides alone, so the same
    investigation resolves the same way on repeat runs. These checks run before
    the model gate, since determinism does not depend on a model.

The fixture carries real pivot results so extract_features is exercised too, not
just the model. Licensed source blocks are stripped from it — they never feed a
feature, and the fixture is published.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detector import detect_type
from core.agent import extract_findings
from core.executor import PivotExecutor
from core.graph_scorer import GraphScorer
from core.stix_exporter import _families, select_indicators, STIXExporter
from connectors.threatfox import _netblocks
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
# infrastructure rather than about everything ever served from it, and the two
# answers differ for a compromised site.
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


def check_actor_designators() -> None:
    """
    An actor name a vendor actually publishes has to resolve to threat_group.

    Checked against every group name and alias in the shipped ATT&CK bundle
    rather than a handful of examples, since the failure mode is a whole naming
    scheme going unrecognised: an unmatched designator is refused by the
    executor, and one that parses as a hostname is routed to the domain pivot.

    The guard is the other half. Digit counts stay per-scheme so a handle ending
    in digits is not swept up, which keeps single-word aliases reading as
    usernames rather than being forced.
    """
    print("\n-- published actor designators resolve to threat_group --")

    for name in ("APT-C-36", "APT-C-43", "APT-Q-98", "T-APT-04", "TAG-144",
                 "TG-3390", "UAC-0056", "ITG07", "HIVE0154", "Group123",
                 "APT28", "FIN7", "TA505", "UNC2452", "G0016"):
        got = (detect_type(name) or {}).get("type")
        check(got == "threat_group", f"{name:12} -> {got}")

    # Roster cases: shaped like a handle, a domain, or nothing at all, so no
    # pattern can reach them safely.
    for name in ("Lorec53", "IRN2", "TEMP.Veles", "TEMP.Hex", "LAPSUS$",
                 "admin@338"):
        got = (detect_type(name) or {}).get("type")
        check(got == "threat_group", f"{name:12} -> {got}  (roster, not pattern)")

    print("\n-- and a handle ending in digits is still a username --")
    for handle in ("ta5", "gamer53", "user123", "bob2024", "tg1", "tag5",
                   "itg1", "hive1", "x99"):
        got = (detect_type(handle) or {}).get("type")
        check(got != "threat_group", f"{handle:10} -> {got}")

    # The whole bundle, so a pattern change cannot quietly misroute an actor
    # into an infrastructure pivot.
    fixture = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data", "enterprise-attack.json")
    if not os.path.exists(fixture):
        return
    names = set()
    for obj in json.load(open(fixture, encoding="utf-8"))["objects"]:
        if obj.get("type") != "intrusion-set" or obj.get("revoked"):
            continue
        names.add(obj.get("name", ""))
        names.update(obj.get("aliases") or [])
    misrouted = sorted(
        n.strip() for n in names if n.strip()
        and (detect_type(n.strip()) or {}).get("type")
        in ("domain", "ipv4", "url", "email", None)
    )
    check(not misrouted,
          f"no ATT&CK actor routes to an infrastructure pivot -> {misrouted[:4] or 'none'}")


def check_publication_gate(entries: dict) -> None:
    """
    A domain the chain discovered needs a source other than our own model
    before it reaches a pulse. The seed does not.

    Both halves pull opposite ways. A quiet self-hosted domain can score high
    on infrastructure alone with no source agreeing, and publishing it would
    name an uninvolved party. But the model is also sometimes right where every
    feed is silent, and that is its most valuable case. The seed exemption is
    what separates them: the analyst chose the seed, the engine merely reached
    the rest.
    """
    print("\n-- an uncorroborated domain publishes only as the seed --")

    briansclub = entries.get("briansclub.cm")
    if not briansclub:
        check(False, "briansclub.cm missing from the fixture")
        return

    as_seed = {"indicator": "briansclub.cm", "risk_level": "HIGH",
               "visited": ["briansclub.cm"], "full_results": [briansclub]}
    included, _ = select_indicators([as_seed])
    check([i["indicator"] for i in included] == ["briansclub.cm"],
          f"the seed publishes with no corroboration at all -> "
          f"{[i['indicator'] for i in included]}")

    chained = {
        "indicator": "1.2.3.4", "risk_level": "HIGH",
        "visited": ["1.2.3.4", "briansclub.cm"],
        "full_results": [
            {"indicator": "1.2.3.4", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 90},
                         "passivedns": {"records": []}}},
            briansclub,
        ],
    }
    included, excluded = select_indicators([chained])
    names = [i["indicator"] for i in included]
    dropped = {e["indicator"]: e["reason"] for e in excluded}
    check("briansclub.cm" not in names and "briansclub.cm" in dropped,
          "the same domain reached by chaining does not")
    check("uncorroborated" in dropped.get("briansclub.cm", ""),
          "and the audit says why, so --include is an informed decision")

    # A certificate only selects for its own domain, so it cannot outlive it.
    with_cert = {
        "indicator": "1.2.3.4", "risk_level": "HIGH",
        "visited": ["1.2.3.4", "quiet.example"],
        "full_results": [
            {"indicator": "1.2.3.4", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 90},
                         "passivedns": {"records": []}}},
            {"indicator": "quiet.example", "type": "domain",
             "results": {"virustotal": {"malicious_votes": 0, "harmless_votes": 56},
                         "threatfox": {"found": False}, "urlhaus": {"found": False},
                         "otx": {"pulse_count": 0},
                         "domaintools": {"certificates": [
                             {"sha1": "a" * 40, "domains_on_cert": 1}]}}},
        ],
    }
    included, excluded = select_indicators([with_cert])
    dropped = {e["indicator"]: e["reason"] for e in excluded}
    check("a" * 40 not in [i["indicator"] for i in included],
          "an unpublished domain's certificate is not published either")
    check("quiet.example" in dropped.get("a" * 40, ""),
          f"and names the domain it belongs to -> {dropped.get('a' * 40, '')[:52]}")


def check_malware_families() -> None:
    """
    Only ATT&CK entries typed as malware reach malware_families.

    A group profile lists the built-in utilities it abuses alongside its own
    implants. Publishing one of those as the group's malware family both names a
    stock Windows binary as attacker code and buries the real families.
    """
    print("\n-- malware_families carries malware, not the tools a group abuses --")

    investigation = {
        "indicator": "Some Group", "risk_level": "HIGH",
        "visited": ["Some Group"],
        "full_results": [{
            "indicator": "Some Group", "type": "threat_group",
            "results": {"mitre": {"software": [
                {"software_id": "S0001", "name": "RealImplant", "type": "malware"},
                {"software_id": "S0075", "name": "Reg", "type": "tool"},
                {"software_id": "S0097", "name": "Ping", "type": "tool"},
                {"software_id": "S0002", "name": "NoTypeStated"},
            ]}},
        }],
    }
    families = _families([investigation])
    check(families == ["RealImplant"],
          f"a tool entry stays out and the implant stays in -> {families}")

    # The other source of a family name states no ATT&CK type, so it is kept on
    # its own key rather than filtered by one it never carries.
    from_bazaar = {
        "indicator": "abc", "risk_level": "HIGH", "visited": ["abc"],
        "full_results": [{
            "indicator": "abc", "type": "hash",
            "results": {"malwarebazaar": {"malware_family": "SomeLoader"}},
        }],
    }
    check(_families([from_bazaar]) == ["SomeLoader"],
          "a MalwareBazaar family is unaffected by the ATT&CK type filter")


def check_stix_patterns() -> None:
    """
    A STIX pattern has to describe the observable the pivot actually found.

    The executor emits nine indicator types. A pattern map that does not cover
    them either raises, or silently declares the value to be something it is
    not, and a TAXII consumer has no way to catch the second case: a threat
    group name published as a domain-name observable imports cleanly and is
    wrong.

    Types with no cyber-observable form get no Indicator at all. A threat group
    belongs in a ThreatActor object and a malware family in Malware, both of
    which the exporter already builds from ATT&CK.
    """
    print("\n-- a STIX pattern matches the observable it describes --")

    SHA256 = "df6d0bd21c124a00510fe2ff5e4923b4f95b61edfbcd06bbef21ee21b33d629d"
    SHA1 = "ee6324a2c40441f34cde9ca5fb66aa4329544713"
    MD5 = "43a39f7b705a9aa3bdbd06a3be6e763c"

    expected = [
        ("ipv4", "45.61.150.229", "[ipv4-addr:value = '45.61.150.229']"),
        ("domain", "evil.example", "[domain-name:value = 'evil.example']"),
        ("url", "http://45.61.150.229:8080/dlr.vbs",
         "[url:value = 'http://45.61.150.229:8080/dlr.vbs']"),
        ("email", "a@b.example", "[email-addr:value = 'a@b.example']"),
        ("filename", "dlr.vbs", "[file:name = 'dlr.vbs']"),
        # The executor reports every digest as "hash", so the algorithm has to
        # come from the digest itself rather than from the type name.
        ("hash", SHA256, f"[file:hashes.'SHA-256' = '{SHA256}']"),
        ("hash", SHA1, f"[file:hashes.'SHA-1' = '{SHA1}']"),
        ("hash", MD5, f"[file:hashes.MD5 = '{MD5}']"),
        ("sha256", SHA256, f"[file:hashes.'SHA-256' = '{SHA256}']"),
        ("md5", MD5, f"[file:hashes.MD5 = '{MD5}']"),
    ]
    for itype, value, pattern in expected:
        try:
            built = STIXExporter()._add_indicator(value, itype)
            got = None if built is None else built.pattern
        except Exception as e:
            got = f"{type(e).__name__}: {str(e)[:44]}"
        check(got == pattern, f"{itype:12} -> {got}")

    # No observable exists for these, so inventing one is worse than omitting it.
    for itype, value in (("threat_group", "Gamaredon Group"),
                         ("software", "VShell"),
                         ("username", "someguy")):
        try:
            built = STIXExporter()._add_indicator(value, itype)
        except Exception as e:
            built = f"{type(e).__name__}"
        check(built is None, f"{itype:12} -> no Indicator object ({built})")

    # End to end, because the crash was in export() rather than in the map.
    for itype, value in (("hash", SHA256), ("url", "http://1.2.3.4:8080/a.vbs"),
                         ("threat_group", "Gamaredon Group")):
        investigation = {
            "indicator": value,
            "full_results": [{"indicator": value, "type": itype,
                              "results": {"virustotal": {"malware_family": "TestFam"}}}],
        }
        target = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "_stix_pattern_probe.json")
        try:
            written = STIXExporter().export(investigation, target)
            bundle = json.load(open(target))
            kinds = sorted({o["type"] for o in bundle["objects"]})
            ok = bool(written)
        except Exception as e:
            ok, kinds = False, f"{type(e).__name__}: {str(e)[:40]}"
        finally:
            if os.path.exists(target):
                os.remove(target)
        check(ok, f"export() completes on a {itype} seed -> {kinds}")


def check_override_accounting_complete() -> None:
    """
    The override record has to cover both kinds of override, keep the analyst's
    words when the engine agreed, and refuse an entry that is not an indicator.

    Three remaining quiet spots. Only the overrides the engine never looked at
    were counted, when the riskier case is the one it looked at and refused. A
    stated exclusion reason was dropped whenever the engine had already made the
    same call, so agreeing with the engine lost the analyst's note. And an
    exclusion line that is not an indicator at all was accepted and then simply
    matched nothing.
    """
    from core.stix_exporter import build_pulse, parse_exclusions

    print("\n-- the override record covers refusals, concurrence and junk --")

    stale = "2019-01-01 00:00:00 UTC"
    investigation = {
        "indicator": "77.88.99.111", "risk_level": "HIGH",
        "visited": ["77.88.99.111", "http://77.88.99.111:8080/a.vbs"],
        "full_results": [
            {"indicator": "77.88.99.111", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 100}}},
            {"indicator": "http://77.88.99.111:8080/a.vbs", "type": "url",
             "results": {"urlhaus": {"found": True, "url_count": "1",
                                     "urls": [{"url": "http://77.88.99.111:8080/a.vbs",
                                               "status": "offline",
                                               "date_added": stale}]}}},
        ],
    }
    url = "http://77.88.99.111:8080/a.vbs"

    # An override the engine looked at and refused is the riskier one, and was
    # counted nowhere.
    refused = build_pulse([investigation], title="t", description="d",
                          include={url: "still open on the incident ticket"})
    check(refused.get("_forced_over_objection") == [url],
          f"an override the engine refused is counted -> "
          f"{refused.get('_forced_over_objection')}")
    check(refused.get("_forced_unassessed") == [],
          f"and is not filed as never-assessed -> "
          f"{refused.get('_forced_unassessed')}")

    unseen = build_pulse([investigation], title="t", description="d",
                         include={"9.9.9.9": "our own telemetry"})
    check(unseen.get("_forced_over_objection") == [],
          f"an unexamined override is not filed as a refusal -> "
          f"{unseen.get('_forced_over_objection')}")

    # Agreeing with the engine must not lose the analyst's reason.
    concur = build_pulse([investigation], title="t", description="d",
                         exclude={url: "concur, and the ticket is closed"})
    entry = next((e for e in concur["_excluded"] if e["indicator"] == url), None)
    check(entry is not None and "campaign link" in (entry.get("reason") or ""),
          f"the engine's reason stays operative -> "
          f"{str((entry or {}).get('reason'))[:38]}")
    check(entry is not None
          and entry.get("analyst_reason") == "concur, and the ticket is closed",
          f"and the analyst's concurrence is kept beside it -> "
          f"{(entry or {}).get('analyst_reason')}")

    # An exclusion line that is not an indicator is refused outright.
    for junk in ("not an indicator", "1.2.3.4.5"):
        try:
            parse_exclusions(f"{junk}=some reason")
            raised = None
        except Exception as e:
            raised = type(e).__name__
        check(raised == "ValueError", f"{junk!r} is refused as an exclusion -> {raised}")

    # The limit of shape checking, pinned so nobody expects more of it: a
    # single-digit typo is a structurally valid address and only the unmatched
    # report can catch it.
    check(parse_exclusions("45.61.150.22=typo for .229") == {"45.61.150.22": "typo for .229"},
          "a plausible-but-wrong address passes shape checking, by necessity")

    typo = build_pulse([investigation], title="t", description="d",
                       exclude={"45.61.150.22": "typo"})
    check(typo.get("_exclusions_unmatched") == ["45.61.150.22"],
          f"and is caught by the unmatched report instead -> "
          f"{typo.get('_exclusions_unmatched')}")

    # The check has to hold at the API boundary too, not only in the file
    # parser, or an inline flag skips it.
    for shape in ({"not an indicator": "r"}, ["not an indicator"]):
        try:
            build_pulse([investigation], title="t", description="d", exclude=shape)
            raised = None
        except Exception as e:
            raised = type(e).__name__
        check(raised == "ValueError",
              f"a junk exclusion is refused however it arrives -> {raised}")


def check_override_accounting() -> None:
    """
    An override that did nothing, or that rests on nothing, has to say so.

    Two quiet failures. An exclusion naming an indicator that is not in the
    selection withholds nothing and reported success, so a mistyped address
    read as protected when it was still being published. And a forced
    indicator the run never touched publishes on the analyst's word alone,
    which is legitimate but is not the same standing as the rest of the pulse
    and was not counted anywhere.

    Neither raises. A shared exclusion list covering several investigations
    will legitimately not match every time, and overriding is the flag's
    purpose. They are counted and surfaced instead.
    """
    from core.stix_exporter import build_pulse

    print("\n-- an override that did nothing, or rests on nothing, is counted --")

    stale = "2019-01-01 00:00:00 UTC"
    investigation = {
        "indicator": "77.88.99.111", "risk_level": "HIGH",
        "visited": ["77.88.99.111", "http://77.88.99.111:8080/a.vbs"],
        "full_results": [
            {"indicator": "77.88.99.111", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 100}}},
            {"indicator": "http://77.88.99.111:8080/a.vbs", "type": "url",
             "results": {"urlhaus": {"found": True, "url_count": "1",
                                     "urls": [{"url": "http://77.88.99.111:8080/a.vbs",
                                               "status": "offline",
                                               "date_added": stale}]}}},
        ],
    }

    # A URL the recency gate dropped, forced back. String derivation would call
    # it a domain, the same way it called a certificate fingerprint one.
    forced = build_pulse([investigation], title="t", description="d",
                         include={"http://77.88.99.111:8080/a.vbs":
                                  "still referenced in the incident ticket"})
    entry = next((e for e in forced["_included_detail"]
                  if e["indicator"].startswith("http://")), None)
    check(entry is not None and entry.get("type") == "URL",
          f"a reinstated URL keeps its own type -> {(entry or {}).get('type')}")

    # A forced indicator with no evidence behind it is counted, not just noted.
    unassessed = build_pulse([investigation], title="t", description="d",
                             include={"9.9.9.9": "our own telemetry"})
    check(unassessed.get("_forced_unassessed") == ["9.9.9.9"],
          f"a forced indicator the engine never saw is counted -> "
          f"{unassessed.get('_forced_unassessed')}")

    assessed = build_pulse([investigation], title="t", description="d",
                           include={"http://77.88.99.111:8080/a.vbs": "ticket"})
    check(assessed.get("_forced_unassessed") == [],
          f"one the engine did assess is not counted there -> "
          f"{assessed.get('_forced_unassessed')}")

    # An exclusion that matched nothing is reported rather than passing quietly.
    typo = build_pulse([investigation], title="t", description="d",
                       exclude={"77.88.99.11": "meant to drop the host"})
    check(typo.get("_exclusions_unmatched") == ["77.88.99.11"],
          f"an exclusion that matched nothing is reported -> "
          f"{typo.get('_exclusions_unmatched')}")
    check("77.88.99.111" in [i["indicator"] for i in typo["indicators"]],
          "and the indicator it failed to name is still published, as it was")

    matched = build_pulse([investigation], title="t", description="d",
                          exclude={"77.88.99.111": "sinkholed"})
    check(matched.get("_exclusions_unmatched") == [],
          f"an exclusion that landed is not reported -> "
          f"{matched.get('_exclusions_unmatched')}")

    # An exclusion the engine had already made agrees with it rather than
    # missing its target, so it is not reported as ineffective.
    agreed = build_pulse([investigation], title="t", description="d",
                         exclude={"http://77.88.99.111:8080/a.vbs":
                                  "concur, the recency gate is right"})
    check(agreed.get("_exclusions_unmatched") == [],
          f"an exclusion the engine already made is not a failure -> "
          f"{agreed.get('_exclusions_unmatched')}")

    # Neither record reaches the upload file.
    payload = {k: v for k, v in typo.items() if not k.startswith("_")}
    check("_exclusions_unmatched" not in json.dumps(payload)
          and "unmatched" not in json.dumps(payload),
          "the accounting stays out of the upload")


def check_override_fidelity() -> None:
    """
    An override has to reinstate the indicator the selector dropped, not a
    reshaped guess at it, and has to say whether the engine ever looked.

    The reinstate path re-derived the type from the string, so a certificate
    fingerprint came back as a domain: a 40-character hex value is a valid
    SHA-1 either way and nothing in the name distinguishes a certificate from a
    file. The type the selector assigned is the only thing that knows.

    And a forced indicator the run never touched was reported under the same
    heading as one the engine refused, which reads as an objection where there
    was only silence.
    """
    from core.stix_exporter import build_pulse, parse_exclusions

    print("\n-- an override reinstates the type the selector assigned --")

    fingerprint = "ee6324a2c40441f34cde9ca5fb66aa4329544713"
    investigation = {
        "indicator": "77.88.99.111", "risk_level": "HIGH",
        "visited": ["77.88.99.111", "quiet.example"],
        "full_results": [
            {"indicator": "77.88.99.111", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 100}}},
            {"indicator": "quiet.example", "type": "domain",
             "results": {"virustotal": {"malicious_votes": 0, "harmless_votes": 54},
                         "threatfox": {"found": False}, "urlhaus": {"found": False},
                         "otx": {"pulse_count": 0},
                         "domaintools": {"certificates": [
                             {"sha1": fingerprint, "domains_on_cert": 1}]}}},
        ],
    }

    forced = build_pulse([investigation], title="t", description="d",
                         include={fingerprint: "the certificate is the pivot"})
    entry = next((e for e in forced["_included_detail"]
                  if e["indicator"] == fingerprint), None)
    check(entry is not None and entry.get("type") == "SSLCertFingerprint",
          f"a reinstated fingerprint keeps its own type -> "
          f"{(entry or {}).get('type')}")

    # An address still reinstates as an address.
    dropped_address = {
        "indicator": "77.88.99.111", "risk_level": "HIGH",
        "visited": ["77.88.99.111", "203.0.113.9"],
        "full_results": [
            {"indicator": "77.88.99.111", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 100}}},
            {"indicator": "203.0.113.9", "type": "ipv4", "results": {}},
        ],
    }
    back = build_pulse([dropped_address], title="t", description="d",
                       include={"203.0.113.9": "documentation space, but deliberate"})
    entry = next((e for e in back["_included_detail"]
                  if e["indicator"] == "203.0.113.9"), None)
    check(entry is not None and entry.get("type") == "IPv4",
          f"a reinstated address keeps its own type -> {(entry or {}).get('type')}")
    check(entry is not None and entry.get("assessed") is True,
          f"and is marked as something the engine did assess -> "
          f"{(entry or {}).get('assessed')}")

    # Silence is not an objection.
    unseen = build_pulse([dropped_address], title="t", description="d",
                         include={"9.9.9.9": "our own telemetry"})
    entry = next((e for e in unseen["_included_detail"]
                  if e["indicator"] == "9.9.9.9"), None)
    check(entry is not None and entry.get("assessed") is False,
          f"an indicator the run never touched is marked unassessed -> "
          f"{(entry or {}).get('assessed')}")

    print("\n-- exclusions state a reason from the command line too --")

    parsed = parse_exclusions("""
# Withholding needs no paperwork, but may carry a reason.
1.2.3.4=sinkholed by the registrar, confirmed with the ISP
evil.example
77.88.99.111\ttab separated
""")
    check(len(parsed) == 3, f"three exclusions parse -> {len(parsed)}")
    check(parsed.get("1.2.3.4", "").startswith("sinkholed"),
          f"a stated reason is kept -> {parsed.get('1.2.3.4', '')[:24]}")
    check(parsed.get("evil.example") == "excluded by analyst",
          f"a bare indicator gets the generic reason -> {parsed.get('evil.example')}")
    check(parsed.get("77.88.99.111") == "tab separated",
          f"a tab separates here too -> {parsed.get('77.88.99.111')}")


def check_forced_include_bulk() -> None:
    """
    Forcing many indicators has to be practical, and a typo must not publish.

    One flag per indicator is correct for three and unusable for a hundred, and
    the pulses this engine has already built carried 24 and 144. So the same
    indicator/reason pairs are readable from a file, in one format shared with
    the TUI.

    Validation is the other half. A forced name was typed straight through with
    an OTX type of "domain" as the fallback, so a mistyped address published as
    a domain with a confident reason attached to it.
    """
    from core.stix_exporter import build_pulse, parse_forced_reasons

    print("\n-- forced indicators come from a file, and a typo is refused --")

    text = """
# Reasons may contain commas, equals signs and prose.
1.2.3.4=confirmed C2 in report ABC-123, blocking is intended
77.88.99.111\tsecond format: a tab, for pasting out of a spreadsheet
evil.example=named in the vendor bulletin at https://x.example/?id=7

"""
    parsed = parse_forced_reasons(text)
    check(len(parsed) == 3, f"three pairs parse, blanks and comments skipped -> {len(parsed)}")
    check(parsed.get("1.2.3.4", "").endswith("blocking is intended"),
          f"a reason keeps its commas -> {parsed.get('1.2.3.4', '')[-28:]}")
    check("?id=7" in parsed.get("evil.example", ""),
          f"and its equals signs -> {parsed.get('evil.example', '')[-18:]}")
    check(parsed.get("77.88.99.111", "").startswith("second format"),
          f"a tab separates too -> {parsed.get('77.88.99.111', '')[:22]}")

    for bad, label in (("1.2.3.4", "no separator at all"),
                       ("1.2.3.4=", "an empty reason"),
                       ("1.2.3.4=   ", "a whitespace reason")):
        try:
            parse_forced_reasons(bad)
            raised = None
        except Exception as e:
            raised = type(e).__name__
        check(raised == "ValueError", f"{label} is refused -> {raised}")

    # A typo must not become a domain indicator with a reason attached.
    def forcing(mapping):
        investigation = {
            "indicator": "77.88.99.111", "risk_level": "HIGH",
            "visited": ["77.88.99.111"],
            "full_results": [{"indicator": "77.88.99.111", "type": "ipv4",
                              "results": {"threatfox": {"found": True,
                                                        "max_confidence": 100}}}],
        }
        return build_pulse([investigation], title="t", description="d",
                           include=mapping)

    for junk in ("1.2.3.4.5", "not an indicator", "someguy"):
        try:
            forcing({junk: "a confident sounding reason"})
            raised, detail = None, ""
        except Exception as e:
            raised, detail = type(e).__name__, str(e)
        check(raised == "ValueError" and junk in detail,
              f"{junk!r} is refused rather than published -> {raised}")

    # Real indicator shapes still pass, including a certificate fingerprint.
    for good in ("1.2.3.4", "evil.example", "a" * 40, "b" * 64):
        try:
            forcing({good: "stated reason"})
            ok = True
        except Exception as e:
            ok = f"{type(e).__name__}: {e}"
        check(ok is True, f"{good[:18]!r} is accepted -> {ok}")

    # An exclusion may now state a reason, and the audit records it rather than
    # the bare "excluded by analyst" it used to carry.
    investigation = {
        "indicator": "77.88.99.111", "risk_level": "HIGH",
        "visited": ["77.88.99.111"],
        "full_results": [{"indicator": "77.88.99.111", "type": "ipv4",
                          "results": {"threatfox": {"found": True,
                                                    "max_confidence": 100}}}],
    }
    stated = build_pulse([investigation], title="t", description="d",
                         exclude={"77.88.99.111": "sinkholed by the registrar"})
    reason = {e["indicator"]: e["reason"] for e in stated["_excluded"]}
    check(reason.get("77.88.99.111") == "sinkholed by the registrar",
          f"a stated exclusion reason is recorded -> {reason.get('77.88.99.111')}")

    # And a bare list still works, because withholding is the cautious
    # direction and should not need paperwork.
    bare = build_pulse([investigation], title="t", description="d",
                       exclude=["77.88.99.111"])
    reason = {e["indicator"]: e["reason"] for e in bare["_excluded"]}
    check(reason.get("77.88.99.111") == "excluded by analyst",
          f"an unexplained exclusion still works -> {reason.get('77.88.99.111')}")


def check_export_screen_disclosure() -> None:
    """
    The TUI has to show what the selector withheld, and let it be overridden.

    The screen computed the exclusions on open and reported only a count, so a
    TUI user could not see which indicators were held back or why, and had no
    way to publish one anyway. The CLI had both. That gap made the TUI the
    lesser tool for the one decision that carries third-party risk.
    """
    from tui import ExportScreen

    print("\n-- the export screen discloses what was withheld --")

    excluded = [
        {"indicator": "1.2.3.4",
         "reason": "shared hosting — 3 unrelated domain(s) on this address"},
        {"indicator": "quiet.example",
         "reason": "discovered by chaining and uncorroborated"},
    ]
    lines = ExportScreen._withheld_lines(excluded)
    joined = "\n".join(lines)
    check("1.2.3.4" in joined and "quiet.example" in joined,
          f"each withheld indicator is named -> {len(lines)} line(s)")
    check("shared hosting" in joined,
          "and the reason it was withheld is shown")

    # A long list is capped, and says how many it did not show, so the preview
    # cannot push the input fields off screen.
    many = [{"indicator": f"10.0.0.{n}", "reason": "shared hosting"}
            for n in range(1, 21)]
    capped = ExportScreen._withheld_lines(many, limit=5)
    check(len(capped) == 6 and "15 more" in capped[-1],
          f"a long list is capped with a remainder -> {capped[-1] if capped else None}")

    check(ExportScreen._withheld_lines([]) == [],
          "nothing withheld renders nothing")

    # The screen accepts overrides in the same format the file uses.
    check(hasattr(ExportScreen, "_forced"),
          "the screen has an override path")
    check(hasattr(ExportScreen, "_dropped"),
          "and a path to withhold one the selector kept")

    # The accounting the CLI prints has to reach the TUI user too.
    bundle = {
        "_forced_unassessed": ["9.9.9.9"],
        "_forced_over_objection": ["1.2.3.4"],
        "_exclusions_unmatched": ["45.61.150.22"],
    }
    notes = "\n".join(ExportScreen._accounting_lines(bundle))
    check("9.9.9.9" in notes and "1.2.3.4" in notes,
          "both kinds of override are surfaced in the screen")
    check("45.61.150.22" in notes,
          "and an exclusion that withheld nothing is surfaced")
    check(ExportScreen._accounting_lines(
        {"_forced_unassessed": [], "_forced_over_objection": [],
         "_exclusions_unmatched": []}) == [],
        "a clean build adds no noise")


def check_forced_include_record() -> None:
    """
    Forcing an indicator past the selector has to leave a record of why.

    The flag exists to override screening, so screening it again would defeat
    it. What was missing is the other half: nothing recorded the analyst's
    reason, and nothing said what the override overrode. A pulse could carry an
    address the engine had refused, with no trace of who decided otherwise or
    what they decided against.

    So the reason is mandatory and the objection is kept beside it. Neither
    replaces the other: one is the analyst's claim, the other is the engine's,
    and a reviewer needs both.
    """
    from core.stix_exporter import build_pulse, write_pulse

    print("\n-- a forced indicator carries its reason and what it overrode --")

    # 203.0.113.9 is documentation space, so the selector refuses it outright.
    # That makes it a reliable stand-in for "the engine said no".
    def investigation():
        return {
            "indicator": "77.88.99.111", "risk_level": "HIGH", "context_score": 0.7,
            "visited": ["77.88.99.111", "203.0.113.9"],
            "full_results": [
                {"indicator": "77.88.99.111", "type": "ipv4",
                 "results": {"threatfox": {"found": True, "max_confidence": 100}}},
                {"indicator": "203.0.113.9", "type": "ipv4", "results": {}},
            ],
        }

    def built(include):
        return build_pulse([investigation()], title="t", description="d",
                           include=include)

    # Mandatory: no reason, no override.
    for empty in ([("203.0.113.9")], {"203.0.113.9": ""}, {"203.0.113.9": "   "}):
        try:
            built(empty)
            raised = None
        except Exception as e:
            raised = type(e).__name__
        check(raised == "ValueError",
              f"a forced indicator with no reason is refused -> {raised}")

    reason = "confirmed C2 in vendor report ABC-123; blocking is intended"
    bundle = built({"203.0.113.9": reason})
    forced = next((e for e in bundle["_included_detail"]
                   if e["indicator"] == "203.0.113.9"), None)

    # The override still works. That is the whole point of the flag.
    check(forced is not None,
          f"the override still publishes what the engine refused -> "
          f"{[e['indicator'] for e in bundle['_included_detail']]}")

    if forced:
        check(forced.get("analyst_reason") == reason,
              f"the analyst's reason is recorded verbatim -> "
              f"{str(forced.get('analyst_reason'))[:44]}")
        # What it would have failed on, kept rather than replaced.
        check("routable" in (forced.get("caveat") or ""),
              f"and what the engine objected to is kept beside it -> "
              f"{str(forced.get('caveat'))[:52]}")

    # An indicator the selector never saw at all still needs a reason, and the
    # record has to say the engine never assessed it.
    unseen = built({"91.92.93.94": "seen in our own telemetry"})
    entry = next((e for e in unseen["_included_detail"]
                  if e["indicator"] == "91.92.93.94"), None)
    check(entry is not None and entry.get("analyst_reason") == "seen in our own telemetry",
          f"a never-assessed indicator records its reason -> {entry}")
    check(entry is not None and "never assessed" in (entry.get("caveat") or ""),
          f"and says the engine never assessed it -> {str((entry or {}).get('caveat'))[:44]}")

    # The record belongs in the audit file, never in the upload.
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "_include_probe.json")
    audit_path = None
    try:
        clean_path, audit_path = write_pulse(bundle, target)
        payload = json.load(open(clean_path))
        audit = json.load(open(audit_path))
        check(reason not in json.dumps(payload),
              "the analyst's reason does not leak into the upload file")
        check(reason in json.dumps(audit),
              "and is written to the audit file")
    finally:
        for path in (target, audit_path):
            if path and os.path.exists(path):
                os.remove(path)


def check_provenance() -> None:
    """
    A saved investigation has to say when it ran, what scored it, and whether
    its evidence is still the evidence that was collected.

    Every claim this engine makes is time-sensitive and none of it was dated, so
    a stored verdict could not be cited. A stored score could not be attributed
    to a formula either, which matters because the scoring paths have changed
    repeatedly: two files with the same number may have been produced by
    different code. And nothing detected an edited payload.

    Unstamped is not altered. A file saved before any of this existed cannot be
    verified, and reporting that as tampering would accuse the archive of a
    defect in the engine.
    """
    import datetime

    from core.provenance import SCORER_VERSION, evidence_digest, stamp, verify

    print("\n-- a saved investigation carries its own provenance --")

    def investigation():
        return {
            "indicator": "77.88.99.111", "indicator_type": "ipv4",
            "context_score": 0.7, "risk_level": "HIGH",
            "visited": ["77.88.99.111"],
            "full_results": [{
                "indicator": "77.88.99.111", "type": "ipv4",
                "results": {"threatfox": {"found": True, "max_confidence": 100}},
            }],
        }

    stamped = stamp(investigation())
    block = stamped.get("provenance") or {}

    # Gap 2 — when it ran.
    when = block.get("run_at")
    parsed = None
    if isinstance(when, str):
        try:
            parsed = datetime.datetime.fromisoformat(when)
        except ValueError:
            parsed = None
    check(parsed is not None and parsed.tzinfo is not None,
          f"run_at is a timezone-aware ISO 8601 stamp -> {when}")
    if parsed is not None:
        age = abs((datetime.datetime.now(datetime.UTC) - parsed).total_seconds())
        check(age < 300, f"and it is the time of the run -> {age:.0f}s ago")

    # Gap 3 — what produced the score.
    check(block.get("scorer_version") == SCORER_VERSION,
          f"the scorer version is recorded -> {block.get('scorer_version')}")
    check(bool(block.get("engine_version")),
          f"the engine version is recorded -> {block.get('engine_version')}")

    # Gap 13 — the evidence is fingerprinted, and the fingerprint is honest.
    digest = block.get("evidence_digest") or ""
    check(digest.startswith("sha256:") and len(digest) == 71,
          f"the evidence carries a sha256 digest -> {digest[:24]}")
    check(verify(stamped).get("status") == "verified",
          f"an untouched investigation verifies -> {verify(stamped)}")

    # The tamper case. Editing a stored payload has to be detectable.
    edited = json.loads(json.dumps(stamped))
    edited["full_results"][0]["results"]["threatfox"]["max_confidence"] = 10
    outcome = verify(edited)
    check(outcome.get("status") == "altered",
          f"an edited payload is detected -> {outcome.get('status')}")

    # Adding a whole source is caught too, not only changing a value.
    added = json.loads(json.dumps(stamped))
    added["full_results"][0]["results"]["urlhaus"] = {"found": True, "url_count": "9"}
    check(verify(added).get("status") == "altered",
          f"an inserted source is detected -> {verify(added).get('status')}")

    # A digest that changed with key order would fail on every reserialization.
    reordered = {
        "results": {"threatfox": {"max_confidence": 100, "found": True}},
        "type": "ipv4", "indicator": "77.88.99.111",
    }
    check(evidence_digest([reordered]) == evidence_digest(investigation()["full_results"]),
          "the digest is stable under key reordering")

    # Rewriting the verdict without touching the evidence is a different claim,
    # and the digest deliberately does not cover it: it protects what the
    # sources said, not what the engine concluded from it.
    rescored = json.loads(json.dumps(stamped))
    rescored["context_score"] = 0.01
    check(verify(rescored).get("status") == "verified",
          f"re-scoring the same evidence still verifies -> {verify(rescored).get('status')}")

    # The absence guard.
    legacy = investigation()
    check(verify(legacy).get("status") == "unstamped",
          f"a file saved before stamping is unverifiable, not altered "
          f"-> {verify(legacy).get('status')}")


def check_campaign_recency() -> None:
    """
    An indicator's own link to the campaign has to be current, not just its
    neighbours'.

    Tenancy recency asks whether the domains beside an address are still there.
    Nothing asked whether the evidence for the address itself is still live, so
    a host a feed listed once in 2023 published as though it were serving now,
    and a domain vouched for only by a years-old bulk feed published on the
    strength of it.

    The absence half matters as much. Evidence carrying no date has said nothing
    about when, and reading that as old would suppress indicators on a missing
    field rather than on a finding.
    """
    import datetime

    print("\n-- an indicator's own campaign link has to be current --")

    now = datetime.datetime.now(datetime.UTC)
    stale = (now - datetime.timedelta(days=400)).strftime("%Y-%m-%d %H:%M:%S UTC")
    fresh = (now - datetime.timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S UTC")
    stale_iso = (now - datetime.timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%S")

    def address(urls=None, threatfox=None, seed="91.92.93.94"):
        """One investigation whose chained address carries the given evidence."""
        pivot = {"indicator": "77.88.99.111", "type": "ipv4", "results": {}}
        if urls is not None:
            pivot["results"]["urlhaus"] = {"found": True, "url_count": str(len(urls)),
                                           "urls": urls}
        if threatfox is not None:
            pivot["results"]["threatfox"] = threatfox
        return {
            "indicator": seed, "risk_level": "HIGH",
            "visited": [seed, "77.88.99.111"],
            "full_results": [
                {"indicator": seed.split(":")[0], "type": "ipv4",
                 "results": {"threatfox": {"found": True, "max_confidence": 90},
                             "passivedns": {"records": []}}},
                pivot,
            ],
        }

    def verdict(investigation, target="77.88.99.111"):
        included, excluded = select_indicators([investigation])
        if target in [i["indicator"] for i in included]:
            return True, ""
        return False, {e["indicator"]: e["reason"] for e in excluded}.get(target, "")

    # Listed once, years ago, and long since offline.
    kept, why = verdict(address(urls=[{"url": "http://77.88.99.111/a", "status": "offline",
                                       "date_added": stale}]))
    check(not kept and "campaign link" in why,
          f"a years-old offline listing is withheld -> {why[:62]}")

    # Still serving, so the date it was first reported does not matter.
    kept, why = verdict(address(urls=[{"url": "http://77.88.99.111/a", "status": "online",
                                       "date_added": stale}]))
    check(kept, f"an online URL is current whatever its date_added -> {why[:56]}")

    # Recently reported.
    kept, why = verdict(address(urls=[{"url": "http://77.88.99.111/a", "status": "offline",
                                       "date_added": fresh}]))
    check(kept, f"a recent listing is published -> {why[:56]}")

    # The absence guard: evidence with no date is not evidence of staleness.
    kept, why = verdict(address(threatfox={"found": True, "max_confidence": 100}))
    check(kept, f"undated evidence is not treated as stale -> {why[:56]}")

    # The analyst chose the seed, so it is exempt as it is from corroboration.
    seeded = {
        "indicator": "77.88.99.111", "risk_level": "HIGH", "visited": ["77.88.99.111"],
        "full_results": [{"indicator": "77.88.99.111", "type": "ipv4",
                          "results": {"urlhaus": {"found": True, "url_count": "1",
                                                  "urls": [{"url": "http://77.88.99.111/a",
                                                            "status": "offline",
                                                            "date_added": stale}]}}}],
    }
    kept, why = verdict(seeded)
    check(kept, f"a stale seed is still published -> {why[:56]}")

    # And the exemption has to survive the host:port form the browse pages hand out.
    kept, why = verdict({**seeded, "indicator": "77.88.99.111:8080"})
    check(kept, f"a host:port seed is recognised as the seed -> {why[:56]}")

    # A domain vouched for only by a years-old pulse.
    domain = {
        "indicator": "91.92.93.94", "risk_level": "HIGH",
        "visited": ["91.92.93.94", "quiet.example"],
        "full_results": [
            {"indicator": "91.92.93.94", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 90},
                         "passivedns": {"records": []}}},
            {"indicator": "quiet.example", "type": "domain",
             "results": {"virustotal": {"malicious_votes": 0, "harmless_votes": 54},
                         "threatfox": {"found": False}, "urlhaus": {"found": False},
                         "otx": {"pulse_count": 1,
                                 "pulses": [{"name": "NewDom-bulk", "created": stale_iso}]}}},
        ],
    }
    kept, why = verdict(domain, target="quiet.example")
    check(not kept and "campaign link" in why,
          f"a domain corroborated only by an old pulse is withheld -> {why[:62]}")


def check_stix_bundle_contract() -> None:
    """
    The bundle has to carry the whole gated indicator set, and assert only what
    the engine measured.

    A seed-only bundle throws away the chain, which is the reason to run the
    engine at all. But every pivot is not the answer either: the chain reaches
    bystanders, so the STIX path has to publish through the same gate as the
    pulse path rather than emitting whatever it walked over.

    The rest is about not stating unmeasured facts. Hardcoded labels asserted
    that every actor was state-sponsored and every indicator malicious, and the
    confidence the engine does compute was never carried at all.
    """
    print("\n-- the STIX bundle publishes the gated set, and asserts only what was measured --")

    SHA256 = "df6d0bd21c124a00510fe2ff5e4923b4f95b61edfbcd06bbef21ee21b33d629d"

    def bundle_for(investigation):
        target = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "_stix_contract_probe.json")
        try:
            STIXExporter().export(investigation, target)
            return json.load(open(target))
        finally:
            if os.path.exists(target):
                os.remove(target)

    # A listed address, a corroborated hash, and a stale bystander co-tenant.
    investigation = {
        "indicator": "45.61.150.229", "risk_level": "HIGH", "context_score": 0.7,
        "visited": ["45.61.150.229", SHA256, "bystander.example"],
        "full_results": [
            {"indicator": "45.61.150.229", "type": "ipv4",
             "results": {"threatfox": {"found": True, "max_confidence": 100},
                         "virustotal": {"malware_family": "TestLoader"}}},
            {"indicator": SHA256, "type": "hash",
             "results": {"threatfox": {"found": True, "max_confidence": 100}}},
            {"indicator": "bystander.example", "type": "domain", "results": {}},
        ],
    }
    bundle = bundle_for(investigation)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    patterns = " ".join(i["pattern"] for i in indicators)

    # 1. the chain is published, not only the seed
    check(len(indicators) >= 2,
          f"a 3-pivot investigation exports more than the seed -> "
          f"{len(indicators)} indicator objects")
    check("45.61.150.229" in patterns and SHA256 in patterns,
          "both the seed and the chained hash are present")

    # and the gate still holds, so the chain does not drag in a bystander
    check("bystander.example" not in patterns,
          "an uncorroborated co-tenant is still withheld")

    # 4. confidence carries the score the engine computed, on the 0-100 scale
    seed = next((i for i in indicators if "45.61.150.229" in i["pattern"]), {})
    check(seed.get("confidence") == 70,
          f"the seed carries its measured confidence -> {seed.get('confidence')}")

    # 3 + 7. the typed property is set, and reflects the level
    check(seed.get("indicator_types") == ["malicious-activity"],
          f"a HIGH indicator is typed malicious-activity -> {seed.get('indicator_types')}")
    check("labels" not in seed,
          f"no hardcoded free-form label -> {seed.get('labels')}")

    low = bundle_for({**investigation, "risk_level": "LOW", "context_score": 0.1})
    low_ind = next((o for o in low["objects"] if o["type"] == "indicator"), {})
    check(low_ind.get("indicator_types") == ["unknown"],
          f"a LOW indicator is not asserted malicious -> {low_ind.get('indicator_types')}")

    # 2. an actor is not asserted to be state-sponsored
    with_actor = bundle_for({
        "indicator": "Some Group", "risk_level": "HIGH", "visited": ["Some Group"],
        "full_results": [{
            "indicator": "Some Group", "type": "threat_group",
            "results": {"virustotal": {"malware_family": "TestFam"},
                        "mitre": {"found": True, "techniques": [],
                                  "groups": [{"name": "Some Group", "aliases": ["SG"]}]}},
        }],
    })
    actors = [o for o in with_actor["objects"] if o["type"] == "threat-actor"]
    check(len(actors) == 1, f"the actor is exported -> {len(actors)}")
    check("nation-state" not in json.dumps(actors),
          f"no hardcoded nation-state attribution -> {actors[0].get('threat_actor_types')}")

    # 5. the unused observable imports are gone
    import core.stix_exporter as exporter_module
    dead = [n for n in ("ObservedData", "DomainName", "IPv4Address", "File")
            if hasattr(exporter_module, n)]
    check(not dead, f"no unused STIX observable imports -> {dead or 'none'}")

    # 6. the MCP tool reports an exporter failure instead of propagating it
    import mcp_server

    class Exploding:
        def export(self, *args, **kwargs):
            raise ValueError("synthetic exporter failure")

    original = mcp_server._engine
    mcp_server._engine = lambda: {"STIXExporter": Exploding}
    mcp_server._INVESTIGATIONS["stixprobe"] = {
        "indicator": "stixprobe", "visited": ["stixprobe"],
        "full_results": [{"indicator": "stixprobe", "type": "domain", "results": {}}],
    }
    try:
        out = mcp_server.export_stix("stixprobe")
        handled = isinstance(out, dict) and "error" in out
    except Exception as e:
        handled, out = False, f"raised {type(e).__name__}"
    finally:
        mcp_server._engine = original
        mcp_server._INVESTIGATIONS.pop("stixprobe", None)
    check(handled, f"an exporter exception becomes an error result -> {str(out)[:60]}")


def check_urlhaus_answer_shapes() -> None:
    """
    A confirmed URL listing is never reported as zero URLs.

    URLhaus answers a host query with a count and a URL query with one URL's
    status. Reading a count from the URL shape turns a live listing into
    "0 malicious URLs (0 currently online)", which is the reverse of the truth
    about the indicator the analyst pasted.
    """
    print("\n-- URLhaus is read in the shape it answered in --")

    def findings_for(indicator, itype, urlhaus):
        return extract_findings(
            {"indicator": indicator, "type": itype, "results": {"urlhaus": urlhaus}}
        )

    url_shape = {
        "found": True, "url_status": "online", "threat": "malware_download",
        "tags": ["ua-wget", "vbs"],
        "payloads": [{"sha256": "a" * 64, "md5": "b" * 32, "file_type": "txt"}],
    }
    lines = findings_for("http://198.51.100.7:8080/dlr.vbs", "url", url_shape)
    joined = " ".join(lines)
    check("0 malicious URLs" not in joined,
          "a listed URL is not reported as zero URLs")
    check("currently online" in joined and "malware_download" in joined,
          f"its own status is reported -> {lines[0][-52:]}")
    check(any("a" * 64 in line for line in lines),
          "the payload it served is named, since that is what the chain pivots on")

    # The host shape still counts, and still separates online from listed.
    host_shape = {
        "found": True, "url_count": "3",
        "urls": [{"status": "online"}, {"status": "online"}, {"status": "offline"}],
    }
    host_line = findings_for("198.51.100.7", "ipv4", host_shape)[0]
    check("3 malicious URLs (2 currently online)" in host_line,
          f"the host shape is unchanged -> {host_line[-44:]}")

    # A source that answered "not found" must add nothing at all.
    check(findings_for("198.51.100.7", "ipv4", {"found": False}) == [],
          "an unlisted indicator produces no URLhaus finding")


def check_netblock_clustering() -> None:
    """
    A family cluster reports the ranges its hosts concentrate in.

    Infrastructure pivots walk an address to its own past tenants, never
    sideways to the operator's other addresses, so bulk provisioning is only
    visible by grouping the family's hosts by network.
    """
    print("\n-- a family cluster surfaces the ranges it concentrates in --")

    # Eight contiguous /24s have to collapse into the one /21 they form, or a
    # fleet reads as eight unrelated coincidences.
    fleet = [{"host": f"154.91.{block}.{host}", "port": "8084",
              "first_seen": "2026-09-02 00:00:00 UTC"}
             for block in range(56, 64) for host in (98, 99, 100, 101)]
    blocks = _netblocks(fleet)
    check(len(blocks) == 1 and blocks[0]["cidr"] == "154.91.56.0/21",
          f"eight adjacent /24s collapse to one supernet -> "
          f"{[b['cidr'] for b in blocks]}")
    check(blocks[0]["hosts"] == 32 and blocks[0]["ports"] == {"8084": 32},
          f"host and port counts carry -> {blocks[0]['hosts']} on {blocks[0]['ports']}")

    # Scattered addresses are what shared hosting looks like, and reporting each
    # as a concentration would make every cluster look coordinated.
    scattered = [{"host": h, "port": "443"} for h in
                 ("8.8.8.8", "1.1.1.1", "9.9.9.9", "203.0.113.7", "198.51.100.9")]
    check(_netblocks(scattered) == [],
          "one host per range is not a concentration")

    # Densest first, so the range a blocklist would be drawn from leads.
    mixed = fleet + [{"host": f"38.46.15.{n}", "port": "4141"} for n in range(1, 6)]
    ordered = _netblocks(mixed)
    check([b["cidr"] for b in ordered] == ["154.91.56.0/21", "38.46.15.0/24"],
          f"ranges are ordered by host count -> {[b['cidr'] for b in ordered]}")

    # Names and IPv6 carry no netblock, and must not abort the summary.
    check(_netblocks([{"host": "evil.example", "port": "80"},
                      {"host": "2001:db8::1", "port": "80"}]) == [],
          "a non-IPv4 host is skipped rather than raising")


def check_seed_formats() -> None:
    """
    A seed the analyst can actually paste has to resolve to a type.

    ThreatFox publishes C2s as host:port and its browse page is the documented
    place to get fresh seeds, so that form has to resolve. The connectors want
    the host, so the detector returns the host and carries the port alongside.
    """
    print("\n-- a pasteable seed resolves to a type --")

    cases = [
        # seed,                        type,     indicator connectors receive
        ("217.60.102.3:56003",         "ipv4",   "217.60.102.3"),
        ("evil.example.com:443",       "domain", "evil.example.com"),
        ("217.60.102.3",               "ipv4",   "217.60.102.3"),
        ("http://217.60.102.3:56003",  "url",    "http://217.60.102.3:56003"),
    ]
    for seed, expected_type, expected_indicator in cases:
        got = detect_type(seed) or {}
        check(
            got.get("type") == expected_type
            and got.get("indicator") == expected_indicator,
            f"{seed[:30]:30} -> {got.get('type')} on {got.get('indicator')}",
        )

    # A port that cannot exist, and a host that is neither an address nor a
    # domain. Accepting these would route junk into a pivot.
    for junk in ["1.2.3.4:0", "1.2.3.4:99999", "1.2.3.4:abc", "notahost:443"]:
        check(detect_type(junk) is None, f"{junk[:30]:30} -> rejected")

    # The executor has to pass on the detector's indicator, not the raw seed.
    validated = PivotExecutor().validate("217.60.102.3:56003")
    check(validated.get("valid") and validated.get("indicator") == "217.60.102.3",
          f"executor validates host:port to {validated.get('indicator')}")
    check(validated.get("port") == 56003,
          f"the port survives for the report: {validated.get('port')}")

    # The seed named a service and the pivot is on the host, so the port only
    # reaches the analyst if extract_findings carries it.
    seed_port = {"source": "seed_port", "port": 56003, "non_standard_port": True}

    def port_finding(results: dict) -> str:
        hits = [f for f in extract_findings(
            {"indicator": "217.60.102.3", "type": "ipv4", "results": results}
        ) if "on port 56003" in f]
        return hits[0] if hits else ""

    confirmed = port_finding({"seed_port": seed_port,
                              "shodan": {"open_ports": [22, 56003]}})
    check("confirmed open" in confirmed, f"scan lists it -> {confirmed[-38:]}")

    absent = port_finding({"seed_port": seed_port,
                           "shodan": {"open_ports": [22, 80]}})
    check("does not list" in absent, f"scan ran without it -> {absent[-38:]}")

    # The one that matters. A source that failed says nothing about the port,
    # and writing that up as closed would retire a live C2 on silence.
    silent = port_finding({"seed_port": seed_port, "shodan": {"error": "401"}})
    check("no scan data came back" in silent,
          f"no scan data is not a closed port -> {silent[-38:]}")

    # visited keeps the seed as pasted, full_results normalises it, and the
    # publisher matches the two by name. Unstripped, the seed matches nothing,
    # types as blank and is dropped, which loses the best-evidenced indicator in
    # the pulse. No OTX or STIX address property accepts a port either.
    investigation = {
        "indicator": "217.60.102.3:56003", "risk_level": "HIGH",
        "visited": ["217.60.102.3:56003"],
        "full_results": [{
            "indicator": "217.60.102.3", "type": "ipv4",
            "results": {"threatfox": {"found": True, "max_confidence": 75}},
        }],
    }
    included, excluded = select_indicators([investigation])
    published = [entry["indicator"] for entry in included]
    check(published == ["217.60.102.3"],
          f"a host:port seed publishes as the bare address -> {published}")
    check(not any(":" in entry["indicator"] for entry in included + excluded),
          "no port survives into either list")


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
    check_seed_formats()
    check_stix_patterns()
    check_forced_include_record()
    check_override_accounting()
    check_override_accounting_complete()
    check_override_fidelity()
    check_forced_include_bulk()
    check_export_screen_disclosure()
    check_provenance()
    check_campaign_recency()
    check_stix_bundle_contract()
    check_urlhaus_answer_shapes()
    check_netblock_clustering()
    check_actor_designators()
    check_malware_families()
    check_publication_gate(entries)

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
    # reliable backstop for it, so feed evidence has to floor the score.
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

    # Exercised through the blending layers rather than through
    # ConfidenceScorer alone, since a layer holding no data must leave a
    # confident score untouched rather than averaging it down.
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
