# scripts/otx_coverage.py
# Asks whether OTX already says what a pulse is about, not just whether it
# holds the same addresses.

"""
Pre-publication coverage check for a built pulse.

Counting pulses per indicator answers the wrong question. A bulk repost holding
thirty thousand indicators with no family, no techniques and generated tags
scores identically to a curated pulse that names the actor, so an indicator can
look covered while nothing in OTX says what it is.

This reports four states per indicator, and the middle one is the reason the
script exists:

    absent        no pulse carries it
    unattributed  pulses carry it, none names the family
    attributed    a pulse already names the family
    unknown       the lookup failed, so coverage was never established

`unknown` is separate on purpose. A timeout is not an absence, and filing a
failed lookup as "absent" would argue for publishing on the strength of a
source that never answered.

    PYTHONPATH=. python scripts/otx_coverage.py pulse.json
    PYTHONPATH=. python scripts/otx_coverage.py pulse.json --family BianLian
"""

import argparse
import json
import re
import sys
import time

from connectors.retry import get_with_retry
from config import OTX_API_KEY

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

# Indicator counts at or above this mark a pulse as a bulk list. Not a judgement
# on its accuracy: a large pulse can be entirely correct. It bounds what the
# pulse can be read as saying, since a set this size carries no per-indicator
# claim and the same address appears in it for reasons no reader can recover.
BULK_INDICATOR_COUNT = 1000

# OTX indicator type to the path segment its lookup uses.
LOOKUP_PATH = {
    "IPv4": "IPv4",
    "IPv6": "IPv6",
    "domain": "domain",
    "hostname": "hostname",
    "URL": "url",
    "FileHash-MD5": "file",
    "FileHash-SHA1": "file",
    "FileHash-SHA256": "file",
}


def _normalise(text: str) -> str:
    """Lowercase with separators dropped, so win.bianlian matches BianLian."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _labels(value) -> list[str]:
    """
    Names out of a field that arrives as plain strings or as objects.

    `malware_families` comes back as `["Akira"]` from some pulses and as
    `[{"id": "Akira - S1129", "display_name": ...}]` from others, so reading
    either shape is the difference between matching a family and raising.
    """
    names = []
    for item in value or []:
        if isinstance(item, dict):
            names.append(item.get("display_name") or item.get("id") or "")
        else:
            names.append(str(item))
    return names


def names_family(pulse: dict, families: list[str]) -> bool:
    """
    Whether a pulse says which family the indicator belongs to.

    Reads the structured field first and the prose second, because a pulse that
    only mentions a family in its title still tells a reader what it found.
    Tags count; generated ones simply will not match.
    """
    if not families:
        return False

    haystack = " ".join([
        pulse.get("name") or "",
        pulse.get("description") or "",
        " ".join(_labels(pulse.get("tags"))),
        " ".join(_labels(pulse.get("malware_families"))),
    ])
    packed = _normalise(haystack)
    return any(_normalise(f) and _normalise(f) in packed for f in families)


def classify(pulses: list[dict] | None, families: list[str]) -> str:
    """
    The coverage state for one indicator.

    None for `pulses` means the lookup failed. That is reported rather than
    folded into "absent", which would read a source that did not answer as a
    source reporting nothing.
    """
    if pulses is None:
        return "unknown"
    if not pulses:
        return "absent"
    return "attributed" if any(names_family(p, families) for p in pulses) else "unattributed"


def fetch_pulses(indicator: str, otx_type: str, exclude: str = "") -> list[dict] | None:
    """
    Pulses carrying one indicator, or None where the lookup did not answer.

    `exclude` drops a pulse by name, so re-running against an already published
    file does not count that file as its own prior coverage.
    """
    path = LOOKUP_PATH.get(otx_type)
    if not path:
        return None

    url = f"{BASE_URL}/{path}/{indicator}/general"
    try:
        response = get_with_retry(
            url, timeout=45, attempts=3, backoff=3.0, source="otx",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
        )
    except Exception:
        return None

    if response.status_code == 404:
        return []
    if response.status_code != 200:
        return None

    try:
        pulses = (response.json().get("pulse_info") or {}).get("pulses") or []
    except ValueError:
        return None

    return [p for p in pulses if not exclude or p.get("name") != exclude]


def report(path: str, families: list[str]) -> int:
    pulse = json.load(open(path, encoding="utf-8"))
    families = families or pulse.get("malware_families") or []
    indicators = pulse.get("indicators") or []
    own_name = pulse.get("name") or ""

    print(f"{path}: {len(indicators)} indicators, "
          f"family {families or ['(none declared)']}")
    if not families:
        print("  no family to match on, so every hit can only be counted, "
              "not weighed")

    states = {}
    print(f"\n{'indicator':<34}{'state':<14}{'pulses':>7}{'bulk':>6}  naming the family")
    for item in indicators:
        name = item.get("indicator", "")
        pulses = fetch_pulses(name, item.get("type", ""), exclude=own_name)
        state = classify(pulses, families)
        states[state] = states.get(state, 0) + 1

        count = "-" if pulses is None else len(pulses)
        bulk = "-" if pulses is None else sum(
            1 for p in pulses
            if (p.get("indicator_count") or 0) >= BULK_INDICATOR_COUNT
        )
        naming = "" if pulses is None else ", ".join(
            (p.get("name") or "?")[:28] for p in pulses if names_family(p, families)
        )
        print(f"{name[:33]:<34}{state:<14}{count:>7}{bulk:>6}  {naming}")
        time.sleep(0.25)

    print("\nsummary")
    for state in ("absent", "unattributed", "attributed", "unknown"):
        if states.get(state):
            print(f"  {state:<14}{states[state]:>4}")

    new_claim = states.get("absent", 0) + states.get("unattributed", 0)
    print(f"\n{new_claim} of {len(indicators)} carry no existing attribution to "
          f"{families or 'this family'}.")
    if states.get("unknown"):
        print(f"{states['unknown']} lookup(s) failed, so their coverage is "
              f"unestablished rather than clear.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pulse", help="pulse JSON file built by core.stix_exporter")
    parser.add_argument("--family", action="append", default=[],
                        help="family or alias to match; repeatable. Defaults to "
                             "the pulse's malware_families")
    args = parser.parse_args()
    return report(args.pulse, args.family)


if __name__ == "__main__":
    sys.exit(main())
