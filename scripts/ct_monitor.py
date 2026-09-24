# scripts/ct_monitor.py
# Watches certificate transparency for names matching a pattern, and reports
# only what is new since the last run.

"""
Certificate transparency monitor.

Every other pivot here queries a corpus that has already been crawled, so none
of them sees infrastructure stood up yesterday: coverage of a freshly
registered cohort climbs over months. A certificate reaches the public logs
within minutes of issuance, which is the lag this closes.

It is also the only source that sees subdomain impersonation. An actor placing
branding under a generic domain registers nothing, so there is no creation
date, no registrar and no new domain for another pivot to match. The
certificate is the one artefact the technique cannot avoid producing.

    PYTHONPATH=. python scripts/ct_monitor.py '%.example.com'
    PYTHONPATH=. python scripts/ct_monitor.py '%-vendor.com' '%product%'
    PYTHONPATH=. python scripts/ct_monitor.py '%.example.com' --since 2026-02-18

A first run establishes a baseline and reports nothing as new, which is stated
rather than printed as a count of zero. A run whose lookup fails leaves the
baseline untouched and is reported as a failure, so the next successful run
still shows the full delta rather than silently swallowing it.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

from connectors.retry import get_with_retry

CRTSH_URL = "https://crt.sh/"
DEFAULT_STATE = "data/ct_seen.json"

# crt.sh answers a wildcard query slowly and fails often, so this is generous.
REQUEST_TIMEOUT = 120


def _names(cert: dict) -> set[str]:
    """
    Every name on one certificate, lowercased. `name_value` is newline separated.

    A leading `*.` is kept rather than trimmed. A wildcard certificate is why
    the subdomains beneath a name never reach these logs, so collapsing
    `*.example.com` onto `example.com` would hide the fact worth reporting:
    the holder can serve any name under it without issuing anything further.
    """
    raw = cert.get("name_value") or ""
    return {n.strip().lower() for n in raw.splitlines() if n.strip()}


def fetch(pattern: str) -> list[dict] | None:
    """
    Certificates matching a crt.sh pattern, or None where the lookup failed.

    None rather than an empty list on failure: a gateway error has not
    established that nothing new was issued, and reporting it as no new names
    is the difference between a quiet day and a blind one.
    """
    try:
        response = get_with_retry(
            CRTSH_URL, timeout=REQUEST_TIMEOUT, attempts=3, backoff=5.0,
            source="crt.sh", params={"q": pattern, "output": "json"},
        )
    except Exception as exc:
        print(f"  lookup failed: {type(exc).__name__} {str(exc)[:80]}")
        return None

    if response.status_code == 404:
        return []
    if response.status_code != 200:
        print(f"  lookup failed: HTTP {response.status_code}")
        return None
    try:
        return response.json()
    except ValueError:
        # crt.sh serves an HTML error page with a 200 when it is unwell.
        print("  lookup failed: response was not JSON")
        return None


def load_state(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        print(f"  state file {path} unreadable, treating as a first run")
        return {}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)


def report(patterns: list[str], state_path: str, since: str = "") -> int:
    state = load_state(state_path)
    failures, new_total = [], 0

    for pattern in patterns:
        print(f"\n[{pattern}]")
        certs = fetch(pattern)
        if certs is None:
            failures.append(pattern)
            continue

        # Earliest issuance per name, so a name can be reported with the date
        # its certificate was actually logged rather than the date it was seen.
        first_seen = {}
        for cert in certs:
            not_before = (cert.get("not_before") or "")[:10]
            for name in _names(cert):
                if name not in first_seen or not_before < first_seen[name]:
                    first_seen[name] = not_before

        if since:
            first_seen = {n: d for n, d in first_seen.items() if d >= since}

        known = set(state.get(pattern, {}).get("names") or [])
        fresh = sorted(set(first_seen) - known)

        if not known:
            print(f"  baseline established: {len(first_seen)} name(s) recorded")
            print("  nothing reported as new, because nothing was known before")
        elif fresh:
            new_total += len(fresh)
            print(f"  {len(fresh)} new name(s) since the last run:")
            for name in sorted(fresh, key=lambda n: (first_seen[n], n), reverse=True):
                print(f"     {first_seen[name]}  {name}")
        else:
            print(f"  no new names, {len(first_seen)} still matching")

        state[pattern] = {
            "names": sorted(set(first_seen) | known),
            "last_run": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "matched": len(first_seen),
        }
        time.sleep(1.0)

    save_state(state_path, state)
    print(f"\nstate written to {state_path}")
    if new_total:
        print(f"{new_total} new name(s) across {len(patterns) - len(failures)} pattern(s)")
    if failures:
        # Named rather than counted, since the point is which question went
        # unanswered rather than how many did.
        print(f"{len(failures)} pattern(s) did not answer and were left unchanged: "
              f"{', '.join(failures)}")
        print("Their coverage is unestablished, not clear. Re-run before trusting a quiet result.")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("patterns", nargs="+", metavar="PATTERN",
                        help="crt.sh query, %% is the wildcard, e.g. '%%-okta.com'")
    parser.add_argument("--state", default=DEFAULT_STATE,
                        help=f"where the seen-names baseline lives (default {DEFAULT_STATE})")
    parser.add_argument("--since", default="",
                        help="only names whose certificate was issued on or after "
                             "this date, YYYY-MM-DD")
    args = parser.parse_args()
    return report(args.patterns, args.state, args.since)


if __name__ == "__main__":
    sys.exit(main())
