# core/patterns.py
# Structural tests over a set of indicators: provisioning, purchase, and reuse.

"""
Questions about a set that no per-indicator lookup can answer.

A scorer asks whether one indicator is malicious. These ask whether a group of
them was built by one hand, which is a different claim and often the more
useful one: it decides whether a range can be published as a range, whether
names were bought in one transaction, and whether an operator's own
infrastructure can be told apart from the surface around it.

Every function returns absence as absence. An empty input yields an empty
result rather than an exception, and an undated or unparseable entry is skipped
rather than counted, since a detector that reports structure in missing data is
worse than one that reports nothing.
"""

import re
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

# Registrations closer together than this belong to one purchase. Bulk
# registration through one registrar lands within seconds; a minute is loose
# enough to absorb clock skew between a registry and whoever recorded it, and
# far tighter than any human buying names one at a time.
BATCH_WINDOW_SECONDS = 60

# An identifier must be at least this long before its recurrence means
# anything. Short tokens repeat by chance and across unrelated software.
MIN_IDENTIFIER_LENGTH = 16

# Tokens that carry no operator signal however often they recur.
IDENTIFIER_STOPWORDS = {"index", "default", "download", "wp-content", "wp-includes"}


def port_profile(pairs: list[tuple[str, int]]) -> dict:
    """
    Whether every host in the set exposes the same number of ports.

    A builder that opens a fixed number of listeners leaves that count on every
    host it provisions, which is a claim about the operator rather than about
    any one address. Distinct from the ports being equal: three hosts on three
    different ports each is still one recipe.

    `shared_ports` is the separate question of which ports recur across hosts,
    since a fleet on one port and a fleet on three private ones are both
    uniform but hunt differently.
    """
    by_host = defaultdict(set)
    for host, port in pairs:
        if host and port is not None:
            by_host[str(host)].add(int(port))

    if not by_host:
        return {"hosts": 0, "uniform": False, "ports_per_host": None,
                "shared_ports": [], "distribution": {}}

    counts = {host: len(ports) for host, ports in by_host.items()}
    distribution = defaultdict(int)
    for n in counts.values():
        distribution[n] += 1

    uniform = len(set(counts.values())) == 1
    shared = [port for port in {p for ports in by_host.values() for p in ports}
              if sum(port in ports for ports in by_host.values()) > 1]

    return {
        "hosts": len(by_host),
        "uniform": uniform,
        "ports_per_host": next(iter(set(counts.values()))) if uniform else None,
        "shared_ports": sorted(shared),
        "distribution": dict(sorted(distribution.items())),
    }


def _moment(value) -> datetime | None:
    """A timestamp from whatever shape a source recorded it in, or None."""
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00").replace(" UTC", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def registration_batches(entries: list[tuple[str, object]],
                         window: int = BATCH_WINDOW_SECONDS) -> list[dict]:
    """
    Names registered close enough together to be one purchase.

    Two domains sharing a creation timestamp to the second were bought in one
    transaction, which links them far more firmly than sharing a registrar or a
    nameserver: millions of names share those. A batch of one is not reported,
    since a single registration is what every domain has.

    Entries without a usable timestamp are dropped rather than grouped. Undated
    names would otherwise all collapse into one enormous false batch.
    """
    dated = []
    for name, value in entries:
        moment = _moment(value)
        if name and moment:
            dated.append((moment, str(name)))
    if not dated:
        return []

    dated.sort()
    batches = []
    run = [dated[0]]
    for moment, name in dated[1:]:
        if (moment - run[0][0]).total_seconds() <= window:
            run.append((moment, name))
        else:
            batches.append(run)
            run = [(moment, name)]
    batches.append(run)

    return [
        {
            "registered": run[0][0].isoformat(),
            "members": sorted(name for _, name in run),
            "span_seconds": int((run[-1][0] - run[0][0]).total_seconds()),
        }
        for run in batches if len(run) > 1
    ]


def shared_identifiers(urls: list[str],
                       min_length: int = MIN_IDENTIFIER_LENGTH) -> list[dict]:
    """
    Long path tokens that appear on more than one host.

    A campaign that stamps the same payload or campaign identifier across many
    hosts has linked them itself. That survives the hosts being unrelated in
    every other respect, which is the case where it is worth the most: shared
    hosting is circumstantial, a shared identifier is deliberate.

    Counted by distinct host, so one host repeating its own identifier is one
    host and not a link.
    """
    seen = defaultdict(set)
    for url in urls:
        parsed = urlparse(str(url))
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        tokens = re.split(r"[/?&=]+", f"{parsed.path}{parsed.query}")
        for token in tokens:
            token = token.strip()
            if (len(token) >= min_length
                    and token.lower() not in IDENTIFIER_STOPWORDS):
                seen[token].add(host)

    return sorted(
        ({"identifier": token, "hosts": len(hosts), "seen_on": sorted(hosts)}
         for token, hosts in seen.items() if len(hosts) > 1),
        key=lambda item: (-item["hosts"], item["identifier"]),
    )
