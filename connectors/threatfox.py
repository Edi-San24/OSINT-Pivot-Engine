# connectors/threatfox.py
# Queries abuse.ch ThreatFox for IOC listings, one indicator at a time or a
# whole cluster by tag or malware family.

import logging

import requests

from config import THREATFOX_API_KEY

logger = logging.getLogger(__name__)

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Entries kept per indicator. ThreatFox lists one row per port or path, so a
# single C2 address can carry several near-identical rows.
MAX_ENTRIES = 10

# Rows kept per cluster query. A tag or a family can carry thousands, and what
# these queries are for is the shape of the set, not every member of it.
MAX_CLUSTER_ENTRIES = 500


def _is_exact(ioc: str, indicator: str) -> bool:
    """
    Whether a returned row is actually about the indicator.

    search_ioc matches substrings, so querying example.com returns
    test-nonexistent-domain-12345.example.com — a different host that merely
    contains the term. Reporting that would invent a finding against an innocent
    domain, so a row is kept only on an exact match or on the ip:port form
    ThreatFox uses for C2 addresses.
    """
    ioc = (ioc or "").strip().lower()
    indicator = (indicator or "").strip().lower()
    if ioc == indicator:
        return True
    return ioc.rsplit(":", 1)[0] == indicator


class ThreatFoxConnector:
    """
    Connector for the abuse.ch ThreatFox API.

    Fills a gap the other free sources leave: an address can be a
    confidence-100 Cobalt Strike C2 on ThreatFox while VirusTotal shows three
    detections and OTX shows nothing, which reads as unremarkable.
    """

    def __init__(self):
        self.headers = {"Auth-Key": THREATFOX_API_KEY} if THREATFOX_API_KEY else {}
        logger.info("ThreatFox connector initialized.")

    def query_indicator(self, indicator: str, indicator_type: str = "") -> dict:
        """
        Looks up one indicator. Returns listing details, or found=False when
        ThreatFox has no record of it.
        """
        base = {"indicator": indicator, "type": indicator_type, "source": "threatfox"}

        if not THREATFOX_API_KEY:
            # An absent key is an unanswered question, not a clean result. Saying
            # found=False here would report "ThreatFox has nothing on this".
            return {**base, "error": "No THREATFOX_API_KEY configured."}

        try:
            response = requests.post(
                BASE_URL,
                json={"query": "search_ioc", "search_term": indicator},
                headers=self.headers,
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as e:
            return {**base, "error": str(e)}
        except ValueError as e:
            return {**base, "error": f"Malformed response: {e}"}

        status = payload.get("query_status")
        if status == "no_result":
            return {**base, "found": False, "entry_count": 0}
        if status != "ok":
            # Covers unauthorized and illegal_search_term, which arrive as 200.
            return {**base, "error": f"query_status {status!r}"}

        rows = payload.get("data") or []
        exact = [r for r in rows if _is_exact(r.get("ioc"), indicator)]
        discarded = len(rows) - len(exact)

        if not exact:
            return {
                **base,
                "found": False,
                "entry_count": 0,
                # Surfaced rather than dropped: a non-zero count here means
                # ThreatFox knows something nearby, which is worth an analyst's
                # attention even though it is not this indicator.
                "partial_matches_discarded": discarded,
            }

        entries = exact[:MAX_ENTRIES]
        families = sorted({r.get("malware_printable") or r.get("malware")
                           for r in entries if r.get("malware_printable") or r.get("malware")})
        threat_types = sorted({r.get("threat_type") for r in entries if r.get("threat_type")})
        tags = sorted({t for r in entries for t in (r.get("tags") or [])})
        confidences = [r.get("confidence_level") or 0 for r in entries]

        first_seen = sorted([r["first_seen"] for r in entries if r.get("first_seen")])
        last_seen = sorted([r["last_seen"] for r in entries if r.get("last_seen")])

        return {
            **base,
            "found": True,
            "entry_count": len(exact),
            "malware_families": families,
            "threat_types": threat_types,
            "max_confidence": max(confidences) if confidences else 0,
            "tags": tags,
            "reporters": sorted({r.get("reporter") for r in entries if r.get("reporter")}),
            # ThreatFox's own call on whether this is a compromised legitimate
            # host rather than attacker-owned. The scoring model reads
            # infrastructure shape and cannot tell those apart, so this is the
            # only source here that answers it directly.
            "is_compromised": any(r.get("is_compromised") for r in entries),
            "first_seen": first_seen[0] if first_seen else "unknown",
            "last_seen": last_seen[-1] if last_seen else "unknown",
            "references": [r["reference"] for r in entries if r.get("reference")][:5],
            "partial_matches_discarded": discarded,
        }

    def _cluster(self, query: str, field: str, value: str, limit: int) -> dict:
        """
        Shared body for the tag and family queries, which differ only in the
        request key and return the same row shape.
        """
        base = {"indicator": value, "type": query, "source": "threatfox"}

        if not THREATFOX_API_KEY:
            return {**base, "error": "No THREATFOX_API_KEY configured."}

        try:
            response = requests.post(
                BASE_URL,
                json={"query": query, field: value, "limit": limit},
                headers=self.headers,
                timeout=45,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as e:
            return {**base, "error": str(e)}
        except ValueError as e:
            return {**base, "error": f"Malformed response: {e}"}

        status = payload.get("query_status")
        if status == "no_result":
            return {**base, "found": False, "entry_count": 0, "hosts": []}
        if status != "ok":
            return {**base, "error": f"query_status {status!r}"}

        rows = payload.get("data") or []
        if not isinstance(rows, list):
            return {**base, "error": "query returned no row list"}
        entries = rows[:MAX_CLUSTER_ENTRIES]

        # C2 rows arrive as host:port, and every connector downstream wants the
        # host. Split here so a caller can pivot without re-parsing, and count
        # unique hosts separately: one address commonly carries several rows.
        hosts, seen = [], set()
        for row in entries:
            ioc = (row.get("ioc") or "").strip()
            if not ioc:
                continue
            host, _, port = ioc.rpartition(":")
            # A colon left in the host means this was an IPv6 address rather
            # than a host:port, unless it came bracketed. Splitting 2001:db8::1
            # on the last colon yields host 2001:db8: and port 1, which is a
            # queryable-looking address that is not the one listed.
            if not host or not port.isdigit() or (":" in host and not host.startswith("[")):
                host, port = ioc, ""
            host = host.strip("[]")
            if host not in seen:
                seen.add(host)
                hosts.append({
                    "host": host,
                    "port": port,
                    "malware_family": row.get("malware_printable") or row.get("malware"),
                    "threat_type": row.get("threat_type"),
                    "confidence": row.get("confidence_level"),
                    "first_seen": row.get("first_seen"),
                    "reporter": row.get("reporter"),
                    "is_compromised": row.get("is_compromised"),
                })

        families, reporters, threat_types = {}, {}, set()
        for row in entries:
            name = row.get("malware_printable") or row.get("malware")
            if name:
                families[name] = families.get(name, 0) + 1
            who = row.get("reporter")
            if who:
                reporters[who] = reporters.get(who, 0) + 1
            if row.get("threat_type"):
                threat_types.add(row["threat_type"])

        first_seen = sorted(r["first_seen"] for r in entries if r.get("first_seen"))

        return {
            **base,
            "found": bool(hosts),
            "entry_count": len(rows),
            "truncated": len(rows) > MAX_CLUSTER_ENTRIES,
            "unique_hosts": len(hosts),
            "hosts": hosts,
            "malware_families": dict(sorted(families.items(), key=lambda kv: -kv[1])),
            "threat_types": sorted(threat_types),
            # Who reported the set, and how much each contributed. A tag can be
            # one hunter's batch label rather than an actor cluster: erebus-v14
            # returned 39 rows across Cobalt Strike, Meterpreter and Sliver, all
            # from one reporter, which is a detection method and not a campaign.
            # A caller treating that as an actor cluster would be wrong, and the
            # only way to see it is the reporter spread.
            "reporters": dict(sorted(reporters.items(), key=lambda kv: -kv[1])),
            "first_seen": first_seen[0] if first_seen else "unknown",
            "last_seen": first_seen[-1] if first_seen else "unknown",
            # ThreatFox's own compromised flag, aggregated. Read it as a floor
            # and never as a clearance: all 64 rows under nation-state-hunter
            # carried False, including an address whose passive DNS showed eight
            # unbroken years of mail service on the same host.
            "flagged_compromised": sum(1 for h in hosts if h.get("is_compromised")),
        }

    def query_tag(self, tag: str, limit: int = 1000) -> dict:
        """
        Every IOC carrying a tag. Reaches a cluster rather than a single row,
        which is what a tag is for.
        """
        return self._cluster("taginfo", "tag", tag, limit)

    def query_malware(self, family: str, limit: int = 1000) -> dict:
        """
        Every IOC attributed to a malware family, by ThreatFox's own name for
        it, such as "Cobalt Strike" or a "win.redline_stealer" style id.
        """
        return self._cluster("malwareinfo", "malware", family, limit)
