# connectors/threatfox.py
# Queries abuse.ch ThreatFox for current IOC listings — malware family,
# threat type, confidence and whether the host is a compromised legitimate site.

import logging

import requests

from config import THREATFOX_API_KEY

logger = logging.getLogger(__name__)

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Entries kept per indicator. ThreatFox lists one row per port or path, so a
# single C2 address can carry several near-identical rows.
MAX_ENTRIES = 10


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
