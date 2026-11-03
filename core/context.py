# core/context.py
# Context layer that adjusts raw ML confidence scores
# based on known infrastructure patterns to reduce false positives.

import logging

from core.risk import is_cdn_edge

logger = logging.getLogger(__name__)

# Known infrastructure patterns that reduce confidence
TOR_EXIT_PATTERNS = [
    "tor-exit", "torservers", "tor relay",
    "for-privacy.net", "torproject.org"
]

SHARED_HOSTING_PATTERNS = [
    "plesk", "cpanel", "whm", "shared hosting",
    "bluehost", "godaddy", "hostgator"
]

def detect_infrastructure_type(pivot_result: dict) -> dict:
    """
    Analyzes pivot results to identify known infrastructure types that
    require confidence score adjustment.
    """
    if pivot_result.get("type") in {"hash", "md5", "sha1", "sha256"}:
        return {
        "is_tor_exit": False,
        "is_cdn": False,
        "is_shared_hosting": False,
        "infrastructure_type": "malware_sample",
        "confidence_modifier": 0.0
    }
    results = pivot_result.get("results", {})
    context = {
        "is_tor_exit": False,
        "is_cdn": False,
        "is_shared_hosting": False,
        "infrastructure_type": "unknown",
        "confidence_modifier": 0.0
    }

    # Check PassiveDNS records for Tor patterns
    passivedns = results.get("passivedns", {})
    records = passivedns.get("records", [])
    for record in records:
        domain = record.get("domain", "").lower()
        for pattern in TOR_EXIT_PATTERNS:
            if pattern in domain:
                context["is_tor_exit"] = True
                context["infrastructure_type"] = "tor_exit_node"
                context["confidence_modifier"] = -0.4
                logger.info("Tor exit node detected. Applying confidence modifier.")
                break

    # Matched on the address, not the provider name. A provider that also sells
    # cloud servers names its single-tenant machines and its shared edge alike.
    if pivot_result.get("type") == "ipv4" and is_cdn_edge(pivot_result.get("indicator", "")):
        context["is_cdn"] = True
        context["infrastructure_type"] = "cdn"
        context["confidence_modifier"] = -0.6
        logger.info("CDN edge address detected. Applying confidence modifier.")

    censys = results.get("censys", {})
    asn = censys.get("autonomous_system", "").lower()

    # Check for shared hosting patterns
    vt = results.get("virustotal", {})
    owner = vt.get("owner", "").lower()
    for pattern in SHARED_HOSTING_PATTERNS:
        if pattern in owner or pattern in asn:
            context["is_shared_hosting"] = True
            context["infrastructure_type"] = "shared_hosting"
            context["confidence_modifier"] = -0.3
            logger.info("Shared hosting detected. Applying confidence modifier.")
            break

    return context
