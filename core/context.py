# core/context.py
# Context layer that adjusts raw ML confidence scores
# based on known infrastructure patterns to reduce false positives.

import logging

logger = logging.getLogger(__name__)

# Known infrastructure patterns that reduce confidence
TOR_EXIT_PATTERNS = [
    "tor-exit", "torservers", "tor relay",
    "for-privacy.net", "torproject.org"
]

CDN_ASNS = {
    "cloudflare", "akamai", "fastly", "amazon",
    "google", "microsoft", "cdnetworks", "limelight"
}

SHARED_HOSTING_PATTERNS = [
    "plesk", "cpanel", "whm", "shared hosting",
    "bluehost", "godaddy", "hostgator"
]

def detect_infrastructure_type(pivot_result: dict) -> dict:
    """
    Analyzes pivot results to identify known infrastructure types that
    require confidence score adjustment.
    """
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

    # Check ASN for CDN providers
    censys = results.get("censys", {})
    asn = censys.get("autonomous_system", "").lower()
    shodan = results.get("shodan", {})
    org = shodan.get("organization", "").lower()

    for cdn in CDN_ASNS:
        if cdn in asn or cdn in org:
            context["is_cdn"] = True
            context["infrastructure_type"] = "cdn"
            context["confidence_modifier"] = -0.6
            logger.info("CDN infrastructure detected. Applying confidence modifier.")
            break

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
