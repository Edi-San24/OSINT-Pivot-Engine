# connectors/whois.py
# WHOIS connector for OSINT Pivot Engine 
# Queries domain registration data [no API key required]

import whois
from config import MAX_RESULTS_PER_SOURCE

class WHOISConnector:
    """
    Connector for WHOIS domain registration lookups.
    No API key required.
    """

    def __init__(self):
        pass

    def query_domain(self, domain: str) -> dict:
        """
        Queries WHOIS for domain registration data.
        Returns registrar, creation date and nameservers.
        """
        try:
            w = whois.whois(domain)

            def parse_date(val):
                if isinstance(val, list):
                    val = val[0]
                return str(val)[:10] if val else "unknown"

            return {
                "indicator": domain,
                "type": "domain",
                "source": "whois",
                "registrar": w.get("registrar", "unknown"),
                "creation_date": parse_date(w.get("creation_date")),
                "expiration_date": parse_date(w.get("expiration_date")),
                "nameservers": w.get("name_servers", []),
                "country": w.get("country", "unknown"),
            }

        except Exception as e:
            error_str = str(e)
            if "No match for" in error_str or "NOT FOUND" in error_str.upper():
                return {
                    "indicator": domain,
                    "type": "domain",
                    "source": "whois",
                    "registrar": "unknown",
                    "creation_date": "unknown",
                    "expiration_date": "unknown",
                    "nameservers": [],
                    "country": "unknown",
                    "note": "Domain not found in WHOIS registry — may be expired, deleted, or unregistered."
                }
            return {"error": error_str[:200], "indicator": domain, "source": "whois"}

       