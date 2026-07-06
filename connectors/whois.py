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
        Queries WHOIS for domain registration data
        Returns: registrar, creation date & nameservers 
        """
        try:
            w = whois.whois(domain)

            return {
                "indicator": domain,
                "type": "domain",
                "source": "whois",
                "registrar": w.get("registrar", "unknown"),
                "creation_date": str(w.get("creation_date", "unknown")),
                "expiration_date": str(w.get("expiration_date", "unknown")),
                "nameservers": w.get("name_servers", []),
                "country": w.get("country", "unknown"),
            }
        
        except Exception as e:
            return {"error": str(e), "indicator": domain, "source": "whois"}