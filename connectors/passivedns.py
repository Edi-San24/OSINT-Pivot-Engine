# connectors/passivedns.py
# PassiveDNS connector for the OSINT Pivot Engine.
# Queries historical DNS records using the public PDNS API. 

import requests
from config import MAX_RESULTS_PER_SOURCE

class PassiveDNSConnector:
    """
    Connector for the PassiveDNS public API.
    Supports domain and IP lookups for historical DNS records.
    """

    BASE_URL = "https://api.mnemonic.no/pdns/v3"

    def __init__(self):
        self.headers = {
            "Accept": "application/json"
        }
    
    def query_domain(self, domain: str) -> dict:
        """
        Queries PassiveDNS for historical DNS records for a domain.
        Returns resolved IPs and record types or an error dict.
        """
        url = f"{self.BASE_URL}/{domain}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()

            records = data.get("data", [])[:MAX_RESULTS_PER_SOURCE]

            return {
                "indicator": domain,
                "type": "domain",
                "source": "passivedns",
                "record_count": len(records),
                "records": [
                    {
                        "ip": r.get("answer", "unknown"),
                        "record_type": r.get("rrtype", "unknown"),
                        "first_seen": r.get("firstSeenTimestamp", "unknown"),
                        "last_seen": r.get("lastSeenTimestamp", "unknown"),
                    }
                    for r in records
                ]
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": domain, "source": "passivedns"}
        
    def query_ip(self, ip: str) -> dict:
        """
        Queries PassiveDNS for historical DNS records for an IP.
        Returns domains that have resolved to this IP or an error dict.
        """
        url = f"{self.BASE_URL}/{ip}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()

            records = data.get("data", [])[:MAX_RESULTS_PER_SOURCE]

            return {
                "indicator": ip,
                "type": "ipv4",
                "source": "passivedns",
                "record_count": len(records),
                "records": [
                    {
                        "domain": r.get("query", "unknown"),
                        "record_type": r.get("rrtype", "unknown"),
                        "first_seen": r.get("firstSeenTimestamp", "unknown"),
                        "last_seen": r.get("lastSeenTimestamp", "unknown"),
                    }
                    for r in records
                ]
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": ip, "source": "passivedns"}