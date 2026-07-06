# connectors/shodan.py
# Shodan connector for the OSINT Pivot Engine.
# Queries IP addresses for open ports, services, and banners.

import shodan
from config import SHODAN_API_KEY, MAX_RESULTS_PER_SOURCE

class ShodanConnector:
    """
    Connector for the Shodan API.
    Supports IP address lookups for open ports and services.
    """

    def __init__(self):
        self.api = shodan.Shodan(SHODAN_API_KEY)

    def query_ip(self, ip: str) -> dict:
        """
        Queries Shodan for a given IP Address.
        Returns open ports, services, and host info or error.
        """
        try:
            host = self.api.host(ip)

            return {
                "indicator": ip,
                "type": "ipv4",
                "source": "shodan",
                "organization": host.get("org", "unknown"),
                "country": host.get("country_name", "unknown"),
                "open_ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "tags": host.get("tags", []),
            }
        
        except shodan.APIError as e:
            return {"error": str(e), "indicator": ip, "source": "shodan"}