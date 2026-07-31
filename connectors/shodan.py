import requests
import logging

logger = logging.getLogger(__name__)

class ShodanConnector:
    """
    Connector for Shodan InternetDB.
    Free endpoint — no API key or query credits required.
    Supports IP address lookups for open ports, hostnames, tags, and CVEs.
    """

    BASE_URL = "https://internetdb.shodan.io"

    def __init__(self):
        pass

    def query_ip(self, ip: str) -> dict:
        """
        Queries Shodan InternetDB for a given IP address.
        Returns open ports, hostnames, tags, and known CVEs.
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/{ip}",
                timeout=10
            )

            if response.status_code == 404:
                return {
                    "indicator": ip,
                    "type": "ipv4",
                    "source": "shodan",
                    "open_ports": [],
                    "hostnames": [],
                    "tags": [],
                    "cves": [],
                    "note": "No data found for this IP."
                }

            response.raise_for_status()
            data = response.json()

            return {
                "indicator": ip,
                "type": "ipv4",
                "source": "shodan",
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
                "cves": data.get("vulns", []),
            }

        except Exception as e:
            logger.error(f"Shodan InternetDB query failed for '{ip}': {str(e)[:100]}")
            return {"error": str(e), "indicator": ip, "source": "shodan"}