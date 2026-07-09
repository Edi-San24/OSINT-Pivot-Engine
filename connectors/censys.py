# connectors: censys.py
# Performs the following: Queries IP addresses for host & certificate data. 

import requests
from config import CENSYS_API_KEY, MAX_RESULTS_PER_SOURCE

class CensysConnector:
    """
    Connector for the Censys Platform API.
    Supports IP address lookups for host data and open services.
    """

    BASE_URL = "https://api.platform.censys.io/v3/global"

    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {CENSYS_API_KEY}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json"
        }

    def query_ip(self, ip: str) -> dict:
        """
        Queries Censys for a given IP address.
        Returns host data, open ports, and services or an error dict.
        """
        url = f"{self.BASE_URL}/asset/host/{ip}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()

            resource = data.get("result", {}).get("resource", {})
            services = resource.get("services", [])[:MAX_RESULTS_PER_SOURCE]

            return {
                "indicator": ip,
                "type": "ipv4",
                "source": "censys",
                "autonomous_system": resource.get("autonomous_system", {}).get("name", "unknown"),
                "country": resource.get("location", {}).get("country", "unknown"),
                "open_ports": [s.get("port") for s in services],
                "services": [
                    {
                        "port": s.get("port", "unknown"),
                        "service_name": s.get("protocol", "unknown"),
                        "transport": s.get("transport_protocol", "unknown"),
                    }
                    for s in services
                ]
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": ip, "source": "censys"}