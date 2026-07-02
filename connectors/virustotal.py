# connector/virustotal.py
# VirusTotal API connector for the OSINT agent
# Queries IP, domain, and hash indicators -- Returns a normalized JSON 

import requests
from config import VIRUSTOTAL_API_KEY, MAX_RESULTS_PER_SOURCE

class VirusTotalConnector:
    """
    Connector for the VirusTotal API.
    [Support]: IP, domain, and hash indicator lookups 
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.headers = {
            "x-apikey": self.api_key
        }

    def query_ip(self, ip: str) -> dict:
        """
        Queries VT for a given IP address.
        Returns normalized results or an error
        """
        url = f"{self.BASE_URL}/ip_addresses/{ip}"

        try:
            response = requests.get(url, headers = self.headers)
            response.raise_for_status()
            data = response.json()

            attributes = data["data"]["attributes"]

            return {
                "indicator": ip,
                "type": "ipv4",
                "source": "virustotal",
                "malicious_votes": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "harmless_votes": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "country": attributes.get("country", "unknown"),
                "owner": attributes.get("as_owner", "unknown"),
            }
        
        except requests.exceptions.RequestException as e:
            return{"error": str(e), "indicator": ip, "source": "virustotal"}
        
    def query_domain(self, domain: str) -> dict:
        """
        Queries VT for a given domain.
        Returns normalized results or an error 
        """
        url = f"{self.BASE_URL}/domains/{domain}"

        try:
            response = requests.get(url, headers = self.headers)
            response.raise_for_status()
            data = response.json()

            attributes = data["data"]["attributes"]

            return {
                "indicator": domain,
                "type": "domain",
                "source": "virustotal",
                "malicious_votes": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "harmless_votes": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "registrar": attributes.get("registrar", "unknown"),
                "creation_date": attributes.get("creation_date", "unknown"),
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": domain, "source": "virustotal"}

    def query_hash(self, hash: str) -> dict:
        """
        Queries VT for a given file hash
        Returns normalized results or an error 
        """
        url = f"{self.BASE_URL}/files/{hash}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()

            attributes = data["data"]["attributes"]

            return {
                "indicator": hash,
                "type": "hash",
                "source": "virustotal",
                "malicious_votes": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "harmless_votes": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "file_type": attributes.get("type_description", "unknown"),
                "file_name": attributes.get("meaningful_name", "unknown"),
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": hash, "source": "virustotal"}  
   
