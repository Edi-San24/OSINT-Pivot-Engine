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
            response = requests.get(url, headers=self.headers)
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
            return {"error": str(e), "indicator": ip, "source": "virustotal"}
        
    def query_domain(self, domain: str) -> dict:
        """
        Queries VT for a given domain.
        Returns normalized results or an error 
        """
        url = f"{self.BASE_URL}/domains/{domain}"

        try:
            response = requests.get(url, headers=self.headers)
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
        Queries VT for a given file hash.
        Returns normalized results or an error 
        """
        url = f"{self.BASE_URL}/files/{hash}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()

            attributes = data["data"]["attributes"]

            threat_classification = attributes.get("popular_threat_classification", {})
            malware_family = threat_classification.get("suggested_threat_label", None)

            return {
                "indicator": hash,
                "type": "hash",
                "source": "virustotal",
                "malicious_votes": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "harmless_votes": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "file_type": attributes.get("type_description", "unknown"),
                "file_name": attributes.get("meaningful_name", "unknown"),
                "malware_family": malware_family,
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": hash, "source": "virustotal"}

    def query_filename(self, filename: str) -> dict:
        """
        Searches VirusTotal for samples matching a given filename.
        Returns matching hashes, detection ratios, and malware families.
        """
        url = f"{self.BASE_URL}/intelligence/search"

        try:
            response = requests.get(
                url,
                headers=self.headers,
                params={"query": f"name:{filename}", "limit": 10},
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            samples = data.get("data", [])

            return {
                "indicator": filename,
                "type": "filename",
                "source": "virustotal",
                "found": len(samples) > 0,
                "sample_count": len(samples),
                "samples": [
                    {
                        "sha256": s.get("id", "unknown"),
                        "malware_family": s.get("attributes", {}).get("popular_threat_classification", {}).get("suggested_threat_label", "unknown"),
                        "malicious_votes": s.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                        "file_type": s.get("attributes", {}).get("type_description", "unknown"),
                        "file_name": s.get("attributes", {}).get("meaningful_name", "unknown"),
                    }
                    for s in samples
                ]
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e)[:200], "indicator": filename, "source": "virustotal"}
