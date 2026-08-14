# connectors/urlhaus.py
# Queries malicious URLS associated with malware families 

import requests
import logging

logger = logging.getLogger(__name__)

from config import MALWAREBAZAAR_API_KEY

BASE_URL = "https://urlhaus-api.abuse.ch/v1"


class URLhausConnector:
    """
    Connector for the URLhaus API.
    Surfaces malicious URLs, delivery infrastructure, and
    hosting details for malware families and seed indicators.
    Supports host and malware family lookups.
    """

    def __init__(self):
        self.headers = {
            "Auth-Key": MALWAREBAZAAR_API_KEY
        }
        logger.info("URLhaus connector initialized.")

    def query_host(self, host: str) -> dict:
        """
        Queries URLhaus for malicious URLs associated with a host.
        Host can be an IP address or domain.
        Returns associated URLs, malware families, and status.
        """
        try:
            response = requests.post(
                f"{BASE_URL}/host/",
                data={"host": host},
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "is_host":
                return {
                    "indicator": host,
                    "type": "host",
                    "source": "urlhaus",
                    "found": False,
                    "reason": data.get("query_status", "unknown")
                }

            urls = data.get("urls", [])[:10]

            return {
                "indicator": host,
                "type": "host",
                "source": "urlhaus",
                "found": True,
                "url_count": data.get("url_count", 0),
                "blacklists": data.get("blacklists", {}),
                "urls": [
                    {
                        "url": u.get("url", "unknown"),
                        "status": u.get("url_status", "unknown"),
                        "malware_family": u.get("tags", []),
                        "date_added": u.get("date_added", "unknown"),
                    }
                    for u in urls
                ]
            }

        except Exception as e:
            logger.error(f"URLhaus host query failed for '{host}': {str(e)[:100]}")
            return {"error": str(e), "indicator": host, "source": "urlhaus"}

    def query_malware_family(self, family: str) -> dict:
        """
        Queries URLhaus for URLs associated with a malware family name.
        Surfaces active delivery infrastructure for known malware families.
        Primary use: called after MalwareBazaar identifies a malware family
        to surface the URLs used to distribute that family in the wild.
        """
        try:
            response = requests.post(
                f"{BASE_URL}/tag/",
                data={"tag": family},
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "is_tag":
                return {
                    "indicator": family,
                    "type": "malware_family",
                    "source": "urlhaus",
                    "found": False,
                    "reason": data.get("query_status", "unknown")
                }

            urls = data.get("urls", [])[:10]

            return {
                "indicator": family,
                "type": "malware_family",
                "source": "urlhaus",
                "found": True,
                "url_count": len(urls),
                "urls": [
                    {
                        "url": u.get("url", "unknown"),
                        "status": u.get("url_status", "unknown"),
                        "host": u.get("host", "unknown"),
                        "date_added": u.get("date_added", "unknown"),
                        "reporter": u.get("reporter", "unknown"),
                    }
                    for u in urls
                ]
            }

        except Exception as e:
            logger.error(f"URLhaus family query failed for '{family}': {str(e)[:100]}")
            return {"error": str(e), "indicator": family, "source": "urlhaus"}

    