# connectors/urlhaus.py
# Queries malicious URLS associated with malware families 

import requests
import logging

logger = logging.getLogger(__name__)

from config import MALWAREBAZAAR_API_KEY

BASE_URL = "https://urlhaus-api.abuse.ch/v1"

# URLhaus returns up to 1000 entries oldest-first, and we only keep a handful.
# Taking the first N straight off the response yields long-dead infrastructure,
# so live URLs get sorted to the front before truncating. Costs nothing extra:
# the whole list is already in the response.
URL_PAYLOAD_LIMIT = 10


def _online_first(urls: list) -> list:
    """Stable sort putting currently-online URLs ahead of offline ones."""
    return sorted(urls, key=lambda u: u.get("url_status") != "online")


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

    def query_url(self, url: str) -> dict:
        """
        Queries URLhaus for one exact URL.
        Distinct from query_host: a host may be clean while a specific path on
        it is a reported payload URL, and vice versa.
        """
        try:
            response = requests.post(
                f"{BASE_URL}/url/",
                data={"url": url},
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "ok":
                return {
                    "indicator": url,
                    "type": "url",
                    "source": "urlhaus",
                    "found": False,
                    "reason": data.get("query_status", "unknown")
                }

            payloads = data.get("payloads") or []
            return {
                "indicator": url,
                "type": "url",
                "source": "urlhaus",
                "found": True,
                "url_status": data.get("url_status", "unknown"),
                "threat": data.get("threat", "unknown"),
                "host": data.get("host", "unknown"),
                "date_added": data.get("date_added", "unknown"),
                "reporter": data.get("reporter", "unknown"),
                "tags": data.get("tags") or [],
                "blacklists": data.get("blacklists") or {},
                "reference": data.get("urlhaus_reference", ""),
                # Sample hashes served from this URL. Chained by core.agent, so
                # a URL seed can reach the payload it delivered.
                "payloads": [
                    {
                        "sha256": pl.get("response_sha256", ""),
                        "md5": pl.get("response_md5", ""),
                        "file_type": pl.get("file_type", ""),
                        "signature": pl.get("signature", ""),
                    }
                    for pl in payloads[:URL_PAYLOAD_LIMIT]
                ],
            }

        except Exception as e:
            return {"error": str(e)[:200], "indicator": url, "source": "urlhaus"}

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

            # URLhaus answers "ok" on success and "no_results" when it has
            # nothing. It does not return "is_host".
            if data.get("query_status") != "ok":
                return {
                    "indicator": host,
                    "type": "host",
                    "source": "urlhaus",
                    "found": False,
                    "reason": data.get("query_status", "unknown")
                }

            all_urls = data.get("urls", []) or []
            urls = _online_first(all_urls)[:URL_PAYLOAD_LIMIT]

            return {
                "indicator": host,
                "type": "host",
                "source": "urlhaus",
                "found": True,
                "url_count": data.get("url_count", 0),
                "online_count": sum(1 for u in all_urls if u.get("url_status") == "online"),
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

            # Same as query_host: "ok" on success, "no_results" when empty.
            if data.get("query_status") != "ok":
                return {
                    "indicator": family,
                    "type": "malware_family",
                    "source": "urlhaus",
                    "found": False,
                    "reason": data.get("query_status", "unknown")
                }

            all_urls = data.get("urls", []) or []
            urls = _online_first(all_urls)[:URL_PAYLOAD_LIMIT]

            return {
                "indicator": family,
                "type": "malware_family",
                "source": "urlhaus",
                "found": True,
                "url_count": len(all_urls),
                "online_count": sum(1 for u in all_urls if u.get("url_status") == "online"),
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

    