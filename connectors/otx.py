# connectors/otx.py
# Queries existing pulses for indicator enrichment from Alienvault OTX
# Submits new pulses after investigations 


import requests
import logging
 
logger = logging.getLogger(__name__)
 
from config import OTX_API_KEY
 
BASE_URL = "https://otx.alienvault.com/api/v1"
 
 
class OTXConnector:
    """
    Connector for AlienVault OTX.
    Read: enriches indicators with existing community pulse data.
    Write: publishes investigation findings as new pulses.
    """
 
    def __init__(self):
        self.headers = {
            "X-OTX-API-KEY": OTX_API_KEY,
            "Content-Type": "application/json"
        }
        logger.info("OTX connector initialized.")
 
    def query_indicator(self, indicator: str, indicator_type: str) -> dict:
        """
        Queries OTX for existing pulses related to an indicator.
        Surfaces community intelligence that other researchers have
        already published about this indicator.
 
        indicator_type options: IPv4, domain, hostname, URL,
        FileHash-MD5, FileHash-SHA1, FileHash-SHA256, email
        """
        try:
            # File hashes use /indicators/file/{hash}/general
            # All other types use /indicators/{type}/{indicator}/general
            if indicator_type.startswith("FileHash"):
                url = f"{BASE_URL}/indicators/file/{indicator}/general"
            else:
                url = f"{BASE_URL}/indicators/{indicator_type}/{indicator}/general"
 
            response = requests.get(
                url,
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()
 
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])[:5]
 
            return {
                "indicator": indicator,
                "type": indicator_type,
                "source": "otx",
                "pulse_count": pulse_info.get("count", 0),
                "pulses": [
                    {
                        "name": p.get("name", "unknown"),
                        "author": p.get("author_name", "unknown"),
                        "created": p.get("created", "unknown"),
                        "tags": p.get("tags", []),
                        "malware_families": p.get("malware_families", []),
                        "targeted_countries": p.get("targeted_countries", []),
                    }
                    for p in pulses
                ]
            }
 
        except Exception as e:
            logger.error(f"OTX query failed for '{indicator}': {str(e)[:100]}")
            return {"error": str(e), "indicator": indicator, "source": "otx"}
 
    def publish_pulse(self, title: str, description: str, indicators: list,
                      tags: list, malware_families: list, adversary: str = "",
                      targeted_countries: list = None) -> dict:
        """
        Publishes a new OTX pulse from investigation findings.
        Called after an investigation completes when --publish-otx flag is set.
 
        indicators format: [{"indicator": "1.2.3.4", "type": "IPv4"}, ...]
        """
        if targeted_countries is None:
            targeted_countries = []
 
        payload = {
            "name": title,
            "description": description,
            "public": 1,
            "TLP": "white",
            "tags": tags,
            "indicators": indicators,
            "malware_families": malware_families,
            "adversary": adversary,
            "targeted_countries": targeted_countries,
        }
 
        try:
            response = requests.post(
                f"{BASE_URL}/pulses/create",
                headers=self.headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
 
            return {
                "success": True,
                "pulse_id": data.get("id", "unknown"),
                "pulse_url": f"https://otx.alienvault.com/pulse/{data.get('id', '')}",
                "name": data.get("name", title),
            }
 
        except Exception as e:
            logger.error(f"OTX pulse creation failed: {str(e)[:100]}")
            return {"success": False, "error": str(e)}
 
