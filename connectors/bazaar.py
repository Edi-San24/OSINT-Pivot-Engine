# connectors/bazaar.py
# MalwareBazaar connector for the OSINT Pivot Engine.
# Queries file hashes for malware metadata, tags, and signatures.
# No API key required.

import requests
import logging
from config import MALWAREBAZAAR_API_KEY

logger = logging.getLogger(__name__)


class MalwareBazaarConnector:
    """
    Connector for the MalwareBazaar API.
    Supports hash lookups for malware metadata, tags, and signatures.
    No API key required — public endpoint.
    """

    BASE_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self):
        pass

    def __init__(self):
        self.headers = {
            "Auth-Key": MALWAREBAZAAR_API_KEY
        }

    def query_hash(self, hash: str) -> dict:
        """
        Queries MalwareBazaar for a given file hash.
        Returns malware metadata, tags, signatures, and delivery method.
        """
        try:
            response = requests.post(
                self.BASE_URL,
                data={"query": "get_info", "hash": hash},
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "ok":
                return {
                    "indicator": hash,
                    "type": "hash",
                    "source": "malwarebazaar",
                    "found": False,
                    "reason": data.get("query_status", "unknown")
                }

            info = data["data"][0]

            return {
                "indicator": hash,
                "type": "hash",
                "source": "malwarebazaar",
                "found": True,
                "file_name": info.get("file_name", "unknown"),
                "file_type": info.get("file_type", "unknown"),
                "malware_family": info.get("signature", None),
                "tags": info.get("tags", []),
                "delivery_method": info.get("delivery_method", "unknown"),
                "first_seen": info.get("first_seen", "unknown"),
                "last_seen": info.get("last_seen", "unknown"),
                "reporter": info.get("reporter", "unknown"),
            }

        except Exception as e:
            logger.error(f"MalwareBazaar query failed for '{hash}': {str(e)}")
            return {"error": str(e), "indicator": hash, "source": "malwarebazaar"}

    def query_filename(self, filename: str) -> dict:
        """
        Queries MalwareBazaar for samples matching a given filename.
        Returns related hashes, malware families, and metadata.
        """
        try:
            response = requests.post(
                self.BASE_URL,
                data={"query": "get_info", "filename": filename},
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "ok":
                return {
                    "indicator": filename,
                    "type": "filename",
                    "source": "malwarebazaar",
                    "found": False,
                    "reason": data.get("query_status", "unknown")
                }

            samples = data.get("data", [])[:10]

            return {
                "indicator": filename,
                "type": "filename",
                "source": "malwarebazaar",
                "found": True,
                "sample_count": len(samples),
                "samples": [
                    {
                        "md5": s.get("md5_hash", "unknown"),
                        "sha256": s.get("sha256_hash", "unknown"),
                        "malware_family": s.get("signature", "unknown"),
                        "tags": s.get("tags", []),
                        "first_seen": s.get("first_seen", "unknown"),
                        "delivery_method": s.get("delivery_method", "unknown"),
                    }
                    for s in samples
                ]
            }

        except Exception as e:
            logger.error(f"MalwareBazaar filename query failed for '{filename}': {str(e)}")
            return {"error": str(e), "indicator": filename, "source": "malwarebazaar"}

    def query_tag(self, tag: str) -> dict:
        """
        Queries MalwareBazaar for samples matching a given tag or malware family.
        Returns related hashes for pivot chaining.
        """
        try:
            response = requests.post(
                self.BASE_URL,
                data={"query": "get_taginfo", "tag": tag, "limit": 10},
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "ok":
                return {
                    "indicator": tag,
                    "type": "tag",
                    "source": "malwarebazaar",
                    "found": False,
                    "samples": []
                }

            samples = data.get("data", [])[:10]

            return {
                "indicator": tag,
                "type": "tag",
                "source": "malwarebazaar",
                "found": True,
                "sample_count": len(samples),
                "samples": [
                    {
                        "md5": s.get("md5_hash", "unknown"),
                        "sha256": s.get("sha256_hash", "unknown"),
                        "malware_family": s.get("signature", "unknown"),
                        "tags": s.get("tags", []),
                        "first_seen": s.get("first_seen", "unknown"),
                    }
                    for s in samples
                ]
            }

        except Exception as e:
            logger.error(f"MalwareBazaar tag query failed for '{tag}': {str(e)}")
            return {"error": str(e), "indicator": tag, "source": "malwarebazaar"}