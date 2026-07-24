# Pivot chain executor 
# Routes seed indicators to the correct connectors and returns
# a normalized result across all sources. 

import time 
import logging

from config import MAX_PIVOT_DEPTH, MAX_RESULTS_PER_SOURCE
from core.detector import detect_type
from connectors.virustotal import VirusTotalConnector
from connectors.shodan import ShodanConnector
from connectors.censys import CensysConnector
from connectors.whois import WHOISConnector
from connectors.passivedns import PassiveDNSConnector
from connectors.onion import OnionConnector
from connectors.mitre import MITREConnector
from connectors.bazaar import MalwareBazaarConnector

# Logging configuration
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

RATE_LIMIT_DELAY = 1.0
REQUEST_TIMEOUT = 10
ALLOWED_TYPES = {"ipv4", "domain", "md5", "sha1", "sha256", "email", "username", "threat_group"}

class PivotExecutor:
    """
    Routes seed indicators to the correct connectors &
    returns a unified result across all sources. 
    """

    def __init__(self):
        self.vt = VirusTotalConnector()
        self.shodan = ShodanConnector()
        self.whois = WHOISConnector()
        self.passivedns = PassiveDNSConnector()
        self.censys = CensysConnector()
        self.ahmia = OnionConnector()
        self.mitre = MITREConnector()
        self.bazaar = MalwareBazaarConnector()
        logger.info("Pivot initialized!")

    def validate(self, seed: str) -> dict:
        seed = seed.strip()
        if not seed:
            return {"valid": False, "reason": "Seed indicator is empty..."}
        if len(seed) > 512:
            return {"valid": False, "reason": "Seed indicator too long..."}
        result = detect_type(seed)
        if not result:
            return {"valid": False, "reason": "Could not detect indicator type."}
        if result["type"] not in ALLOWED_TYPES:
            return {"valid": False, "reason": f"Unknown indicator type: {result['type']}"}
        return {"valid": True, "indicator": seed, "type": result["type"]}

    def _rate_limit(self):
        time.sleep(RATE_LIMIT_DELAY)

    def pivot_ip(self, ip: str) -> dict:
        logger.info(f"Starting IP pivot for: {ip[:50]}")
        results = {}
        try:
            results["virustotal"] = self.vt.query_ip(ip)
            self._rate_limit()
            results["shodan"] = self.shodan.query_ip(ip)
            self._rate_limit()
            results["passivedns"] = self.passivedns.query_ip(ip)
            self._rate_limit()
            results["censys"] = self.censys.query_ip(ip)
            results["ahmia"] = self.ahmia.search(ip)
            self._rate_limit()
        except Exception as e:
            logger.error(f"Error during IP pivot: {str(e)[:100]}")
        return {"indicator": ip, "type": "ipv4", "results": results}

    def pivot_domain(self, domain: str) -> dict:
        logger.info(f"Starting domain pivot for: {domain[:50]}")
        results = {}
        try:
            results["virustotal"] = self.vt.query_domain(domain)
            self._rate_limit()
            results["whois"] = self.whois.query_domain(domain)
            self._rate_limit()
            results["passivedns"] = self.passivedns.query_domain(domain)
            self._rate_limit()
            results["censys"] = self.censys.query_domain_certificates(domain)
            self._rate_limit()
            results["ahmia"] = self.ahmia.search(domain)
            self._rate_limit()
        except Exception as e:
            logger.error(f"Error during domain pivot: {str(e)[:100]}")
        return {"indicator": domain, "type": "domain", "results": results}

    def pivot_hash(self, hash: str) -> dict:
        """
        Runs all relevant connectors for a file hash indicator.
        Queries VirusTotal and MalwareBazaar for detections, then enriches
        with MITRE ATT&CK TTP data and related samples by malware family tag.
        """
        logger.info(f"Starting hash pivot for: {hash[:50]}")
        results = {}

        try:
            logger.info("Querying VirusTotal...")
            vt_result = self.vt.query_hash(hash)
            results["virustotal"] = vt_result
            self._rate_limit()

            logger.info("Querying MalwareBazaar...")
            bazaar_result = self.bazaar.query_hash(hash)
            results["malwarebazaar"] = bazaar_result
            self._rate_limit()

            malware_tag = bazaar_result.get("malware_family") if isinstance(bazaar_result, dict) else None
            if malware_tag and bazaar_result.get("found"):
                logger.info(f"Querying MalwareBazaar for related samples by tag: {malware_tag}")
                results["malwarebazaar_related"] = self.bazaar.query_tag(malware_tag)
                self._rate_limit()

            malware_name = vt_result.get("malware_family") if isinstance(vt_result, dict) else None

            if malware_name and "error" not in vt_result:
                logger.info(f"Querying MITRE ATT&CK for software: {malware_name}")
                results["mitre"] = self.mitre.query_software(malware_name)
            else:
                logger.info("No malware family from VT — skipping MITRE lookup.")
                results["mitre"] = {
                    "source": "mitre_attack",
                    "skipped": True,
                    "reason": "No malware family name available from VirusTotal result."
                }

        except Exception as e:
            logger.error(f"Error during hash pivot: {str(e)[:100]}")

        return {
            "indicator": hash,
            "type": "hash",
            "results": results
        }
    
    def pivot_group(self, group_name: str) -> dict:
        """
        Looks up a threat group by name in MITRE ATT&CK.
        Returns associated techniques, software, and group metadata. 
        """
        logger.info(f"Starting threat group pivot for: {group_name}")
        results = {}

        try:
            logger.info("Querying MITRE ATT&CK...")
            results["mitre"] = self.mitre.query_group(group_name)

        except Exception as e:
            logger.error(f"Error during group pivot: {str(e)[:100]}")

        return {
            "indicator": group_name,
            "type": "threat_group",
            "results": results
        }

    def pivot_filename(self, filename: str) -> dict:
        """
        Queries VirusTotal and MalwareBazaar for samples matching a given filename.
        Returns related hashes and malware families for further pivoting.
        """
        logger.info(f"Starting filename pivot for: {filename[:50]}")
        results = {}

        try:
            logger.info("Querying VirusTotal...")
            results["virustotal"] = self.vt.query_filename(filename)
            self._rate_limit()

            logger.info("Querying MalwareBazaar...")
            results["malwarebazaar"] = self.bazaar.query_filename(filename)

        except Exception as e:
            logger.error(f"Error during filename pivot: {str(e)[:100]}")

        return {
            "indicator": filename,
            "type": "filename",
            "results": results
        }


    def run(self, seed: str) -> dict:
        validation = self.validate(seed)
        if not validation["valid"]:
            return {"error": validation["reason"], "indicator": seed}
        indicator = validation["indicator"]
        indicator_type = validation["type"]
        if indicator_type == "ipv4":
            return self.pivot_ip(indicator)
        elif indicator_type == "domain":
            return self.pivot_domain(indicator)
        elif indicator_type in {"md5", "sha1", "sha256"}:
            return self.pivot_hash(indicator)
        elif indicator_type == "threat_group":
            return self.pivot_group(indicator)
        elif indicator_type == "filename":
            return self.pivot_filename(indicator)
        else:
            return {"error": f"No pivot chain defined for type {indicator_type}", "indicator": indicator}
       