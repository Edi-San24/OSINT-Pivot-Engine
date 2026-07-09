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

# Logging configuration
logging.basicConfig(
    level = logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Rate limit delay (in seconds)
RATE_LIMIT_DELAY = 1.0

# Request timeout for all API calls 
REQUEST_TIMEOUT = 10

# Allowed Indicators 
ALLOWED_TYPES = {"ipv4", "domain", "md5", "sha1", "sha256", "email", "username"}

# Class PivotExecutor
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
        logger.info("Pivot initalized!")

    def validate(self, seed: str) -> dict:
        """
        Validates and detects the type of a seed indicator.
        Rejects: oversized, empty, or unknown indicator types
        """

        seed = seed.strip()
        if not seed:
            logger.warning("Empty seed received!")
            return {"valid": False, "reason": "Seed indicator is empty..."}
        
        if len(seed) > 512:
            logger.warning("Seed indicator exceeds character limit!")
            return {"valid": False, "reason": "Seed indicator too long..."}
        
        result = detect_type(seed)

        if result["type"] not in ALLOWED_TYPES:
            logger.warning(f"Unknown indicator type for seed: {seed[:50]}")
            return {"valid": False, "reason": f"Unknown indicator type: {result['type']}"}
        
        logger.info(f"Seed recognized! Type: {result['type']}")
        return {"valid": True, "indicator": seed, "type": result["type"]}
    
    def _rate_limit(self):
        """
        Pauses execution between API calls to respect rate limits
        """
        time.sleep(RATE_LIMIT_DELAY)

    def pivot_ip(self, ip: str) -> dict:
        """
        Runs all connectors for an IP address.
        Returns a unified result across VT, Shodan, PassiveDNS, and
        Censys.
        """
        logger.info(f"Starting IP pivot for: {ip[:50]}")
        results = {}

        try:
            logger.info("Querying VirusTotal...")
            results["virustotal"] = self.vt.query_ip(ip)
            self._rate_limit()

            logger.info("Querying Shodan...")
            results["shodan"] = self.shodan.query_ip(ip)
            self._rate_limit()

            logger.info("Querying PassiveDNS...")
            results["passivedns"] = self.passivedns.query_ip(ip)
            self._rate_limit()

            logger.info("Querying Censys...")
            results["censys"] = self.censys.query_ip(ip)

        except Exception as e:
            logger.error(f"Error during IP pivot: {str(e)[:100]}")

        return {
            "indicator" : ip,
            "type": "ipv4",
            "results": results
        }
        
    def pivot_domain(self, domain: str) -> dict:
        """
        Runs all connectors for a domain indicator.
        Returns unified results across, VT, WHOIS, passiveDNS, and Censys
        """
        logger.info(f"Starting domain pivot for: {domain[:50]}")
        results = {}

        try:
            logger.info("Querying VirusTotal...")
            results["virustotal"] = self.vt.query_domain(domain)
            self._rate_limit()

            logger.info("Querying WHOIS...")
            results["whois"] = self.whois.query_domain(domain)
            self._rate_limit()

            logger.info("Querying PassiveDNS...")
            results["passivedns"] = self.passivedns.query_domain(domain)
            self._rate_limit()

            logger.info("Querying Censys...")
            results["censys"] = self.censys.query_domain(domain)
            self._rate_limit()

        except Exception as e:
            logger.error(f"Error during domain pivot: {str(e)[:100]}")

        return{
            "indicator": domain,
            "type": "domain",
            "results": results
        }
    
    def pivot_hash(self, hash: str) -> dict:
        """
        Runs all relevant connectors for a file hash indicator
        Returns a unified result from VT. 
        """
        logger.info(f"Starting hash pivot for: {hash[:50]}")
        results = {}

        try:
            logger.info("Querying VirusTotal...")
            results["virustotal"] = self.vt.query_hash(hash)

        except Exception as e:
            logger.error(f"Error during hash pivot: {str(e)[:100]}")
        
        return{
            "indicator": hash,
            "type": "hash",
            "results": results
        }
    
    def run(self, seed: str) -> dict:
        """
        Main entry point for pivot chain
        Validates: seed, detects type & routes to the correct pivot method
        """
        validation = self.validate(seed)
        if not validation["valid"]:
            logger.warning(f"Invalid seed rejected: {validation['reason']}")
            return {"error": validation["reason"], "indicator": seed}
        
        indicator = validation["indicator"]
        indicator_type = validation["type"]

        if indicator_type == "ipv4":
            return self.pivot_ip(indicator)
        elif indicator_type == "domain":
            return self.pivot_domain(indicator)
        elif indicator_type in {"md5", "sha1", "sha256"}:
            return self.pivot_hash(indicator)
        else:
            logger.warning(f"No pivot method for type: {indicator_type}")
            return {
                "error": f"No pivot chain defined for type {indicator_type}",
                "indicator": indicator
            }
    
