# Pivot chain executor 
# Routes seed indicators to the correct connectors and returns
# a normalized result across all sources. 


import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
 
import config
from core.detector import detect_type
from connectors.virustotal import VirusTotalConnector
from connectors.shodan import ShodanConnector
from connectors.censys import CensysConnector
from connectors.whois import WHOISConnector
from connectors.passivedns import PassiveDNSConnector
from connectors.onion import OnionConnector
from connectors.mitre import MITREConnector
from connectors.bazaar import MalwareBazaarConnector
from connectors.spiderfoot import SpiderFootConnector
 
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)
 
REQUEST_TIMEOUT = 10
ALLOWED_TYPES = {
    "ipv4", "domain", "md5", "sha1", "sha256",
    "email", "username", "threat_group", "software"
}
 
 
def _run_parallel(tasks: dict) -> dict:
    """
    Runs a dict of {name: callable} in parallel using a thread pool.
    Returns {name: result} preserving all results including errors.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"error": str(e)[:100], "source": name}
    return results
 
 
class PivotExecutor:
    """
    Routes seed indicators to the correct connectors and
    returns a unified result across all sources.
    Connectors fire in parallel to reduce total pivot time.
    SpiderFoot only fires when deep=True is passed.
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
        self.spiderfoot = SpiderFootConnector()
        logger.info("Pivot executor initialized.")
 
    def validate(self, seed: str) -> dict:
        seed = seed.strip()
        if not seed:
            return {"valid": False, "reason": "Seed indicator is empty."}
        if len(seed) > 512:
            return {"valid": False, "reason": "Seed indicator too long."}
        result = detect_type(seed)
        if not result:
            return {"valid": False, "reason": "Could not detect indicator type."}
        if result["type"] not in ALLOWED_TYPES:
            return {"valid": False, "reason": f"Unknown indicator type: {result['type']}"}
        return {"valid": True, "indicator": seed, "type": result["type"]}
 
    def pivot_ip(self, ip: str, deep: bool = False) -> dict:
        """
        Queries all relevant connectors for an IP address indicator.
        Connectors run in parallel. SpiderFoot only runs when deep=True.
        """
        logger.info(f"Starting IP pivot for: {ip[:50]}")
 
        tasks = {
            "virustotal": lambda: self.vt.query_ip(ip),
            "shodan": lambda: self.shodan.query_ip(ip),
            "passivedns": lambda: self.passivedns.query_ip(ip),
            "censys": lambda: self.censys.query_ip(ip),
            "ahmia": lambda: self.ahmia.search(ip),
        }
 
        results = _run_parallel(tasks)
        return {"indicator": ip, "type": "ipv4", "results": results}
 
    def pivot_domain(self, domain: str, deep: bool = False) -> dict:
        """
        Queries all relevant connectors for a domain indicator.
        Connectors run in parallel. SpiderFoot only runs when deep=True.
        """
        logger.info(f"Starting domain pivot for: {domain[:50]}")
 
        tasks = {
            "virustotal": lambda: self.vt.query_domain(domain),
            "whois": lambda: self.whois.query_domain(domain),
            "passivedns": lambda: self.passivedns.query_domain(domain),
            "censys": lambda: self.censys.query_domain_certificates(domain),
            "ahmia": lambda: self.ahmia.search(domain),
        }
 
        results = _run_parallel(tasks)
        return {"indicator": domain, "type": "domain", "results": results}
 
    def pivot_hash(self, hash_val: str, deep: bool = False) -> dict:
        """
        Queries VirusTotal and MalwareBazaar for a file hash indicator.
        Chains into related samples via malware family tag clustering.
        MITRE enrichment runs after VT returns a malware family name.
        """
        logger.info(f"Starting hash pivot for: {hash_val[:50]}")
        results = {}
 
        try:
            # VT and Bazaar in parallel
            hash_tasks = {
                "virustotal": lambda: self.vt.query_hash(hash_val),
                "malwarebazaar": lambda: self.bazaar.query_hash(hash_val),
            }
            hash_results = _run_parallel(hash_tasks)
            results.update(hash_results)
 
            vt_result = results.get("virustotal", {})
            bazaar_result = results.get("malwarebazaar", {})
 
            # Chain into related samples via malware family tag
            malware_tag = bazaar_result.get("malware_family") if isinstance(bazaar_result, dict) else None
            if malware_tag and bazaar_result.get("found"):
                logger.info(f"Querying MalwareBazaar for related samples by tag: {malware_tag}")
                results["malwarebazaar_related"] = self.bazaar.query_tag(malware_tag)
 
            # MITRE enrichment using VT malware family name
            malware_name = vt_result.get("malware_family") if isinstance(vt_result, dict) else None
            if malware_name and "error" not in vt_result:
                logger.info(f"Querying MITRE ATT&CK for software: {malware_name}")
                results["mitre"] = self.mitre.query_software(malware_name)
            else:
                results["mitre"] = {
                    "source": "mitre_attack",
                    "skipped": True,
                    "reason": "No malware family name available from VirusTotal."
                }
 
        except Exception as e:
            logger.error(f"Error during hash pivot: {str(e)[:100]}")
 
        return {"indicator": hash_val, "type": "hash", "results": results}
 
    def pivot_group(self, group_name: str, deep: bool = False) -> dict:
        """
        Looks up a threat group by name in MITRE ATT&CK.
        Returns associated techniques, software, and group metadata.
        """
        logger.info(f"Starting threat group pivot for: {group_name[:50]}")
        results = {}
 
        try:
            results["mitre"] = self.mitre.query_group(group_name)
        except Exception as e:
            logger.error(f"Error during group pivot: {str(e)[:100]}")
 
        return {"indicator": group_name, "type": "threat_group", "results": results}
 
    def pivot_software(self, name: str, deep: bool = False) -> dict:
        """
        Queries MalwareBazaar for samples matching a malware family name.
        Chains related sample hashes into the pivot queue for follow-on investigation.
        """
        logger.info(f"Starting software pivot for: {name[:50]}")
        results = {}
 
        try:
            bazaar_result = self.bazaar.query_signature(name)
            results["malwarebazaar"] = bazaar_result
 
            # Extract sample hashes for chaining — fixes bug where software
            # pivot samples were never queued for follow-on hash pivots
            samples = bazaar_result.get("samples", [])
            if samples:
                results["_chainable_hashes"] = [
                    s.get("sha256") for s in samples
                    if s.get("sha256") and s.get("sha256") != "unknown"
                ]
 
        except Exception as e:
            logger.error(f"Error during software pivot: {str(e)[:100]}")
 
        return {"indicator": name, "type": "software", "results": results}
 
    def pivot_email(self, email: str, deep: bool = False) -> dict:
        """
        Queries SpiderFoot for email address intelligence.
        Only runs SpiderFoot when deep=True. Returns empty otherwise.
        """
        logger.info(f"Starting email pivot for: {email[:50]}")
        results = {}
 
        if deep:
            try:
                results["spiderfoot"] = self.spiderfoot.query_email(email)
            except Exception as e:
                logger.error(f"Error during email pivot: {str(e)[:100]}")
        else:
            results["spiderfoot"] = {
                "source": "spiderfoot",
                "skipped": True,
                "reason": "SpiderFoot requires --deep flag. Re-run with --deep to enable."
            }
 
        return {"indicator": email, "type": "email", "results": results}
 
    def pivot_username(self, username: str, deep: bool = False) -> dict:
        """
        Queries SpiderFoot for username intelligence.
        Only runs SpiderFoot when deep=True. Returns empty otherwise.
        """
        logger.info(f"Starting username pivot for: {username[:50]}")
        results = {}
 
        if deep:
            try:
                results["spiderfoot"] = self.spiderfoot.query_username(username)
            except Exception as e:
                logger.error(f"Error during username pivot: {str(e)[:100]}")
        else:
            results["spiderfoot"] = {
                "source": "spiderfoot",
                "skipped": True,
                "reason": "SpiderFoot requires --deep flag. Re-run with --deep to enable."
            }
 
        return {"indicator": username, "type": "username", "results": results}
 
    def pivot_filename(self, filename: str, deep: bool = False) -> dict:
        """
        Queries VirusTotal and MalwareBazaar for samples matching a filename.
        """
        logger.info(f"Starting filename pivot for: {filename[:50]}")
 
        tasks = {
            "virustotal": lambda: self.vt.query_filename(filename),
            "malwarebazaar": lambda: self.bazaar.query_filename(filename),
        }
 
        results = _run_parallel(tasks)
        return {"indicator": filename, "type": "filename", "results": results}
 
    def run(self, seed: str, deep: bool = False) -> dict:
        """
        Validates the seed indicator and routes to the correct pivot method.
        Pass deep=True to enable SpiderFoot for email and username pivots.
        """
        validation = self.validate(seed)
        if not validation["valid"]:
            return {"error": validation["reason"], "indicator": seed}
 
        indicator = validation["indicator"]
        indicator_type = validation["type"]
 
        if indicator_type == "ipv4":
            return self.pivot_ip(indicator, deep=deep)
        elif indicator_type == "domain":
            return self.pivot_domain(indicator, deep=deep)
        elif indicator_type in {"md5", "sha1", "sha256"}:
            return self.pivot_hash(indicator, deep=deep)
        elif indicator_type == "threat_group":
            return self.pivot_group(indicator, deep=deep)
        elif indicator_type == "software":
            return self.pivot_software(indicator, deep=deep)
        elif indicator_type == "email":
            return self.pivot_email(indicator, deep=deep)
        elif indicator_type == "username":
            return self.pivot_username(indicator, deep=deep)
        elif indicator_type == "filename":
            return self.pivot_filename(indicator, deep=deep)
        else:
            return {"error": f"No pivot chain defined for type: {indicator_type}", "indicator": indicator}