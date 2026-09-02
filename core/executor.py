# Pivot chain executor 
# Routes seed indicators to the correct connectors and returns
# a normalized result across all sources. 


import time
import logging
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
 
import config
from core import hacktivist
from core.detector import detect_type
from connectors.virustotal import VirusTotalConnector
from connectors.shodan import ShodanConnector
from connectors.censys import CensysConnector
from connectors.whois import WHOISConnector
from connectors.rdap import RDAPConnector

# Licensed sources. Their connectors are gitignored and absent from any clone,
# so they are imported defensively — the public engine has to run without them.
try:
    from connectors.domaintools import DomainToolsConnector
except ImportError:
    DomainToolsConnector = None

try:
    from connectors.dnsdb import DNSDBConnector
except ImportError:
    DNSDBConnector = None
from connectors.dns import DNSConnector
from connectors.passivedns import PassiveDNSConnector
from connectors.onion import OnionConnector
from connectors.mitre import MITREConnector
from connectors.bazaar import MalwareBazaarConnector
from connectors.spiderfoot import SpiderFootConnector
from connectors.urlhaus import URLhausConnector
from connectors.threatfox import ThreatFoxConnector
from connectors.otx import OTXConnector
 
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)
 
# Ceiling on one pivot's whole connector fan-out. Wired into
# _run_parallel; previously defined and never used.
REQUEST_TIMEOUT = 25
ALLOWED_TYPES = {
    "ipv4", "domain", "url", "md5", "sha1", "sha256",
    "email", "username", "threat_group", "software"
}

# Dual-use tooling worth chaining anyway — offensive frameworks that do
# circulate as samples. Everything else MITRE types as "tool" is a
# living-off-the-land binary and gets skipped.
CHAINABLE_TOOLS = {
    "cobalt strike", "mimikatz", "impacket", "sliver", "brute ratel c4",
    "empire", "powersploit", "koadic", "pupy", "metasploit", "winexe",
}

# Caps the MalwareBazaar lookups fired per threat group pivot.
MAX_TOOLING_LOOKUPS = 5

# Threat group discovery gets a longer ceiling than the default fan-out.
# OTX pulse search measures 28-58s, which is slow but is the only source that
# knows about actors ATT&CK has not profiled. Group pivots make no VirusTotal
# calls and run three connectors, so the extra wait is affordable here and
# nowhere else.
#
# Sized for two OTX attempts: 65s each plus a 2s backoff is 132s, and at 75s
# the retry added for its 504s was abandoned mid-flight, which is no retry at
# all. Nothing slows down on the happy path, since as_completed returns when
# the batch finishes and only reaches this ceiling if a source really hangs.
GROUP_DISCOVERY_TIMEOUT = 140
 
 
def _run_parallel(tasks: dict, timeout: int = None) -> dict:
    """
    Runs a dict of {name: callable} in parallel and returns {name: result},
    keeping errors rather than dropping them.

    The whole batch is bounded by REQUEST_TIMEOUT. Without it a single
    connector that never returns blocks the entire pivot forever: measured
    stalls of 42 and 29 minutes on a pivot that normally takes 5 seconds.
    Connectors set their own per-request timeouts, but those do not cover a
    hung browser launch or a socket that never completes a handshake.

    timeout overrides that ceiling for a specific batch. Used only where a
    source is known to be slow yet worth waiting for, rather than raising the
    global bound and losing the protection everywhere else.
    """
    timeout = REQUEST_TIMEOUT if timeout is None else timeout
    results = {}
    # Deliberately not a context manager. Its __exit__ calls
    # shutdown(wait=True), which joins every thread, so a hung connector still
    # blocks the return even once the timeout has produced its result.
    pool = ThreadPoolExecutor(max_workers=len(tasks))
    try:
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        try:
            for future in as_completed(futures, timeout=timeout):
                name = futures[future]
                try:
                    results[name] = future.result(timeout=0)
                except Exception as e:
                    results[name] = {"error": str(e)[:100], "source": name}
        except FuturesTimeout:
            pass  # Whatever finished is kept; the rest are recorded below.

        # Report stragglers as timeouts rather than leaving them absent, so a
        # slow source stays distinguishable from one that returned nothing.
        for future, name in futures.items():
            if name not in results:
                results[name] = {
                    "error": f"timed out after {timeout}s",
                    "source": name,
                }
    finally:
        # Pending work is cancelled; work already running is abandoned, since
        # Python cannot interrupt a blocked call. The pivot moves on either way.
        pool.shutdown(wait=False, cancel_futures=True)
    return results
 
 
def _record_seed_port(results: dict, port: int) -> None:
    """
    Keeps the port from a host:port seed, which the pivot itself drops.

    ThreatFox names a C2 as host:port and the connectors can only be asked
    about the host, so without this the report never says which service was
    reported. Recorded like url_parts: context for the write-up, and nothing
    scores on it.
    """
    if not port:
        return
    results["seed_port"] = {
        "source": "seed_port",
        "port": port,
        "non_standard_port": port not in (80, 443),
    }


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
        self.rdap = RDAPConnector()
        self.domaintools = DomainToolsConnector() if DomainToolsConnector else None
        self.dnsdb = DNSDBConnector() if DNSDBConnector else None
        self.dns = DNSConnector()
        self.passivedns = PassiveDNSConnector()
        self.censys = CensysConnector()
        self.ahmia = OnionConnector()
        self.mitre = MITREConnector()
        self.bazaar = MalwareBazaarConnector()
        self.spiderfoot = SpiderFootConnector()
        self.urlhaus = URLhausConnector()
        self.threatfox = ThreatFoxConnector()
        self.otx = OTXConnector()
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
        # The detector's indicator, not the raw seed. Identical for every type
        # except a host:port C2, where it is the host and the seed is what no
        # connector can query.
        return {"valid": True, "indicator": result["indicator"],
                "type": result["type"], "port": result.get("port")}
 
    def pivot_ip(self, ip: str, deep: bool = False, port: int = None) -> dict:
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
            "dns": lambda: self.dns.query_ip(ip),
            "ahmia": lambda: self.ahmia.search(ip),
            "urlhaus": lambda: self.urlhaus.query_host(ip),
            "threatfox": lambda: self.threatfox.query_indicator(ip, "ipv4"),
            "otx": lambda: self.otx.query_indicator(ip, "IPv4"),
        }
        # Alongside the free tier, not instead of it. The reverse lookup here is
        # what decides shared hosting versus dedicated, which mnemonic cannot
        # answer, but keeping both means a licence lapse degrades rather than
        # breaks the pivot.
        if self.dnsdb:
            tasks["dnsdb"] = lambda: self.dnsdb.query_ip(ip)

        results = _run_parallel(tasks)
        _record_seed_port(results, port)

        return {"indicator": ip, "type": "ipv4", "results": results}
 
    def pivot_domain(self, domain: str, deep: bool = False, port: int = None) -> dict:
        """
        Queries all relevant connectors for a domain indicator.
        Connectors run in parallel. SpiderFoot only runs when deep=True.
        """
        logger.info(f"Starting domain pivot for: {domain[:50]}")
 
        tasks = {
            "virustotal": lambda: self.vt.query_domain(domain),
            "whois": lambda: self._registration(domain),
            # Current state. passivedns covers history; neither substitutes
            # for the other, and only a live query sees a wildcard zone.
            "dns": lambda: self.dns.query_domain(domain),
            "passivedns": lambda: self.passivedns.query_domain(domain),
            # Its own key. This is crt.sh, not Censys, and filing it under
            # "censys" meant every crt.sh 502 was reported as a Censys failure —
            # days spent suspecting the wrong service.
            "crtsh": lambda: self.censys.query_domain_certificates(domain),
            "ahmia": lambda: self.ahmia.search(domain),
            "urlhaus": lambda: self.urlhaus.query_host(domain),
            "threatfox": lambda: self.threatfox.query_indicator(domain, "domain"),
            "otx": lambda: self.otx.query_indicator(domain, "domain"),
        }
        # Supplements rather than replaces: DomainTools adds registrar and IP
        # history to the RDAP/WHOIS answer, DNSDB adds observation timestamps to
        # passive DNS. Both are reported under their own keys so a licensed
        # result and a public one stay distinguishable.
        if self.domaintools:
            tasks["domaintools"] = lambda: self.domaintools.query_domain(domain)
        if self.dnsdb:
            tasks["dnsdb"] = lambda: self.dnsdb.query_domain(domain)

        results = _run_parallel(tasks)
        _record_seed_port(results, port)

        return {"indicator": domain, "type": "domain", "results": results}
 
    def _registration(self, domain: str) -> dict:
        """
        Registration data, RDAP first and port-43 WHOIS as fallback.

        ICANN has moved gTLDs onto RDAP and retired the port-43 requirement, and
        RDAP returns structured JSON instead of free text needing a regex parse.
        Many ccTLDs still publish no RDAP service though, so WHOIS stays rather
        than being replaced.

        Kept under the "whois" result key so saved investigations and the MCP
        source filter keep working. The payload's own "source" says which
        protocol actually answered.
        """
        result = self.rdap.query_domain(domain)
        if "error" not in result:
            return result

        reason = result["error"]
        logger.info(f"RDAP unavailable for {domain[:50]} ({reason[:60]}), trying WHOIS.")

        fallback = self.whois.query_domain(domain)
        if "error" in fallback:
            # Neither answered. Report both, so the gap is not mistaken for a
            # domain with no registration.
            return {
                "error": f"RDAP: {reason[:80]} | WHOIS: {str(fallback['error'])[:80]}",
                "indicator": domain,
                "source": "rdap+whois",
            }

        fallback["fallback_from_rdap"] = reason
        return fallback

    def pivot_url(self, url: str, deep: bool = False) -> dict:
        """
        Queries URLhaus for an exact URL and decomposes it for chaining.

        A URL carries more than its host — the port and path are the lure, and
        URLhaus indexes the full string. The host is chained separately so the
        domain or IP still gets its own full pivot.
        """
        logger.info(f"Starting URL pivot for: {url[:80]}")

        parsed = urlparse(url)
        host = parsed.hostname or ""

        results = _run_parallel({
            "urlhaus": lambda: self.urlhaus.query_url(url),
            "threatfox": lambda: self.threatfox.query_indicator(url, "url"),
        })

        # Recorded so the agent can reason about the shape of the lure, which is
        # often all there is when no source has seen the URL itself.
        results["url_parts"] = {
            "source": "url_parts",
            "scheme": parsed.scheme,
            "host": host,
            "port": parsed.port,
            "path": parsed.path or "/",
            "query": parsed.query,
            "non_standard_port": bool(
                parsed.port and parsed.port not in (80, 443)
            ),
        }

        return {"indicator": url, "type": "url", "results": results}

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

            # OTX enrichment — detect hash type from length
            hash_type = "FileHash-MD5" if len(hash_val) == 32 else "FileHash-SHA1" if len(hash_val) == 40 else "FileHash-SHA256"
            results["otx"] = self.otx.query_indicator(hash_val, hash_type)
 
            # Chain into related samples via malware family tag
            malware_tag = bazaar_result.get("malware_family") if isinstance(bazaar_result, dict) else None
            if malware_tag and bazaar_result.get("found"):
                logger.info(f"Querying MalwareBazaar for related samples by tag: {malware_tag}")
                results["malwarebazaar_related"] = self.bazaar.query_tag(malware_tag)

            # URLhaus enrichment using Bazaar malware family tag
            if malware_tag and bazaar_result.get("found"):
                logger.info(f"Querying URLhaus for delivery URLs: {malware_tag}")
                results["urlhaus"] = self.urlhaus.query_malware_family(malware_tag)
 
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
 
    def _chainable_tooling(self, mitre_result: dict) -> list[str]:
        """
        Picks the group's software entries worth looking up in MalwareBazaar.
        Purpose-built malware always qualifies; dual-use tooling only if it is
        in CHAINABLE_TOOLS.
        """
        if not mitre_result.get("found"):
            return []

        chainable = []
        for entry in mitre_result.get("software", []):
            name = (entry.get("name") or "").strip()
            if not name:
                continue
            if entry.get("type") == "malware" or name.lower() in CHAINABLE_TOOLS:
                chainable.append(name)

        return chainable[:MAX_TOOLING_LOOKUPS]

    def pivot_group(self, group_name: str, deep: bool = False) -> dict:
        """
        Looks up a threat group in MITRE ATT&CK, then chains its malware into
        MalwareBazaar. Sample hashes found here get queued for hash pivots.
        """
        logger.info(f"Starting threat group pivot for: {group_name[:50]}")
        results = {}

        try:
            # MITRE alone cannot answer for an emerging actor. ATT&CK only
            # profiles groups that clear its bar, months to years after the
            # fact, so hacktivist crews and freshly named groups are simply
            # absent. OTX and the dark web index are queried alongside it so
            # "not in ATT&CK" stops being indistinguishable from "unknown".
            discovery = _run_parallel({
                "mitre": lambda: self.mitre.query_group(group_name),
                "otx_search": lambda: self.otx.search_pulses(group_name),
                "ahmia": lambda: self.ahmia.search(group_name),
            }, timeout=GROUP_DISCOVERY_TIMEOUT)
            results.update(discovery)
            mitre_result = results.get("mitre", {})

            chainable = self._chainable_tooling(mitre_result)

            # A group absent from ATT&CK can still have tooling named in
            # community reporting, so fold those in when MITRE gave nothing.
            otx_families = results.get("otx_search", {})
            if isinstance(otx_families, dict):
                for family in otx_families.get("malware_families", [])[:3]:
                    if family and family.lower() not in {c.lower() for c in chainable}:
                        chainable.append(family)

            # Hacktivist read, parsed off the pulse text. ATT&CK does not profile
            # these crews, they are on Telegram rather than onion sites, and they
            # rarely have malware, so this is the only thing the pivot returns for
            # them beyond a bare count.
            otx_search = results.get("otx_search", {})
            results["hacktivist"] = hacktivist.assess(
                group_name,
                otx_search.get("pulses", []) if isinstance(otx_search, dict) else [],
            )

            chainable = chainable[:MAX_TOOLING_LOOKUPS]
            if chainable:
                logger.info(f"Querying MalwareBazaar for group tooling: {chainable}")
                tasks = {
                    name: (lambda n=name: self.bazaar.query_signature(n))
                    for name in chainable
                }
                results["malwarebazaar_tooling"] = _run_parallel(tasks)
            else:
                results["malwarebazaar_tooling"] = {}
                logger.info(
                    "No chainable tooling — group uses only living-off-the-land binaries."
                )

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
        port = validation.get("port")
 
        if indicator_type == "ipv4":
            return self.pivot_ip(indicator, deep=deep, port=port)
        elif indicator_type == "domain":
            return self.pivot_domain(indicator, deep=deep, port=port)
        elif indicator_type == "url":
            return self.pivot_url(indicator, deep=deep)
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