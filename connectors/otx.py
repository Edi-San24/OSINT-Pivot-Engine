# connectors/otx.py
# Queries existing pulses for indicator enrichment from Alienvault OTX
# Submits new pulses after investigations 


import re
import requests
import logging
 
logger = logging.getLogger(__name__)
 
from config import OTX_API_KEY
from connectors.retry import get_with_retry
 
BASE_URL = "https://otx.alienvault.com/api/v1"

# Sentinel so "lookup failed, cached None" stays distinguishable from
# "not looked up yet", which would otherwise retry on every call.
_UNSET = object()
 
 
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
        self._username = _UNSET
        logger.info("OTX connector initialized.")
 
    def _self_username(self) -> str | None:
        """
        The OTX account behind the API key, cached for the process.

        Needed so our own pulses are not counted as corroboration. Fetched
        rather than configured, so it is always right for whichever key is in
        use. Returns None if the lookup fails, and the caller reports that no
        filtering happened rather than filtering silently.
        """
        if self._username is not _UNSET:
            return self._username

        try:
            response = requests.get(
                f"{BASE_URL}/user/me", headers=self.headers, timeout=15
            )
            response.raise_for_status()
            self._username = response.json().get("username") or None
        except Exception as e:
            logger.warning(f"Could not resolve own OTX username: {str(e)[:80]}")
            self._username = None

        return self._username

    @staticmethod
    def _pulse_author(pulse: dict) -> str:
        """
        Author of a pulse, across both response shapes OTX uses.

        /indicators/.../general nests it as author.username while /search/pulses
        returns author_name. Only the latter was read, so every pulse from an
        indicator lookup reported its author as "unknown".
        """
        author = pulse.get("author")
        if isinstance(author, dict):
            return author.get("username") or "unknown"
        if pulse.get("author_name"):
            return pulse["author_name"]
        return author if isinstance(author, str) and author else "unknown"

    def _split_own_pulses(self, pulses: list) -> tuple[list, list]:
        """
        Separates pulses we published from everyone else's.

        Our own reporting is not independent evidence. Counting it inflates
        corroboration with our own assumptions and, worse, feeds published tags
        back in as findings on the next investigation.
        """
        mine = self._self_username()
        if not mine:
            return list(pulses), []

        external, own = [], []
        for pulse in pulses:
            (own if self._pulse_author(pulse) == mine else external).append(pulse)
        return external, own

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
            external, own = self._split_own_pulses(pulse_info.get("pulses", []))
            pulses = external[:5]
 
            return {
                "indicator": indicator,
                "type": indicator_type,
                "source": "otx",
                # Other researchers' pulses only. Our own are listed
                # separately so they stay visible without counting as
                # corroboration.
                # OTX's own verdict on whether it will accept this indicator.
                # Non-empty means it sits in a whitelisted prefix or is otherwise
                # rejected, and a pulse containing it will silently drop it.
                # Nothing else the engine queries knows this: 178.128.173.150 was
                # ThreatFox Aisuru at confidence 100, and OTX refused it anyway.
                "otx_validation": [
                    v.get("message") or v.get("name")
                    for v in (data.get("validation") or [])
                ],
                "pulse_count": len(external),
                "pulse_count_including_own": pulse_info.get("count", 0),
                "own_pulse_count": len(own),
                "own_pulses": [p.get("name", "unknown") for p in own],
                "self_filter_applied": self._self_username() is not None,
                "pulses": [
                    {
                        "name": p.get("name", "unknown"),
                        "author": self._pulse_author(p),
                        "created": p.get("created", "unknown"),
                        "tags": p.get("tags", []),
                        "malware_families": p.get("malware_families", []),
                        "targeted_countries": p.get("targeted_countries", []),
                        # Structured sector targeting — the only source in the
                        # pipeline that has it. MITRE groups carry targeting in
                        # prose only. Consumed by core/relevance.py.
                        "industries": p.get("industries", []),
                    }
                    for p in pulses
                ]
            }
 
        except Exception as e:
            logger.error(f"OTX query failed for '{indicator}': {str(e)[:100]}")
            return {"error": str(e), "indicator": indicator, "source": "otx"}
 
    def _relevant_pulses(self, pulses: list, query: str) -> list:
        """
        Keeps the pulses actually about the query, deduplicated by title.
        Measured relevant-of-returned: Lynx 9/50, KillNet 12/50, Handala 25/50.
        The rest are bulk feeds that merely contain the term.
        """
        # Word boundary, not containment, so "Lynx" misses "Lynxware". A generic
        # name still pulls in Hidden Lynx and Cosmic Lynx — name ambiguity, not a
        # filter failure, and the counts stay visible either way.
        needle = re.compile(rf"\b{re.escape(query.strip())}\b", re.IGNORECASE)

        relevant, seen_titles = [], set()
        for pulse in pulses:
            name = pulse.get("name") or ""
            if not needle.search(f"{name} {pulse.get('description') or ''}"):
                continue
            title = re.sub(r"\s+", " ", name).strip().lower()
            if title and title in seen_titles:
                continue
            seen_titles.add(title)
            relevant.append(pulse)
        return relevant

    def search_pulses(self, query: str, limit: int = 50) -> dict:
        """
        Searches community pulses by free text, used for threat group names.

        MITRE ATT&CK only profiles groups that clear its inclusion bar, and it
        lags real activity by months. Hacktivist crews and newly named actors
        are usually absent entirely. OTX is community-written and same-day, so
        it catches names ATT&CK has never heard of.

        Counts are reported after _relevant_pulses filters. limit is high because
        that filter discards most of what comes back.
        """
        try:
            response = get_with_retry(
                f"{BASE_URL}/search/pulses",
                params={"q": query, "limit": limit},
                headers=self.headers,
                # Measured at 28-58s. Slow, but it is the only source that
                # knows about actors ATT&CK has not profiled, and it sits
                # inside executor.GROUP_DISCOVERY_TIMEOUT, which is sized for
                # two attempts.
                timeout=65,
                source="otx search",
            )
            response.raise_for_status()
            data = response.json()
            returned = data.get("results", []) or []
            pulses, own = self._split_own_pulses(
                self._relevant_pulses(returned, query)
            )

            authors, malware, adversaries, tags = set(), set(), set(), set()
            for p in pulses:
                author = self._pulse_author(p)
                if author != "unknown":
                    authors.add(author)
                malware.update(p.get("malware_families", []) or [])
                if p.get("adversary"):
                    adversaries.add(p["adversary"])
                tags.update(p.get("tags", []) or [])

            return {
                "indicator": query,
                "type": "pulse_search",
                "source": "otx",
                "found": bool(pulses),
                # Relevant and deduplicated, not the API's total — that counts
                # every unrelated pulse containing the term. Lynx reports 784.
                "pulse_count": len(pulses),
                "pulse_count_reported": data.get("count", len(returned)),
                "pulses_screened": len(returned),
                "own_pulse_count": len(own),
                "self_filter_applied": self._self_username() is not None,
                "distinct_authors": len(authors),
                "malware_families": sorted(malware)[:10],
                "adversaries": sorted(adversaries)[:5],
                "tags": sorted(tags)[:15],
                "pulses": [
                    {
                        "name": p.get("name", "unknown"),
                        # core.hacktivist parses targeting out of this text —
                        # OTX's structured targeting fields are empty.
                        "description": (p.get("description") or "")[:500],
                        "author": p.get("author_name", "unknown"),
                        "created": p.get("created", "unknown"),
                        "modified": p.get("modified", "unknown"),
                        "indicator_count": p.get("indicator_count", 0),
                        "tags": p.get("tags", []),
                    }
                    for p in pulses
                ],
            }

        except Exception as e:
            logger.error(f"OTX pulse search failed for '{query}': {str(e)[:100]}")
            return {"error": str(e), "indicator": query, "source": "otx"}

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
 
