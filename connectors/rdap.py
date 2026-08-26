# connectors/rdap.py
# RDAP registration lookups — the structured replacement for port-43 WHOIS.

import logging
import requests

logger = logging.getLogger(__name__)

# IANA's bootstrap registry maps each TLD to its authoritative RDAP server.
# Resolved here rather than through a redirect service like rdap.org, so no
# third party sits in the path.
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

REQUEST_TIMEOUT = 10

# Second-level public suffixes, so stripping toward the registrable domain stops
# before it asks a registry about itself. Not a full public suffix list — the
# common ccTLD structures, which is what shows up in practice.
PUBLIC_SUFFIXES_2LD = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.za", "org.za", "net.za", "web.za",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in", "gov.in",
    "com.cn", "net.cn", "org.cn",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.tw", "com.hk",
    "co.kr", "or.kr", "co.il", "org.il", "co.th", "com.my", "com.ph",
}

# Dates RDAP reports as events, mapped to the field names the WHOIS connector
# already returns so either source is a drop-in for the other.
EVENT_FIELDS = {
    "registration": "creation_date",
    "expiration": "expiration_date",
    "last changed": "updated_date",
}


class RDAPConnector:
    """
    Connector for RDAP domain registration lookups.
    No API key required. Returns registrar, dates, nameservers and DNSSEC
    state as structured JSON rather than free text needing a regex parse.
    """

    def __init__(self):
        self._services = None  # tld -> base url, loaded on first use

    def _bootstrap(self) -> dict:
        """
        Loads and caches the IANA TLD-to-server map.
        Returns an empty map on failure, which makes every lookup report no
        RDAP service and hand off to the caller's fallback.
        """
        if self._services is not None:
            return self._services

        self._services = {}
        try:
            response = requests.get(BOOTSTRAP_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            for tlds, urls in response.json().get("services", []):
                if not urls:
                    continue
                for tld in tlds:
                    self._services[tld.lower()] = urls[0].rstrip("/")
            logger.info(f"RDAP bootstrap loaded {len(self._services)} TLDs.")
        except Exception as e:
            logger.error(f"RDAP bootstrap failed: {str(e)[:100]}")

        return self._services

    def _server_for(self, domain: str) -> str | None:
        """Authoritative RDAP base URL for a domain's TLD, or None."""
        services = self._bootstrap()
        labels = domain.lower().strip(".").split(".")
        # Longest suffix first, so multi-label delegations win over the bare TLD.
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in services:
                return services[suffix]
        return None

    @staticmethod
    def _vcard(entity: dict, field: str) -> str:
        """Pulls one field out of an entity's jCard, which is nested positionally."""
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == field:
                value = item[3]
                if isinstance(value, list):
                    # Addresses arrive as an array of components.
                    return ", ".join(str(v) for v in value if v)
                return str(value)
        return ""

    def _registrar(self, entities: list) -> str:
        for entity in entities or []:
            if "registrar" in (entity.get("roles") or []):
                return self._vcard(entity, "fn") or entity.get("handle", "unknown")
        return "unknown"

    def _country(self, entities: list) -> str:
        # Registrant contacts are usually redacted post-GDPR, so this is often
        # absent. Registrar address is a weaker but sometimes present signal.
        for role in ("registrant", "administrative", "registrar"):
            for entity in entities or []:
                if role in (entity.get("roles") or []):
                    address = self._vcard(entity, "adr")
                    if address:
                        return address.split(",")[-1].strip() or "unknown"
        return "unknown"

    def _parse(self, data: dict, domain: str) -> dict:
        entities = data.get("entities") or []

        parsed = {
            "indicator": domain,
            "type": "domain",
            "source": "rdap",
            "registrar": self._registrar(entities),
            "creation_date": "unknown",
            "expiration_date": "unknown",
            "updated_date": "unknown",
            "nameservers": [
                ns.get("ldhName", "") for ns in data.get("nameservers") or []
                if ns.get("ldhName")
            ],
            "country": self._country(entities),
            # RDAP exposes these; port-43 WHOIS mostly does not.
            "statuses": data.get("status") or [],
            "dnssec": bool((data.get("secureDNS") or {}).get("delegationSigned")),
        }

        for event in data.get("events") or []:
            field = EVENT_FIELDS.get((event.get("eventAction") or "").lower())
            if field and event.get("eventDate"):
                parsed[field] = str(event["eventDate"])[:10]

        return parsed

    @staticmethod
    def _candidates(domain: str) -> list[str]:
        """
        The name as given, then progressively stripped toward the registrable
        domain.

        Registries hold records for registrable domains, not hostnames, so
        app.dinkfoundry.com returns 404 while dinkfoundry.com is a live
        Namecheap registration. Querying only the full name reported registered
        domains as unregistered whenever the seed was a subdomain, and the agent
        then explained the phantom discrepancy as possible "deliberate
        obfuscation".
        """
        labels = domain.lower().strip(".").split(".")
        candidates = []
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            candidates.append(candidate)
            # Stop once the next strip would leave a public suffix.
            remainder = ".".join(labels[i + 1:])
            if len(labels) - (i + 1) < 2 or remainder in PUBLIC_SUFFIXES_2LD:
                break
        return candidates

    def query_domain(self, domain: str) -> dict:
        """
        Queries the authoritative RDAP server for a domain.
        Returns an error dict when the TLD has no RDAP service or the lookup
        fails, so the caller can fall back to WHOIS.
        """
        server = self._server_for(domain)
        if not server:
            return {
                "error": "No RDAP service published for this TLD",
                "indicator": domain,
                "source": "rdap",
            }

        candidates = self._candidates(domain)
        try:
            for candidate in candidates:
                response = requests.get(
                    f"{server}/domain/{candidate}",
                    headers={"Accept": "application/rdap+json"},
                    timeout=REQUEST_TIMEOUT,
                )

                if response.status_code == 404:
                    continue

                response.raise_for_status()
                parsed = self._parse(response.json(), domain)
                if candidate != domain:
                    # The registration belongs to the parent, not the seed.
                    parsed["registrable_domain"] = candidate
                return parsed

            return {
                "indicator": domain,
                "type": "domain",
                "source": "rdap",
                "registrar": "unknown",
                "creation_date": "unknown",
                "expiration_date": "unknown",
                "updated_date": "unknown",
                "nameservers": [],
                "country": "unknown",
                "statuses": [],
                "dnssec": False,
                "queried": candidates,
                "note": (
                    "Not registered, or removed from the registry. Checked "
                    f"{len(candidates)} name(s) up to the registrable domain."
                ),
            }

        except Exception as e:
            logger.error(f"RDAP query failed for '{domain}': {str(e)[:100]}")
            return {"error": str(e)[:200], "indicator": domain, "source": "rdap"}
