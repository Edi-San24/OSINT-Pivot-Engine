# connectors/dns.py
# Live DNS — current resolution and wildcard behaviour, which passive DNS cannot show.

import logging
import random
import string

import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)

# Per-query and total budget. Kept well inside core.executor.REQUEST_TIMEOUT so
# an unresponsive authoritative server fails here first.
QUERY_TIMEOUT = 4
QUERY_LIFETIME = 6

RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX")

# Random label length for the wildcard probe. Long enough that a collision with
# a real host is not a practical concern.
PROBE_LABEL_LENGTH = 16


class DNSConnector:
    """
    Connector for live DNS lookups.
    No API key required. Reports what a name resolves to right now, plus
    whether its zone answers for any label at all.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = QUERY_TIMEOUT
        self.resolver.lifetime = QUERY_LIFETIME

    def _query(self, name: str, rtype: str) -> list[str]:
        try:
            answers = self.resolver.resolve(name, rtype)
            return sorted(str(r).rstrip(".") for r in answers)
        except Exception:
            # NXDOMAIN, NoAnswer, timeout — all mean "nothing to report here".
            return []

    def _zone_apex(self, domain: str) -> str | None:
        """
        The closest enclosing zone. Needed because a wildcard is a property of
        the zone, and a probe under the wrong name misses it: *.example.com
        answers for one label, so probing under a subdomain finds nothing.
        """
        try:
            return str(dns.resolver.zone_for_name(domain)).rstrip(".") or None
        except Exception:
            return None

    def _wildcard(self, domain: str) -> dict:
        """
        Resolves a random label under the zone apex. If it answers, the zone
        takes any name and the specific hostname is not a durable indicator —
        blocking has to happen at the apex instead.
        """
        apex = self._zone_apex(domain)
        if not apex:
            return {"checked": False, "reason": "zone apex could not be determined"}

        label = "".join(random.choices(string.ascii_lowercase + string.digits,
                                       k=PROBE_LABEL_LENGTH))
        probe = f"{label}.{apex}"
        addresses = self._query(probe, "A")

        return {
            "checked": True,
            "zone_apex": apex,
            "is_wildcard": bool(addresses),
            "probe": probe,
            "probe_resolved_to": addresses,
        }

    def query_domain(self, domain: str) -> dict:
        """
        Resolves a domain live and probes its zone for a wildcard.
        Records are current state only — core.passivedns covers history.
        """
        try:
            records = {rtype: self._query(domain, rtype) for rtype in RECORD_TYPES}
            resolves = bool(records["A"] or records["AAAA"] or records["CNAME"])

            result = {
                "indicator": domain,
                "type": "domain",
                "source": "dns",
                "resolves": resolves,
                "a": records["A"],
                "aaaa": records["AAAA"],
                "cname": records["CNAME"],
                "nameservers": records["NS"],
                "mx": records["MX"],
            }

            # Only meaningful for a name that answers; a dead domain tells us
            # nothing about its zone.
            result["wildcard"] = (
                self._wildcard(domain) if resolves
                else {"checked": False, "reason": "domain does not resolve"}
            )
            return result

        except Exception as e:
            logger.error(f"DNS query failed for '{domain}': {str(e)[:100]}")
            return {"error": str(e)[:200], "indicator": domain, "source": "dns"}

    def query_ip(self, ip: str) -> dict:
        """
        Reverse lookup for an IP. The PTR name often identifies the hosting
        tenant outright, which separates a customer box from attacker rented
        infrastructure.
        """
        try:
            pointer = dns.reversename.from_address(ip)
            names = self._query(str(pointer), "PTR")
            return {
                "indicator": ip,
                "type": "ipv4",
                "source": "dns",
                "ptr": names,
                "has_reverse": bool(names),
            }
        except Exception as e:
            logger.error(f"Reverse DNS failed for '{ip}': {str(e)[:100]}")
            return {"error": str(e)[:200], "indicator": ip, "source": "dns"}
