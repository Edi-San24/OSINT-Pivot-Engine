# connectors: censys.py
# Performs the following: Queries IP addresses for host & certificate data. 

import requests
from config import CENSYS_API_KEY, MAX_RESULTS_PER_SOURCE
from connectors.retry import get_with_retry

import logging
logger = logging.getLogger(__name__)

class CensysConnector:
    """
    Connector for the Censys Platform API.
    Supports IP address lookups for host data and open services.
    """

    BASE_URL = "https://api.platform.censys.io/v3/global"

    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {CENSYS_API_KEY}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json"
        }

    @staticmethod
    def _explain(response, indicator: str) -> dict:
        """
        Turns a Censys failure into something an analyst can act on.

        A 422 here carries {"errors":[{"message":"insufficient balance"}]} — the
        account is out of credits, not the request malformed. Reported plainly
        because "422 Unprocessable Entity" reads like a code fault and sent me
        looking for an API contract change that had not happened.
        """
        detail = ""
        try:
            body = response.json()
            detail = "; ".join(
                e.get("message", "") for e in (body.get("errors") or [])
            ) or body.get("detail", "")
        except Exception:
            detail = (response.text or "")[:120]

        if "balance" in detail.lower() or "quota" in detail.lower():
            detail = f"{detail} — Censys account has no remaining credits"

        return {
            "error": f"HTTP {response.status_code}: {detail}"[:200],
            "indicator": indicator,
            "source": "censys",
        }

    def query_ip(self, ip: str) -> dict:
        """
        Queries Censys for a given IP address.
        Returns host data, open ports, and services or an error dict.
        """
        url = f"{self.BASE_URL}/asset/host/{ip}"

        try:
            response = requests.get(url, headers=self.headers, timeout=20)
            if not response.ok:
                return self._explain(response, ip)
            response.raise_for_status()
            data = response.json()

            resource = data.get("result", {}).get("resource", {})
            services = resource.get("services", [])[:MAX_RESULTS_PER_SOURCE]

            return {
                "indicator": ip,
                "type": "ipv4",
                "source": "censys",
                "autonomous_system": resource.get("autonomous_system", {}).get("name", "unknown"),
                "country": resource.get("location", {}).get("country", "unknown"),
                "open_ports": [s.get("port") for s in services],
                "services": [
                    {
                        "port": s.get("port", "unknown"),
                        "service_name": s.get("protocol", "unknown"),
                        "transport": s.get("transport_protocol", "unknown"),
                    }
                    for s in services
                ]
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": ip, "source": "censys"}
        
    def query_domain(self, domain: str) -> dict:
        """
        Queries Censys for a given domain.
        Returns host data and services or an error dict.
        """
        url = f"{self.BASE_URL}/asset/host/{domain}"

        try:
            response = requests.get(url, headers=self.headers, timeout=20)
            if not response.ok:
                return self._explain(response, domain)
            response.raise_for_status()
            data = response.json()

            resource = data.get("result", {}).get("resource", {})
            services = resource.get("services", [])[:MAX_RESULTS_PER_SOURCE]

            return {
                "indicator": domain,
                "type": "domain",
                "source": "censys",
                "autonomous_system": resource.get("autonomous_system", {}).get("name", "unknown"),
                "country": resource.get("location", {}).get("country", "unknown"),
                "open_ports": [s.get("port") for s in services],
                "services": [
                    {
                        "port": s.get("port", "unknown"),
                        "service_name": s.get("protocol", "unknown"),
                        "transport": s.get("transport_protocol", "unknown"),
                    }
                    for s in services
                ]
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e), "indicator": domain, "source": "censys"}
        
    def query_domain_certificates(self, domain: str) -> dict:
        """
        Queries crt.sh certificate transparency logs for a domain.
        Returns TLS certificate data and associated names.

        Retries a 5xx as well as a timeout. The old retry fired only on
        Timeout, so the frequent failure never reached it: a 502 raises
        HTTPError from raise_for_status and went straight out the bottom.
        """
        url = f"https://crt.sh/?q={domain}&output=json"

        try:
            response = get_with_retry(url, timeout=45, source="crt.sh")

            if response.status_code == 404:
                return {
                    "indicator": domain,
                    "type": "domain",
                    "source": "crt.sh",
                    "certificate_count": 0,
                    "certificates": [],
                    "note": "No certificate records found."
                }

            response.raise_for_status()
            certs = response.json()[:5]

            return {
                "indicator": domain,
                "type": "domain",
                "source": "crt.sh",
                "certificate_count": len(certs),
                "certificates": [
                    {
                        "issuer": c.get("issuer_name", "unknown"),
                        "names": c.get("name_value", "unknown"),
                        "not_before": c.get("not_before", "unknown"),
                        "not_after": c.get("not_after", "unknown"),
                    }
                    for c in certs
                ]
            }

        # Carries an error key on purpose. This used to return
        # certificate_count 0 with only a note, so an exhausted retry was
        # indistinguishable from a domain with no certificates: it never
        # appeared as a visibility gap, and the subdomains it failed to fetch
        # read as subdomains that did not exist.
        except requests.exceptions.Timeout:
            return {
                "error": "crt.sh timed out after 2 attempts",
                "indicator": domain,
                "source": "crt.sh",
                "certificate_count": 0,
                "certificates": [],
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e)[:200], "indicator": domain, "source": "crt.sh"}