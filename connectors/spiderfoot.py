# connectors/spiderfoot.py
# SpiderFoot connector for the OSINT Pivot Engine.

# Requires SpiderFoot running locally on port 5001.
# Start with: docker run -p 5001:5001 spiderfoot


import requests
import logging
import time
 
logger = logging.getLogger(__name__)
 
SPIDERFOOT_URL = "http://127.0.0.1:5001"
 
 
class SpiderFootConnector:
    """
    Connector for the local SpiderFoot instance.
    Submits a scan target and polls for results.
    Supports email and username indicators — filling the
    analytical blind spots not covered by other connectors.
    """
 
    def __init__(self):
        self.base_url = SPIDERFOOT_URL
        self._check_connection()
 
    def _check_connection(self):
        """Verifies SpiderFoot is running before initializing."""
        try:
            response = requests.get(f"{self.base_url}", timeout=5)
            if response.status_code == 200:
                logger.info("SpiderFoot connection established.")
        except Exception:
            logger.warning("SpiderFoot not reachable at 127.0.0.1:5001. Start with: docker run -p 5001:5001 spiderfoot")
 
    def _start_scan(self, target: str, scan_name: str, modules: list) -> str | None:
        """
        Starts a SpiderFoot scan and returns the scan ID.
        SpiderFoot returns a redirect to /scaninfo?id=SCANID on success.
        """
        try:
            response = requests.post(
                f"{self.base_url}/startscan",
                data={
                    "scanname": scan_name,
                    "scantarget": target,
                    "usecase": "all",
                    "modulelist": ",".join(modules),
                    "typelist": "",
                },
                timeout=15,
                allow_redirects=False
            )
            # SpiderFoot returns a redirect to /scaninfo?id=SCANID
            location = response.headers.get("Location", "")
            if "id=" in location:
                scan_id = location.split("id=")[-1]
                logger.info(f"SpiderFoot scan started: {scan_id}")
                return scan_id
            return None
        except Exception as e:
            logger.error(f"Failed to start SpiderFoot scan: {str(e)[:100]}")
            return None
 
    def _poll_scan(self, scan_id: str, timeout: int = 300) -> str:
        """
        Polls SpiderFoot until scan completes or timeout is reached.
        Returns final scan status.
        """
        elapsed = 0
        while elapsed < timeout:
            try:
                response = requests.get(
                    f"{self.base_url}/scanstatus/{scan_id}",
                    timeout=10
                )
                data = response.json()
                status = data[0][5] if data else ""
                if status in ("FINISHED", "ABORTED", "ERROR-FAILED"):
                    return status
            except Exception:
                pass
            time.sleep(5)
            elapsed += 5
        return "TIMEOUT"
 
    def _get_results(self, scan_id: str) -> list:
        """
        Retrieves scan results from SpiderFoot.
        Returns a list of result dicts.
        """
        try:
            response = requests.get(
                f"{self.base_url}/scaneventresults/{scan_id}/ALL",
                timeout=15
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to retrieve SpiderFoot results: {str(e)[:100]}")
            return []
 
    def query_email(self, email: str) -> dict:
        """
        Runs a SpiderFoot scan on an email address.
        Surfaces breach exposure, associated domains, and social accounts.
        """
        modules = [
            "sfp_haveibeenpwned",
            "sfp_hunter",
            "sfp_whois",
            "sfp_dns",
            "sfp_social",
        ]
 
        scan_id = self._start_scan(email, f"email_{email}", modules)
        if not scan_id:
            return {"error": "Failed to start scan", "indicator": email, "source": "spiderfoot"}
 
        status = self._poll_scan(scan_id, timeout=300)
        results = self._get_results(scan_id)
        findings = [r for r in results if r[4] not in ("ERROR", "")]
 
        return {
            "indicator": email,
            "type": "email",
            "source": "spiderfoot",
            "scan_status": status,
            "finding_count": len(findings),
            "findings": findings[:20],
        }
 
    def query_username(self, username: str) -> dict:
        """
        Runs a SpiderFoot scan on a username.
        Surfaces cross-platform presence and linked accounts.
        """
        modules = [
            "sfp_accounts",
            "sfp_social",
            "sfp_github",
        ]
 
        scan_id = self._start_scan(username, f"username_{username}", modules)
        if not scan_id:
            return {"error": "Failed to start scan", "indicator": username, "source": "spiderfoot"}
 
        status = self._poll_scan(scan_id)
        results = self._get_results(scan_id)
        findings = [r for r in results if r[4] not in ("ERROR", "")]
 
        return {
            "indicator": username,
            "type": "username",
            "source": "spiderfoot",
            "scan_status": status,
            "finding_count": len(findings),
            "findings": findings[:20],
        }
 