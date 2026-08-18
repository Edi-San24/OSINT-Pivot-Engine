# connectors/spiderfoot.py
# SpiderFoot connector for the OSINT Pivot Engine.

# Requires SpiderFoot running locally on port 5001.
# Start with: docker run -p 5001:5001 spiderfoot


import requests
import logging
import time
 
logger = logging.getLogger(__name__)
 
from config import SPIDERFOOT_URL
 
 
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

        Success is a 303 redirect to /scaninfo?id=SCANID. A 200 means
        SpiderFoot re-rendered its own form instead of starting, which is how
        it reports a rejected target: no error, no status code, just the page.
        """
        try:
            response = requests.post(
                f"{self.base_url}/startscan",
                data={
                    "scanname": scan_name,
                    "scantarget": target,
                    # modulelist only. Sending usecase alongside it makes
                    # SpiderFoot ignore both and hand back the form page.
                    "usecase": "",
                    "modulelist": ",".join(modules),
                    "typelist": "",
                },
                timeout=15,
                allow_redirects=False
            )
            location = response.headers.get("Location", "")
            if "id=" in location:
                scan_id = location.split("id=")[-1]
                logger.info(f"SpiderFoot scan started: {scan_id}")
                return scan_id

            logger.error(
                f"SpiderFoot rejected target {target!r} (HTTP {response.status_code}, "
                "no redirect). It could not classify the target type."
            )
            return None
        except Exception as e:
            logger.error(f"Failed to start SpiderFoot scan: {str(e)[:100]}")
            return None
 
    # /scanstatus returns a flat row, and the status is its last field:
    #   ["name", "target", created, started, ended, "FINISHED"]
    # Indexing it as data[0][5] read character 5 of the scan name instead, so
    # the status never matched and every scan burned the full timeout before
    # reporting TIMEOUT. A three-second scan took five minutes.
    STATUS_INDEX = 5
    TERMINAL_STATUSES = ("FINISHED", "ABORTED", "ERROR-FAILED")

    def _poll_scan(self, scan_id: str, timeout: int = 300, interval: int = 2) -> str:
        """
        Polls until the scan reaches a terminal status or the timeout expires.
        Returns the final status, or TIMEOUT if it never settled.
        """
        elapsed = 0
        while elapsed < timeout:
            try:
                data = requests.get(
                    f"{self.base_url}/scanstatus/{scan_id}", timeout=10
                ).json()
                if isinstance(data, list) and len(data) > self.STATUS_INDEX:
                    status = str(data[self.STATUS_INDEX])
                    if status in self.TERMINAL_STATUSES:
                        logger.info(f"SpiderFoot scan {scan_id}: {status} after {elapsed}s")
                        return status
            except Exception:
                pass
            time.sleep(interval)
            elapsed += interval
        logger.warning(f"SpiderFoot scan {scan_id} still running after {timeout}s")
        return "TIMEOUT"

    def _module_errors(self, scan_id: str) -> list:
        """
        Collects module-level errors from the scan log.

        SpiderFoot reports a broken module in its log and finishes the scan
        normally, so without this a module failing looks identical to a module
        finding nothing.
        """
        try:
            log = requests.get(
                f"{self.base_url}/scanlog",
                params={"id": scan_id, "limit": 200},
                timeout=15,
            ).json()
        except Exception:
            return []

        errors = []
        for row in log:
            fields = [str(c) for c in row]
            if "ERROR" in fields:
                module = next((f for f in fields if f.startswith("sfp_")), "unknown")
                detail = fields[-1][:120]
                entry = f"{module}: {detail}"
                if entry not in errors:
                    errors.append(entry)
        return errors[:5]
 
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
 
    @staticmethod
    def _real_findings(results: list) -> list:
        """
        Drops the target's own ROOT event and the UI's echo of it.

        The previous filter compared r[4] (an integer score) against strings,
        so it excluded nothing and counted the target itself as a finding.
        An empty scan reported two findings.
        """
        return [
            r for r in results
            if len(r) > 7 and r[7] != "ROOT" and str(r[3]).startswith("sfp_")
        ]

    def query_email(self, email: str) -> dict:
        """
        Runs a SpiderFoot scan on an email address.
        Surfaces breach exposure, associated domains, and social accounts.
        """
        modules = [
            "sfp_haveibeenpwned",
            "sfp_hunter",
            "sfp_whois",
            "sfp_dnsresolve",
            "sfp_social",
        ]
 
        scan_id = self._start_scan(email, f"email_{email}", modules)
        if not scan_id:
            return {"error": "Failed to start scan", "indicator": email, "source": "spiderfoot"}
 
        status = self._poll_scan(scan_id, timeout=300)
        findings = self._real_findings(self._get_results(scan_id))

        return {
            "indicator": email,
            "type": "email",
            "source": "spiderfoot",
            "scan_status": status,
            "finding_count": len(findings),
            "findings": findings[:20],
            "module_errors": self._module_errors(scan_id),
        }
 
    def query_username(self, username: str) -> dict:
        """
        Runs a SpiderFoot scan on a username.
        Surfaces cross-platform presence and linked accounts.
        """
        # sfp_accounts is the broad username enumerator but is broken in
        # SpiderFoot 3.5.0 (it cannot parse the remote site list any more), so
        # it is kept for when that is fixed upstream and paired with modules
        # that work today.
        modules = [
            "sfp_accounts",
            "sfp_social",
            "sfp_github",
            "sfp_keybase",
            "sfp_instagram",
            "sfp_twitter",
        ]
 
        # SpiderFoot infers target type from the value, and a bare word is
        # unclassifiable, so it silently rejects it. Double quotes mark it as
        # a username. Emails and domains are self-describing and need none.
        scan_id = self._start_scan(f'"{username}"', f"username_{username}", modules)
        if not scan_id:
            return {"error": "Failed to start scan", "indicator": username, "source": "spiderfoot"}
 
        status = self._poll_scan(scan_id)
        findings = self._real_findings(self._get_results(scan_id))

        return {
            "indicator": username,
            "type": "username",
            "source": "spiderfoot",
            "scan_status": status,
            "finding_count": len(findings),
            "findings": findings[:20],
            "module_errors": self._module_errors(scan_id),
        }
 