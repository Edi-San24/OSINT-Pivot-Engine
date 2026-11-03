# connectors/cve.py
# Vulnerability context from NVD, CISA's Known Exploited Vulnerabilities catalog, and EPSS.

import logging
import threading
import time

import requests

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 30

# The catalog is one file covering every entry, so it is fetched once and reused
# across lookups. CISA republishes it a few times a week.
KEV_TTL_SECONDS = 6 * 3600

# Preferred CVSS version first. Within a version NVD's own Primary score wins
# over a vendor's Secondary one.
CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

MAX_PRODUCTS = 8
MAX_EXPLOIT_REFERENCES = 5

_kev_lock = threading.Lock()
_kev_cache = {"fetched": 0.0, "catalog": None}


def normalize(cve: str) -> str:
    """CVE IDs are case-insensitive, and every source indexes the uppercase form."""
    return (cve or "").strip().upper()


def _cvss(metrics: dict) -> dict | None:
    for key in CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData") or {}
        if data.get("baseScore") is None:
            continue
        return {
            "version": data.get("version") or key[len("cvssMetricV"):],
            "score": data.get("baseScore"),
            # Version 2 keeps severity beside the data rather than inside it.
            "severity": data.get("baseSeverity") or chosen.get("baseSeverity") or "unrated",
            "vector": data.get("vectorString", ""),
            "source": chosen.get("source", ""),
        }
    return None


def _ssvc(metrics: dict) -> dict:
    """CISA's own triage decision points, where it has recorded them."""
    for key, entries in metrics.items():
        if not key.startswith("ssvc"):
            continue
        for entry in entries or []:
            data = entry.get("ssvcData") or {}
            options = {}
            for option in data.get("options") or []:
                options.update(option)
            if options:
                return {**options, "role": data.get("role", ""),
                        "timestamp": data.get("timestamp", "")}
    return {}


def _products(cve: dict) -> list[str]:
    names = []
    for block in cve.get("affected") or []:
        for item in block.get("affectedData") or []:
            vendor, product = item.get("vendor", ""), item.get("product", "")
            # CNAs write "n/a" where they name no vendor.
            if vendor.strip().lower() == "n/a":
                vendor = ""
            if product and product.strip().lower() != "n/a":
                names.append(f"{vendor} {product}".strip())
    if not names:
        # Older records carry products only as CPE strings.
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    parts = (match.get("criteria") or "").split(":")
                    if len(parts) > 4:
                        names.append(f"{parts[3]} {parts[4]}".replace("_", " "))
    return list(dict.fromkeys(names))[:MAX_PRODUCTS]


def parse_nvd(payload: dict, cve_id: str) -> dict:
    """One NVD API response, reduced to what an analyst reads first."""
    base = {"indicator": cve_id, "type": "cve", "source": "nvd"}
    records = payload.get("vulnerabilities") or []
    if not records:
        # NVD answered and has nothing: reserved, never published, or mistyped.
        return {**base, "found": False}

    cve = records[0].get("cve") or {}
    english = next((d.get("value", "") for d in cve.get("descriptions") or []
                    if d.get("lang") == "en"), "")
    metrics = cve.get("metrics") or {}
    weaknesses = [d.get("value") for w in cve.get("weaknesses") or []
                  for d in w.get("description") or [] if d.get("value")]
    exploits = [r.get("url") for r in cve.get("references") or []
                if "Exploit" in (r.get("tags") or []) and r.get("url")]

    return {
        **base,
        "found": True,
        "status": cve.get("vulnStatus", "unknown"),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "description": english.split("\n\n")[0].strip(),
        # None rather than zero: an unscored record has no severity yet, which
        # is a different fact from a low one.
        "cvss": _cvss(metrics),
        "ssvc": _ssvc(metrics),
        "products": _products(cve),
        "cwes": list(dict.fromkeys(weaknesses)),
        "exploit_references": list(dict.fromkeys(exploits))[:MAX_EXPLOIT_REFERENCES],
        "reference_count": len(cve.get("references") or []),
    }


def kev_entry(catalog: dict, cve_id: str) -> dict:
    """Whether a fetched catalog lists this CVE, with the catalog it was checked against."""
    base = {"indicator": cve_id, "type": "cve", "source": "cisa_kev",
            "catalog_version": catalog.get("catalogVersion", ""),
            "catalog_count": catalog.get("count", len(catalog.get("vulnerabilities") or []))}
    for entry in catalog.get("vulnerabilities") or []:
        if normalize(entry.get("cveID")) == cve_id:
            return {
                **base,
                "found": True,
                "name": entry.get("vulnerabilityName", ""),
                "vendor": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "date_added": entry.get("dateAdded", ""),
                "due_date": entry.get("dueDate", ""),
                "required_action": entry.get("requiredAction", ""),
                "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
            }
    return {**base, "found": False}


def parse_epss(payload: dict, cve_id: str) -> dict:
    base = {"indicator": cve_id, "type": "cve", "source": "epss"}
    if payload.get("status") != "OK":
        return {**base, "error": f"EPSS status {payload.get('status')!r}"}
    rows = payload.get("data") or []
    if not rows:
        # A new CVE is not scored until the next daily model run.
        return {**base, "found": False}
    row = rows[0]
    return {
        **base,
        "found": True,
        "epss": float(row.get("epss", 0.0)),
        "percentile": float(row.get("percentile", 0.0)),
        "date": row.get("date", ""),
    }


class CVEConnector:
    """
    Three free sources, each answering a different question about a CVE: what
    it is (NVD), whether exploitation is confirmed (CISA KEV), and how likely it
    is in the next 30 days (EPSS).
    """

    def query_nvd(self, cve: str) -> dict:
        cve_id = normalize(cve)
        try:
            response = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                return {"indicator": cve_id, "source": "nvd",
                        "error": f"HTTP {response.status_code}: {response.text[:200]}"}
            return parse_nvd(response.json(), cve_id)
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"NVD lookup failed for {cve_id}: {str(e)[:100]}")
            return {"indicator": cve_id, "source": "nvd", "error": str(e)[:200]}

    def _catalog(self) -> dict:
        with _kev_lock:
            fresh = time.time() - _kev_cache["fetched"] < KEV_TTL_SECONDS
            if fresh and _kev_cache["catalog"]:
                return _kev_cache["catalog"]
            response = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            catalog = response.json()
            if not isinstance(catalog.get("vulnerabilities"), list):
                raise ValueError("catalog has no vulnerabilities list")
            _kev_cache.update(fetched=time.time(), catalog=catalog)
            return catalog

    def query_kev(self, cve: str) -> dict:
        """
        Listed or not, against a catalog that was actually fetched. A failed
        download is an error and never "not listed", since that would read as
        CISA having no exploitation on record.
        """
        cve_id = normalize(cve)
        try:
            return kev_entry(self._catalog(), cve_id)
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"KEV catalog fetch failed: {str(e)[:100]}")
            return {"indicator": cve_id, "source": "cisa_kev", "error": str(e)[:200]}

    def query_epss(self, cve: str) -> dict:
        cve_id = normalize(cve)
        try:
            response = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return parse_epss(response.json(), cve_id)
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"EPSS lookup failed for {cve_id}: {str(e)[:100]}")
            return {"indicator": cve_id, "source": "epss", "error": str(e)[:200]}
