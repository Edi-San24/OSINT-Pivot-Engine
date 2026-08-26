# core/features.py

# Feature engineering for engine: Extracts numerical
# signals from the pivot results for ML scoring. 

from datetime import datetime, timezone

import pandas as pd
import numpy as np

HIGH_RISK_COUNTRIES = {
    # State sponsored/ APT origins
    "Russia", "China", "North Korea", "Iran",
    "Belarus", "Pakistan", "Syria",

    # "Bulletproof" hosting hubs
    "Moldova", "Seychelles", "Panama", "Latvia",

    # High volume cybercrime infrastructure
    "Nigeria", "Vietnam", "Romania", "Bulgaria",
    "Netherlands"
}

# Every feature here must come from a source anyone can run. DomainTools risk
# scores and DNSDB observation counts discriminate far better, but a model
# trained on them would be useless to anyone cloning this repo without those
# licences. Licensed data enriches the report and the agent's reasoning, where a
# missing source degrades gracefully instead of shifting a feature distribution.
FEATURE_COLUMNS = [
    "malicious_votes",
    "harmless_votes",
    "malicious_ratio",
    "shodan_blocked",
    "dns_record_count",
    "total_open_ports",
    "high_risk_country",
    # Added because the seven above collapse to one live signal on a domain
    # pivot: Shodan and Censys are IP services, so three of them are
    # structurally zero for every domain, and the VirusTotal trio is one number
    # counted three ways. All of the below come from RDAP, live DNS, OTX and
    # URLhaus — free, and available on a domain.
    "domain_age_days",
    "has_wildcard_dns",
    "nameserver_count",
    "has_mx",
    "otx_pulse_count",
    "urlhaus_listed",
    # Whether the age above is a measurement or a blank. Without this, a lookup
    # failure and a domain registered today are both 0, and a source that fails
    # more often on one class teaches the model its own outage.
    "domain_age_known",
]

# Cap on domain age, so a 1995 registration and a 2010 one are both simply
# "long established" rather than dominating the scale.
MAX_AGE_DAYS = 3650


def _age_days(created: str) -> int:
    """
    Days since registration, 0 when unknown.

    Free from RDAP, and the single most discriminating signal available on a
    domain: an eleven-day-old Dynadot registration and a seven-year-old business
    site are indistinguishable to a VirusTotal ratio.
    """
    if not created or created in ("unknown", ""):
        return 0
    text = str(created)[:10]
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"):
        try:
            when = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return max(0, min((datetime.now(timezone.utc) - when).days, MAX_AGE_DAYS))
        except ValueError:
            continue
    return 0

def extract_features(pivot_result: dict) -> dict:
    """
    Extracts numerical features from a single pivot result.
    Returns a flat dictionary of features for ML scoring. 
    """
    
    results = pivot_result.get("results", {})

    # VirusTotal features 
    vt = results.get("virustotal", {})
    malicious_votes = vt.get("malicious_votes", 0)
    harmless_votes = vt.get("harmless_votes", 0)
    total_votes = malicious_votes + harmless_votes
    malicious_ratio = malicious_votes / total_votes if total_votes > 0 else 0

    # Shodan features 
    shodan = results.get("shodan", {})
    shodan_blocked = 1 if "error" in shodan else 0
    open_ports_shodan = len(shodan.get("open_ports", []))

    # PassiveDNS features
    passivedns = results.get("passivedns", {})
    dns_record_count = passivedns.get("record_count", 0)

    # Censys features 
    censys = results.get("censys", {})
    open_ports_censys = len(censys.get("open_ports", []))
    country = censys.get("country", "unknown")
    high_risk_country = 1 if country in HIGH_RISK_COUNTRIES else 0

    # Combined port signal
    total_open_ports = max(open_ports_shodan, open_ports_censys)

    # Registration age, from whichever of RDAP or WHOIS answered.
    registration = results.get("whois", {}) or {}
    domain_age_days = _age_days(
        registration.get("creation_date") or registration.get("created")
    )
    domain_age_known = 1 if domain_age_days else 0

    # Live DNS shape. A wildcard zone means every hostname resolves, which is
    # how generated attacker hostnames behave — though cPanel sets one by
    # default, so it is a weak signal on its own rather than a tell.
    live = results.get("dns", {}) or {}
    wildcard = (live.get("wildcard") or {}).get("is_wildcard")
    has_wildcard_dns = 1 if wildcard else 0
    nameserver_count = len(live.get("nameservers") or [])
    has_mx = 1 if (live.get("mx") or []) else 0

    # Community reporting and known malicious URLs.
    otx_pulse_count = (results.get("otx", {}) or {}).get("pulse_count", 0) or 0
    urlhaus_listed = 1 if (results.get("urlhaus", {}) or {}).get("found") else 0

    return {
        "malicious_votes" : malicious_votes,
        "harmless_votes": harmless_votes,
        "malicious_ratio": malicious_ratio,
        "shodan_blocked": shodan_blocked,
        "dns_record_count": dns_record_count,
        "total_open_ports": total_open_ports,
        "high_risk_country": high_risk_country,
        "domain_age_days": domain_age_days,
        "has_wildcard_dns": has_wildcard_dns,
        "nameserver_count": nameserver_count,
        "has_mx": has_mx,
        "otx_pulse_count": otx_pulse_count,
        "urlhaus_listed": urlhaus_listed,
        "domain_age_known": domain_age_known,
    }

def build_feature_matrix(pivot_results: list) -> pd.DataFrame:
    """
    Converts a list of pivot results into a feature matrix.
    Returns a pandas DataFrame ready for ML model input.
    """
    features = [extract_features(result) for result in pivot_results]
    return pd.DataFrame(features)