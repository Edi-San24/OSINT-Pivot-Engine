# core/features.py

# Feature engineering for engine: Extracts numerical
# signals from the pivot results for ML scoring. 

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

FEATURE_COLUMNS = [
    "malicious_votes",
    "harmless_votes",
    "malicious_ratio",
    "shodan_blocked",
    "dns_record_count",
    "total_open_ports",
    "high_risk_country",
]

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

    return {
        "malicious_votes" : malicious_votes,
        "harmless_votes": harmless_votes,
        "malicious_ratio": malicious_ratio,
        "shodan_blocked": shodan_blocked,
        "dns_record_count": dns_record_count,
        "total_open_ports": total_open_ports,
        "high_risk_country": high_risk_country,
    }

def build_feature_matrix(pivot_results: list) -> pd.DataFrame:
    """
    Converts a list of pivot results into a feature matrix.
    Returns a pandas DataFrame ready for ML model input.
    """
    features = [extract_features(result) for result in pivot_results]
    return pd.DataFrame(features)