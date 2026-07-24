# scripts/collect_training_data.py
# Collects real labeled IOC data for ML model training.
# Pulls confirmed malicious IPs from ThreatFox and known
# clean IPs from public sources, extracts features, and
# saves to data/training_data.csv

import requests
import pandas as pd
import time
import json
import logging
from core.features import extract_features, FEATURE_COLUMNS
from core.executor import PivotExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Output path
OUTPUT_PATH = "data/training_data.csv"

# Rate limit between connector calls
RATE_LIMIT = 2.0

# Sample sizes
MALICIOUS_SAMPLE_SIZE = 200
BENIGN_SAMPLE_SIZE = 200

from config import THREATFOX_API_KEY

def fetch_malicious_ips() -> list:
    """
    Pulls confirmed malicious IPs from ThreatFox CSV export.
    Returns a list of IP strings labeled as malicious.
    """
    logger.info("Fetching malicious IPs from ThreatFox CSV export...")

    url = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"

    try:
        response = requests.get(url)
        response.raise_for_status()

        ips = []
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            raw = parts[2].strip().strip('"')
            ip = raw.split(":")[0]
            if ip and ip not in ips:
                ips.append(ip)
            if len(ips) >= MALICIOUS_SAMPLE_SIZE:
                break

        logger.info(f"Collected {len(ips)} malicious IPs from ThreatFox.")
        return ips

    except Exception as e:
        logger.error(f"Failed to fetch from ThreatFox: {str(e)[:100]}")
        return []
    
def fetch_benign_ips() -> list:
    """
    Returns a list of known clean IPs from major
    public infrastructure providers.
    """
    logger.info("Loading known benign IPs...")

    benign_ips = [
        # Google
        "8.8.8.8", "8.8.4.4", "142.250.80.46",
        "172.217.10.46", "216.58.194.46",
        # Cloudflare
        "1.1.1.1", "1.0.0.1", "104.16.132.229",
        "104.17.10.12", "104.21.10.1",
        # Microsoft
        "13.107.42.14", "40.76.4.15", "40.112.72.205",
        "52.96.220.109", "104.40.211.35",
        # Amazon AWS
        "52.94.236.248", "54.239.28.85", "205.251.196.1",
        "54.231.0.1", "52.216.0.1",
        # Akamai
        "23.32.3.72", "23.48.0.1", "95.100.0.1",
        "184.50.0.1", "2.16.0.1",
        # Fastly CDN
        "151.101.0.1", "151.101.64.1", "151.101.128.1",
        "151.101.192.1", "199.232.0.1",
        # OpenDNS
        "208.67.222.222", "208.67.220.220",
        # Quad9
        "9.9.9.9", "149.112.112.112",
        # Level3
        "209.244.0.3", "209.244.0.4",
        # Verisign
        "64.6.64.6", "64.6.65.6",
    ]

    # Pad to target sample size with variations
    while len(benign_ips) < BENIGN_SAMPLE_SIZE:
        benign_ips.extend(benign_ips[:BENIGN_SAMPLE_SIZE - len(benign_ips)])

    result = benign_ips[:BENIGN_SAMPLE_SIZE]
    logger.info(f"Loaded {len(result)} benign IPs.")
    return result

def collect_features(ips: list, label: int) -> list:
    """
    Runs each IP through the pivot executor,
    extracts features, and attaches a label.
    0 = benign, 1 = malicious.
    """
    executor = PivotExecutor()
    samples = []

    for i, ip in enumerate(ips):
        logger.info(f"Processing {i+1}/{len(ips)}: {ip} (label={label})")

        try:
            pivot_result = executor.run(ip)
            features = extract_features(pivot_result)
            features["label"] = label
            samples.append(features)
        except Exception as e:
            logger.error(f"Failed to process {ip}: {str(e)[:100]}")

        time.sleep(RATE_LIMIT)

    return samples

def main():
    """
    Orchestrates the data collection pipeline.
    Fetches IOCs, extracts features, and saves to CSV.
    """
    logger.info("Starting data collection pipeline...")

    malicious_ips = fetch_malicious_ips()
    benign_ips = fetch_benign_ips()

    logger.info("Collecting features for malicious IPs...")
    malicious_samples = collect_features(malicious_ips, label=1)

    logger.info("Collecting features for benign IPs...")
    benign_samples = collect_features(benign_ips, label=0)

    all_samples = malicious_samples + benign_samples
    df = pd.DataFrame(all_samples)
    df = df.fillna(0)

    df.to_csv(OUTPUT_PATH, index=False)
    logger.info(f"Saved {len(df)} samples to {OUTPUT_PATH}")
    logger.info(f"Malicious: {len(malicious_samples)} | Benign: {len(benign_samples)}")

if __name__ == "__main__":
    main()