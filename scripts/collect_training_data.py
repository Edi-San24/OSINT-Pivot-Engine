# scripts/collect_training_data.py
# Collects real labeled IOC data for ML model training.
# Pulls confirmed malicious IPs from ThreatFox, Feodo Tracker, and URLhaus,
# and diverse benign IPs including Tor exit nodes and shared hosting,
# extracts features, and saves to data/training_data.csv

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import pandas as pd
import time
import random
import logging
from urllib.parse import urlparse
from core.features import extract_features, FEATURE_COLUMNS
from core.executor import PivotExecutor
from config import DATA_DIR

# Dedicated logger — avoids conflict with executor's logging config.
# propagate=False is load-bearing: importing PivotExecutor runs
# logging.basicConfig(), which attaches a handler to the root logger. Without
# this, every record is emitted by both handlers and prints twice.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.propagate = False
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# Output path — matches where core/trainer.py reads from
OUTPUT_PATH = os.path.join(DATA_DIR, "training_data.csv")

# Rate limit between connector calls
RATE_LIMIT = 2.0

# Sample sizes
MALICIOUS_SAMPLE_SIZE = 200
BENIGN_SAMPLE_SIZE = 200

from config import THREATFOX_API_KEY


def fetch_malicious_ips() -> list:
    """
    Pulls confirmed malicious IPs from multiple threat feeds
    to create a diverse and challenging malicious training set.
    Sources: ThreatFox, Feodo Tracker, URLhaus.
    """
    logger.info("Fetching malicious IPs from multiple threat feeds...")

    ips = []

    # Source 1 — ThreatFox recent C2 IPs
    try:
        logger.info("Fetching from ThreatFox...")
        response = requests.get(
            "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
            timeout=15
        )
        response.raise_for_status()
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            raw = parts[2].strip().strip('"')
            ip = raw.split(":")[0]
            if ip and ip not in ips:
                ips.append(ip)
            if len(ips) >= 80:
                break
        logger.info(f"ThreatFox: {len(ips)} IPs collected.")
    except Exception as e:
        logger.warning(f"ThreatFox failed: {str(e)[:100]}")

    # Source 2 — Feodo Tracker botnet C2s
    try:
        logger.info("Fetching from Feodo Tracker...")
        before = len(ips)
        response = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            timeout=15
        )
        response.raise_for_status()
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            ip = line.strip()
            if ip and ip not in ips:
                ips.append(ip)
            if len(ips) >= 160:
                break
        logger.info(f"Feodo Tracker: {len(ips) - before} IPs added.")
    except Exception as e:
        logger.warning(f"Feodo Tracker failed: {str(e)[:100]}")

    # Source 3 — URLhaus malware delivery IPs
    try:
        logger.info("Fetching from URLhaus...")
        before = len(ips)
        response = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=15
        )
        response.raise_for_status()
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            url = parts[2].strip().strip('"')
            try:
                host = urlparse(url).hostname
                if host and host[0].isdigit() and host not in ips:
                    ips.append(host)
            except Exception:
                continue
            if len(ips) >= MALICIOUS_SAMPLE_SIZE:
                break
        logger.info(f"URLhaus: {len(ips) - before} IPs added.")
    except Exception as e:
        logger.warning(f"URLhaus failed: {str(e)[:100]}")

    ips = list(dict.fromkeys(ips))[:MALICIOUS_SAMPLE_SIZE]
    logger.info(f"Total malicious IPs collected: {len(ips)}")
    return ips


def fetch_benign_ips() -> list:
    """
    Returns a diverse set of benign IPs including obvious clean
    infrastructure, Tor exit nodes, and shared hosting to create
    a more realistic and challenging training set.
    """
    logger.info("Fetching benign IPs from multiple sources...")

    benign_ips = []

    # Anchor IPs — obvious benign infrastructure
    anchors = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112", "208.67.222.222",
        "208.67.220.220", "209.244.0.3", "64.6.64.6",
    ]
    benign_ips.extend(anchors)

    # Tor exit nodes — look suspicious but are benign infrastructure
    try:
        logger.info("Fetching Tor exit node list...")
        response = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            timeout=15
        )
        if response.status_code == 200:
            tor_ips = [
                line.strip() for line in response.text.splitlines()
                if line.strip() and not line.startswith("#")
            ]
            random.shuffle(tor_ips)
            benign_ips.extend(tor_ips[:60])
            logger.info(f"Added {min(60, len(tor_ips))} Tor exit nodes.")
    except Exception as e:
        logger.warning(f"Could not fetch Tor list: {str(e)[:100]}")

    # Shared hosting IPs — mixed reputation, ambiguous
    shared_hosting = [
        "198.54.117.197", "198.54.117.198", "198.54.117.199",
        "198.54.117.200", "198.54.117.201",
        "162.241.224.4", "162.241.224.5", "162.241.224.6",
        "192.185.25.1", "192.185.25.2", "192.185.25.3",
        "160.153.128.10", "160.153.128.11", "160.153.128.12",
        "193.169.145.20", "193.169.145.21", "193.169.145.22",
    ]
    benign_ips.extend(shared_hosting)

    # Academic and government infrastructure
    academic = [
        "128.112.136.11", "18.7.22.69", "171.67.215.200",
        "169.229.131.81", "128.95.155.135", "192.20.225.10",
        "199.43.135.53", "192.5.6.30",
    ]
    benign_ips.extend(academic)

    benign_ips = list(dict.fromkeys(benign_ips))

    while len(benign_ips) < BENIGN_SAMPLE_SIZE:
        benign_ips.extend(benign_ips[:BENIGN_SAMPLE_SIZE - len(benign_ips)])

    result = benign_ips[:BENIGN_SAMPLE_SIZE]
    logger.info(f"Collected {len(result)} diverse benign IPs.")
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

    if os.path.exists(OUTPUT_PATH):
        existing = pd.read_csv(OUTPUT_PATH)
        df = pd.concat([existing, df], ignore_index=True).drop_duplicates()
        logger.info(f"Appended to existing dataset. Total samples: {len(df)}")

    df.to_csv(OUTPUT_PATH, index=False)
    logger.info(f"Saved {len(df)} samples to {OUTPUT_PATH}")
    logger.info(f"Malicious: {len(malicious_samples)} | Benign: {len(benign_samples)}")


main()