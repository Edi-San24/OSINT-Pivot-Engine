# scripts/collect_training_data.py
# Collects real labeled IOC data for ML model training.
# Pulls confirmed malicious IPs from ThreatFox, Feodo Tracker, and URLhaus,
# and diverse benign IPs including Tor exit nodes and shared hosting,
# extracts features, and saves to data/training_data.csv

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import socket
import threading

import requests
import pandas as pd
import time
import random
import logging
from urllib.parse import urlparse
from core.features import extract_features, FEATURE_COLUMNS
from core.executor import PivotExecutor, _run_parallel
from config import DATA_DIR, THREATFOX_API_KEY

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

# Delay between IPs, set by the slowest quota in the fan-out.
#
# VirusTotal's free tier allows 4 requests per minute. A 2.0s delay is 30/min,
# which 429s on essentially every call. The connector turns that error into
# zeroed features, so the run still "succeeds" and quietly writes rows saying a
# confirmed C2 has no VirusTotal detections. One run at 2.0s added 37 such rows
# and dropped cross-validated ROC-AUC from 0.91 to 0.84.
#
# 16s is 3.75/min, just under the limit. 365 IPs takes about 100 minutes. Raise
# this only if you are on a paid VirusTotal tier.
RATE_LIMIT = 16.0

# Rows whose VirusTotal lookup failed are dropped rather than written with
# zeros. Pacing alone is not enough: a transient 429 or outage would otherwise
# still poison the labels, and three of seven features come from VirusTotal.
REQUIRE_VIRUSTOTAL = True

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


# Tor exits are genuinely benign infrastructure that looks malicious to
# reputation feeds, so a few are worth teaching. Previously they were 60 of
# only 95 unique benign IPs, which meant 55% of the benign class carried three
# or more VirusTotal detections. malicious_ratio then had to separate classes
# that barely differed on it, while carrying half the model's weight.
BENIGN_TOR_CAP = 20

# Resolved live rather than hardcoded, which gives real and varied hosting:
# CDN edges, cloud front ends, and corporate infrastructure.
CLEAN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "reddit.com", "x.com", "instagram.com", "linkedin.com", "netflix.com",
    "microsoft.com", "apple.com", "office.com", "live.com", "bing.com",
    "github.com", "gitlab.com", "stackoverflow.com", "python.org", "npmjs.com",
    "docker.com", "kubernetes.io", "mozilla.org", "debian.org", "ubuntu.com",
    "redhat.com", "apache.org", "nginx.org", "cloudflare.com", "fastly.com",
    "akamai.com", "digitalocean.com", "linode.com", "heroku.com", "vercel.com",
    "netlify.com", "atlassian.com", "slack.com", "zoom.us", "dropbox.com",
    "salesforce.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
    "adobe.com", "shopify.com", "stripe.com", "paypal.com", "visa.com",
    "mastercard.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "nytimes.com", "bbc.co.uk", "theguardian.com", "reuters.com", "cnn.com",
    "npr.org", "economist.com", "ft.com", "bloomberg.com", "wsj.com",
    "harvard.edu", "mit.edu", "stanford.edu", "berkeley.edu", "ox.ac.uk",
    "cam.ac.uk", "ethz.ch", "cern.ch", "nasa.gov", "nih.gov",
    "cdc.gov", "noaa.gov", "usa.gov", "europa.eu", "who.int",
    "un.org", "ietf.org", "iana.org", "icann.org", "w3.org",
    "archive.org", "wikimedia.org", "creativecommons.org", "eff.org", "fsf.org",
    "spotify.com", "twitch.tv", "vimeo.com", "soundcloud.com", "imdb.com",
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com", "uber.com",
    "ebay.com", "etsy.com", "walmart.com", "target.com", "costco.com",
    "wordpress.org", "wix.com", "squarespace.com", "godaddy.com", "namecheap.com",
    "zendesk.com", "hubspot.com", "mailchimp.com", "twilio.com", "sendgrid.com",
]


# Whole-batch ceiling on DNS. Most lookups take milliseconds, but
# socket.gethostbyname accepts no timeout and a single unanswerable domain can
# block for minutes. Threads are daemons and the batch is bounded, so a
# straggler is abandoned rather than stalling the run or interpreter exit.
DNS_BATCH_TIMEOUT = 25


def _resolve_domains(domains: list, timeout: int = DNS_BATCH_TIMEOUT) -> list:
    """
    Resolves domains to IPs concurrently, bounded overall.

    Failures and stragglers are skipped rather than substituted. A slightly
    smaller benign set is fine; a wrong IP in the benign class is not.
    """
    resolved: dict = {}
    lock = threading.Lock()

    def one(domain):
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return
        with lock:
            resolved[domain] = ip

    threads = [threading.Thread(target=one, args=(d,), daemon=True) for d in domains]
    for t in threads:
        t.start()

    deadline = time.time() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.time()))

    missed = len(domains) - len(resolved)
    if missed:
        logger.warning(f"{missed} domains failed to resolve or exceeded {timeout}s.")
    return list(resolved.values())


def fetch_benign_ips() -> list:
    """
    Builds the benign set from live resolution of well-known domains, plus a
    capped number of Tor exits, shared hosting, and public resolvers.

    Never pads by duplication. The previous version repeated its own list to
    reach the target size, so more than half the benign samples were copies of
    the same 95 addresses. Returning fewer real samples beats inflating the
    count with duplicates.
    """
    logger.info("Building benign set...")
    benign_ips = []

    # Public DNS resolvers, unambiguously clean
    benign_ips.extend([
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112", "208.67.222.222",
        "208.67.220.220", "209.244.0.3", "64.6.64.6",
    ])

    # The bulk of the class: real hosting behind well-known domains
    resolved = _resolve_domains(CLEAN_DOMAINS)
    logger.info(f"Resolved {len(resolved)}/{len(CLEAN_DOMAINS)} clean domains.")
    benign_ips.extend(resolved)

    # Shared hosting, ambiguous reputation by design
    benign_ips.extend([
        "198.54.117.197", "198.54.117.198", "198.54.117.199",
        "198.54.117.200", "198.54.117.201",
        "162.241.224.4", "162.241.224.5", "162.241.224.6",
        "192.185.25.1", "192.185.25.2", "192.185.25.3",
        "160.153.128.10", "160.153.128.11", "160.153.128.12",
        "193.169.145.20", "193.169.145.21", "193.169.145.22",
    ])

    # Academic and government
    benign_ips.extend([
        "128.112.136.11", "18.7.22.69", "171.67.215.200",
        "169.229.131.81", "128.95.155.135", "192.20.225.10",
        "199.43.135.53", "192.5.6.30",
    ])

    # Tor exits last and capped, so they are a minority voice rather than the
    # dominant definition of "benign"
    try:
        response = requests.get(
            "https://check.torproject.org/torbulkexitlist", timeout=15
        )
        if response.status_code == 200:
            tor_ips = [
                line.strip() for line in response.text.splitlines()
                if line.strip() and not line.startswith("#")
            ]
            random.shuffle(tor_ips)
            benign_ips.extend(tor_ips[:BENIGN_TOR_CAP])
            logger.info(f"Added {min(BENIGN_TOR_CAP, len(tor_ips))} Tor exit nodes (capped).")
    except Exception as e:
        logger.warning(f"Could not fetch Tor list: {str(e)[:100]}")

    unique = list(dict.fromkeys(benign_ips))[:BENIGN_SAMPLE_SIZE]
    tor_share = min(BENIGN_TOR_CAP, len(unique)) / max(len(unique), 1)
    logger.info(
        f"Collected {len(unique)} unique benign IPs, no duplicates. "
        f"Tor exits at most {tor_share:.0%} of the class."
    )
    return unique


def collect_features(ips: list, label: int) -> list:
    """
    Extracts features for each IP and attaches a label. 0 = benign, 1 = malicious.

    Queries only the four connectors that extract_features actually reads.
    The full pivot also fires Ahmia, URLhaus and OTX, none of which contribute
    a single feature, and Ahmia launches a headless browser per IP. Collecting
    400 samples through the full pivot took twelve hours.
    """
    executor = PivotExecutor()
    samples = []
    skipped = 0

    for i, ip in enumerate(ips):
        logger.info(f"Processing {i+1}/{len(ips)}: {ip} (label={label})")

        try:
            results = _run_parallel({
                "virustotal": lambda ip=ip: executor.vt.query_ip(ip),
                "shodan": lambda ip=ip: executor.shodan.query_ip(ip),
                "passivedns": lambda ip=ip: executor.passivedns.query_ip(ip),
                "censys": lambda ip=ip: executor.censys.query_ip(ip),
            })

            vt_error = results.get("virustotal", {}).get("error")
            if REQUIRE_VIRUSTOTAL and vt_error:
                skipped += 1
                logger.warning(f"  skipped {ip}: VirusTotal {str(vt_error)[:60]}")
                time.sleep(RATE_LIMIT)
                continue

            features = extract_features({"indicator": ip, "type": "ipv4", "results": results})
            features["label"] = label
            samples.append(features)
        except Exception as e:
            logger.error(f"Failed to process {ip}: {str(e)[:100]}")

        time.sleep(RATE_LIMIT)

    if skipped:
        logger.warning(
            f"Skipped {skipped}/{len(ips)} IPs with no VirusTotal data. "
            "Sustained skips mean rate limiting; raise RATE_LIMIT."
        )
    return samples


# Separate file, because a domain row and an IP row are not interchangeable.
# Three of the seven original features come from Shodan and Censys, which are IP
# services the domain pivot never calls, so they are structurally zero on every
# domain. A model trained on IP rows and served domain rows loses a third of its
# learned signal to that mismatch — which is what the live engine was doing.
DOMAIN_OUTPUT_PATH = os.path.join(DATA_DIR, "training_data_domains.csv")


def fetch_malicious_domains(limit: int = MALICIOUS_SAMPLE_SIZE) -> list:
    """
    Recent malicious domains from ThreatFox and URLhaus.

    Both are free and same-day. URLhaus entries are URLs, so only the host is
    kept — the feature set describes a domain, not a path.
    """
    from urllib.parse import urlparse

    domains: list[str] = []

    try:
        headers = {"Auth-Key": THREATFOX_API_KEY} if THREATFOX_API_KEY else {}
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 7},
            headers=headers, timeout=60,
        )
        for row in (response.json().get("data") or []):
            if row.get("ioc_type") not in ("domain", "url"):
                continue
            value = row.get("ioc") or ""
            host = urlparse(value).hostname if "://" in value else value.split("/")[0]
            host = (host or "").split(":")[0].strip().lower()
            if host and "." in host and not host.replace(".", "").isdigit():
                domains.append(host)
        logger.info(f"ThreatFox returned {len(domains)} candidate domains.")
    except Exception as e:
        logger.warning(f"ThreatFox fetch failed: {str(e)[:100]}")

    try:
        response = requests.get(
            "https://urlhaus.abuse.ch/downloads/text_recent/", timeout=60
        )
        added = 0
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = (urlparse(line).hostname or "").split(":")[0].strip().lower()
            if host and "." in host and not host.replace(".", "").isdigit():
                domains.append(host)
                added += 1
        logger.info(f"URLhaus added {added} candidate domains.")
    except Exception as e:
        logger.warning(f"URLhaus fetch failed: {str(e)[:100]}")

    random.shuffle(domains)
    unique = list(dict.fromkeys(domains))[:limit]
    logger.info(f"Collected {len(unique)} unique malicious domains.")
    return unique


def fetch_benign_domains(limit: int = BENIGN_SAMPLE_SIZE) -> list:
    """
    The clean domain list, used directly rather than resolved to addresses.
    Never padded by duplication — a smaller real set beats an inflated one.
    """
    unique = list(dict.fromkeys(d.lower() for d in CLEAN_DOMAINS))[:limit]
    logger.info(f"Collected {len(unique)} benign domains.")
    return unique


def collect_domain_features(domains: list, label: int) -> list:
    """
    Extracts features for each domain and attaches a label.

    Queries exactly the connectors that feed a domain feature: VirusTotal, RDAP
    with WHOIS fallback for registration age, live DNS, passive DNS, OTX and
    URLhaus. Shodan and Censys are skipped because they cannot answer for a
    domain, and Ahmia because it launches a headless browser per lookup and
    contributes no feature.
    """
    executor = PivotExecutor()
    samples = []
    skipped = 0

    for i, domain in enumerate(domains):
        logger.info(f"Processing {i+1}/{len(domains)}: {domain} (label={label})")

        try:
            results = _run_parallel({
                "virustotal": lambda d=domain: executor.vt.query_domain(d),
                "whois": lambda d=domain: executor._registration(d),
                "dns": lambda d=domain: executor.dns.query_domain(d),
                "passivedns": lambda d=domain: executor.passivedns.query_domain(d),
                "otx": lambda d=domain: executor.otx.query_indicator(d, "domain"),
                "urlhaus": lambda d=domain: executor.urlhaus.query_host(d),
            })

            vt_error = results.get("virustotal", {}).get("error")
            if REQUIRE_VIRUSTOTAL and vt_error:
                skipped += 1
                logger.warning(f"  skipped {domain}: VirusTotal {str(vt_error)[:60]}")
                time.sleep(RATE_LIMIT)
                continue

            features = extract_features(
                {"indicator": domain, "type": "domain", "results": results}
            )
            features["label"] = label
            samples.append(features)
        except Exception as e:
            logger.error(f"  failed {domain}: {str(e)[:100]}")

        time.sleep(RATE_LIMIT)

    if skipped:
        logger.warning(
            f"Skipped {skipped}/{len(domains)} domains with no VirusTotal data. "
            "Sustained skips mean rate limiting; raise RATE_LIMIT."
        )
    return samples


def main():
    """
    Orchestrates the data collection pipeline.
    Fetches IOCs, extracts features, and saves to CSV.

    --indicators domain writes a separate dataset. Domain and IP rows are not
    interchangeable, so they must not be appended to the same file.
    """
    parser = argparse.ArgumentParser(description="Collect ML training data.")
    parser.add_argument("--indicators", choices=("ip", "domain"), default="ip")
    parser.add_argument("--malicious", type=int, default=MALICIOUS_SAMPLE_SIZE)
    parser.add_argument("--benign", type=int, default=BENIGN_SAMPLE_SIZE)
    args = parser.parse_args()

    if args.indicators == "domain":
        return _collect_domains(args.malicious, args.benign)

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


def _collect_domains(malicious_limit: int, benign_limit: int) -> None:
    """Domain arm of the pipeline, writing to its own dataset."""
    logger.info("Starting domain data collection...")

    malicious = fetch_malicious_domains(malicious_limit)
    benign = fetch_benign_domains(benign_limit)

    total = len(malicious) + len(benign)
    logger.info(
        f"{total} domains at {RATE_LIMIT}s pacing — roughly "
        f"{total * RATE_LIMIT / 60:.0f} minutes."
    )

    malicious_samples = collect_domain_features(malicious, label=1)
    benign_samples = collect_domain_features(benign, label=0)

    df = pd.DataFrame(malicious_samples + benign_samples).fillna(0)
    if os.path.exists(DOMAIN_OUTPUT_PATH):
        existing = pd.read_csv(DOMAIN_OUTPUT_PATH)
        df = pd.concat([existing, df], ignore_index=True).drop_duplicates()

    df.to_csv(DOMAIN_OUTPUT_PATH, index=False)
    logger.info(f"Saved {len(df)} domain samples to {DOMAIN_OUTPUT_PATH}")
    logger.info(f"Malicious: {len(malicious_samples)} | Benign: {len(benign_samples)}")


if __name__ == "__main__":
    # Guarded so the module can be imported without kicking off a full
    # collection run. It was previously called at import time.
    main()
