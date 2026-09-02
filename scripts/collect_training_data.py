# scripts/collect_training_data.py
# Collects real labeled IOC data for ML model training.
# Pulls confirmed malicious IOCs from ThreatFox, Feodo Tracker, and URLhaus,
# benign IPs from Tor exits and shared hosting and benign domains from the
# Tranco rank window, extracts features, and saves to data/.

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import io
import ipaddress
import socket
import threading
import zipfile

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

# The free tier also caps the DAY at 500 lookups, which pacing cannot help with.
# Budget a run against what is left of that, not just against the minute rate:
# one collection of 199 domains plus a handful of live investigations crosses it,
# and every lookup past the cap 429s and is dropped by REQUIRE_VIRUSTOTAL.
VT_DAILY_QUOTA = 500

# Consecutive 429s mean the daily cap, not congestion. Pacing will not clear it,
# so the run stops and keeps what it has rather than sleeping through the
# remainder of the list collecting nothing.
MAX_CONSECUTIVE_QUOTA_ERRORS = 5

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


# Tranco domains resolved per batch. Resolution loses some to failures, more to
# deduplication, and most of all to the CDN filter below, so the pool is heavily
# oversampled against the target.
TRANCO_IP_OVERSAMPLE = 12

# CDN edge ranges, dropped from the benign class.
#
# Resolving ordinary Tranco domains does not by itself give ordinary hosting:
# 68% of a sample landed on Cloudflare, because most small businesses now sit
# behind a CDN. That reproduces the exact defect this rewrite exists to remove,
# since a CDN edge is not indexed by Shodan and fronts hundreds of names.
#
# Filtering here is on infrastructure identity, not on a feature. Dropping an
# address because it belongs to Cloudflare is the same kind of judgement as
# dropping a domain because it is a piracy site; dropping one because it has no
# Shodan record would be filtering on shodan_blocked and would manufacture the
# separation the model is supposed to find.
#
# Not exhaustive, and does not need to be. Anything it misses stays in the class
# as a hard negative rather than being silently mislabelled.
CDN_RANGES = [
    # Cloudflare
    "104.16.0.0/12", "172.64.0.0/13", "162.158.0.0/15", "198.41.128.0/17",
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16",
    # Akamai
    "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
    # Amazon CloudFront
    "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.192.0.0/16",
    # Google / GCP front ends
    "34.96.0.0/12", "35.190.0.0/17", "142.250.0.0/15",
]


def fetch_tranco_ips(limit: int, exclude: set | None = None) -> list:
    """
    Ordinary business hosting addresses, from resolving the Tranco rank window.

    This replaces resolution of a hardcoded famous-domain list, which was the
    bulk of the benign class and quietly taught the model two things that are
    properties of famous domains rather than of safety.

    Famous domains resolve to CDN edges. Shodan InternetDB does not index those,
    so 61% of the old benign class had shodan_blocked set against 43% of the
    malicious class, and the model learned that an absent Shodan record means
    benign — absence read as evidence, the same failure this codebase keeps
    finding elsewhere. CDN edges also front hundreds of names, so benign rows
    averaged 4.19 passive DNS records against 1.30 for malicious, inverting that
    feature too.

    Ordinary business hosting is a real server that Shodan indexes and that
    carries ordinary tenancy, which is the distribution an investigated address
    is actually drawn from.
    """
    try:
        ranked = _load_tranco()
    except Exception as e:
        logger.warning(f"Tranco fetch failed: {str(e)[:100]}")
        return []

    window = [d for rank, d in ranked if TRANCO_MIN_RANK <= rank <= TRANCO_MAX_RANK]
    random.shuffle(window)

    blocked = {ip.strip() for ip in (exclude or set())}
    cdn_nets = [ipaddress.ip_network(c) for c in CDN_RANGES]
    found: list[str] = []
    dropped = {"cdn": 0, "reserved": 0}

    for start in range(0, len(window), limit * TRANCO_IP_OVERSAMPLE):
        batch = window[start:start + limit * TRANCO_IP_OVERSAMPLE]
        if not batch:
            break
        for ip in _resolve_domains(batch):
            if ip in blocked or ip in found:
                continue
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            # Documentation, private and loopback space reaches here through
            # misconfigured DNS. One sample resolved to 198.51.100.100, which is
            # RFC 5737 documentation space and describes nothing real.
            if not parsed.is_global:
                dropped["reserved"] += 1
                continue
            if any(parsed in net for net in cdn_nets):
                dropped["cdn"] += 1
                continue
            found.append(ip)
        logger.info(
            f"{len(found)}/{limit} ordinary addresses "
            f"(dropped {dropped['cdn']} CDN, {dropped['reserved']} reserved)"
        )
        if len(found) >= limit:
            break

    return found[:limit]


def fetch_benign_ips(limit: int = BENIGN_SAMPLE_SIZE, exclude: set | None = None) -> list:
    """
    Builds the benign set from ordinary business hosting, plus capped Tor exits
    and shared hosting kept deliberately as hard negatives.

    Never pads by duplication. The previous version repeated its own list to
    reach the target size, so more than half the benign samples were copies of
    the same 95 addresses. Returning fewer real samples beats inflating the
    count with duplicates.
    """
    logger.info("Building benign set...")
    benign_ips = []

    # The bulk of the class. Public DNS resolvers and famous-domain resolution
    # used to sit here; both are anycast or CDN infrastructure that no ordinary
    # investigation encounters, and both are what inverted the features above.
    resolved = fetch_tranco_ips(limit, exclude=exclude)
    logger.info(f"Resolved {len(resolved)} ordinary hosting addresses from Tranco.")
    benign_ips.extend(resolved)

    # Shared hosting, ambiguous reputation by design. Kept for the same reason
    # the domain set keeps its junky-but-legitimate names: removing the hard
    # cases inflates the metrics and hides the real error rate.
    benign_ips.extend([
        "198.54.117.197", "198.54.117.198", "198.54.117.199",
        "198.54.117.200", "198.54.117.201",
        "162.241.224.4", "162.241.224.5", "162.241.224.6",
        "192.185.25.1", "192.185.25.2", "192.185.25.3",
        "160.153.128.10", "160.153.128.11", "160.153.128.12",
        "193.169.145.20", "193.169.145.21", "193.169.145.22",
    ])

    # Academic and government. Real servers rather than CDN edges, so they stay,
    # but capped in the same spirit as the Tor exits.
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

    blocked = {ip.strip() for ip in (exclude or set())}
    unique = [ip for ip in dict.fromkeys(benign_ips) if ip not in blocked][:limit]
    tor_share = min(BENIGN_TOR_CAP, len(unique)) / max(len(unique), 1)
    logger.info(
        f"Collected {len(unique)} unique benign IPs, no duplicates. "
        f"Tor exits at most {tor_share:.0%} of the class."
    )
    return unique


def collect_features(ips: list, label: int, checkpoint: str | None = None) -> list:
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
    consecutive_quota_errors = 0

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

                if "429" in str(vt_error):
                    consecutive_quota_errors += 1
                    if consecutive_quota_errors >= MAX_CONSECUTIVE_QUOTA_ERRORS:
                        logger.error(
                            f"{consecutive_quota_errors} consecutive 429s — daily "
                            f"VirusTotal quota ({VT_DAILY_QUOTA}) is spent. Stopping "
                            f"with {len(samples)} row(s); resume tomorrow."
                        )
                        break
                time.sleep(RATE_LIMIT)
                continue

            consecutive_quota_errors = 0
            features = extract_features({"indicator": ip, "type": "ipv4", "results": results})
            features["indicator"] = ip
            features["label"] = label
            samples.append(features)
            if checkpoint:
                _checkpoint(samples, checkpoint)
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


def _fetch_threat_feed_domains() -> list:
    """
    Every domain ThreatFox and URLhaus currently list, uncapped.

    Kept separate from the sampling below because the full set is also the
    exclusion list for benign candidates. Sampling 200 malicious domains and
    excluding only those 200 would leave the rest of the feed free to turn up
    in the benign class.

    Raises when every source fails. Neither feed is ever legitimately empty, so
    a zero-length result means the lookup did not happen — and an exclusion list
    that quietly became empty lets listed malware domains into the benign class
    while the run reports success.
    """
    domains: list[str] = []
    reached = 0

    try:
        headers = {"Auth-Key": THREATFOX_API_KEY} if THREATFOX_API_KEY else {}
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 7},
            headers=headers, timeout=60,
        )
        response.raise_for_status()

        # An unauthenticated call answers 200 with query_status "unauthorized"
        # and no data key, which the parse below would read as zero IOCs.
        payload = response.json()
        status = payload.get("query_status")
        if status != "ok":
            raise RuntimeError(f"query_status {status!r}")

        reached += 1
        for row in (payload.get("data") or []):
            if row.get("ioc_type") not in ("domain", "url"):
                continue
            value = row.get("ioc") or ""
            host = urlparse(value).hostname if "://" in value else value.split("/")[0]
            host = (host or "").split(":")[0].strip().lower()
            if host and "." in host and not host.replace(".", "").isdigit():
                domains.append(host)
        logger.info(f"ThreatFox returned {len(domains)} candidate domains.")
    except Exception as e:
        logger.warning(f"ThreatFox fetch failed: {str(e)[:300]}")

    try:
        response = requests.get(
            "https://urlhaus.abuse.ch/downloads/text_recent/", timeout=60
        )
        response.raise_for_status()
        reached += 1
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
        logger.warning(f"URLhaus fetch failed: {str(e)[:300]}")

    if not reached:
        raise RuntimeError(
            "ThreatFox and URLhaus both unreachable — refusing to treat an "
            "absent exclusion list as an empty one."
        )
    return list(dict.fromkeys(domains))


def fetch_malicious_domains(limit: int = MALICIOUS_SAMPLE_SIZE) -> list:
    """
    A random sample of recent malicious domains from ThreatFox and URLhaus.

    Both are free and same-day. URLhaus entries are URLs, so only the host is
    kept — the feature set describes a domain, not a path.
    """
    if limit <= 0:
        return []

    domains = _fetch_threat_feed_domains()
    random.shuffle(domains)
    unique = domains[:limit]
    logger.info(f"Collected {len(unique)} unique malicious domains.")
    return unique


# Benign domains come from the Tranco rank window, not from a famous-domain list.
#
# A benign class of household names is trivially separable by VirusTotal vote
# count, so gradient boosting took that shortcut and ignored everything else:
# harmless_votes importance 0.8992, domain_age_days 0.0000, ROC-AUC 1.0000. The
# resulting model called a legitimate hosting provider with zero VirusTotal
# detections malicious at p=1.000. What it had learned was "is this domain
# famous", which is not "is this domain safe".
#
# Past rank 100k the list is ordinary low-profile businesses with the modest
# vote counts to match, which is the distribution a real unknown domain is drawn
# from. Ranks 100k-1M also carry near-zero OTX pulses, which should collapse the
# other popularity proxy in the feature set alongside harmless_votes.
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_CACHE = os.path.join(DATA_DIR, "tranco_top1m.csv")
TRANCO_MIN_RANK = 100_000
TRANCO_MAX_RANK = 1_000_000

# Rank drift over a week does not change whether a domain is an ordinary
# business, and the download is ~10 MB.
TRANCO_CACHE_MAX_AGE = 7 * 86400


def _load_tranco(refresh: bool = False) -> list:
    """
    The daily Tranco list as (rank, domain) pairs, cached under DATA_DIR.

    Rank is parsed from the row rather than inferred from position, so a
    reordered or partial list cannot silently shift the sampling window.
    """
    cached = os.path.exists(TRANCO_CACHE)
    stale = cached and (time.time() - os.path.getmtime(TRANCO_CACHE)) > TRANCO_CACHE_MAX_AGE

    if cached and not stale and not refresh:
        with open(TRANCO_CACHE, encoding="utf-8") as handle:
            raw = handle.read()
    else:
        logger.info("Downloading Tranco top-1M...")
        response = requests.get(TRANCO_URL, timeout=120)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            raw = archive.read(archive.namelist()[0]).decode("utf-8", errors="ignore")
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(TRANCO_CACHE, "w", encoding="utf-8") as handle:
            handle.write(raw)
        logger.info(f"Cached Tranco list at {TRANCO_CACHE}.")

    ranked = []
    for line in raw.splitlines():
        rank, _, domain = line.partition(",")
        domain = domain.strip().lower()
        if domain and rank.strip().isdigit():
            ranked.append((int(rank), domain))
    return ranked


def fetch_tranco_domains(
    limit: int = BENIGN_SAMPLE_SIZE,
    exclude: set | None = None,
    min_rank: int = TRANCO_MIN_RANK,
    max_rank: int = TRANCO_MAX_RANK,
) -> list:
    """
    A random sample of ordinary registered domains from the Tranco rank window.

    Sampled across the whole window rather than taken from the top of it, so the
    class is not quietly biased toward the more popular end.
    """
    try:
        ranked = _load_tranco()
    except Exception as e:
        logger.warning(f"Tranco fetch failed: {str(e)[:100]}")
        return []

    blocked = {d.lower() for d in (exclude or set())}
    window = [d for rank, d in ranked if min_rank <= rank <= max_rank and d not in blocked]
    logger.info(f"{len(window)} candidates in Tranco ranks {min_rank}-{max_rank}.")

    random.shuffle(window)
    return list(dict.fromkeys(window))[:limit]


def fetch_benign_domains(limit: int = BENIGN_SAMPLE_SIZE, exclude: set | None = None) -> list:
    """
    Benign domains: ordinary businesses from the Tranco rank window.

    There is deliberately no famous-domain option here. That list was the bug
    this source exists to fix, since every variant trained against it found a
    shortcut, so the ability to regenerate it is a footgun rather than a
    feature. It has now been removed from the IP arm too.
    """
    domains = fetch_tranco_domains(limit, exclude={d.lower() for d in (exclude or set())})
    if not domains:
        logger.error("Tranco unavailable — collecting no benign domains.")
    else:
        logger.info(f"Collected {len(domains)} benign domains from Tranco.")
    return domains


def collect_domain_features(domains: list, label: int, checkpoint: str | None = None) -> list:
    """
    Extracts features for each domain and attaches a label.

    Queries exactly the connectors that feed a domain feature: VirusTotal, RDAP
    with WHOIS fallback for registration age, live DNS, passive DNS, OTX and
    URLhaus. Shodan and Censys are skipped because they cannot answer for a
    domain, and Ahmia because it launches a headless browser per lookup and
    contributes no feature.

    checkpoint writes rows as they are collected. Without it the whole run lives
    in memory until the final to_csv, so an interruption an hour in loses every
    row — which is exactly what a daily quota wall causes.
    """
    executor = PivotExecutor()
    samples = []
    skipped = 0
    consecutive_quota_errors = 0

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

                if "429" in str(vt_error):
                    consecutive_quota_errors += 1
                    if consecutive_quota_errors >= MAX_CONSECUTIVE_QUOTA_ERRORS:
                        logger.error(
                            f"{consecutive_quota_errors} consecutive 429s — daily "
                            f"VirusTotal quota ({VT_DAILY_QUOTA}) is spent. Stopping "
                            f"with {len(samples)} row(s); resume tomorrow with the "
                            "remaining domains."
                        )
                        break
                time.sleep(RATE_LIMIT)
                continue

            consecutive_quota_errors = 0
            features = extract_features(
                {"indicator": domain, "type": "domain", "results": results}
            )
            features["indicator"] = domain
            features["label"] = label
            samples.append(features)
            if checkpoint:
                _checkpoint(samples, checkpoint)
        except Exception as e:
            logger.error(f"  failed {domain}: {str(e)[:100]}")

        time.sleep(RATE_LIMIT)

    if skipped:
        logger.warning(
            f"Skipped {skipped}/{len(domains)} domains with no VirusTotal data. "
            "Sustained skips mean the daily quota, which pacing cannot clear."
        )
    return samples


def _checkpoint(samples: list, path: str) -> None:
    """Rewrites the partial rows so an interrupted run keeps what it paid for."""
    try:
        pd.DataFrame(samples).fillna(0).to_csv(path, index=False)
    except Exception as e:
        logger.warning(f"Checkpoint failed: {str(e)[:100]}")


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
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Sample the benign class and write it for review. Spends no VirusTotal quota.",
    )
    parser.add_argument(
        "--benign-file", help="Collect the benign class from a vetted list instead.",
    )
    parser.add_argument(
        "--output", default=DOMAIN_OUTPUT_PATH,
        help="Dataset to write. Defaults to the domain set; point it elsewhere "
             "to build a new one without touching the existing file.",
    )
    parser.add_argument(
        "--reuse-malicious", action="store_true",
        help="Copy malicious rows from the existing dataset instead of "
             "re-collecting them. Read-only on the source file.",
    )
    args = parser.parse_args()

    if args.indicators == "domain":
        if args.dry_run:
            return _dry_run_benign(args.benign)
        return _collect_domains(
            args.malicious, args.benign,
            args.benign_file, args.output, args.reuse_malicious,
        )

    logger.info("Starting data collection pipeline...")
    output_path = args.output if args.output != DOMAIN_OUTPUT_PATH else OUTPUT_PATH

    malicious_ips = fetch_malicious_ips()

    # An address serving malware is not a benign sample whatever else resolves
    # to it, so the malicious set is excluded from the benign one before either
    # is collected.
    if args.benign_file:
        benign_ips = [b for b in _read_candidates(args.benign_file) if b not in set(malicious_ips)]
        logger.info(f"Loaded {len(benign_ips)} vetted benign addresses from {args.benign_file}.")
    else:
        benign_ips = fetch_benign_ips(args.benign, exclude=set(malicious_ips))

    if args.dry_run:
        _write_candidates(benign_ips, BENIGN_IP_CANDIDATES_PATH)
        return

    if not benign_ips:
        logger.error("No benign addresses — aborting rather than writing a one-class dataset.")
        return

    logger.info("Collecting features for malicious IPs...")
    malicious_samples = collect_features(
        malicious_ips[:args.malicious], label=1,
        checkpoint=f"{output_path}.malicious.partial",
    )

    logger.info("Collecting features for benign IPs...")
    benign_samples = _drop_suspect_benign(
        collect_features(benign_ips, label=0, checkpoint=f"{output_path}.benign.partial")
    )

    df = pd.DataFrame(malicious_samples + benign_samples).fillna(0)

    if os.path.exists(output_path):
        existing = pd.read_csv(output_path)
        df = pd.concat([existing, df], ignore_index=True).drop_duplicates()
        logger.info(f"Appended to existing dataset. Total samples: {len(df)}")

    df.to_csv(output_path, index=False)
    logger.info(f"Saved {len(df)} samples to {output_path}")
    logger.info(f"Malicious: {len(malicious_samples)} | Benign: {len(benign_samples)}")


# Tranco ranks a domain by traffic, not by safety, so the window does contain
# real malware hosts that must not be labelled benign.
#
# The threshold is deliberately not zero. Dropping every candidate with a single
# detection would leave malicious_votes at 0 across the entire benign class and
# make malicious_ratio a perfect separator — the same shortcut as harmless_votes
# in a new place. One or two vendors disagreeing is ordinary false-positive
# noise and is exactly what the model needs to see.
BENIGN_MAX_MALICIOUS_VOTES = 4


def _drop_suspect_benign(samples: list) -> list:
    """Removes benign candidates that several vendors independently flag."""
    suspect = [s for s in samples if s.get("malicious_votes", 0) >= BENIGN_MAX_MALICIOUS_VOTES]
    if suspect:
        names = ", ".join(str(s.get("indicator")) for s in suspect[:10])
        logger.warning(
            f"Dropped {len(suspect)} benign candidate(s) with "
            f">= {BENIGN_MAX_MALICIOUS_VOTES} detections: {names}"
        )
    return [s for s in samples if s.get("malicious_votes", 0) < BENIGN_MAX_MALICIOUS_VOTES]


# Where --dry-run writes the benign shortlist, and where --benign-file reads a
# vetted one back. Review is the only thing that catches the candidates no
# automated filter can: domains that are not malicious but are structurally
# indistinguishable from attacker infrastructure — young, cheap TLD, no MX. A
# benign label on one of those teaches the model the exact opposite of the
# signal it is meant to learn.
BENIGN_CANDIDATES_PATH = os.path.join(DATA_DIR, "benign_candidates.txt")
BENIGN_IP_CANDIDATES_PATH = os.path.join(DATA_DIR, "benign_ip_candidates.txt")


def _write_candidates(values: list, path: str) -> None:
    """Writes a benign shortlist for review before any quota is spent on it."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "# Benign candidates for review. Delete any line that could plausibly\n"
            "# be attacker infrastructure, then collect with --benign-file.\n"
            "# Do NOT filter on ports, DNS records or Shodan coverage — those are\n"
            "# features, and filtering on them manufactures the separation you are\n"
            "# measuring.\n"
        )
        handle.write("\n".join(values) + "\n")
    logger.info(f"Wrote {len(values)} benign candidates to {path}")
    logger.info(f"Review it, then re-run with --benign-file {path}")


def _read_candidates(path: str) -> list:
    """
    Reads a vetted domain list, ignoring blanks and comments.

    Comments are stripped from the end of a line too, not just from the start —
    the shortlist carries rank and flag annotations after a #, and leaving those
    attached turns every lookup into a 404.
    """
    domains = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            domain = line.split("#")[0].strip().lower()
            if domain:
                domains.append(domain)
    return list(dict.fromkeys(domains))


def _dry_run_benign(limit: int) -> None:
    """
    Samples the benign class and writes it for review, so the shortlist can be
    edited before an hour of collection. Hits only the free unmetered feeds —
    no VirusTotal quota is spent.
    """
    try:
        feed = set(_fetch_threat_feed_domains())
    except RuntimeError as e:
        logger.error(f"{e} Re-run when the feeds are reachable.")
        return
    logger.info(f"Excluding {len(feed)} domains currently listed by ThreatFox/URLhaus.")

    benign = fetch_benign_domains(limit, exclude=feed)
    if not benign:
        logger.error("No benign candidates sampled.")
        return

    try:
        ranks = {domain: rank for rank, domain in _load_tranco()}
    except Exception:
        ranks = {}

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(BENIGN_CANDIDATES_PATH, "w", encoding="utf-8") as handle:
        handle.write(
            "# Benign candidates for review. Delete any line that could plausibly\n"
            "# be attacker infrastructure, then collect with --benign-file.\n"
            "# Do NOT filter on age, nameservers or MX — those are features, and\n"
            "# filtering on them manufactures the separation you are measuring.\n"
        )
        for domain in benign:
            rank = ranks.get(domain)
            handle.write(f"{domain}{f'  # rank {rank}' if rank else ''}\n")

    logger.info(f"Wrote {len(benign)} benign candidates to {BENIGN_CANDIDATES_PATH}")
    logger.info(
        f"Review it, then: --indicators domain --benign-file {BENIGN_CANDIDATES_PATH}"
    )


def _collect_domains(
    malicious_limit: int,
    benign_limit: int,
    benign_file: str | None = None,
    output_path: str = DOMAIN_OUTPUT_PATH,
    reuse_malicious: bool = False,
) -> None:
    """Domain arm of the pipeline, writing to its own dataset."""
    logger.info("Starting domain data collection...")

    try:
        feed = set(_fetch_threat_feed_domains())
    except RuntimeError as e:
        logger.error(f"{e} Re-run when the feeds are reachable.")
        return

    if reuse_malicious:
        malicious, malicious_samples = [], _reuse_malicious_rows()
    else:
        malicious = fetch_malicious_domains(malicious_limit)
        malicious_samples = []

    if benign_file:
        benign = [d for d in _read_candidates(benign_file) if d not in feed]
        logger.info(f"Loaded {len(benign)} vetted benign domains from {benign_file}.")
    else:
        benign = fetch_benign_domains(benign_limit, exclude=feed)

    if not benign:
        logger.error("No benign domains — aborting rather than writing a one-class dataset.")
        return

    total = len(malicious) + len(benign)
    logger.info(
        f"{total} domains at {RATE_LIMIT}s pacing — roughly "
        f"{total * RATE_LIMIT / 60:.0f} minutes."
    )

    if malicious:
        malicious_samples = collect_domain_features(
            malicious, label=1, checkpoint=f"{output_path}.malicious.partial"
        )
    benign_samples = _drop_suspect_benign(
        collect_domain_features(benign, label=0, checkpoint=f"{output_path}.benign.partial")
    )

    df = pd.DataFrame(malicious_samples + benign_samples).fillna(0)

    # Appends only to the file it was told to write. Nothing is ever discarded
    # from an existing dataset — a benign class collected under a different
    # definition belongs in a different file, not in place of this one.
    if os.path.exists(output_path):
        existing = pd.read_csv(output_path)
        df = pd.concat([existing, df], ignore_index=True).drop_duplicates()
        logger.info(f"Appended to existing {os.path.basename(output_path)}.")

    df.to_csv(output_path, index=False)
    logger.info(f"Saved {len(df)} domain samples to {output_path}")
    logger.info(f"Malicious: {len(malicious_samples)} | Benign: {len(benign_samples)}")


def _reuse_malicious_rows(source_path: str = DOMAIN_OUTPUT_PATH) -> list:
    """
    Copies already-collected malicious rows out of an existing dataset.

    They cost roughly an hour of VirusTotal quota and nothing about them is
    wrong — only the benign class is being replaced. Read-only: the source file
    is never modified.
    """
    if not os.path.exists(source_path):
        logger.warning(f"No dataset at {source_path} to reuse malicious rows from.")
        return []

    existing = pd.read_csv(source_path)
    rows = existing[existing["label"] == 1].to_dict("records")
    logger.info(f"Reusing {len(rows)} malicious row(s) from {os.path.basename(source_path)}.")
    return rows


if __name__ == "__main__":
    # Guarded so the module can be imported without kicking off a full
    # collection run. It was previously called at import time.
    main()
