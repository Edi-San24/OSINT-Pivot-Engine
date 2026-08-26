# core/relevance.py
# Organisational relevance layer.
#
# Every other source answers "what is this indicator". This answers "does it
# matter to us", which no external feed can. It is the difference between an
# investigation that reads "this is malicious infrastructure" and one that
# reads "this is your host".
#
# Absent configuration is silent by design. A stale profile that reports "not
# your infrastructure" about a host that is yours is worse than no answer, so
# nothing here ever emits a negative finding — only positives it can evidence.

import ipaddress
import logging

import yaml

from config import ORG_PROFILE_PATH

logger = logging.getLogger(__name__)

# Maximum edit distance for a domain to count as a typosquat of a brand domain.
MAX_TYPOSQUAT_DISTANCE = 2

# Ordered by urgency — the first match wins when several apply.
RELEVANCE_LEVELS = ["own_asset", "brand_abuse", "sector_targeted", "none"]


def load_profile(path: str = ORG_PROFILE_PATH) -> dict | None:
    """
    Loads the org profile. Returns None when the file is absent or empty,
    which switches the whole layer off rather than defaulting to anything.
    """
    try:
        with open(path) as f:
            profile = yaml.safe_load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.error(f"Could not read org profile at {path}: {str(e)[:120]}")
        return None

    if not isinstance(profile, dict) or not any(profile.values()):
        return None
    return profile


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance between two strings."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (char_a != char_b),
            ))
        previous = current
    return previous[-1]


def _registrable(domain: str) -> str:
    """Strips the TLD so brand comparison isn't dominated by .com matching .com."""
    parts = domain.lower().strip().split(".")
    return parts[-2] if len(parts) >= 2 else domain.lower().strip()


def _harvest(pivot_results: list) -> dict:
    """
    Walks the whole investigation once and collects everything the checks below
    need — seeds, discovered indicators, hosting metadata, OTX targeting, and
    ATT&CK techniques.
    """
    ips: set[str] = set()
    domains: set[str] = set()
    hosting: set[str] = set()
    industries: set[str] = set()
    countries: set[str] = set()
    techniques: dict[str, str] = {}

    for pivot in pivot_results:
        indicator = (pivot.get("indicator") or "").strip()
        results = pivot.get("results", {})

        if pivot.get("type") == "ipv4":
            ips.add(indicator)
        elif pivot.get("type") == "domain":
            domains.add(indicator.lower())

        # Discovered indicators, not just the seeds
        for record in results.get("passivedns", {}).get("records", []):
            value = (record.get("ip") or record.get("domain") or "").strip()
            if not value:
                continue
            try:
                ipaddress.ip_address(value)
                ips.add(value)
            except ValueError:
                domains.add(value.lower())

        certs = results.get("crtsh") or results.get("censys") or {}
        for cert in certs.get("certificates", []):
            for name in (cert.get("names", "") or "").replace("\n", ",").split(","):
                name = name.strip().lstrip("*.").lower()
                if name:
                    domains.add(name)

        # Hosting identity, for ASN and provider matching. Still Censys proper —
        # only the certificate lookup moved to its own key.
        for value in ((results.get("censys") or {}).get("autonomous_system", ""),
                      results.get("shodan", {}).get("organization", ""),
                      results.get("virustotal", {}).get("owner", "")):
            if value:
                hosting.add(str(value).lower())

        # OTX carries the only structured targeting data in the pipeline.
        # Group pivots file theirs under otx_search, not otx.
        for key in ("otx", "otx_search"):
            for pulse in results.get(key, {}).get("pulses", []):
                industries.update(i.lower() for i in pulse.get("industries", []) or [])
                countries.update(c.lower() for c in pulse.get("targeted_countries", []) or [])

        # Those structured fields are empty for hacktivist crews, so core.hacktivist
        # parses targeting out of the pulse text instead.
        hack = results.get("hacktivist", {})
        industries.update(s.lower() for s in hack.get("target_sectors", []) or [])
        countries.update(c.lower() for c in hack.get("target_countries", []) or [])

        mitre = results.get("mitre", {})
        for technique in mitre.get("techniques", []):
            tid = technique.get("technique_id", "")
            if tid and tid != "unknown":
                techniques[tid] = technique.get("name", "")

    return {
        "ips": ips, "domains": domains, "hosting": hosting,
        "industries": industries, "countries": countries, "techniques": techniques,
    }


def _check_own_assets(harvest: dict, profile: dict) -> list[str]:
    """IPs inside our declared netblocks, or infrastructure in our own ASN."""
    hits = []

    networks = []
    for cidr in profile.get("netblocks", []) or []:
        try:
            networks.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            logger.error(f"Skipping malformed netblock in org profile: {cidr}")

    for ip in sorted(harvest["ips"]):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for net in networks:
            if addr in net:
                hits.append(f"{ip} is inside your netblock {net}")
                break

    for asn in profile.get("asns", []) or []:
        needle = str(asn).lower()
        if any(needle in h for h in harvest["hosting"]):
            hits.append(f"infrastructure is hosted in your ASN ({asn})")

    return hits


def _check_brand_abuse(harvest: dict, profile: dict) -> list[str]:
    """
    Domains impersonating ours: either a near-miss spelling, or one that
    embeds our brand name without being ours.
    """
    ours = {d.lower().strip() for d in (profile.get("domains", []) or [])}
    if not ours:
        return []

    brands = {_registrable(d) for d in ours}
    hits = []

    for domain in sorted(harvest["domains"]):
        if domain in ours:
            continue
        for our_domain in ours:
            if _edit_distance(domain, our_domain) <= MAX_TYPOSQUAT_DISTANCE:
                hits.append(f"{domain} is a near-identical spelling of {our_domain}")
                break
        else:
            label = _registrable(domain)
            for brand in brands:
                if brand in label and label != brand:
                    hits.append(f"{domain} embeds your brand name '{brand}'")
                    break

    return hits


def _check_targeting(harvest: dict, profile: dict) -> list[str]:
    """Sector and country overlap between our profile and OTX pulse targeting."""
    hits = []

    # Matched case-insensitively but reported using the profile's own spelling,
    # so the output reads like the analyst wrote it.
    sectors = {s.lower(): s for s in (profile.get("sectors", []) or [])}
    overlap = sorted(sectors[k] for k in sectors if k in harvest["industries"])
    if overlap:
        hits.append(f"reporting names your sector ({', '.join(overlap)}) as targeted")

    countries = {c.lower(): c for c in (profile.get("countries", []) or [])}
    overlap = sorted(countries[k] for k in countries if k in harvest["countries"])
    if overlap:
        hits.append(f"reporting names your country ({', '.join(overlap)}) as targeted")

    return hits


def _check_coverage(harvest: dict, profile: dict) -> list[str]:
    """ATT&CK techniques seen here that our profile doesn't claim to mitigate."""
    covered = {t.upper() for t in (profile.get("mitigated_techniques", []) or [])}
    if not covered:
        return []

    seen = harvest["techniques"]
    if not seen:
        return []

    # A sub-technique is covered when its parent is, e.g. T1021 covers T1021.001
    uncovered = [
        tid for tid in sorted(seen)
        if tid.upper() not in covered and tid.split(".")[0].upper() not in covered
    ]
    if not uncovered:
        return []

    preview = ", ".join(uncovered[:6])
    return [
        f"{len(uncovered)} of {len(seen)} mapped techniques have no stated "
        f"coverage in your profile — {preview}"
    ]


def assess_relevance(pivot_results: list, profile: dict | None = None) -> dict:
    """
    Scores an investigation against the org profile.

    Returns configured=False when no profile exists, and never emits a finding
    asserting that something is NOT relevant — only ones it can evidence.
    """
    if profile is None:
        profile = load_profile()

    if not profile:
        return {"configured": False, "level": "none", "findings": []}

    harvest = _harvest(pivot_results)

    own_assets = _check_own_assets(harvest, profile)
    brand_abuse = _check_brand_abuse(harvest, profile)
    targeting = _check_targeting(harvest, profile)
    coverage = _check_coverage(harvest, profile)

    findings = []
    for hit in own_assets:
        findings.append(f"OWN ASSET: {hit}. Treat as a potential compromise, not an external threat.")
    for hit in brand_abuse:
        findings.append(f"BRAND ABUSE: {hit}.")
    for hit in targeting:
        findings.append(f"ORG RELEVANCE: {hit}.")
    findings.extend(f"COVERAGE GAP: {hit}." for hit in coverage)

    if own_assets:
        level = "own_asset"
    elif brand_abuse:
        level = "brand_abuse"
    elif targeting:
        level = "sector_targeted"
    else:
        level = "none"

    if findings:
        logger.info(f"Org relevance: {level} ({len(findings)} findings)")

    return {
        "configured": True,
        "level": level,
        "findings": findings,
        "own_assets": own_assets,
        "brand_abuse": brand_abuse,
        "targeting": targeting,
        "coverage_gaps": coverage,
    }
