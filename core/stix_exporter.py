# core/stix_exporter.py
# STIX 2.1 exporter: 
# Converts investigation results into a standardized STIX bundle.

import json
import logging
import re
import time
from datetime import datetime, timezone

from core.detector import detect_type
from core.risk import TENANCY_WINDOW_DAYS, is_routable_ip, last_seen_within

logger = logging.getLogger(__name__)

from stix2 import (
    Bundle,
    Indicator,
    Malware, 
    Relationship,
    ThreatActor,
    AttackPattern,
    ObservedData,
    DomainName,
    IPv4Address,
    File,
    Identity,
)

TOOL_IDENTITY = Identity(
    name= "OSINT Pivot Engine",
    identity_class="system",
    description="Autonomous threat intelligence enrichment system"
)

class STIXExporter:
    """
    Converts Engine investigation results in STIX format (bundles)
    Supports: IP, domain, hash, threat group indicators
    """

    def __init__(self):
        self.objects = [TOOL_IDENTITY]

    def _now(self) -> str:
        """Returns current UTC timestamp in STIX format."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _add_indicator(self, indicator: str, indicator_type: str) -> Indicator:
        """
        Creates a STIX Indicator object for the seed indicator.
        """
        pattern_map = {
            "ipv4": f"[ipv4-addr:value = '{indicator}']",
            "domain": f"[domain-name:value = '{indicator}']",
            "md5": f"[file:hashes.MD5 = '{indicator}']",
            "sha1": f"[file:hashes.SHA-1 = '{indicator}']",
            "sha256": f"[file:hashes.'SHA-256' = '{indicator}']",
            "hash": f"[file:hashes.MD5 = '{indicator}']",
        }

        pattern = pattern_map.get(indicator_type, f"[domain-name:value = '{indicator}']")

        stix_indicator = Indicator(
            name=f"Indicator: {indicator}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=self._now(),
            created_by_ref=TOOL_IDENTITY.id,
            labels=["malicious-activity"],
        )
        self.objects.append(stix_indicator)
        return stix_indicator

    def _add_malware(self, name: str, description: str = "") -> Malware:
        """
        Creates a STIX Malware object from VT or MalwareBazaar family name.
        """
        stix_malware = Malware(
            name=name,
            is_family=True,
            description=description,
            created_by_ref=TOOL_IDENTITY.id,
        )
        self.objects.append(stix_malware)
        return stix_malware

    def _add_attack_pattern(self, technique_id: str, name: str, tactics: list) -> AttackPattern:
        """
        Creates a STIX AttackPattern object from a MITRE ATT&CK technique.
        """
        tactic_refs = ", ".join([f"'{t}'" for t in tactics])
        stix_ap = AttackPattern(
            name=f"{technique_id}: {name}",
            description=f"MITRE ATT&CK Technique {technique_id} — Tactics: {tactic_refs}",
            created_by_ref=TOOL_IDENTITY.id,
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                }
            ]
        )
        self.objects.append(stix_ap)
        return stix_ap

    def _add_threat_actor(self, name: str, aliases: list, description: str = "") -> ThreatActor:
        """
        Creates a STIX ThreatActor object from MITRE group data.
        """
        stix_actor = ThreatActor(
            name=name,
            aliases=aliases,
            description=description,
            created_by_ref=TOOL_IDENTITY.id,
            labels=["nation-state"],
        )
        self.objects.append(stix_actor)
        return stix_actor

    def _add_relationship(self, source, target, relationship_type: str) -> Relationship:
        """
        Creates a STIX Relationship object linking two STIX objects together.
        e.g. Malware "uses" AttackPattern, Indicator "indicates" Malware
        """
        rel = Relationship(
            relationship_type=relationship_type,
            source_ref=source.id,
            target_ref=target.id,
            created_by_ref=TOOL_IDENTITY.id,
        )
        self.objects.append(rel)
        return rel

    def export(self, investigation: dict, output_path: str) -> str:
        """
        Main export method. Takes a full investigation result dict
        and converts it into a STIX 2.1 bundle saved to disk.
        """
        self.objects = [TOOL_IDENTITY]

        seed = investigation.get("indicator", "unknown")
        pivot_results = investigation.get("full_results", [])

        if not pivot_results:
            logger.warning("No pivot results to export.")
            return None

        first_result = pivot_results[0]
        indicator_type = first_result.get("type", "unknown")

        # Create the seed indicator
        stix_indicator = self._add_indicator(seed, indicator_type)

        for pivot in pivot_results:
            results = pivot.get("results", {})

            # Wire up malware from VT
            vt = results.get("virustotal", {})
            malware_family = vt.get("malware_family")
            stix_malware = None

            if malware_family and "error" not in vt:
                stix_malware = self._add_malware(malware_family)
                self._add_relationship(stix_indicator, stix_malware, "indicates")

            # Wire up MITRE techniques
            mitre = results.get("mitre", {})
            if mitre.get("found"):
                for technique in mitre.get("techniques", []):
                    stix_ap = self._add_attack_pattern(
                        technique["technique_id"],
                        technique["name"],
                        technique.get("tactics", [])
                    )
                    if stix_malware:
                        self._add_relationship(stix_malware, stix_ap, "uses")

                # Wire up threat groups
                for group in mitre.get("groups", []):
                    stix_actor = self._add_threat_actor(
                        group["name"],
                        group.get("aliases", []),
                    )
                    if stix_malware:
                        self._add_relationship(stix_actor, stix_malware, "uses")

        # Build and write bundle
        bundle = Bundle(objects=self.objects, allow_custom=True)
        with open(output_path, "w") as f:
            f.write(bundle.serialize(pretty=True))

        logger.info(f"STIX bundle written to {output_path}")
        return output_path


# --- OTX pulse export ------------------------------------------------------
#
# A second export format. An investigation result holds every indicator the
# pivot chain touched, including passive DNS neighbours of the seed. Handing
# that file to OTX's extractor produced 41 indicators of which 39 were wrong,
# 24 of them naming unrelated businesses sharing a server with the victim. A
# pulse is a curated claim, so only what the agent investigated goes in, and
# everything dropped is recorded with a reason.

# OTX indicator type names, keyed by the engine's own types.

OTX_TYPES = {
    "ipv4": "IPv4",
    "domain": "domain",
    "hostname": "hostname",
    "url": "URL",
    "md5": "FileHash-MD5",
    "sha1": "FileHash-SHA1",
    "sha256": "FileHash-SHA256",
    "email": "email",
}

# Engine types that are not OTX indicators. A threat group belongs in a pulse's
# adversary field and a malware family in malware_families.
NOT_OTX_INDICATORS = {"threat_group", "software", "filename", "username"}

# OTX's ceiling on the description field. It rejects the whole submission above
# this.
OTX_DESCRIPTION_LIMIT = 1024

# Digest length to OTX name, for pivots typed only as the generic "hash".
_HASH_BY_LENGTH = {32: "FileHash-MD5", 40: "FileHash-SHA1", 64: "FileHash-SHA256"}


def otx_type(name: str, itype: str) -> str:
    """
    The OTX type name for an indicator, or "" when OTX has no type for it.

    An unmapped type returns empty rather than falling through as the engine's
    own name, since OTX drops an indicator it cannot type and the analyst would
    believe they had published it. `executor.pivot_hash` types every digest as
    `hash` regardless of algorithm, so the length resolves it.
    """
    if itype in NOT_OTX_INDICATORS:
        return ""
    if itype in OTX_TYPES:
        return OTX_TYPES[itype]
    if itype == "hash" or re.fullmatch(r"[a-fA-F0-9]{32,64}", name or ""):
        return _HASH_BY_LENGTH.get(len(name or ""), "")
    return ""


def _is_under(name: str, parents: set[str]) -> bool:
    """Whether name is one of parents, or a subdomain of one."""
    name = name.lower().rstrip(".")
    return any(name == p or name.endswith("." + p) for p in parents)




# Cache so one export does not re-query the same neighbour repeatedly.
_TENANT_VERDICTS: dict[str, bool] = {}


def _is_known_malicious(domain: str) -> bool:
    """
    Whether a co-resolving neighbour is itself listed as malicious.

    Bystander protection exists for uninvolved third parties, and a neighbour
    that the feeds already flag is not one. cnc-server.com sharing an address
    with a Mirai distribution host was counted as a bystander and suppressed
    publication of the attacker-owned IP entirely.

    Fails open on purpose. Any error, missing key or unreachable feed returns
    False, which keeps the neighbour protected. Only positive evidence of
    maliciousness removes that protection, because the cost of wrongly stripping
    it is a real business on somebody's blocklist.
    """
    key = domain.strip().lower()
    if key in _TENANT_VERDICTS:
        return _TENANT_VERDICTS[key]

    verdict = False
    try:
        from connectors.threatfox import ThreatFoxConnector
        from connectors.urlhaus import URLhausConnector

        tf = ThreatFoxConnector().query_indicator(key, "domain")
        if tf.get("found"):
            verdict = True
        else:
            uh = URLhausConnector().query_host(key)
            verdict = bool(uh.get("found"))
    except Exception as e:
        logger.warning(f"Could not check neighbour {key}: {str(e)[:80]}")
        verdict = False

    _TENANT_VERDICTS[key] = verdict
    return verdict



def pivot_for(investigation: dict, name: str) -> dict:
    """The pivot result for one indicator, or an empty dict."""
    return next(
        (p for p in investigation.get("full_results", [])
         if (p.get("indicator") or "").lower() == name),
        {},
    )


def _otx_rejection(pivot: dict) -> str:
    """
    Why OTX would refuse this indicator, or "" when it would accept it.

    Empty on an unanswered lookup as well as a clean one, which is deliberate:
    an OTX timeout is not grounds to drop an indicator the other sources back.
    """
    otx = (pivot.get("results") or {}).get("otx") or {}
    return "; ".join(otx.get("otx_validation") or [])


def _co_hosted_tenants(pivot: dict, investigated_domains: set[str]) -> list[str] | None:
    """
    Domains on this IP that belong to somebody else.

    Returns [] when the host is verifiably single-tenant, a list when it is
    shared, and None when there is no passive DNS coverage to judge by.

    That third case matters. Returning [] for an IP with zero records read as
    "nobody else is here" when it actually means "we cannot see" — which let
    162.35.105.61 through as publishable, an address whose reverse DNS is a
    hosting provider's own nameserver. Same shape as the risk scoring bug where
    an empty result scored as LOW instead of UNKNOWN.
    """
    results = pivot.get("results", {})
    records = list((results.get("passivedns") or {}).get("records") or [])
    records.extend((results.get("dnsdb") or {}).get("records") or [])
    if not records:
        return None

    tenants = []
    for record in records:
        value = (record.get("domain") or record.get("ip") or "").strip().lower()
        if not value or value.replace(".", "").isdigit():
            continue
        if _is_under(value, investigated_domains):
            continue
        # Only current neighbours count. Names that stopped resolving here years
        # ago are not bystanders a block would harm, and counting them excluded
        # an address whose only live co-tenant was one other domain — DomainTools
        # said 3 domains on it while this returned 10, nine of them last seen
        # between 2019 and 2025.
        if last_seen_within(record, TENANCY_WINDOW_DAYS):
            tenants.append(value)

    # Neighbours the feeds already flag are not bystanders, so they do not earn
    # protection and must not suppress publication of the address.
    protected = [t for t in sorted(set(tenants)) if not _is_known_malicious(t)]
    return protected


def _feed_listed(pivot: dict) -> str:
    """
    Whether a feed lists this indicator itself, named so the audit can say so.

    Read from the saved pivot rather than queried, so it costs nothing and
    reflects what the investigation saw. Distinct from _is_known_malicious,
    which asks the same question about a neighbour.
    """
    results = pivot.get("results") or {}

    threatfox = results.get("threatfox") or {}
    if threatfox.get("found"):
        confidence = threatfox.get("max_confidence")
        families = ", ".join(threatfox.get("malware_families") or [])
        detail = f" at confidence {confidence}" if confidence is not None else ""
        return f"ThreatFox{detail}{f' ({families})' if families else ''}"

    urlhaus = results.get("urlhaus") or {}
    if urlhaus.get("found"):
        return "URLhaus"

    return ""


def _adversary(investigations: list[dict]) -> str:
    """
    The actor name for the pulse's adversary field, from ATT&CK rather than the
    seed string, so an alias resolves to the name MITRE uses.
    """
    for investigation in investigations:
        for pivot in investigation.get("full_results", []):
            mitre = (pivot.get("results") or {}).get("mitre") or {}
            if mitre.get("group_name"):
                return mitre["group_name"]
    return ""


def _families(investigations: list[dict]) -> list[str]:
    """Malware family names seen across the chain, for malware_families."""
    names = set()
    for investigation in investigations:
        for pivot in investigation.get("full_results", []):
            results = pivot.get("results") or {}
            for software in (results.get("mitre") or {}).get("software") or []:
                if software.get("name"):
                    names.add(software["name"])
            family = (results.get("malwarebazaar") or {}).get("malware_family")
            if family and family != "unknown":
                names.add(family)
    return sorted(names)


def _corroboration(pivot: dict) -> str:
    """
    Any independent source saying something about this indicator, named so the
    audit can quote it. Empty string when nothing does.

    Broader than _feed_listed, which overrides bystander protection and so needs
    abuse.ch-grade evidence. This only decides whether a discovered domain may be
    published, so a VirusTotal detection or a community pulse is enough.
    """
    results = pivot.get("results") or {}

    threatfox = results.get("threatfox") or {}
    if threatfox.get("found"):
        return f"ThreatFox at confidence {threatfox.get('max_confidence')}"

    if (results.get("urlhaus") or {}).get("found"):
        return "URLhaus"

    votes = (results.get("virustotal") or {}).get("malicious_votes") or 0
    if votes:
        harmless = (results.get("virustotal") or {}).get("harmless_votes") or 0
        return f"VirusTotal {votes}/{votes + harmless}"

    # pulse_count excludes our own pulses, so a pulse we published earlier
    # cannot corroborate the domain it was about.
    otx = results.get("otx") or {}
    if (otx.get("pulse_count") or 0) > 0:
        return f"{otx['pulse_count']} OTX pulse(s)"

    return ""


def _engine_artifacts(investigation: dict) -> set[str]:
    """
    Names the engine invented or read off the hosting provider.

    The wildcard probe is a random label our own code generated to test the
    zone; it never existed. Nameservers and PTR names identify the provider,
    not the campaign.
    """
    artifacts = set()
    for pivot in investigation.get("full_results", []):
        live = pivot.get("results", {}).get("dns") or {}
        probe = (live.get("wildcard") or {}).get("probe")
        if probe:
            artifacts.add(probe.lower())
        for name in (live.get("nameservers") or []) + (live.get("ptr") or []):
            artifacts.add(name.lower().rstrip("."))
        shodan = pivot.get("results", {}).get("shodan") or {}
        for name in shodan.get("hostnames") or []:
            artifacts.add(name.lower().rstrip("."))
    return artifacts


def select_indicators(investigations: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Picks the indicators worth publishing, and records what was dropped.

    Only indicators the agent actually investigated are eligible — a passive
    DNS neighbour was never assessed and has no place in a pulse.
    """
    # Both forms are carried: the lowercased key matches and deduplicates, the
    # original is what gets published. URL paths are case-sensitive, so
    # publishing the folded form emitted http://host/okami.x86 for a payload
    # actually served at /Okami.x86 — an indicator that cannot match anything.
    investigated: list[tuple[str, str, dict]] = []
    for investigation in investigations:
        for name in investigation.get("visited", []):
            investigated.append((name.strip().lower(), name.strip(), investigation))

    domains = {
        n for n, _, _ in investigated
        if not n.replace(".", "").isdigit() and "." in n
    }

    included, excluded = [], []
    seen = set()

    for name, original, investigation in investigated:
        if name in seen:
            continue
        seen.add(name)

        # OTX publishes its own verdict, and it is the only source here that
        # knows whether the destination will accept an indicator. Publishing one
        # it whitelists means it is silently dropped from the pulse, so the
        # analyst believes they shared something they did not.
        rejected = _otx_rejection(pivot_for(investigation, name))
        if rejected:
            excluded.append({"indicator": name,
                             "reason": f"OTX will not accept this indicator: {rejected}"})
            continue

        if name in _engine_artifacts(investigation):
            excluded.append({"indicator": name,
                             "reason": "engine artifact or hosting provider infrastructure"})
            continue

        pivot = next(
            (p for p in investigation.get("full_results", [])
             if (p.get("indicator") or "").lower() == name),
            {},
        )
        itype = pivot.get("type", "")

        if itype == "ipv4":
            # Reserved, private, multicast and documentation space cannot host
            # anything, so it cannot be an indicator. A zone that poisons passive
            # DNS will otherwise feed such addresses straight through.
            if not is_routable_ip(name):
                excluded.append({
                    "indicator": name,
                    "reason": (
                        "not a globally routable address (reserved, private, "
                        "multicast or documentation space), so it cannot host"
                    ),
                })
                continue

            # Feed evidence on the address itself outranks the co-tenancy
            # heuristic, and the ordering is load-bearing. On a compromised host,
            # co-tenancy with a legitimate domain is the definition of the case
            # rather than a reason to shield the address.
            listed = _feed_listed(pivot)
            if not listed:
                tenants = _co_hosted_tenants(pivot, domains)
                if tenants is None:
                    excluded.append({
                        "indicator": name,
                        "reason": (
                            "tenancy unknown — no passive DNS coverage on this address, "
                            "so whether it is shared cannot be established"
                        ),
                    })
                    continue
                if tenants:
                    excluded.append({
                        "indicator": name,
                        "reason": (
                            f"shared hosting — {len(tenants)} unrelated domain(s) on this "
                            f"address, blocking it would hit bystanders"
                        ),
                        "co_hosted": tenants[:10],
                    })
                    continue

        # A name sitting under another published domain is a hostname to OTX.
        others = domains - {name}
        resolved = "hostname" if (itype == "domain" and _is_under(name, others)) else itype

        # A domain the chain discovered needs a source other than our own model
        # before it goes in a pulse. The seed is exempt: the analyst chose to
        # investigate it, so publishing it is their claim rather than the
        # engine's inference.
        #
        # Held back rather than blocked. The model can be right where every feed
        # is silent, and it can equally flag a small self-hosted host that is
        # simply quiet, and those two look identical here. The reason lands in
        # the audit and --include publishes it once someone has decided.
        is_seed = name == (investigation.get("indicator") or "").strip().lower()
        if resolved in ("domain", "hostname") and not is_seed:
            corroboration = _corroboration(pivot)
            if not corroboration:
                excluded.append({
                    "indicator": name,
                    "reason": (
                        "discovered by chaining and uncorroborated — no feed lists "
                        "it, VirusTotal is clean and no pulse names it, so "
                        "publishing would rest on the model alone"
                    ),
                })
                continue

        kind = otx_type(name, resolved)
        if not kind:
            excluded.append({
                "indicator": name,
                "reason": (
                    f"OTX has no indicator type for {resolved!r}; a threat group "
                    "belongs in the pulse's adversary field and a malware family "
                    "in malware_families, not in the indicator list"
                ),
            })
            continue
        included.append({
            "indicator": original,
            "type": kind,
            "engine_risk_level": investigation.get("risk_level", "unknown"),
        })

    # A TLS certificate unique to an investigated domain is a safe, durable
    # selector — other analysts can hunt it directly. One shared across many
    # domains is a hosting artifact and says nothing, so the corpus count from
    # DomainTools decides which is which.
    #
    # A certificate only selects for the domain it belongs to, so it is not
    # publishable when that domain is not: publishing it would identify that
    # host as precisely as naming it.
    publishable = {entry["indicator"].strip().lower() for entry in included}
    for investigation in investigations:
        for pivot in investigation.get("full_results", []):
            dt = (pivot.get("results") or {}).get("domaintools") or {}
            owner = (pivot.get("indicator") or "").strip().lower()
            for cert in dt.get("certificates") or []:
                sha1 = (cert.get("sha1") or "").strip().lower()
                shared = cert.get("domains_on_cert", 0)
                if not sha1 or sha1 == "unknown" or sha1 in seen:
                    continue
                seen.add(sha1)
                if owner and owner not in publishable:
                    excluded.append({
                        "indicator": sha1,
                        "reason": (
                            f"certificate belongs to {owner}, which was not "
                            "published, so publishing it would identify that "
                            "host anyway"
                        ),
                    })
                elif shared == 1:
                    included.append({
                        "indicator": sha1,
                        "type": "SSLCertFingerprint",
                        "engine_risk_level": investigation.get("risk_level", "unknown"),
                    })
                else:
                    excluded.append({
                        "indicator": sha1,
                        "reason": (
                            f"TLS certificate shared across {shared} domains, so it "
                            "identifies the host rather than this actor"
                        ),
                    })

    return included, excluded


# Sources it is normal to name in a write-up. OTX extracts these from the prose
# and whitelists them, so warning about them is noise rather than signal.
CITED_SOURCES = {
    "abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch", "bazaar.abuse.ch",
    "feodotracker.abuse.ch", "virustotal.com", "www.virustotal.com",
    "otx.alienvault.com", "alienvault.com", "shodan.io", "internetdb.shodan.io",
    "censys.io", "search.censys.io", "crt.sh", "domaintools.com", "dnsdb.info",
    "mitre.org", "attack.mitre.org", "tranco-list.eu", "digitalocean.com",
}

# Indicator-shaped strings, for checking a description does not smuggle any.
#
# The TLD is matched generically rather than from a list. A hardcoded list was
# missing .ch, so a description citing abuse.ch and urlhaus.abuse.ch passed the
# check clean and OTX extracted both as indicators — the exact leak this exists
# to catch, hidden by the very allowlist meant to make it precise.
_INDICATOR_SHAPES = re.compile(
    r"\b(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|[a-fA-F0-9]{32,64}"
    r"|(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}"
    r")\b"
)


def leaked_indicators(description: str, included: list[dict]) -> list[str]:
    """
    Indicator-shaped strings in the description that are not published IOCs.

    OTX's file extractor reads the description as well as the indicator list, so
    naming an excluded address in prose republishes it. A description that said
    "neither address is published as an indicator here" put both addresses back
    in, plus two other researchers' phishing domains cited as context.
    """
    published = {i["indicator"].lower() for i in included}
    leaked = []
    for match in _INDICATOR_SHAPES.findall(description):
        value = match.lower().strip(".")
        if not value or value in published or value in leaked:
            continue
        # Naming the source of a claim is how a write-up stays checkable, so
        # those are excluded rather than reported. Everything else is a leak.
        if value in CITED_SOURCES:
            continue
        leaked.append(value)
    return leaked


def build_pulse(investigations: list[dict], title: str, description: str,
          tags: list[str] = None, attack_ids: list[str] = None,
          exclude: list[str] = None, include: list[str] = None) -> dict:
    """
    Assembles the pulse payload plus an audit of what was left out.

    The payload matches what OTXConnector.publish_pulse posts, so the same
    object can be uploaded or published without reshaping.
    """
    included, excluded = select_indicators(investigations)

    # Analyst override. The selector judges evidence, not what a destination can
    # represent — OTX types any 40-char hex as FileHash-SHA1 whatever type is
    # chosen, which mislabels a certificate fingerprint as a file hash.
    dropped = {e.strip().lower() for e in (exclude or []) if e.strip()}
    if dropped:
        kept = []
        for entry in included:
            if entry["indicator"].lower() in dropped:
                excluded.append({
                    "indicator": entry["indicator"],
                    "reason": "excluded by analyst",
                })
            else:
                kept.append(entry)
        included = kept

    # The mirror of exclude. The selector errs toward protecting bystanders, so
    # it drops an address with even one live co-tenant. An analyst who has read
    # the audit trail can put it back, and the description should then say why
    # blocking it needs care.
    forced = {i.strip().lower() for i in (include or []) if i.strip()}
    if forced:
        published = {e["indicator"].lower() for e in included}
        remaining, reinstated = [], set()
        for entry in excluded:
            name = entry["indicator"].lower()
            if name in forced and name not in published:
                reinstated.add(name)
                included.append({
                    "indicator": entry["indicator"],
                    "type": otx_type(
                        name, "ipv4" if name.replace(".", "").isdigit() else "domain"
                    ) or "domain",
                    "engine_risk_level": "analyst-included",
                    "caveat": entry.get("reason", ""),
                })
            else:
                remaining.append(entry)
        excluded = remaining

        # A name the selector never saw, rather than one it dropped. Only
        # investigated indicators are eligible, so a passive DNS neighbour the
        # chain never pivoted was never a candidate. Carries a caveat because the
        # engine has no assessment of it, so the claim is the analyst's.
        for name in sorted(forced - published - reinstated):
            detected = detect_type(name) or {}
            kind = detected.get("type", "domain")
            included.append({
                "indicator": detected.get("indicator", name),
                "type": otx_type(detected.get("indicator", name), kind) or "domain",
                "engine_risk_level": "analyst-included",
                "caveat": (
                    "never assessed by the engine — not investigated, so this "
                    "rests on analyst judgement rather than any score"
                ),
            })

    leaked = leaked_indicators(description, included)
    if leaked:
        logger.warning(
            f"Description names {len(leaked)} indicator-shaped string(s) that are "
            f"not published IOCs; OTX will extract them: {leaked[:6]}"
        )

    # Checked at build time, with the overshoot named, so an over-long
    # description surfaces when the file is written rather than on submission.
    if len(description) > OTX_DESCRIPTION_LIMIT:
        logger.warning(
            f"Description is {len(description)} chars and OTX accepts "
            f"{OTX_DESCRIPTION_LIMIT}; trim {len(description) - OTX_DESCRIPTION_LIMIT} "
            "before uploading."
        )

    return {
        "name": title,
        "description": description,
        # A boolean. OTX rejects the integer form.
        "public": True,
        "TLP": "white",
        "tags": tags or [],
        "attack_ids": attack_ids or [],
        "indicators": [
            {"indicator": i["indicator"], "type": i["type"]} for i in included
        ],
        # Where a threat group and a malware family belong, rather than in the
        # indicator list.
        "malware_families": _families(investigations),
        "adversary": _adversary(investigations),
        "targeted_countries": [],
        # Not part of the OTX payload. Kept so every dropped indicator has a
        # stated reason rather than vanishing silently.
        "_excluded": excluded,
        "_description_leaks": leaked,
        "_included_detail": included,
        "_source_investigations": [
            {
                "seed": inv.get("indicator"),
                "risk_level": inv.get("risk_level"),
                "pivot_count": inv.get("pivot_count"),
                "indicators_investigated": inv.get("visited", []),
            }
            for inv in investigations
        ],
    }


def write_pulse(pulse: dict, output_path: str) -> tuple[str, str]:
    """
    Writes the pulse twice: a clean payload to upload, and a full audit copy.

    Split because the audit sections name the co-hosted domains that were
    excluded, and OTX's file extractor would scrape them straight back out —
    reintroducing the exact indicators the selection just removed.
    """
    clean = {k: v for k, v in pulse.items() if not k.startswith("_")}
    with open(output_path, "w") as f:
        json.dump(clean, f, indent=2)

    audit_path = output_path.replace(".json", "") + ".audit.json"
    with open(audit_path, "w") as f:
        json.dump(pulse, f, indent=2)

    return output_path, audit_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Build an OTX pulse from saved investigation JSON files.",
    )
    parser.add_argument("investigations", nargs="+", metavar="FILE")
    parser.add_argument("--title", "-t", required=True)
    parser.add_argument("--description", "-d", required=True,
                        help="Text, or @path to read it from a file.")
    parser.add_argument("--tags", default="")
    parser.add_argument("--attack-ids", default="")
    parser.add_argument("--output", "-o", default="pulse.json")
    parser.add_argument("--exclude", default="",
                        help="Comma-separated indicators to drop from the selection.")
    parser.add_argument("--include", default="",
                        help="Comma-separated excluded indicators to publish anyway.")
    args = parser.parse_args()

    description = args.description
    if description.startswith("@"):
        with open(description[1:]) as fh:
            description = fh.read().strip()

    loaded = []
    for path in args.investigations:
        with open(path) as fh:
            loaded.append(json.load(fh))

    built = build_pulse(
        loaded,
        title=args.title,
        description=description,
        tags=[t.strip() for t in args.tags.split(",") if t.strip()],
        attack_ids=[a.strip() for a in args.attack_ids.split(",") if a.strip()],
        exclude=[e.strip() for e in args.exclude.split(",") if e.strip()],
        include=[i.strip() for i in args.include.split(",") if i.strip()],
    )
    clean_path, audit_path = write_pulse(built, args.output)

    print(f"upload this : {clean_path}")
    for i in built["_included_detail"]:
        print(f"    {i['type']:<10} {i['indicator']}  (engine: {i['engine_risk_level']})")
    print(f"\naudit trail : {audit_path}")
    for e in built["_excluded"]:
        print(f"    excluded {e['indicator']} — {e['reason']}")
