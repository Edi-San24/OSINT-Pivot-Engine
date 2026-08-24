# core/stix_exporter.py
# STIX 2.1 exporter: 
# Converts investigation results into a standardized STIX bundle.

import json
import logging
from datetime import datetime, timezone

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
    "md5": "FileHash-MD5",
    "sha1": "FileHash-SHA1",
    "sha256": "FileHash-SHA256",
    "email": "email",
}


def _is_under(name: str, parents: set[str]) -> bool:
    """Whether name is one of parents, or a subdomain of one."""
    name = name.lower().rstrip(".")
    return any(name == p or name.endswith("." + p) for p in parents)


def _co_hosted_tenants(pivot: dict, investigated_domains: set[str]) -> list[str]:
    """
    Domains on this IP that belong to somebody else.

    A host serving names outside the investigated domains is shared, so
    publishing its address asks other defenders to block bystanders. This is
    the check that separates a tenant's own box from a multi-tenant one, and it
    is deliberately strict: one foreign name is enough.
    """
    records = (pivot.get("results", {}).get("passivedns") or {}).get("records") or []
    tenants = []
    for record in records:
        value = (record.get("domain") or record.get("ip") or "").strip().lower()
        if value and not value.replace(".", "").isdigit():
            if not _is_under(value, investigated_domains):
                tenants.append(value)
    return sorted(set(tenants))


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
    investigated: list[tuple[str, dict]] = []
    for investigation in investigations:
        for name in investigation.get("visited", []):
            investigated.append((name.strip().lower(), investigation))

    domains = {
        n for n, _ in investigated
        if not n.replace(".", "").isdigit() and "." in n
    }

    included, excluded = [], []
    seen = set()

    for name, investigation in investigated:
        if name in seen:
            continue
        seen.add(name)

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
            tenants = _co_hosted_tenants(pivot, domains)
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
        included.append({
            "indicator": name,
            "type": OTX_TYPES.get(resolved, resolved),
            "engine_risk_level": investigation.get("risk_level", "unknown"),
        })

    return included, excluded


def build_pulse(investigations: list[dict], title: str, description: str,
          tags: list[str] = None, attack_ids: list[str] = None) -> dict:
    """
    Assembles the pulse payload plus an audit of what was left out.

    The payload matches what OTXConnector.publish_pulse posts, so the same
    object can be uploaded or published without reshaping.
    """
    included, excluded = select_indicators(investigations)

    return {
        "name": title,
        "description": description,
        "public": 1,
        "TLP": "white",
        "tags": tags or [],
        "attack_ids": attack_ids or [],
        "indicators": [
            {"indicator": i["indicator"], "type": i["type"]} for i in included
        ],
        "malware_families": [],
        "adversary": "",
        "targeted_countries": [],
        # Not part of the OTX payload. Kept so every dropped indicator has a
        # stated reason rather than vanishing silently.
        "_excluded": excluded,
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
    )
    clean_path, audit_path = write_pulse(built, args.output)

    print(f"upload this : {clean_path}")
    for i in built["_included_detail"]:
        print(f"    {i['type']:<10} {i['indicator']}  (engine: {i['engine_risk_level']})")
    print(f"\naudit trail : {audit_path}")
    for e in built["_excluded"]:
        print(f"    excluded {e['indicator']} — {e['reason']}")
