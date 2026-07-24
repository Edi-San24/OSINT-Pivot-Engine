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
