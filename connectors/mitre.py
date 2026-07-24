# connectors/mitre.py
# MITRE ATT&CK connector for the OSINT Pivot Engine.
# Enriches indicators with TTP data, threat groups, and malware profiles.

import os
import json
import logging
import requests
from mitreattack.stix20 import MitreAttackData

logger = logging.getLogger(__name__)

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
STIX_CACHE_PATH = "data/enterprise-attack.json"

MAX_TECHNIQUES = 20
MAX_GROUPS = 10
MAX_SOFTWARE = 10
DESCRIPTION_LIMIT = 300


class MITREConnector:
    """
    Connector for the MITRE ATT&CK framework.
    Downloads and caches the Enterprise ATT&CK STIX bundle on first run.
    Supports software and threat group lookups by name.
    """

    def __init__(self):
        self._ensure_stix_data()
        self.attack_data = MitreAttackData(STIX_CACHE_PATH)
        logger.info("MITRE ATT&CK connector initialized.")

    def _ensure_stix_data(self):
        """
        Downloads and caches the MITRE ATT&CK STIX bundle if not already present.
        Only runs on first use — subsequent calls load from disk.
        """
        if not os.path.exists(STIX_CACHE_PATH):
            os.makedirs("data", exist_ok=True)
            logger.info("Downloading MITRE ATT&CK STIX bundle (first run)...")
            try:
                response = requests.get(STIX_URL, timeout=60)
                response.raise_for_status()
                with open(STIX_CACHE_PATH, "w") as f:
                    json.dump(response.json(), f)
                logger.info("STIX bundle cached to data/enterprise-attack.json")
            except Exception as e:
                logger.error(f"Failed to download STIX bundle: {str(e)}")
                raise

    def _get_attack_id(self, stix_obj) -> str:
        """
        Extracts the ATT&CK ID (e.g. T1059, G0016) from a STIX object.
        """
        try:
            for ref in stix_obj.external_references:
                if ref.source_name == "mitre-attack":
                    return ref.external_id
        except Exception:
            pass
        return "unknown"

    def _clean_malware_name(self, label: str) -> str:
        """
        Cleans a VT threat label into a searchable MITRE name.
        e.g. "trojan.wannacry/wanna" -> "wannacry"
        """
        if "." in label:
            label = label.split(".", 1)[1]
        if "/" in label:
            label = label.split("/")[0]
        return label.strip().lower()

    def _find_software_by_name(self, name: str):
        """
        Searches all ATT&CK software entries for a name match.
        Uses substring match to handle naming variations.
        """
        all_software = self.attack_data.get_software()
        name_lower = name.lower()
        for sw in all_software:
            if name_lower in sw.name.lower():
                return sw
        return None

    def _find_group_by_name(self, name: str):
        """
        Searches all ATT&CK groups for a name or alias match.
        """
        all_groups = self.attack_data.get_groups()
        name_lower = name.lower()
        for group in all_groups:
            if name_lower in group.name.lower():
                return group
            aliases = getattr(group, "aliases", []) or []
            for alias in aliases:
                if name_lower in alias.lower():
                    return group
        return None

    def _extract_techniques(self, techniques_used: list) -> list:
        """
        Normalizes a list of technique relationship objects into clean dicts.
        """
        results = []
        for entry in techniques_used[:MAX_TECHNIQUES]:
            technique = entry["object"]
            tactics = []
            if hasattr(technique, "kill_chain_phases") and technique.kill_chain_phases:
                tactics = [phase.phase_name for phase in technique.kill_chain_phases]
            results.append({
                "technique_id": self._get_attack_id(technique),
                "name": technique.name,
                "tactics": tactics,
            })
        return results

    def query_software(self, name: str) -> dict:
        """
        Looks up a malware family or tool by name in ATT&CK.
        Cleans VT threat labels before searching.
        Returns associated techniques and threat groups that use it.
        """
        try:
            clean_name = self._clean_malware_name(name)
            software = self._find_software_by_name(clean_name)

            if not software:
                return {
                    "indicator": name,
                    "type": "software",
                    "source": "mitre_attack",
                    "found": False,
                    "searched_as": clean_name,
                    "techniques": [],
                    "groups": [],
                }

            stix_id = software.id

            techniques_raw = self.attack_data.get_techniques_used_by_software(stix_id)
            techniques = self._extract_techniques(techniques_raw)

            groups_raw = self.attack_data.get_groups_using_software(stix_id)
            groups = []
            for entry in groups_raw[:MAX_GROUPS]:
                group = entry["object"]
                groups.append({
                    "group_id": self._get_attack_id(group),
                    "name": group.name,
                    "aliases": getattr(group, "aliases", []),
                })

            return {
                "indicator": name,
                "type": "software",
                "source": "mitre_attack",
                "found": True,
                "searched_as": clean_name,
                "stix_id": stix_id,
                "software_name": software.name,
                "description": getattr(software, "description", "")[:DESCRIPTION_LIMIT],
                "techniques": techniques,
                "groups": groups,
            }

        except Exception as e:
            logger.error(f"MITRE software lookup failed for '{name}': {str(e)}")
            return {"error": str(e), "indicator": name, "source": "mitre_attack"}

    def query_group(self, name: str) -> dict:
        """
        Looks up a threat group by name or alias in ATT&CK.
        Returns associated techniques and software used by the group.
        """
        try:
            group = self._find_group_by_name(name)

            if not group:
                return {
                    "indicator": name,
                    "type": "group",
                    "source": "mitre_attack",
                    "found": False,
                    "techniques": [],
                    "software": [],
                }

            stix_id = group.id

            techniques_raw = self.attack_data.get_techniques_used_by_group(stix_id)
            techniques = self._extract_techniques(techniques_raw)

            software_raw = self.attack_data.get_software_used_by_group(stix_id)
            software = []
            for entry in software_raw[:MAX_SOFTWARE]:
                sw = entry["object"]
                software.append({
                    "software_id": self._get_attack_id(sw),
                    "name": sw.name,
                    "type": sw.type,
                })

            return {
                "indicator": name,
                "type": "group",
                "source": "mitre_attack",
                "found": True,
                "stix_id": stix_id,
                "group_name": group.name,
                "aliases": getattr(group, "aliases", []),
                "description": getattr(group, "description", "")[:DESCRIPTION_LIMIT],
                "techniques": techniques,
                "software": software,
            }

        except Exception as e:
            logger.error(f"MITRE group lookup failed for '{name}': {str(e)}")
            return {"error": str(e), "indicator": name, "source": "mitre_attack"}
