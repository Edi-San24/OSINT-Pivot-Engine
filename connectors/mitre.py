# connectors/mitre.py
# MITRE ATT&CK connector for the OSINT Pivot Engine.
# Enriches indicators with TTP data, threat groups, and malware profiles.

import os
import re
import time
import logging
import requests
from mitreattack.stix20 import MitreAttackData

from config import STIX_CACHE_PATH

logger = logging.getLogger(__name__)

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# ATT&CK adds groups and aliases between releases, and a name it gained since
# the cached copy cannot be matched at all.
BUNDLE_MAX_AGE_DAYS = 30
BUNDLE_TIMEOUT = 120

MAX_TECHNIQUES = 20
MAX_GROUPS = 10
MAX_SOFTWARE = 10
DESCRIPTION_LIMIT = 300


def ensure_bundle(path: str = STIX_CACHE_PATH, max_age_days: int = BUNDLE_MAX_AGE_DAYS) -> None:
    """
    Downloads the Enterprise ATT&CK bundle when it is missing or older than
    max_age_days.

    A failed refresh keeps the copy on disk, since a stale bundle still answers.
    A failed first download raises, since nothing does. The file is replaced
    only once a complete bundle has arrived.
    """
    exists = os.path.exists(path)
    if exists and time.time() - os.path.getmtime(path) < max_age_days * 86400:
        return

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        response = requests.get(STIX_URL, timeout=BUNDLE_TIMEOUT)
        response.raise_for_status()
        objects = response.json().get("objects") or []
        if not any(o.get("type") == "intrusion-set" for o in objects):
            raise ValueError("downloaded bundle holds no groups")
        partial = f"{path}.partial"
        with open(partial, "wb") as f:
            f.write(response.content)
        os.replace(partial, path)
        logger.info(f"ATT&CK bundle refreshed: {path}")
    except Exception as e:
        if not exists:
            logger.error(f"Failed to download the ATT&CK bundle: {str(e)[:200]}")
            raise
        logger.warning(f"ATT&CK refresh failed, keeping the cached bundle: {str(e)[:120]}")


def _names(entry) -> list[str]:
    """An ATT&CK object's name and aliases. Groups and software keep them under different keys."""
    aliases = getattr(entry, "aliases", None) or getattr(entry, "x_mitre_aliases", None) or []
    return [entry.name, *aliases]


def resolve_name(entries: list, name: str) -> tuple:
    """
    The entry a name refers to, as (entry, match, candidates).

    An exact match wins, ignoring case: an entry's own name first, since ATT&CK
    also lists some names as another entry's alias, then its aliases. Failing
    that, a whole-word match is accepted when exactly one entry has one, and is
    reported as "partial" so the reader can confirm it. A name shared by
    several entries is "ambiguous" and picks none, since the first hit is an
    accident of file order.
    """
    query = (name or "").strip().lower()
    if not query:
        return None, None, []

    named = [e for e in entries if e.name.lower() == query]
    if len(named) == 1:
        return named[0], "exact", []

    exact = {e.id: e for e in entries if query in (n.lower() for n in _names(e))}
    if len(exact) == 1:
        return next(iter(exact.values())), "exact", []
    if len(exact) > 1:
        return None, "ambiguous", sorted(e.name for e in exact.values())

    word = re.compile(rf"(?<!\w){re.escape(query)}(?!\w)", re.IGNORECASE)
    partial = {e.id: e for e in entries if any(word.search(n) for n in _names(e))}
    if len(partial) == 1:
        return next(iter(partial.values())), "partial", []
    if len(partial) > 1:
        return None, "ambiguous", sorted(e.name for e in partial.values())
    return None, None, []


class MITREConnector:
    """
    Connector for the MITRE ATT&CK framework.
    Downloads the Enterprise ATT&CK STIX bundle on first run and refreshes it
    monthly. Supports software and threat group lookups by name.
    """

    def __init__(self):
        ensure_bundle()
        self.attack_data = MitreAttackData(STIX_CACHE_PATH)
        logger.info("MITRE ATT&CK connector initialized.")

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

    def _find_software_by_name(self, name: str) -> tuple:
        """
        Resolves a software name among live entries, as (entry, match,
        candidates, searched_as).

        The name is tried as given first. A VirusTotal label is cleaned only
        when that fails, since cleaning splits on dots and slashes that real
        names such as "LockBit 3.0" and "OSX/Shlayer" contain.
        """
        live = self.attack_data.get_software(remove_revoked_deprecated=True)
        software, match, candidates = resolve_name(live, name)
        searched_as = (name or "").strip().lower()
        if software is None and match != "ambiguous":
            cleaned = self._clean_malware_name(name)
            if cleaned != searched_as:
                software, match, candidates = resolve_name(live, cleaned)
                searched_as = cleaned
        return software, match, candidates, searched_as

    def _find_group_by_name(self, name: str) -> tuple:
        """Resolves a group name among live groups, as (group, match, candidates)."""
        live = self.attack_data.get_groups(remove_revoked_deprecated=True)
        return resolve_name(live, name)

    def group_ref(self, name: str) -> dict | None:
        """
        The ATT&CK group a name exactly is, or None. No partial matching, for
        callers relating one actor name to another.
        """
        group, match, _ = self._find_group_by_name(name)
        if group is None or match != "exact":
            return None
        return {"group_id": self._get_attack_id(group), "group_name": group.name}

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
            software, match, candidates, clean_name = self._find_software_by_name(name)

            if not software:
                return {
                    "indicator": name,
                    "type": "software",
                    "source": "mitre_attack",
                    "found": False,
                    "searched_as": clean_name,
                    "match": match,
                    "candidates": candidates,
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
                "match": match,
                "stix_id": stix_id,
                "software_name": software.name,
                "software_type": getattr(software, "type", "unknown"),
                "description": getattr(software, "description", "")[:DESCRIPTION_LIMIT],
                # True totals, taken before truncation — see query_group.
                "technique_count": len(techniques_raw),
                "group_count": len(groups_raw),
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
            group, match, candidates = self._find_group_by_name(name)

            if not group:
                return {
                    "indicator": name,
                    "type": "group",
                    "source": "mitre_attack",
                    "found": False,
                    "match": match,
                    "candidates": candidates,
                    "techniques": [],
                    "software": [],
                }

            stix_id = group.id

            techniques_raw = self.attack_data.get_techniques_used_by_group(stix_id)
            techniques = self._extract_techniques(techniques_raw)

            software_raw = self.attack_data.get_software_used_by_group(stix_id)
            # Malware first, so truncation keeps the entries worth pivoting into.
            software_sorted = sorted(
                software_raw,
                key=lambda e: 0 if getattr(e["object"], "type", "") == "malware" else 1
            )
            software = []
            for entry in software_sorted[:MAX_SOFTWARE]:
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
                "match": match,
                "stix_id": stix_id,
                "group_name": group.name,
                "aliases": getattr(group, "aliases", []),
                "description": getattr(group, "description", "")[:DESCRIPTION_LIMIT],
                # True totals, taken before the lists below are truncated.
                # Scoring must use these, not len() of the truncated lists.
                "technique_count": len(techniques_raw),
                "software_count": len(software_raw),
                "techniques": techniques,
                "software": software,
            }

        except Exception as e:
            logger.error(f"MITRE group lookup failed for '{name}': {str(e)}")
            return {"error": str(e), "indicator": name, "source": "mitre_attack"}
