# core/ner_extractor.py
# NER-based threat actor extraction: 
# Scans pivot result text fields for known threat group names
# and automatically queues them for MITRE ATT&CK pivot chaining.

import logging
from mitreattack.stix20 import MitreAttackData

from config import STIX_CACHE_PATH

logger = logging.getLogger(__name__)
 
 
class NERExtractor:
    """
    Extracts threat actor names from pivot result text fields
    using a dictionary-based matching approach against MITRE ATT&CK
    group names and aliases. Recognized names are queued as
    threat_group seeds for automated MITRE pivot chaining.
    """
 
    def __init__(self):
        self.group_names = set()
        self.group_name_map = {}  # lowercase -> original casing
        self._load_group_names()
 
    def _load_group_names(self):
        """
        Loads all ATT&CK group names and aliases from the cached
        STIX bundle into a lookup set for fast matching.
        """
        try:
            attack_data = MitreAttackData(STIX_CACHE_PATH)
            groups = attack_data.get_groups()
            for group in groups:
                name = group.name
                self.group_names.add(name.lower())
                self.group_name_map[name.lower()] = name
                aliases = getattr(group, "aliases", []) or []
                for alias in aliases:
                    self.group_names.add(alias.lower())
                    self.group_name_map[alias.lower()] = alias
            logger.info(f"NER loaded {len(self.group_names)} group names and aliases.")
        except Exception as e:
            logger.error(f"Failed to load ATT&CK group names: {str(e)[:100]}")
 
    def _extract_text_fields(self, pivot_result: dict) -> list:
        """
        Extracts all text content from a pivot result that may
        contain threat actor mentions. Scans Ahmia snippets,
        MalwareBazaar tags, MITRE descriptions, groups, and VT file names.
        """
        texts = []
        results = pivot_result.get("results", {})
 
        # Ahmia dark web snippets
        ahmia = results.get("ahmia", {})
        for hit in ahmia.get("results", []):
            if hit.get("title"):
                texts.append(hit["title"])
            if hit.get("snippet"):
                texts.append(hit["snippet"])
 
        # MalwareBazaar tags and family names
        bazaar = results.get("malwarebazaar", {})
        if bazaar.get("malware_family"):
            texts.append(bazaar["malware_family"])
        for tag in bazaar.get("tags", []):
            texts.append(tag)
 
        # Related sample tags
        bazaar_related = results.get("malwarebazaar_related", {})
        for sample in bazaar_related.get("samples", []):
            for tag in sample.get("tags", []):
                texts.append(tag)
 
        # MITRE description text
        mitre = results.get("mitre", {})
        if mitre.get("description"):
            texts.append(mitre["description"])
 
        # MITRE groups — extract group names and aliases directly
        for group in mitre.get("groups", []):
            if group.get("name"):
                texts.append(group["name"])
            for alias in group.get("aliases", []):
                texts.append(alias)
 
        # VirusTotal file name
        vt = results.get("virustotal", {})
        if vt.get("file_name"):
            texts.append(vt["file_name"])
 
        return texts
 
    def extract_threat_actors(self, pivot_result: dict, visited: list) -> list:
        """
        Scans all text fields in a pivot result for known threat
        actor names and aliases. Returns a deduplicated list of
        recognized group names not already in the visited list.
        """
        texts = self._extract_text_fields(pivot_result)
        found = set()
        visited_lower = {v.lower() for v in visited}
 
        for text in texts:
            if not text:
                continue
 
            text_lower = text.lower().strip()
 
            # Exact match — text field is exactly a group name
            if text_lower in self.group_names and text_lower not in visited_lower:
                original = self.group_name_map.get(text_lower, text.strip())
                found.add(original)
                continue
 
            # Substring match — group name appears within longer text
            for group_name in self.group_names:
                if len(group_name) < 4:
                    # Skip very short names to avoid false positives
                    continue
                if group_name in text_lower and group_name not in visited_lower:
                    original = self.group_name_map.get(group_name, group_name)
                    found.add(original)
 
        if found:
            logger.info(f"NER extracted {len(found)} threat actor(s): {found}")
 
        return list(found)
 