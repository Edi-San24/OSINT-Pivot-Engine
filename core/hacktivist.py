# core/hacktivist.py
# Reads hacktivist alignment, activity, and targeting out of OTX pulse text.

import re

from core.detector import HACKTIVIST_GROUPS

# Every structured OTX field — industries, targeted_countries, malware_families,
# tags, adversary — is empty for these actors. The titles carry it all:
# "Pro-Russian Group Killnet Targets Romanian Government Websites with DDoS".

# Alignment is the most diagnostic signal. APT and ransomware reporting almost
# never uses this vocabulary; hacktivist reporting leads with it.
ALIGNMENT_PATTERNS = {
    "pro-Russia": r"pro[-\s]?(?:russia|russian|kremlin|moscow)",
    "pro-Ukraine": r"pro[-\s]?ukrain(?:e|ian)",
    "pro-Palestine": r"pro[-\s]?palestin(?:e|ian)",
    "pro-Israel": r"pro[-\s]?israel(?:i)?",
    "pro-Iran": r"pro[-\s]?iran(?:ian)?",
    "pro-India": r"pro[-\s]?india(?:n)?",
    "pro-Pakistan": r"pro[-\s]?pakistan(?:i)?",
    "pro-China": r"pro[-\s]?chin(?:a|ese)",
    "pro-Bangladesh": r"pro[-\s]?banglades(?:h|hi)",
    "anti-Israel": r"anti[-\s]?israel(?:i)?",
    "anti-Ukraine": r"anti[-\s]?ukrain(?:e|ian)",
    "anti-NATO": r"anti[-\s]?nato",
    "anti-Western": r"anti[-\s]?west(?:ern)?",
    "Islamist": r"\b(?:islamist|jihadist|caliphate)\b",
    "anti-establishment": r"\b(?:anarchist|anti[-\s]?capitalist)\b",
}

ACTIVITY_PATTERNS = {
    "DDoS": (
        r"\b(?:ddos|dos attack|distributed denial|denial[-\s]of[-\s]service|"
        r"knocked offline|taken offline)\b"
    ),
    "defacement": r"\bdeface(?:d|s|ment|ments)?\b",
    "hack-and-leak": (
        r"\b(?:hack[-\s]and[-\s]leak|data (?:leak|dump)|leak(?:ed|ing) (?:data|records)|"
        r"dumped (?:data|records|database)|doxx?(?:ed|ing))\b"
    ),
    "data breach": r"\b(?:breach(?:ed|es)?|exfiltrat(?:ed|ing|ion)|stole[n]? data)\b",
    "OT/ICS interference": (
        r"\b(?:scada|ics|plc[s]?|hmi|water (?:utility|treatment|system)|"
        r"industrial control)\b"
    ),
    "wiper": r"\b(?:wiper|wipe[ds]?|destructive attack|system wipes)\b",
    "ransomware": r"\bransomware\b",
}

# Wiping systems is a different problem from defacing a homepage, though both
# get called hacktivism. Lowest rank is reported first.
_SEVERITY_RANK = {
    "wiper": 0, "ransomware": 1, "OT/ICS interference": 2, "hack-and-leak": 3,
    "data breach": 4, "defacement": 5, "DDoS": 6,
}

# Name and demonym both, since titles use either: "Targets Romania" or
# "Romanian Government Websites".
COUNTRY_TERMS = {
    "Russia": r"russia[n]?",
    "Ukraine": r"ukrain(?:e|ian)",
    "Israel": r"israel(?:i)?",
    "Palestine": r"palestin(?:e|ian)",
    "Iran": r"iran(?:ian)?",
    "India": r"india[n]?",
    "Pakistan": r"pakistan(?:i)?",
    "Bangladesh": r"banglades(?:h|hi)",
    "China": r"chin(?:a|ese)",
    "Taiwan": r"taiwan(?:ese)?",
    "Japan": r"japan(?:ese)?",
    "South Korea": r"south korea[n]?",
    "North Korea": r"north korea[n]?",
    "United States": r"(?:united states|u\.?s\.?a?|american)",
    "United Kingdom": r"(?:united kingdom|u\.?k\.?|britain|british)",
    "Canada": r"canad(?:a|ian)",
    "Germany": r"german(?:y)?",
    "France": r"fren(?:ch)|france",
    "Italy": r"ital(?:y|ian)",
    "Spain": r"spain|spanish",
    "Portugal": r"portug(?:al|uese)",
    "Netherlands": r"netherlands|dutch",
    "Belgium": r"belgi(?:um|an)",
    "Poland": r"pol(?:and|ish)",
    "Romania": r"romania[n]?",
    "Bulgaria": r"bulgaria[n]?",
    "Hungary": r"hungar(?:y|ian)",
    "Czechia": r"czech(?:ia|\srepublic)?",
    "Slovakia": r"slovak(?:ia|ian)?",
    "Lithuania": r"lithuania[n]?",
    "Latvia": r"latvia[n]?",
    "Estonia": r"estonia[n]?",
    "Finland": r"fin(?:land|nish)",
    "Sweden": r"swed(?:en|ish)",
    "Norway": r"norw(?:ay|egian)",
    "Denmark": r"denmark|danish",
    "Moldova": r"moldova[n]?",
    "Georgia": r"georgia[n]?",
    "Turkey": r"turk(?:ey|ish)",
    "Greece": r"gree(?:ce|k)",
    "Albania": r"albania[n]?",
    "Serbia": r"serbia[n]?",
    "Croatia": r"croatia[n]?",
    "Switzerland": r"swi(?:tzerland|ss)",
    "Austria": r"austria[n]?",
    "Ireland": r"ir(?:eland|ish)",
    "Australia": r"australia[n]?",
    "Saudi Arabia": r"saudi(?:\sarabia[n]?)?",
    "United Arab Emirates": r"(?:united arab emirates|u\.?a\.?e\.?|emirati)",
    "Qatar": r"qatar(?:i)?",
    "Egypt": r"egypt(?:ian)?",
    "Jordan": r"jordan(?:ian)?",
    "Lebanon": r"leban(?:on|ese)",
    "Iraq": r"iraq(?:i)?",
    "Syria": r"syria[n]?",
    "Yemen": r"yemen(?:i)?",
    "Morocco": r"morocc(?:o|an)",
    "Algeria": r"algeria[n]?",
    "Tunisia": r"tunisia[n]?",
    "Nigeria": r"nigeria[n]?",
    "Kenya": r"kenya[n]?",
    "South Africa": r"south africa[n]?",
    "Indonesia": r"indonesia[n]?",
    "Malaysia": r"malaysia[n]?",
    "Philippines": r"philippin(?:es|e)|filipino",
    "Brazil": r"brazil(?:ian)?",
    "Mexico": r"mexic(?:o|an)",
    "Argentina": r"argentin(?:a|ian)",
}

# Phrased to match the labels an org profile uses, so core.relevance can
# compare the two directly.
SECTOR_PATTERNS = {
    "government": (
        r"\b(?:government|govt|ministry|ministries|parliament|municipal|"
        r"public sector|state agenc(?:y|ies)|federal agenc)"
    ),
    "financial services": (
        r"\b(?:bank(?:s|ing)?|financial|stock exchange|insurer|insurance|"
        r"payment processor|fintech)\b"
    ),
    "healthcare": r"\b(?:hospital[s]?|healthcare|health service|medical|clinic)\b",
    "energy": r"\b(?:energy|power grid|electric(?:ity)?|oil|gas|nuclear|refiner)\b",
    "water": r"\bwater (?:utility|utilities|system|treatment|authority|infrastructure)\b",
    "transportation": (
        r"\b(?:airport[s]?|airline[s]?|railway[s]?|rail|seaport[s]?|maritime|"
        r"shipping|transport(?:ation)?|logistics)\b"
    ),
    "telecommunications": r"\b(?:telecom(?:s|munications)?|isp[s]?|mobile operator|broadband)\b",
    "defense": r"\b(?:defen[cs]e|military|army|navy|air force|arms manufacturer)\b",
    "education": r"\b(?:universit(?:y|ies)|school[s]?|college[s]?|education)\b",
    "media": r"\b(?:media|news (?:agency|outlet|site)|broadcaster|television)\b",
    "technology": r"\b(?:tech(?:nology)? (?:firm|compan)|software (?:firm|compan)|cloud provider)\b",
    "manufacturing": r"\b(?:manufactur(?:ing|er)|industrial|factor(?:y|ies))\b",
    "retail": r"\b(?:retail(?:er)?|e-?commerce|supermarket)\b",
    "aviation": r"\b(?:aviation|aerospace)\b",
}

_HACKTIVIST_KEYWORD = re.compile(r"\b(?:hacktivis[tm]|hacktivists|cyber\s?partisan)\b", re.I)

# DDoS and defacement pay nothing, so a crew doing only those is ideological.
_IDEOLOGICAL_ACTIVITIES = {"DDoS", "defacement"}

MAX_EVIDENCE = 4

# Country names appear for two opposite reasons and a plain match cannot tell
# them apart. "Pro-Russian Killnet Targets Romanian Government" names Russia as
# alignment and Romania as target; "Russian hacktivist group" and
# "HANDALA-Iranian Nexus Actor" name origin. Attribution is stripped first, so
# only what is left counts as targeting.
#
# Deliberately narrow: the noun has to be the actor itself. "Russian banks" and
# "Romanian Government" are targets and must survive.
_ATTRIBUTION = re.compile(
    # "Iranian-nexus", "Russian state-sponsored"
    r"\b[a-z]+[-\s](?:nexus|linked|based|backed|sponsored|aligned|affiliated|"
    r"speaking|state|origin)\b"
    # "Russian hacktivist group", "Chinese APT"
    r"|\b[a-z]+[-\s](?:hacktivists?|hackers?|group|crew|gang|collective|"
    r"actor|apt|threat actor)\b"
    # "attributed to North Korea", "operating out of Iran"
    r"|\b(?:attributed|linked|tied|traced)\s+to\s+[a-z]+(?:\s+[a-z]+)?"
    r"|\b(?:backed by|on behalf of|operating out of)\s+[a-z]+(?:\s+[a-z]+)?",
    re.I,
)
# Possessive origin ("North Korea's Lazarus Group") is deliberately not stripped.
# A rule broad enough to catch it also eats real targets like "Romania's
# government", and for non-hacktivist groups these countries do not reach the
# score — only the relevance harvest.

_COMPILED_ALIGNMENTS = {k: re.compile(v, re.I) for k, v in ALIGNMENT_PATTERNS.items()}
_COMPILED_ACTIVITIES = {k: re.compile(v, re.I) for k, v in ACTIVITY_PATTERNS.items()}
_COMPILED_COUNTRIES = {k: re.compile(rf"\b(?:{v})\b", re.I) for k, v in COUNTRY_TERMS.items()}
_COMPILED_SECTORS = {k: re.compile(v, re.I) for k, v in SECTOR_PATTERNS.items()}


def _matches(compiled: dict, text: str) -> list[str]:
    return [label for label, pattern in compiled.items() if pattern.search(text)]


def _strip_attribution(text: str) -> str:
    """Removes alignment and origin phrasing. Countries only — nobody is 'pro-hospital'."""
    for pattern in _COMPILED_ALIGNMENTS.values():
        text = pattern.sub(" ", text)
    return _ATTRIBUTION.sub(" ", text)


def assess(group_name: str, pulses: list[dict]) -> dict:
    """
    Reads a group's OTX pulses for hacktivist alignment, activity, and targeting.
    Returns is_hacktivist False with empty lists when reporting does not support
    it — an absence, not a denial.
    """
    on_roster = group_name.strip().lower().replace(" ", "") in HACKTIVIST_GROUPS

    alignments: dict[str, int] = {}
    activities: dict[str, int] = {}
    countries: dict[str, int] = {}
    sectors: dict[str, int] = {}
    keyword_hits = 0
    evidence: list[str] = []

    for pulse in pulses or []:
        title = pulse.get("name") or ""
        text = f"{title} {pulse.get('description') or ''}"
        if not text.strip():
            continue

        found_alignments = _matches(_COMPILED_ALIGNMENTS, text)
        found_activities = _matches(_COMPILED_ACTIVITIES, text)

        # Targeting comes off the title alone, and only when the title describes
        # an action. Titles are short and shaped like "X Targets Y"; descriptions
        # are prose where a country is as likely to be the actor's own, and no
        # amount of attribution stripping reliably tells the two apart.
        if found_activities and _matches(_COMPILED_ACTIVITIES, title):
            found_countries = _matches(_COMPILED_COUNTRIES, _strip_attribution(title))
            found_sectors = _matches(_COMPILED_SECTORS, title)
        else:
            found_countries, found_sectors = [], []

        for label in found_alignments:
            alignments[label] = alignments.get(label, 0) + 1
        for label in found_activities:
            activities[label] = activities.get(label, 0) + 1
        for label in found_countries:
            countries[label] = countries.get(label, 0) + 1
        for label in found_sectors:
            sectors[label] = sectors.get(label, 0) + 1

        if _HACKTIVIST_KEYWORD.search(text):
            keyword_hits += 1

        if (found_alignments or found_activities) and len(evidence) < MAX_EVIDENCE:
            title = re.sub(r"\s+", " ", pulse.get("name") or "").strip()
            if title:
                evidence.append(title[:160])

    activity_labels = sorted(activities, key=lambda a: _SEVERITY_RANK.get(a, 99))
    ideological_only = bool(activity_labels) and set(activity_labels) <= _IDEOLOGICAL_ACTIVITIES

    # Alignment, roster, and the explicit keyword are each conclusive. DDoS or
    # defacement alone is suggestive only — a criminal crew can do both.
    if on_roster or alignments or keyword_hits:
        is_hacktivist = True
        confidence = "high" if (alignments and activity_labels) or on_roster else "medium"
    elif ideological_only:
        is_hacktivist = True
        confidence = "low"
    else:
        is_hacktivist = False
        confidence = "none"

    return {
        "is_hacktivist": is_hacktivist,
        "confidence": confidence,
        "on_roster": on_roster,
        "alignments": sorted(alignments, key=lambda a: -alignments[a]),
        "activities": activity_labels,
        "target_countries": sorted(countries, key=lambda c: -countries[c]),
        "target_sectors": sorted(sectors, key=lambda s: -sectors[s]),
        "keyword_mentions": keyword_hits,
        "pulses_analysed": len(pulses or []),
        "evidence": evidence,
    }


def targeting_overlap(assessment: dict, org_profile: dict | None) -> dict:
    """
    Which of the crew's stated targets match the org profile.
    Separate from core.relevance's own check, which compares OTX's structured
    fields — empty for these actors.
    """
    if not org_profile or not assessment.get("is_hacktivist"):
        return {"countries": [], "sectors": [], "matched": False}

    def overlap(stated: list[str], declared: list[str]) -> list[str]:
        # Matched case-insensitively, reported in the profile's own spelling.
        by_lower = {d.lower(): d for d in (declared or [])}
        return sorted(by_lower[s.lower()] for s in stated if s.lower() in by_lower)

    countries = overlap(assessment.get("target_countries", []), org_profile.get("countries", []))
    sectors = overlap(assessment.get("target_sectors", []), org_profile.get("sectors", []))

    return {
        "countries": countries,
        "sectors": sectors,
        "matched": bool(countries or sectors),
    }
