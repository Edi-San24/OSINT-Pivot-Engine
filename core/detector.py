# core/detector.py
import re

KNOWN_MALWARE_FAMILIES = {
    # Top RATs 2025-2026
    "remcos", "asyncrat", "xworm", "quasarrat", "njrat", "dcrat",
    "nanocore", "darkcomet", "imminent monitor", "purecrypter",
    "warzone rat", "netwire", "gh0st rat", "androrat", "bifrost",
    "havoc", "havoc c2",

    # Top stealers 2025-2026
    "lumma", "lummastealer", "vidar", "redline", "raccoon", "azorult",
    "formbook", "agentesla", "snakekeylogger", "acreed", "katana",
    "aurora stealer", "titan stealer", "rhadamanthys", "meduza",
    "whitesnake", "stealc", "mystic stealer",

    # Ransomware
    "wannacry", "lockbit", "ryuk", "conti", "darkside", "revil",
    "blackcat", "alphv", "magniber", "hive", "blackbasta", "akira",
    "cl0p", "medusa", "play", "royal", "rhysida", "hunters",
    "dark angels", "genielocker", "ransomexx",

    # Loaders and droppers
    "emotet", "trickbot", "qakbot", "icedid", "bazarloader",
    "gootloader", "hancitor", "ursnif", "dridex", "smokeloader",
    "systembc", "amadey", "guloader", "dbatloader", "modiloader",
    "privateloader", "nullzereptool",

    # Backdoors and implants
    "cobalt strike", "cobaltstrike", "mimikatz", "meterpreter",
    "metasploit", "sliver", "brute ratel", "bruteratel",
    "blindingcan", "hoplight", "fatcash", "keyplug", "vshell",
    "zimreaper", "carbanak", "fin7 toolset", "powersploit",
    "empire", "covenant", "deimos",

    # AI-powered and emerging threats 2025-2026
    "fraudgpt", "wormgpt", "jadepuffer", "agentforger",
    "promptflux", "promptsteal", "nullzereptool",

    # Cryptominers
    "xmrig", "lemon duck", "kinsing",

    # Wipers
    "hermetic wiper", "whispergate", "industroyer", "apostle",
    "caddywiper", "orcshred",

    # PhaaS kits
    "evilproxy", "tycoon 2fa", "modlishka", "evilginx",
    "greatness", "caffeine",

    # Android and mobile
    "craxsrat", "spynote", "ahrat", "flubot", "sharkbot",
    "vultur", "hook", "brasdex",

    # Nation-state tooling
    "snake", "turla", "carbon", "uroburos", "sunburst",
    "teardrop", "raindrop", "goldmax", "sibot", "hoplight",
    "typeframe", "artfulpie",

    # Botnets
    "mirai", "botnet", "mozi", "meris", "dark iot",
}

# --- Regex patterns for each indicator type ---
PATTERNS = {
    "ipv4": re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    ),
    "domain": re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ),
    "md5": re.compile(
        r"^[a-fA-F0-9]{32}$"
    ),
    "sha1": re.compile(
        r"^[a-fA-F0-9]{40}$"
    ),
    "sha256": re.compile(
        r"^[a-fA-F0-9]{64}$"
    ),
    "email": re.compile(
        r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    ),

    "username": re.compile(
        r"^[a-zA-Z0-9._\-]{3,30}$"

    ),
    "threat_group": re.compile(
    r"^[A-Z][a-zA-Z0-9\s\-\_\.]{1,60}$"
    ),

    "software": re.compile(
    r"^[A-Z][a-zA-Z0-9\s\-\_\.]{1,60}$"
    ),

}

# Priority order matters — more specific patterns run first
DETECTION_ORDER = ["email", "ipv4", "sha256", "sha1", "md5", "domain", "threat_group","software", "username"]

def detect_type(seed: str) -> dict:
    """
    Accepts a seed indicator string:
    Returns a dict with 'indicator', 'type', and 'confidence'
    Username is fallback -- matches almost anything [runs last]
    """
    seed = seed.strip()

    # Check known malware families before regex matching
    if seed.lower() in KNOWN_MALWARE_FAMILIES:
        return {
            "indicator": seed,
            "type": "software",
            "confidence": "high"
        }


    for indicator_type in DETECTION_ORDER:
        pattern = PATTERNS[indicator_type]
        if pattern.match(seed):
            confidence = "low" if indicator_type == "username" else "high"
            return {
                "indicator": seed,
                "type": indicator_type,
                "confidence": confidence
            }