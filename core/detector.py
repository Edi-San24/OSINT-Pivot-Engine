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
    "dark angels", "genielocker", "ransomexx", "qilin", "agenda ransomware",

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

# Its own set because core.hacktivist uses it as a roster — a name here is a
# known crew before any reporting is read. Folded into KNOWN_THREAT_GROUPS, so
# detection treats them like any other actor name.
HACKTIVIST_GROUPS = {
    "killnet", "cybervolk", "shinyhunters", "handala", "noname057",
    "anonsudan", "ghostsec", "sylhet", "arvinclub", "siegedsec",
    "cyberav3ngers", "usersec", "anonymousrussia", "phoenix", "zarya",
    "cyberarmyofrussia", "solntsepek", "twelve", "beregini",
    "predatorysparrow", "tengriteam", "moroccanblackcyberarmy", "stucx",
    "mysteriousteam", "keymous", "eagleteam", "lulzsec", "darkstorm",
    # Space-stripped, so "Cyber Toufan" and "Dark Storm Team" match too.
    "cybertoufan", "cybertoufanalaqsa", "darkstormteam", "anonymoussudan",
    "holyleague", "indohaxsec", "rippersec", "mrhamza", "zpentest",
    "sylhetgang", "keymousplus",
}

# Single-token actor names, matched case-insensitively like the families above.
# Only single tokens need listing: multi-word names are caught by the whitespace
# rule in detect_type and APT28/TA505/UNC2452 by ACTOR_DESIGNATOR. A bare word is
# all that is left, and it is indistinguishable from a username.
#
# Names also in KNOWN_MALWARE_FAMILIES resolve as software, since that is checked
# first. Intended — for Akira the family and the crew share a name.
KNOWN_THREAT_GROUPS = {
    # ATT&CK-profiled actors whose names are one word
    "lazarus", "sandworm", "kimsuky", "andariel", "gamaredon", "oilrig",
    "menupass", "patchwork", "leviathan", "naikon", "machete", "silence",
    "strider", "suckfly", "sowbug", "thrip", "winnti", "zirconium",
    "equation", "axiom", "cleaver", "confucius", "darkhotel", "darkhydrus",
    "darkvishnya", "dragonfly", "dragonok", "evilnum", "gallmaker",
    "gelsemium", "higaisa", "honeybee", "inception", "ke3chang",
    "lazyscripter", "leafminer", "malteiro", "metador", "moafee", "mofang",
    "molerats", "oceanlotus", "orangeworm", "promethium", "rancor", "rocke",
    "sidecopy", "sidewinder", "taidoor", "whitefly", "windigo", "windshift",
    "wirte", "blacktech", "bitter", "chimera", "coreid", "elderwood",
    "indrik", "poseidon", "silverterrier", "tortoiseshell", "aoqin",

    # Ransomware crews, mostly absent from ATT&CK
    "lynx", "ransomhub", "blacksuit", "cactus", "cloak", "everest",
    "hellcat", "interlock", "kairos", "sarcoma", "spacebears", "termite",
    "trigona", "vanhelsing", "embargo", "fog", "helldown", "braincipher",
    "nitrogen", "rhysida", "funksec", "safepay",

} | HACKTIVIST_GROUPS

# Naming conventions rather than names, so a pattern covers actors no list keeps
# up with. Digit counts are per-scheme so short handles are not swept up: APT1
# and FIN7 are real, "ta5" and "g1" are likelier to be usernames.
ACTOR_DESIGNATOR = re.compile(
    r"^(?:"
    r"(?:apt|fin)[\s\-._]?\d{1,3}"                     # APT1, APT28, FIN7
    r"|(?:ta|unc|temp|storm|dev|utg)[\s\-._]?\d{3,5}"  # TA505, UNC2452, Storm-0558
    r"|g\d{4}"                                         # ATT&CK group IDs, G0016
    r")[a-z]?$",
    re.IGNORECASE,
)

_WHITESPACE = re.compile(r"\s")

# Second-level public suffixes, so stripping a hostname to its registrable
# domain stops before it returns a public suffix. Not a full PSL — the common
# ccTLD structures, which is what shows up in practice.
PUBLIC_SUFFIXES_2LD = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.za", "org.za", "net.za", "web.za",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in", "gov.in",
    "com.cn", "net.cn", "org.cn",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.tw", "com.hk",
    "co.kr", "or.kr", "co.il", "org.il", "co.th", "com.my", "com.ph",
}


def registrable_domain(name: str) -> str:
    """
    The registrable domain for a hostname — app.dinkfoundry.com to
    dinkfoundry.com, a.b.example.co.za to example.co.za.

    Registries and domain-level products index registrable names, not
    hostnames, so querying the full name returns nothing and reads as "not
    found" rather than "wrong question".
    """
    labels = name.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in PUBLIC_SUFFIXES_2LD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

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
    # Scheme-prefixed, so it cannot collide with a bare domain. Ports, paths and
    # query strings all belong to the URL rather than to the host, which is why
    # the domain pattern rejected them.
    "url": re.compile(
        r"^https?://[^\s<>\"{}|\\^`\[\]]+$",
        re.IGNORECASE,
    ),
}

# Priority order matters — more specific patterns run first. Username is last
# because it matches almost any bare token.
#
# threat_group and software were in here as regexes requiring a capital first
# letter, which is a property of how fast someone types, not of the indicator.
# Both are resolved by name lookup in detect_type now. The software regex was
# unreachable anyway — threat_group held an identical pattern and ran first.
DETECTION_ORDER = ["url", "email", "ipv4", "sha256", "sha1", "md5", "domain", "username"]


def _detected(seed: str, indicator_type: str, confidence: str) -> dict:
    return {"indicator": seed, "type": indicator_type, "confidence": confidence}


def detect_type(seed: str) -> dict | None:
    """
    Accepts a seed indicator string.
    Returns a dict with 'indicator', 'type' and 'confidence', or None for no
    supported type. Case-insensitive throughout — the original spelling is
    returned untouched in 'indicator', since that is what connectors receive.
    """
    seed = seed.strip()
    if not seed:
        return None

    normalized = seed.lower()

    # Named entities beat every pattern, matched lowercase so capitalisation
    # never changes the answer.
    if normalized in KNOWN_MALWARE_FAMILIES:
        return _detected(seed, "software", "high")

    if normalized in KNOWN_THREAT_GROUPS:
        return _detected(seed, "threat_group", "high")

    if ACTOR_DESIGNATOR.match(seed):
        return _detected(seed, "threat_group", "high")

    # Structural types. Already case-agnostic — hex digests accept both cases and
    # hostnames are case-insensitive by definition.
    for indicator_type in DETECTION_ORDER:
        if PATTERNS[indicator_type].match(seed):
            confidence = "low" if indicator_type == "username" else "high"
            return _detected(seed, indicator_type, confidence)

    # Whitespace rules out a username, so this is an actor name we have not seen
    # before — what the group pivot's OTX fallback exists for. This returned None
    # before, which is how a lowercase "lazarus group" ended up scored LOW.
    if _WHITESPACE.search(seed):
        return _detected(seed, "threat_group", "medium")

    return None