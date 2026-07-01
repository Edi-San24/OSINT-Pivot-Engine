# core/detector.py
import re

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
}

# Priority order matters — more specific patterns run first
DETECTION_ORDER = ["email", "ipv4", "sha256", "sha1", "md5", "domain", "username"]

def detect_type(seed: str) -> dict:
    """
    Accepts a seed indicator string:
    Returns a dict with 'indicator', 'type', and 'confidence'
    Username is fallback -- matches almost anything [runs last]
    """
    seed = seed.strip()
    for indicator_type in DETECTION_ORDER:
        pattern = PATTERNS[indicator_type]
        if pattern.match(seed):
            confidence = "low" if indicator_type == "username" else "high"
            return {
                "indicator": seed,
                "type": indicator_type,
                "confidence": confidence
            }