# core/provenance.py
# Run provenance for a saved investigation: when it ran, what scored it, and a
# digest of the evidence the score was derived from.

import hashlib
import json
from datetime import datetime, timezone

from config import VERSION

# Bumped whenever a scoring path changes, so a stored score can be attributed to
# the code that produced it. Two investigations carrying the same number and
# different versions were not scored the same way, and the scoring paths here
# have already changed several times.
SCORER_VERSION = "1.0"

# What the digest covers, recorded alongside it so a reader does not have to
# guess. The verdict sits outside it on purpose: re-scoring saved evidence is a
# supported operation, and it must not read as tampering.
DIGEST_SCOPE = "full_results"


def evidence_digest(evidence) -> str:
    """
    sha256 over the collected evidence, canonically serialised.

    Sorted keys and fixed separators, because a JSON round trip does not
    preserve key order and a digest that depended on it would disagree with
    itself after the first save.
    """
    canonical = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), default=str
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def stamp(result: dict) -> dict:
    """
    Records when the investigation ran, what scored it, and a digest of the
    evidence. Mutates and returns the result.
    """
    result["provenance"] = {
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "engine_version": VERSION,
        "scorer_version": SCORER_VERSION,
        "evidence_digest": evidence_digest(result.get("full_results") or []),
        "digest_covers": DIGEST_SCOPE,
    }
    return result


def verify(result: dict) -> dict:
    """
    Whether a saved investigation's evidence is still the evidence collected.

    Three answers, and the third is the one that matters. "unstamped" means the
    file predates provenance and cannot be checked, which is not the same as
    "altered": reporting an older archive as tampered would blame the file for a
    gap in the engine.
    """
    block = result.get("provenance") or {}
    recorded = block.get("evidence_digest")

    if not recorded:
        return {
            "status": "unstamped",
            "detail": "saved before provenance was recorded, so it cannot be verified",
        }

    actual = evidence_digest(result.get("full_results") or [])
    if actual == recorded:
        return {"status": "verified", "digest": actual}

    return {"status": "altered", "recorded": recorded, "actual": actual}
