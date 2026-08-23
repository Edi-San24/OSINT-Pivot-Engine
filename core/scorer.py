# core/scorer.py
# Loads trained models and scores indicators at runtime.
# Returns a confidence score and anomaly flag for each pivot result.


import joblib
import numpy as np
import logging
from core import hacktivist
from core.features import extract_features
from config import MODEL_DIR

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Full marks on each component, set to the 95th percentile of the measured
# distribution across all ATT&CK groups. Must stay above the connector's
# truncation caps, or every well-documented group scores identically.
TECHNIQUE_FULL_MARKS = 78
SOFTWARE_FULL_MARKS = 23
ALIAS_FULL_MARKS = 9

# Sample volume earning full marks on a malware family pivot. Measured across
# established families: targeted ransomware sits around 27-80 while commodity
# malware runs into the thousands. Volume therefore marks whether a family is
# established, not how dangerous it is — severity comes from the tag signal —
# so this saturates early on purpose.
SAMPLE_VOLUME_FULL_MARKS = 50
 
 
class ConfidenceScorer:
    """
    Loads trained models and scores pivot results.
    Returns a confidence score between 0 and 1
    and an anomaly flag from Isolation Forest.
 
    Use score_any() as the single entry point — it routes
    to the correct scoring method based on indicator type.
    """
 
    def __init__(self, org_profile: dict | None = None):
        # Only used to score hacktivist targeting overlap. Passed in rather than
        # loaded here so core.agent stays the single place the profile is read.
        self.org_profile = org_profile
        try:
            self.gb_model = joblib.load(f"{MODEL_DIR}/gradient_boosting.joblib")
            self.iso_forest = joblib.load(f"{MODEL_DIR}/isolation_forest.joblib")
            logger.info("Confidence scoring models loaded successfully.")
        except FileNotFoundError:
            logger.error("Models not found. Run core/trainer.py first.")
            self.gb_model = None
            self.iso_forest = None
 
    def _risk_level(self, score: float, thresholds: tuple = (0.7, 0.4)) -> str:
        """Returns HIGH / MEDIUM / LOW based on score and thresholds."""
        high, medium = thresholds
        if score >= high:
            return "HIGH"
        elif score >= medium:
            return "MEDIUM"
        return "LOW"

    def _risk_fields(self, score: float, thresholds: tuple = (0.7, 0.4)) -> dict:
        """
        risk_level plus the thresholds used to reach it.

        These are calibrated per indicator type and were being thrown away: only
        confidence_score propagated, so the front end reapplied a global 0.7/0.4
        and could disagree with the level reported here. A community-scored group
        at 0.55 was HIGH to the scorer and MEDIUM on screen. Emitted as a list
        because the value round-trips through JSON.
        """
        return {
            "risk_level": self._risk_level(score, thresholds),
            "thresholds": list(thresholds),
        }
 
    def score(self, pivot_result: dict) -> dict:
        """
        ML-based scoring for infrastructure indicators — IP, domain, hash.
        Uses Gradient Boosting + Isolation Forest trained on ThreatFox data.
        """
        if not self.gb_model or not self.iso_forest:
            return {"error": "Models not loaded. Run trainer first."}
 
        features = extract_features(pivot_result)
 
        import pandas as pd
        from core.features import FEATURE_COLUMNS
        X = pd.DataFrame([features])[FEATURE_COLUMNS]
 
        confidence_score = self.gb_model.predict_proba(X)[0][1]
        anomaly_flag = self.iso_forest.predict(X)[0]
        is_anomaly = anomaly_flag == -1
 
        return {
            "confidence_score": round(float(confidence_score), 4),
            "is_anomaly": is_anomaly,
            **self._risk_fields(confidence_score),
            "features_used": features,
        }
 
    # Relevant, deduplicated pulses earning full marks when ATT&CK has nothing.
    # Measured on filtered counts: NoName057 27, Handala 25, KillNet 12,
    # CyberVolk 11. Modest on purpose — a genuinely new actor may have a handful
    # on day one, and the point is to register it exists at all.
    COMMUNITY_PULSE_FULL_MARKS = 15

    def _score_group_from_community(self, pivot_result: dict, results: dict) -> dict:
        """
        Scores a threat group that MITRE ATT&CK does not profile, from OTX pulse
        volume, distinct authors, and dark web mentions.

        Caps below the ATT&CK-backed range on purpose. Community reporting
        establishes that an actor is real and active; it does not carry the
        same evidentiary weight as a curated ATT&CK profile.

        Targeting overlap is deliberately not scored here. Measured against
        KillNet, a profile the crew names scored 0.75 and one it does not scored
        0.7025 — both HIGH, because the 0.75 cap swallows the term. It is routed
        through core.relevance instead, which is what relevance_level is for.
        """
        otx = results.get("otx_search", {})
        ahmia = results.get("ahmia", {})
        assessment = results.get("hacktivist", {}) or {}

        pulse_count = otx.get("pulse_count", 0) if isinstance(otx, dict) else 0
        authors = otx.get("distinct_authors", 0) if isinstance(otx, dict) else 0
        onion_hits = len(ahmia.get("results", []) or []) if isinstance(ahmia, dict) else 0
        is_hacktivist = bool(assessment.get("is_hacktivist"))
        otx_failed = isinstance(otx, dict) and "error" in otx

        # What the branch below can actually score from. The hacktivist branch
        # ignores onion hits, so they are not usable evidence there.
        scoreable = bool(pulse_count) or (bool(onion_hits) and not is_hacktivist)

        # A failed lookup is not an empty result, and neither is a clean bill.
        if otx_failed or not scoreable:
            reason = (
                "OTX pulse search failed, so community reporting could not be checked"
                if otx_failed else
                "No match in MITRE ATT&CK, OTX community reporting, or dark web indexes"
            )
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "is_hacktivist": is_hacktivist,
                "note": (
                    f"{reason}. Either the name is wrong, the source was "
                    "unavailable, or the actor is too new to have been written "
                    "up. This is an absence of data, not a clean bill."
                ),
            }

        # Volume says an actor is discussed; independent authors say it is not
        # one person's post amplified.
        volume = min(pulse_count / self.COMMUNITY_PULSE_FULL_MARKS, 1.0)
        corroboration = min(authors / 5, 1.0)

        if is_hacktivist:
            # These crews coordinate on Telegram, so onion hits are structurally
            # near zero and carrying that weight would only suppress the score.
            # It goes to corroboration instead.
            score = (volume * 0.55) + (corroboration * 0.45)
            basis = self._hacktivist_note(assessment, pulse_count, authors)
        else:
            underground = min(onion_hits / 5, 1.0)
            score = (volume * 0.45) + (corroboration * 0.35) + (underground * 0.20)
            basis = (
                f"{pulse_count} OTX pulses from {authors} authors, "
                f"{onion_hits} dark web mentions."
            )

        score = round(min(score, 0.75), 4)

        return {
            "confidence_score": score,
            "is_anomaly": False,
            **self._risk_fields(score, thresholds=(0.5, 0.25)),
            "pulse_count": pulse_count,
            "distinct_authors": authors,
            "onion_mentions": onion_hits,
            "is_hacktivist": is_hacktivist,
            "note": (
                f"Not in MITRE ATT&CK, scored from community reporting: {basis} "
                "Capped at 0.75 since community reporting is weaker evidence "
                "than a curated ATT&CK profile."
            ),
        }

    def _hacktivist_note(self, assessment: dict, pulse_count: int, authors: int) -> str:
        """One line on what the hacktivist read was scored from."""
        parts = [f"{pulse_count} OTX pulses from {authors} authors"]
        if assessment.get("alignments"):
            parts.append(f"assessed {', '.join(assessment['alignments'][:2])}")
        if assessment.get("activities"):
            parts.append(f"activity {', '.join(assessment['activities'][:3])}")
        parts.append("dark web weight reassigned, these crews are on Telegram")
        return "; ".join(parts) + "."

    def score_threat_group(self, pivot_result: dict) -> dict:
        """
        Scores a threat group pivot based on MITRE ATT&CK coverage.
        Bypasses ML models since infrastructure features don't apply.
        Tuned thresholds: HIGH >= 0.5, MEDIUM >= 0.3.
        """
        results = pivot_result.get("results", {})
        mitre = results.get("mitre", {})
 
        if not mitre.get("found"):
            # ATT&CK absence is not evidence of absence. Hacktivist crews and
            # newly named actors are routinely missing from it, so fall back to
            # community reporting rather than returning a flat zero that reads
            # as "harmless".
            return self._score_group_from_community(pivot_result, results)
 
        # True totals from the connector. The len() fallback is for older
        # cached results only, and undercounts.
        technique_count = mitre.get("technique_count", len(mitre.get("techniques", [])))
        software_count = mitre.get("software_count", len(mitre.get("software", [])))
        alias_count = len(mitre.get("aliases", []))

        technique_score = min(technique_count / TECHNIQUE_FULL_MARKS, 1.0)
        software_score = min(software_count / SOFTWARE_FULL_MARKS, 1.0)
        alias_score = min(alias_count / ALIAS_FULL_MARKS, 1.0)
 
        confidence_score = (
            technique_score * 0.5 +
            software_score * 0.3 +
            alias_score * 0.2
        )
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.65, 0.4)),
            "technique_count": technique_count,
            "software_count": software_count,
            "alias_count": alias_count,
            "note": "Score derived from MITRE ATT&CK coverage — technique breadth, tooling, and documentation depth.",
        }
 
    def score_software(self, pivot_result: dict) -> dict:
        """
        Scores a software/malware family pivot based on MalwareBazaar data.
        Uses sample count and average VT detection ratio as signals.
        """
        results = pivot_result.get("results", {})
        bazaar = results.get("malwarebazaar", {})
 
        if not bazaar.get("found"):
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "Malware family not found in MalwareBazaar."
            }
 
        samples = bazaar.get("samples", [])
        # True total from the connector. The len() fallback is for older cached
        # results only, and undercounts.
        sample_count = bazaar.get("sample_count", len(samples))

        sample_score = min(sample_count / SAMPLE_VOLUME_FULL_MARKS, 1.0)

        # Tag risk signal — ransomware/rat/stealer tags elevate score.
        # Measured over the samples actually returned, not the true total,
        # which would dilute the ratio toward zero.
        high_risk_tags = {"ransomware", "rat", "stealer", "backdoor", "loader", "worm", "rootkit"}
        tag_hits = 0
        for sample in samples:
            tags = {t.lower() for t in sample.get("tags", [])}
            if tags & high_risk_tags:
                tag_hits += 1
        tag_score = tag_hits / len(samples) if samples else 0.0

        confidence_score = (sample_score * 0.5) + (tag_score * 0.5)
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.65, 0.4)),
            "sample_count": sample_count,
            "note": "Score derived from MalwareBazaar sample volume and malware category tags.",
        }
 
    def score_identity(self, pivot_result: dict) -> dict:
        """
        Scores email and username pivots based on SpiderFoot findings.
        Returns 0.0 when --deep was not used and SpiderFoot was skipped.
        """
        results = pivot_result.get("results", {})
        spiderfoot = results.get("spiderfoot", {})
 
        if spiderfoot.get("skipped"):
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "SpiderFoot skipped — re-run with --deep for identity enrichment.",
            }
 
        finding_count = spiderfoot.get("finding_count", 0)
        scan_status = spiderfoot.get("scan_status", "")
 
        if scan_status == "TIMEOUT" or finding_count == 0:
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "SpiderFoot scan timed out or returned no findings.",
            }
 
        # More findings = more exposed footprint = higher risk
        confidence_score = min(finding_count / 50, 1.0)
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.5, 0.3)),
            "finding_count": finding_count,
            "note": "Score derived from SpiderFoot identity footprint breadth.",
        }
 
    def score_any(self, pivot_result: dict) -> dict:
        """
        Centralized scoring router. Picks the right method based on
        indicator type so every pivot gets a meaningful score instead
        of defaulting to 0.0205 when infrastructure features are absent.
 
        Routing:
          threat_group -> score_threat_group (MITRE ATT&CK coverage)
          software     -> score_software     (MalwareBazaar sample volume)
          email/username/filename -> score_identity (SpiderFoot findings)
          ipv4/domain/hash/other  -> score (ML model, infrastructure features)
        """
        indicator_type = pivot_result.get("type", "")
 
        if indicator_type == "threat_group":
            return self.score_threat_group(pivot_result)
        elif indicator_type == "software":
            return self.score_software(pivot_result)
        elif indicator_type in {"email", "username", "filename"}:
            return self.score_identity(pivot_result)
        else:
            return self.score(pivot_result)
 